-- ============================================================
-- MIGRATION 5: SOC-2 security hardening
--
-- Addresses critical and significant findings from the April 2026
-- architecture review (SOC2_AUDIT_README.md).
--
-- Changes:
--   1. [Critical]     handle_new_user() SECURITY DEFINER — add SET search_path
--                     to close search-path injection.
--   2. [Critical]     allowlist DELETE policy — add role-on-role enforcement
--                     mirroring the INSERT policy so tenant_admin cannot delete
--                     tenant_superuser entries (privilege escalation path).
--   3. [Significant]  Audit log immutability — revoke DELETE and UPDATE on
--                     audit_log from the application roles (SOC-2 CC7.2).
--   4. [Significant]  Drop impersonation_sessions.access_token — column was
--                     made nullable in migration3 but still invites credential
--                     storage; remove entirely.
--   5. [Significant]  Constant-time HMAC comparison in current_impersonator_id()
--                     — replace sig != expected with a hash-of-hash comparison to
--                     make the check length-independent.
--   6. [Moderate]     ReBAC project access at the database layer — replace the
--                     broad tenant-scope SELECT policy on projects with an
--                     owner-or-shared policy so the access boundary is enforced
--                     regardless of which query path is used.
--
-- Prerequisites: migration1.sql, migration2_impersonation.sql,
--                migration3_hmac_audit.sql, migration4_projects.sql
-- ============================================================


-- ============================================================
-- 1. Fix handle_new_user() search-path injection
--    The function is SECURITY DEFINER but previously lacked
--    SET search_path, allowing objects in an earlier search_path
--    entry to shadow public.tenant_email_allowlist or public.users.
-- ============================================================

CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  matched_tenant_id uuid;
  matched_role      public.user_role;
  matched_username  text;
BEGIN
  SELECT tenant_id, role, username
    INTO matched_tenant_id, matched_role, matched_username
    FROM public.tenant_email_allowlist
   WHERE email = lower(new.email);

  IF matched_tenant_id IS NOT NULL THEN
    INSERT INTO public.users (user_id, user_email, username, tenant_id, role)
    VALUES (new.id, new.email, matched_username, matched_tenant_id, COALESCE(matched_role, 'user'));

    DELETE FROM public.tenant_email_allowlist WHERE email = lower(new.email);
  END IF;

  RETURN new;
END;
$$;


-- ============================================================
-- 2. Allowlist DELETE policy — add role-on-role enforcement
--
--    Old policy allowed tenant_admin to delete any entry in
--    their tenant, including tenant_superuser entries (privilege
--    escalation: delete → re-add as 'user').
--
--    New policy mirrors the INSERT role-on-role constraints:
--      saasco_staff       → any entry (unchanged)
--      tenant_superuser   → tenant_admin or user entries only
--      tenant_admin       → user entries only
-- ============================================================

DROP POLICY IF EXISTS "allowlist_delete_admin" ON public.tenant_email_allowlist;

CREATE POLICY "allowlist_delete_admin"
  ON public.tenant_email_allowlist FOR DELETE
  TO authenticated
  USING (
    -- SaasCo staff may remove any entry
    (SELECT public.is_saasco_staff())
    OR (
      -- tenant_superuser may remove tenant_admin or user entries in own tenant
      (SELECT public.current_user_role()) = 'tenant_superuser'
      AND tenant_id = (SELECT public.current_user_tenant_id())
      AND role IN ('tenant_admin', 'user')
    )
    OR (
      -- tenant_admin may remove user entries in own tenant only
      (SELECT public.current_user_role()) = 'tenant_admin'
      AND tenant_id = (SELECT public.current_user_tenant_id())
      AND role = 'user'
    )
  );


-- ============================================================
-- 3. Audit log immutability (SOC-2 CC7.2)
--
--    Revoke UPDATE and DELETE privileges on audit_log from the
--    application-facing roles.  Audit rows are written by
--    SECURITY DEFINER triggers only; no application path requires
--    direct UPDATE/DELETE on this table.
--
--    Note: postgres/superuser still has full access via the
--    database owner role.  For a fully append-only design consider
--    replicating to an external SIEM that the application cannot
--    reach, or using pg_partman for rotation without deletion.
-- ============================================================

REVOKE UPDATE, DELETE ON public.audit_log FROM authenticated;
REVOKE UPDATE, DELETE ON public.audit_log FROM anon;
-- service_role bypasses RLS but removing the explicit table grant prevents
-- accidental DELETE in application code that uses the service-role client.
REVOKE UPDATE, DELETE ON public.audit_log FROM service_role;


-- ============================================================
-- 4. Drop impersonation_sessions.access_token
--
--    The column was made nullable in migration3 with the intent
--    of "never storing the JWT in DB", but its presence invites
--    future developers to populate it.  If populated, the audit
--    trigger would capture the JWT in audit_log.new_data (plaintext
--    in an append-only log).
--
--    Scrub any non-null residual values first, then drop the column.
-- ============================================================

UPDATE public.impersonation_sessions
SET access_token = NULL
WHERE access_token IS NOT NULL;

ALTER TABLE public.impersonation_sessions
  DROP COLUMN IF EXISTS access_token;


-- ============================================================
-- 5. Constant-time HMAC comparison in current_impersonator_id()
--
--    Replace `sig != expected` (plain string comparison, vulnerable
--    to timing side-channels) with a hash-of-hash comparison.
--    Both inputs are first hashed with SHA-256, making the compared
--    values the same fixed length and eliminating early-exit
--    length-based timing leakage.
-- ============================================================

CREATE OR REPLACE FUNCTION public.current_impersonator_id()
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
STABLE
AS $$
DECLARE
  raw      text;
  parts    text[];
  imp_uuid text;
  ts_str   text;
  sig      text;
  expected text;
  secret   text;
  max_age  int := 60; -- seconds; header is minted fresh on every request
BEGIN
  raw := current_setting('request.headers', true)::json->>'x-impersonator-id';
  IF raw IS NULL OR raw = '' THEN
    RETURN NULL;
  END IF;

  -- Expected format: uuid.timestamp.hmac  (UUIDs contain hyphens, not dots)
  parts := string_to_array(raw, '.');
  IF array_length(parts, 1) != 3 THEN
    RETURN NULL;
  END IF;

  imp_uuid := parts[1];
  ts_str   := parts[2];
  sig      := parts[3];

  -- Reject stale claims
  IF abs(extract(epoch from now())::bigint - ts_str::bigint) > max_age THEN
    RETURN NULL;
  END IF;

  -- Read the HMAC secret from Supabase Vault.
  SELECT decrypted_secret INTO secret
  FROM vault.decrypted_secrets
  WHERE name = 'impersonation_hmac_secret'
  LIMIT 1;

  IF secret IS NULL THEN
    RETURN NULL;
  END IF;

  -- Compute expected HMAC-SHA256
  expected := encode(
    hmac(
      (imp_uuid || '.' || ts_str)::bytea,
      secret::bytea,
      'sha256'
    ),
    'hex'
  );

  -- Constant-time comparison: hash both values so the compared strings are
  -- the same fixed length (32 bytes), eliminating length-based timing leakage.
  -- digest() is from pgcrypto (enabled in migration3).
  IF digest(sig::bytea, 'sha256') != digest(expected::bytea, 'sha256') THEN
    RETURN NULL;
  END IF;

  RETURN imp_uuid::uuid;
EXCEPTION
  WHEN others THEN
    -- Catches Vault unavailability, invalid UUID cast, or any unexpected error.
    RETURN NULL;
END;
$$;


-- ============================================================
-- 6. ReBAC project access enforced at the database layer
--
--    The previous projects SELECT policy granted access to all
--    projects within the user's tenant, relying on the Python
--    layer (list_accessible_projects) to filter to owned + shared.
--    Any new query path that bypassed the Python layer (direct
--    PostgREST call, future endpoint) would leak all tenant
--    projects to any tenant member.
--
--    Replace with a policy that enforces the owner-or-shared
--    boundary at the database level.  The Python layer's
--    list_accessible_projects() filter becomes redundant but
--    harmless — it no longer needs to be the sole enforcement
--    point.
-- ============================================================

DROP POLICY IF EXISTS "projects_select_tenant" ON public.projects;

CREATE POLICY "projects_select_rebac"
  ON public.projects FOR SELECT
  TO authenticated
  USING (
    -- Hard tenant boundary: never show cross-tenant rows
    tenant_id = (SELECT public.current_user_tenant_id())
    AND (
      -- Creator always sees their own projects
      created_by = (SELECT auth.uid())
      -- Explicitly shared projects
      OR EXISTS (
        SELECT 1 FROM public.project_roles
        WHERE project_id = id
          AND user_id = (SELECT auth.uid())
      )
    )
  );

-- Note: SaasCo staff have no direct project visibility (unchanged from
-- migration4).  To debug tenant project state they must impersonate a
-- tenant user, which then routes through the ReBAC policy above.
