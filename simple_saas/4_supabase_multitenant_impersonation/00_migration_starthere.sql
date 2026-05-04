-- ============================================================
-- COMPLETE SCHEMA MIGRATION — start from a clean database
--
-- One-time manual step after applying this migration:
--   Store the HMAC secret in Supabase Vault so current_impersonator_id()
--   can verify signed impersonation headers:
--
--     SELECT vault.create_secret('<your-secret>', 'impersonation_hmac_secret');
--
--   Use the same value as IMPERSONATION_HMAC_SECRET in your Python .env.
--   Generate a secret with: openssl rand -hex 32
-- ============================================================


-- ============================================================
-- EXTENSIONS
-- ============================================================
CREATE EXTENSION IF NOT EXISTS pgcrypto;


-- ============================================================
-- SCHEMAS
-- ============================================================
CREATE SCHEMA IF NOT EXISTS private;
GRANT USAGE ON SCHEMA private TO supabase_auth_admin;


-- ============================================================
-- TYPES
-- ============================================================
CREATE TYPE public.user_role AS ENUM (
  'saasco_superuser',
  'saasco_employee',
  'tenant_superuser',
  'tenant_admin',
  'user'
);


-- ============================================================
-- TABLES
-- (in dependency order)
-- ============================================================

CREATE TABLE public.tenants (
  id   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL DEFAULT ''
);

CREATE TABLE public.users (
  user_id    uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  tenant_id  uuid NOT NULL REFERENCES public.tenants(id) ON DELETE RESTRICT,
  username   text NOT NULL,
  user_email text NOT NULL,
  role       public.user_role NOT NULL DEFAULT 'user',
  UNIQUE(tenant_id, username),
  UNIQUE(user_email)
);
CREATE INDEX idx_users_user_email ON public.users(user_email);

-- Pending signups: lives in public so RLS can gate REST API access.
-- supabase_auth_admin reads it via SECURITY DEFINER hook functions.
CREATE TABLE public.tenant_email_allowlist (
  email      text PRIMARY KEY,
  tenant_id  uuid NOT NULL REFERENCES public.tenants(id),
  username   text NOT NULL,
  role       public.user_role NOT NULL DEFAULT 'user',
  created_at timestamptz DEFAULT now(),
  UNIQUE(tenant_id, username)
);

-- Fast tenant lookup used by RLS helpers (no RLS needed here).
CREATE TABLE private.user_tenant_map (
  user_id   uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  tenant_id uuid NOT NULL REFERENCES public.tenants(id) ON DELETE RESTRICT
);
ALTER TABLE private.user_tenant_map DISABLE ROW LEVEL SECURITY;

-- Audit log of all impersonation activity.
-- Rows are inserted/updated via the service role (bypasses RLS).
-- Note: access_token is intentionally omitted — JWTs live in process memory only.
CREATE TABLE public.impersonation_sessions (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  impersonator_id  uuid NOT NULL REFERENCES public.users(user_id) ON DELETE CASCADE,
  target_user_id   uuid NOT NULL REFERENCES public.users(user_id) ON DELETE CASCADE,
  target_email     text NOT NULL,
  target_tenant_id uuid NOT NULL REFERENCES public.tenants(id),
  reason           text NOT NULL DEFAULT '',
  started_at       timestamptz NOT NULL DEFAULT now(),
  expires_at       timestamptz NOT NULL DEFAULT (now() + interval '1 hour'),
  ended_at         timestamptz
);

-- Append-only audit log capturing INSERT / UPDATE / DELETE with
-- dual-identity attribution (actor + impersonator).
CREATE TABLE public.audit_log (
  id               bigserial PRIMARY KEY,
  table_name       text        NOT NULL,
  operation        text        NOT NULL,  -- INSERT | UPDATE | DELETE
  -- auth.uid() at the time of the operation.
  -- This is the impersonated user's id when impersonation is active.
  actor_user_id    uuid,
  -- Non-null only when the operation was driven by an admin impersonating actor_user_id.
  impersonator_id  uuid,
  changed_at       timestamptz NOT NULL DEFAULT now(),
  old_data         jsonb,
  new_data         jsonb
);

-- Projects — ReBAC demo
CREATE TABLE public.projects (
  id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  uuid        NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
  name       text        NOT NULL,
  created_by uuid        NOT NULL REFERENCES public.users(user_id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE public.project_roles (
  project_id uuid        NOT NULL REFERENCES public.projects(id) ON DELETE CASCADE,
  user_id    uuid        NOT NULL REFERENCES public.users(user_id) ON DELETE CASCADE,
  granted_by uuid        NOT NULL REFERENCES public.users(user_id) ON DELETE CASCADE,
  granted_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (project_id, user_id)
);


-- ============================================================
-- ENABLE ROW LEVEL SECURITY
-- ============================================================
ALTER TABLE public.tenants                ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.users                  ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_email_allowlist ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.impersonation_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_log              ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.projects               ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.project_roles          ENABLE ROW LEVEL SECURITY;


-- ============================================================
-- HELPER FUNCTIONS (SECURITY DEFINER, bypass RLS)
-- Used inside RLS policy USING/WITH CHECK expressions.
-- Wrap auth.uid() in (select ...) per Supabase performance docs.
-- ============================================================

-- Current user's tenant id (reads private map to avoid RLS recursion).
CREATE OR REPLACE FUNCTION public.current_user_tenant_id()
RETURNS uuid
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
STABLE
AS $$
  SELECT tenant_id FROM private.user_tenant_map
  WHERE user_id = (SELECT auth.uid()) LIMIT 1;
$$;

-- Current user's role.
CREATE OR REPLACE FUNCTION public.current_user_role()
RETURNS public.user_role
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
STABLE
AS $$
  SELECT role FROM public.users
  WHERE user_id = (SELECT auth.uid()) LIMIT 1;
$$;

-- Convenience predicate: is the current user SaasCo staff?
CREATE OR REPLACE FUNCTION public.is_saasco_staff()
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
STABLE
AS $$
  SELECT (SELECT public.current_user_role()) IN ('saasco_superuser', 'saasco_employee');
$$;

-- Returns true if check_user_id belongs to check_tenant_id.
CREATE OR REPLACE FUNCTION public.user_belongs_to_tenant(
  check_user_id uuid, check_tenant_id uuid
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
STABLE
AS $$
  SELECT EXISTS (
    SELECT 1 FROM private.user_tenant_map
    WHERE user_id = check_user_id AND tenant_id = check_tenant_id
  );
$$;

-- Returns true if (p_tenant_id, p_username) is available in both users and
-- the allowlist.  Non-staff users may only query their own tenant; foreign-
-- tenant queries always return false to prevent cross-tenant enumeration.
-- p_exclude_email: skip this allowlist row (upsert / edit semantics).
CREATE OR REPLACE FUNCTION public.check_username_available(
  p_tenant_id     uuid,
  p_username      text,
  p_exclude_email text DEFAULT NULL
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
STABLE
AS $$
BEGIN
  IF NOT (SELECT public.is_saasco_staff())
     AND p_tenant_id IS DISTINCT FROM (SELECT public.current_user_tenant_id())
  THEN
    RETURN false;
  END IF;

  RETURN NOT EXISTS (
    SELECT 1 FROM public.users
    WHERE tenant_id = p_tenant_id AND username = p_username
    UNION ALL
    SELECT 1 FROM public.tenant_email_allowlist
    WHERE tenant_id = p_tenant_id
      AND username = p_username
      AND (p_exclude_email IS NULL OR email != lower(p_exclude_email))
  );
END;
$$;

GRANT EXECUTE ON FUNCTION public.check_username_available TO authenticated;

-- Extracts and verifies the impersonator's user_id from the HMAC-signed
-- x-impersonator-id request header.  Returns NULL for normal requests or
-- when the header is missing, malformed, stale (>60 s), or has a bad signature.
--
-- Header format:  <uuid>.<unix_timestamp>.<hmac_sha256_hex>
-- Secret stored in Supabase Vault under name 'impersonation_hmac_secret'.
-- Constant-time comparison (hash-of-hash) prevents timing side-channels.
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
  -- SECURITY DEFINER is required because vault.decrypted_secrets is not
  -- accessible to the authenticated role.
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

-- Returns true if the current user holds a project_role for p_project_id.
-- SECURITY DEFINER bypasses RLS on project_roles, breaking the cycle that
-- would otherwise form between projects_select_rebac and project_roles_select_tenant.
CREATE OR REPLACE FUNCTION public.current_user_has_project_role(p_project_id uuid)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
STABLE
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.project_roles
    WHERE project_id = p_project_id
      AND user_id = (SELECT auth.uid())
  );
$$;

GRANT EXECUTE ON FUNCTION public.current_user_has_project_role TO authenticated;


-- ============================================================
-- AUTH HOOK: block signups not on the allowlist
-- SECURITY DEFINER so it bypasses RLS when called by supabase_auth_admin.
-- ============================================================
CREATE OR REPLACE FUNCTION public.hook_check_allowlist(event jsonb)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  user_email text;
  allowed    boolean;
BEGIN
  user_email := event->'user'->>'email';
  IF user_email IS NULL THEN
    user_email := event->'user'->'user_metadata'->>'email';
  END IF;

  SELECT EXISTS(
    SELECT 1 FROM public.tenant_email_allowlist
    WHERE email = lower(user_email)
  ) INTO allowed;

  IF NOT allowed THEN
    RETURN jsonb_build_object(
      'error', jsonb_build_object(
        'http_code', 403,
        'message', 'No account is associated with this email. Please contact your administrator.'
      )
    );
  END IF;

  RETURN event;
END;
$$;

GRANT EXECUTE ON FUNCTION public.hook_check_allowlist TO supabase_auth_admin;
REVOKE EXECUTE ON FUNCTION public.hook_check_allowlist FROM authenticated, anon, public;


-- ============================================================
-- TRIGGER FUNCTIONS
-- ============================================================

-- Populate public.users on first login by looking up the allowlist entry.
-- SECURITY DEFINER + SET search_path prevents search-path injection.
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

-- Keep private.user_tenant_map in sync with public.users.
CREATE OR REPLACE FUNCTION public.sync_user_tenant_map()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  INSERT INTO private.user_tenant_map (user_id, tenant_id)
  VALUES (NEW.user_id, NEW.tenant_id)
  ON CONFLICT (user_id) DO UPDATE SET tenant_id = EXCLUDED.tenant_id;
  RETURN NEW;
END;
$$;

-- Shared audit trigger function.  Captures auth.uid() and the impersonator
-- header so every mutation has full dual-identity attribution.
-- actor_user_id will be NULL for system-driven INSERTs (e.g. handle_new_user
-- running under supabase_auth_admin); that is expected and correct.
CREATE OR REPLACE FUNCTION public.audit_trigger_fn()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  INSERT INTO public.audit_log
    (table_name, operation, actor_user_id, impersonator_id, old_data, new_data)
  VALUES (
    TG_TABLE_NAME,
    TG_OP,
    (SELECT auth.uid()),
    (SELECT public.current_impersonator_id()),
    CASE WHEN TG_OP IN ('DELETE', 'UPDATE') THEN to_jsonb(OLD) ELSE NULL END,
    CASE WHEN TG_OP IN ('INSERT', 'UPDATE') THEN to_jsonb(NEW) ELSE NULL END
  );
  RETURN COALESCE(NEW, OLD);
END;
$$;


-- ============================================================
-- TRIGGERS
-- ============================================================

CREATE OR REPLACE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

CREATE OR REPLACE TRIGGER sync_user_tenant_map_on_upsert
  AFTER INSERT OR UPDATE ON public.users
  FOR EACH ROW EXECUTE FUNCTION public.sync_user_tenant_map();

CREATE OR REPLACE TRIGGER audit_tenants
  AFTER INSERT OR UPDATE OR DELETE ON public.tenants
  FOR EACH ROW EXECUTE FUNCTION public.audit_trigger_fn();

CREATE OR REPLACE TRIGGER audit_users
  AFTER INSERT OR UPDATE OR DELETE ON public.users
  FOR EACH ROW EXECUTE FUNCTION public.audit_trigger_fn();

CREATE OR REPLACE TRIGGER audit_tenant_email_allowlist
  AFTER INSERT OR UPDATE OR DELETE ON public.tenant_email_allowlist
  FOR EACH ROW EXECUTE FUNCTION public.audit_trigger_fn();

CREATE OR REPLACE TRIGGER audit_impersonation_sessions
  AFTER INSERT OR UPDATE OR DELETE ON public.impersonation_sessions
  FOR EACH ROW EXECUTE FUNCTION public.audit_trigger_fn();

CREATE OR REPLACE TRIGGER audit_projects
  AFTER INSERT OR UPDATE OR DELETE ON public.projects
  FOR EACH ROW EXECUTE FUNCTION public.audit_trigger_fn();

CREATE OR REPLACE TRIGGER audit_project_roles
  AFTER INSERT OR UPDATE OR DELETE ON public.project_roles
  FOR EACH ROW EXECUTE FUNCTION public.audit_trigger_fn();


-- ============================================================
-- RLS POLICIES
-- Wrap helper calls in (select ...) for per-statement caching.
-- Multiple SELECT policies combine with OR.
-- ============================================================

-- ---- public.tenants ----

CREATE POLICY "tenants_select_own"
  ON public.tenants FOR SELECT
  TO authenticated
  USING (id = (SELECT public.current_user_tenant_id()));

CREATE POLICY "tenants_select_saasco_staff"
  ON public.tenants FOR SELECT
  TO authenticated
  USING ((SELECT public.is_saasco_staff()));

-- Only SaasCo staff may create tenants.
CREATE POLICY "tenants_insert_saasco_staff"
  ON public.tenants FOR INSERT
  TO authenticated
  WITH CHECK ((SELECT public.is_saasco_staff()));

-- ---- public.users ----

CREATE POLICY "users_select_same_tenant"
  ON public.users FOR SELECT
  TO authenticated
  USING (tenant_id = (SELECT public.current_user_tenant_id()));

CREATE POLICY "users_select_saasco_staff"
  ON public.users FOR SELECT
  TO authenticated
  USING ((SELECT public.is_saasco_staff()));

-- ---- public.tenant_email_allowlist ----

-- SELECT: SaasCo staff see all; tenant admins/superusers see their own tenant.
CREATE POLICY "allowlist_select_saasco_staff"
  ON public.tenant_email_allowlist FOR SELECT
  TO authenticated
  USING ((SELECT public.is_saasco_staff()));

CREATE POLICY "allowlist_select_tenant_admin"
  ON public.tenant_email_allowlist FOR SELECT
  TO authenticated
  USING (
    tenant_id = (SELECT public.current_user_tenant_id())
    AND (SELECT public.current_user_role()) IN ('tenant_superuser', 'tenant_admin')
  );

-- INSERT: role-on-role constraints
--   saasco_superuser → any role, any tenant
--   saasco_employee  → any role except saasco_superuser, any tenant
--   tenant_superuser → tenant_admin or user, own tenant only
--   tenant_admin     → user only, own tenant only
CREATE POLICY "allowlist_insert_admin"
  ON public.tenant_email_allowlist FOR INSERT
  TO authenticated
  WITH CHECK (
    (SELECT public.current_user_role()) = 'saasco_superuser'
    OR (
      (SELECT public.current_user_role()) = 'saasco_employee'
      AND role IN ('tenant_superuser', 'tenant_admin', 'user')
    )
    OR (
      (SELECT public.current_user_role()) = 'tenant_superuser'
      AND tenant_id = (SELECT public.current_user_tenant_id())
      AND role IN ('tenant_admin', 'user')
    )
    OR (
      (SELECT public.current_user_role()) = 'tenant_admin'
      AND tenant_id = (SELECT public.current_user_tenant_id())
      AND role = 'user'
    )
  );

-- DELETE: mirrors INSERT role-on-role constraints to prevent privilege escalation
--   (e.g. tenant_admin deleting a tenant_superuser entry then re-adding as 'user').
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

-- ---- public.impersonation_sessions ----

-- Impersonator sees their own sessions; SaasCo staff see all.
-- INSERT and UPDATE are performed via service role (bypasses RLS).
CREATE POLICY "impersonation_sessions_select"
  ON public.impersonation_sessions FOR SELECT
  TO authenticated
  USING (
    impersonator_id = (SELECT auth.uid())
    OR (SELECT public.is_saasco_staff())
  );

-- ---- public.audit_log ----

-- Users see rows where they were the actor or the impersonator; staff see all.
-- Audit rows are written by SECURITY DEFINER triggers only.
CREATE POLICY "audit_log_select"
  ON public.audit_log FOR SELECT
  TO authenticated
  USING (
    actor_user_id   = (SELECT auth.uid())
    OR impersonator_id = (SELECT auth.uid())
    OR (SELECT public.is_saasco_staff())
  );

-- ---- public.projects ----

-- ReBAC: owner-or-shared, within tenant boundary.
-- SaasCo staff have no direct project visibility; they must impersonate
-- a tenant user, which routes through this same policy.
CREATE POLICY "projects_select_rebac"
  ON public.projects FOR SELECT
  TO authenticated
  USING (
    -- Hard tenant boundary
    tenant_id = (SELECT public.current_user_tenant_id())
    AND (
      -- Creator always sees their own projects
      created_by = (SELECT auth.uid())
      -- Shared projects — via SECURITY DEFINER helper to avoid RLS cycle
      OR (SELECT public.current_user_has_project_role(id))
    )
  );

-- Users may only create projects in their own tenant, attributed to themselves.
CREATE POLICY "projects_insert_own"
  ON public.projects FOR INSERT
  TO authenticated
  WITH CHECK (
    tenant_id  = (SELECT public.current_user_tenant_id())
    AND created_by = (SELECT auth.uid())
  );

-- Only the project creator may delete it.
CREATE POLICY "projects_delete_owner"
  ON public.projects FOR DELETE
  TO authenticated
  USING (created_by = (SELECT auth.uid()));

-- ---- public.project_roles ----

-- Tenant-scoped visibility: you can see sharing records for projects in your tenant.
CREATE POLICY "project_roles_select_tenant"
  ON public.project_roles FOR SELECT
  TO authenticated
  USING (
    project_id IN (
      SELECT id FROM public.projects
      WHERE tenant_id = (SELECT public.current_user_tenant_id())
    )
  );

-- Only the project creator may add sharing records.
CREATE POLICY "project_roles_insert_owner"
  ON public.project_roles FOR INSERT
  TO authenticated
  WITH CHECK (
    project_id IN (
      SELECT id FROM public.projects
      WHERE created_by = (SELECT auth.uid())
    )
  );

-- Only the project creator may revoke sharing.
CREATE POLICY "project_roles_delete_owner"
  ON public.project_roles FOR DELETE
  TO authenticated
  USING (
    project_id IN (
      SELECT id FROM public.projects
      WHERE created_by = (SELECT auth.uid())
    )
  );


-- ============================================================
-- AUDIT LOG IMMUTABILITY (SOC-2 CC7.2)
--
-- Revoke UPDATE and DELETE from application-facing roles.
-- Audit rows are written by SECURITY DEFINER triggers only.
-- The postgres/superuser role retains full access via ownership.
-- ============================================================
REVOKE UPDATE, DELETE ON public.audit_log FROM authenticated;
REVOKE UPDATE, DELETE ON public.audit_log FROM anon;
-- Prevent accidental DELETE in application code using the service-role client.
REVOKE UPDATE, DELETE ON public.audit_log FROM service_role;
