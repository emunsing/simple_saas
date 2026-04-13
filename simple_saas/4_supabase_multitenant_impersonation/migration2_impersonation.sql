-- ============================================================
-- IMPERSONATION SESSIONS TABLE
-- Audit log of all impersonation activity.
-- Rows are inserted/updated via the service role (bypasses RLS).
-- Authenticated users can read their own sessions via RLS.
-- Store the impersonation JWT server-side so it doesn't bloat the session
-- cookie. The cookie only holds a reference UUID; the middleware fetches the
-- token from this column on each page load.

-- ============================================================

CREATE TABLE public.impersonation_sessions (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  impersonator_id  uuid NOT NULL REFERENCES public.users(user_id) ON DELETE CASCADE,
  target_user_id   uuid NOT NULL REFERENCES public.users(user_id) ON DELETE CASCADE,
  target_email     text NOT NULL,
  target_tenant_id uuid NOT NULL REFERENCES public.tenants(id),
  reason           text NOT NULL DEFAULT '',
  access_token     text NOT NULL default '',
  started_at       timestamptz NOT NULL DEFAULT now(),
  expires_at       timestamptz NOT NULL DEFAULT (now() + interval '1 hour'),
  ended_at         timestamptz
);

ALTER TABLE public.impersonation_sessions ENABLE ROW LEVEL SECURITY;

-- Impersonator sees their own sessions; SaasCo staff see all
CREATE POLICY "impersonation_sessions_select"
  ON public.impersonation_sessions FOR SELECT
  TO authenticated
  USING (
    impersonator_id = (SELECT auth.uid())
    OR (SELECT public.is_saasco_staff())
  );

-- INSERT and UPDATE are performed via service role (bypasses RLS), so no
-- authenticated INSERT/UPDATE policy is needed.


-- ============================================================
-- AUDIT INFRASTRUCTURE: per-row attribution for mutations
--
-- The Python layer attaches an x-impersonator-id request header on every
-- Supabase call made while impersonation is active.  PostgREST exposes all
-- request headers as the request.headers GUC (a JSON string), letting
-- triggers read the real actor even when auth.uid() is the impersonated user.
-- ============================================================

-- Helper: extracts the impersonator's user_id from the request headers, or
-- returns NULL when the request is a normal (non-impersonated) call.
-- STABLE so it is evaluated once per statement (correct for trigger context).
CREATE OR REPLACE FUNCTION public.current_impersonator_id()
RETURNS uuid
LANGUAGE sql
STABLE
AS $$
  SELECT nullif(
    current_setting('request.headers', true)::json->>'x-impersonator-id',
    ''
  )::uuid;
$$;

-- ============================================================
-- AUDIT LOG TABLE
-- Captures INSERT / UPDATE / DELETE with dual-identity attribution.
-- ============================================================

CREATE TABLE public.audit_log (
  id               bigserial PRIMARY KEY,
  table_name       text        NOT NULL,
  operation        text        NOT NULL,  -- INSERT | UPDATE | DELETE
  -- auth.uid() at the time of the operation.
  -- This is the impersonated user's id when impersonation is active.
  actor_user_id    uuid,
  -- Non-null only when the operation was driven by an admin impersonating actor_user_id.
  -- Lets you ask: "did Alice change this row, or did a support staffer do it for her?"
  impersonator_id  uuid,
  changed_at       timestamptz NOT NULL DEFAULT now(),
  -- Full row snapshots so the log is self-contained.
  old_data         jsonb,
  new_data         jsonb
);

ALTER TABLE public.audit_log ENABLE ROW LEVEL SECURITY;

-- Users see rows where they were the actor or the impersonator; staff see all.
CREATE POLICY "audit_log_select"
  ON public.audit_log FOR SELECT
  TO authenticated
  USING (
    actor_user_id   = (SELECT auth.uid())
    OR impersonator_id = (SELECT auth.uid())
    OR (SELECT public.is_saasco_staff())
  );

-- Audit rows are written by SECURITY DEFINER triggers; no authenticated INSERT needed.


-- ============================================================
-- AUDIT TRIGGER FUNCTION
-- Shared by all audited tables.  Captures auth.uid() and the impersonator
-- header so every mutation has full dual-identity attribution.
-- ============================================================

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
    CASE WHEN TG_OP = 'DELETE' THEN to_jsonb(OLD)
         WHEN TG_OP = 'UPDATE' THEN to_jsonb(OLD)
         ELSE NULL
    END,
    CASE WHEN TG_OP = 'INSERT' THEN to_jsonb(NEW)
         WHEN TG_OP = 'UPDATE' THEN to_jsonb(NEW)
         ELSE NULL
    END
  );
  RETURN COALESCE(NEW, OLD);
END;
$$;

-- ============================================================
-- APPLY TRIGGERS
--
-- public.users: captures user creation (first login via handle_new_user) and
--   any future profile updates.  actor_user_id will be NULL for system-driven
--   INSERTs (supabase_auth_admin context); that is expected and correct.
--
-- public.tenant_email_allowlist: captures admin allowlist management.
--   During normal admin use (no impersonation), impersonator_id will be NULL;
--   if an admin somehow performs allowlist changes via an impersonation session
--   (future feature), both identities are recorded.
-- ============================================================

CREATE OR REPLACE TRIGGER audit_users
  AFTER INSERT OR UPDATE OR DELETE ON public.users
  FOR EACH ROW EXECUTE FUNCTION public.audit_trigger_fn();

CREATE OR REPLACE TRIGGER audit_tenant_email_allowlist
  AFTER INSERT OR UPDATE OR DELETE ON public.tenant_email_allowlist
  FOR EACH ROW EXECUTE FUNCTION public.audit_trigger_fn();
