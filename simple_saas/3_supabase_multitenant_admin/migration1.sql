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
  role       public.user_role NOT NULL DEFAULT 'user',
  created_at timestamptz DEFAULT now()
);

-- ============================================================
-- PRIVATE SCHEMA
-- Only non-REST internal tables live here.
-- ============================================================
CREATE SCHEMA IF NOT EXISTS private;
GRANT USAGE ON SCHEMA private TO supabase_auth_admin;

-- Fast tenant lookup used by RLS helper (no RLS needed here)
CREATE TABLE private.user_tenant_map (
  user_id   uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  tenant_id uuid NOT NULL REFERENCES public.tenants(id) ON DELETE RESTRICT
);
ALTER TABLE private.user_tenant_map DISABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS private.auth_debug_log (
  id         serial PRIMARY KEY,
  func_name  text,
  payload    jsonb,
  created_at timestamptz DEFAULT now()
);
ALTER TABLE private.auth_debug_log DISABLE ROW LEVEL SECURITY;
GRANT INSERT ON private.auth_debug_log TO supabase_auth_admin;
GRANT USAGE ON SEQUENCE private.auth_debug_log_id_seq TO supabase_auth_admin;

-- ============================================================
-- ENABLE RLS
-- ============================================================
ALTER TABLE public.tenants               ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.users                 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_email_allowlist ENABLE ROW LEVEL SECURITY;

-- ============================================================
-- HELPER FUNCTIONS (SECURITY DEFINER, bypass RLS)
-- Used inside RLS policy USING/WITH CHECK expressions.
-- Wrap auth.uid() in (select ...) per Supabase performance docs.
-- ============================================================

-- Current user's tenant id (reads private map to avoid RLS recursion)
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

-- Current user's role
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
--  insert into private.auth_debug_log (func_name, payload)
--  values ('hook_check_allowlist', event);
  user_email := event->'user'->>'email';
  IF user_email IS NULL THEN
    user_email := event->'user'->'user_metadata'->>'email';
  END IF;

--  insert into private.auth_debug_log (func_name, payload)
--    values ('hook_check_allowlist_extracted', jsonb_build_object(
--      'extracted_email', user_email,
--      'raw_user_meta_data', event->'raw_user_meta_data',
--      'top_level_email', event->>'email'
--    ));

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
-- TRIGGER: populate public.users on first login
-- SECURITY DEFINER bypasses RLS to read allowlist and write users.
-- ============================================================
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  matched_tenant_id uuid;
  matched_role      public.user_role;
BEGIN
  SELECT tenant_id, role
    INTO matched_tenant_id, matched_role
    FROM public.tenant_email_allowlist
   WHERE email = lower(new.email);

  IF matched_tenant_id IS NOT NULL THEN
    INSERT INTO public.users (user_id, user_email, username, tenant_id, role)
    VALUES (new.id, new.email, '', matched_tenant_id, COALESCE(matched_role, 'user'));

    DELETE FROM public.tenant_email_allowlist WHERE email = lower(new.email);
  END IF;

  RETURN new;
END;
$$;

CREATE OR REPLACE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- ============================================================
-- TRIGGER: keep private.user_tenant_map in sync
-- ============================================================
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

CREATE TRIGGER sync_user_tenant_map_on_upsert
  AFTER INSERT OR UPDATE ON public.users
  FOR EACH ROW
  EXECUTE FUNCTION public.sync_user_tenant_map();

-- ============================================================
-- RLS POLICIES
-- Wrap helper calls in (select ...) for per-statement caching.
-- Multiple SELECT policies combine with OR: a row is visible if
-- ANY passing policy matches.
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

-- Only SaasCo staff may create tenants
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

-- SELECT: SaasCo staff see all; tenant admins/superusers see their own tenant
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

-- INSERT: role-on-role constraints expressed directly in WITH CHECK
--   saasco_superuser  → any role, any tenant
--   saasco_employee   → any role except saasco_superuser, any tenant
--   tenant_superuser  → tenant_admin or user, own tenant only
--   tenant_admin      → user only, own tenant only
CREATE POLICY "allowlist_insert_admin"
  ON public.tenant_email_allowlist FOR INSERT
  TO authenticated
  WITH CHECK (
    (SELECT public.current_user_role()) = 'saasco_superuser'
    OR (
      (SELECT public.current_user_role()) = 'saasco_employee'
      AND role != 'saasco_superuser'
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

-- DELETE: SaasCo staff can remove any entry; tenant admins/superusers only their tenant
CREATE POLICY "allowlist_delete_admin"
  ON public.tenant_email_allowlist FOR DELETE
  TO authenticated
  USING (
    (SELECT public.is_saasco_staff())
    OR (
      tenant_id = (SELECT public.current_user_tenant_id())
      AND (SELECT public.current_user_role()) IN ('tenant_superuser', 'tenant_admin')
    )
  );
