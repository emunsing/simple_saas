CREATE TABLE public.tenants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid()
);

CREATE TABLE public.users (
  user_id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  tenant_id uuid NOT NULL REFERENCES public.tenants(id) ON DELETE RESTRICT,
  username text NOT NULL,
  user_email text NOT NULL,
  UNIQUE(tenant_id, username),
  UNIQUE(user_email)
);
CREATE INDEX idx_users_user_email ON public.users(user_email);

-- Lookup table: NO RLS, and explicitly disable it even if
-- Supabase auto-enables it
CREATE SCHEMA IF NOT EXISTS private;
CREATE TABLE private.user_tenant_map (
  user_id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  tenant_id uuid NOT NULL REFERENCES public.tenants(id) ON DELETE RESTRICT
);
-- Force RLS OFF on this table
ALTER TABLE private.user_tenant_map DISABLE ROW LEVEL SECURITY;

-- ============================================================
-- ENABLE RLS (except user_tenant_map)
-- ============================================================
ALTER TABLE public.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;

-- ============================================================
-- HELPER FUNCTIONS
-- Reads from user_tenant_map (no RLS) to avoid recursion.
-- Wrapping auth.uid() in (select ...) for performance per Supabase docs.
-- ============================================================
CREATE OR REPLACE FUNCTION public.current_user_tenant_id()
RETURNS uuid
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
STABLE
AS $$
  SELECT tenant_id FROM private.user_tenant_map
  WHERE user_id = (select auth.uid()) LIMIT 1;
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

-- Keep user_tenant_map in sync via trigger
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
-- POLICIES
-- Wrap function calls in (select ...) for performance.
-- ============================================================

-- Users: see same-tenant users
CREATE POLICY "users_select_same_tenant"
  ON public.users FOR SELECT
  TO authenticated
  USING (tenant_id = (select public.current_user_tenant_id()));

-- Tenants: see own tenant
CREATE POLICY "tenants_select_own"
  ON public.tenants FOR SELECT
  TO authenticated
  USING (id = (select public.current_user_tenant_id()));
