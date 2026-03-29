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
GRANT USAGE ON SCHEMA private TO supabase_auth_admin;
CREATE TABLE private.user_tenant_map (
  user_id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  tenant_id uuid NOT NULL REFERENCES public.tenants(id) ON DELETE RESTRICT
);
-- Force RLS OFF on this table
ALTER TABLE private.user_tenant_map DISABLE ROW LEVEL SECURITY;

create table private.tenant_email_allowlist (
  email       text primary key,
  tenant_id   uuid not null references tenants(id),
  created_at  timestamptz default now()
);
ALTER TABLE private.tenant_email_allowlist DISABLE ROW LEVEL SECURITY;
grant select on table private.tenant_email_allowlist to supabase_auth_admin;

create table if not exists private.auth_debug_log (
  id serial primary key,
  func_name text,
  payload jsonb,
  created_at timestamptz default now()
);
alter table private.auth_debug_log disable row level security;
grant insert on private.auth_debug_log to supabase_auth_admin;
grant usage on sequence private.auth_debug_log_id_seq to supabase_auth_admin;

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

create or replace function public.hook_check_allowlist(event jsonb)
returns jsonb
language plpgsql
as $$
declare
  user_email text;
  allowed boolean;
begin
  -- The before-user-created hook nests everything under "user"
  user_email := event->'user'->>'email';

  -- Fallback to user_metadata if needed
  if user_email is null then
    user_email := event->'user'->'user_metadata'->>'email';
  end if;

  select exists(
    select 1 from private.tenant_email_allowlist
    where email = lower(user_email)
  ) into allowed;

  if not allowed then
    return jsonb_build_object(
      'error', jsonb_build_object(
        'http_code', 403,
        'message', 'No account is associated with this email. Please contact your administrator.'
      )
    );
  end if;

  return event;
end;
$$;

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
as $$
declare
  matched_tenant_id uuid;
begin
  -- Look up the tenant for this email
  select tenant_id into matched_tenant_id
  from private.tenant_email_allowlist
  where email = lower(new.email);

  if matched_tenant_id is not null then
    -- Insert into your users/profiles table
    insert into public.users (user_id, user_email, username, tenant_id)
    values (new.id, new.email, '', matched_tenant_id);

    -- Clean up the allowlist entry
    delete from private.tenant_email_allowlist
    where email = lower(new.email);
  end if;

  return new;
end;
$$;

grant execute on function public.hook_check_allowlist to supabase_auth_admin;
revoke execute on function public.hook_check_allowlist from authenticated, anon, public;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

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
