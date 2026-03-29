-- Enable RLS on all tables
alter table public.tenants enable row level security;
alter table public.users enable row level security;
alter table public.products enable row level security;
alter table public.product_user_map enable row level security;

-- Helper function: Get current user's tenant_id (bypasses RLS to avoid recursion)
-- SECURITY DEFINER runs with the function owner's privileges, bypassing RLS
create or replace function public.current_user_tenant_id()
returns uuid
language sql
security definer
set search_path = public
stable
as $$
  select tenant_id from public.users where user_id = auth.uid() limit 1;
$$;

-- Helper function: Check if a user_id belongs to a tenant_id (bypasses RLS)
create or replace function public.user_belongs_to_tenant(check_user_id uuid, check_tenant_id uuid)
returns boolean
language sql
security definer
set search_path = public
stable
as $$
  select exists (
    select 1 from public.users
    where user_id = check_user_id and tenant_id = check_tenant_id
  );
$$;

-- Admin helper: Get tenant_id from email (for admin operations, not RLS)
-- This allows admins to manage users by email without needing auth.uid()
create or replace function public.tenant_id_from_email(check_email text)
returns uuid
language sql
security definer
set search_path = public
stable
as $$
  select tenant_id from public.users where user_email = check_email limit 1;
$$;

-- Admin helper: Get user_id from email (for admin operations)
create or replace function public.user_id_from_email(check_email text)
returns uuid
language sql
security definer
set search_path = public
stable
as $$
  select user_id from public.users where user_email = check_email limit 1;
$$;

-- Auto-sync email from auth.users when user signs in (optional trigger)
-- This ensures user_email stays in sync with auth.users.email
create or replace function public.sync_user_email()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  -- Update user_email from auth.users.email if it exists
  update public.users
  set user_email = (select email from auth.users where id = new.user_id)
  where user_id = new.user_id
    and (user_email is null or user_email != (select email from auth.users where id = new.user_id));
  return new;
end;
$$;

-- Trigger to sync email on insert (when admin adds user before they sign in)
-- Note: This requires the user to exist in auth.users first
create trigger sync_user_email_on_insert
  after insert on public.users
  for each row
  execute function public.sync_user_email();

-- Users: can see users in the same tenant (for sharing dropdown)
-- Uses helper function to avoid recursion
create policy "users_select_same_tenant"
  on public.users for select
  using (tenant_id = public.current_user_tenant_id());

-- Tenants: users can see their own tenant
create policy "tenants_select_own"
  on public.tenants for select
  using (id = public.current_user_tenant_id());

-- Products: select if same tenant OR in product_user_map
create policy "products_select"
  on public.products for select
  using (
    tenant_id = public.current_user_tenant_id()
    or product_id in (
      select product_id from public.product_user_map where user_id = auth.uid()
    )
  );

-- Products: insert allowed for users in public.users; new row must use their tenant_id and created_by = self
create policy "products_insert"
  on public.products for insert
  with check (
    public.current_user_tenant_id() is not null
    and tenant_id = public.current_user_tenant_id()
    and created_by = auth.uid()
  );

-- product_user_map: select if user is the row's user_id or product owner
create policy "product_user_map_select"
  on public.product_user_map for select
  using (
    user_id = auth.uid()
    or product_id in (select product_id from public.products where created_by = auth.uid())
  );

-- product_user_map: insert only if current user is product creator (share)
-- Check: product belongs to current user AND target user is in same tenant as product
create policy "product_user_map_insert"
  on public.product_user_map for insert
  with check (
    exists (
      select 1
      from public.products p
      where p.product_id = product_user_map.product_id
        and p.created_by = auth.uid()
        and p.tenant_id = public.current_user_tenant_id()
    )
    and public.user_belongs_to_tenant(
      product_user_map.user_id,
      (select tenant_id from public.products where product_id = product_user_map.product_id)
    )
  );

-- product_user_map: delete only if current user is product creator (unshare)
create policy "product_user_map_delete"
  on public.product_user_map for delete
  using (
    product_id in (select product_id from public.products where created_by = auth.uid())
  );