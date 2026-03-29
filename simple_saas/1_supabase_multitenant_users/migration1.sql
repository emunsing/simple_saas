-- Multi-tenant ReBAC: tenants, users, products, product_user_map
-- Users are defined in DB; auth.uid() links to public.users.user_id (from Supabase Auth).

create table if not exists public.tenants (
  id uuid primary key default gen_random_uuid()
);

create table if not exists public.users (
  user_id uuid primary key references auth.users(id) on delete cascade,
  tenant_id uuid not null references public.tenants(id) on delete restrict,
  username text not null,
  user_email text not null,  -- Required for email-based admin management
  unique(tenant_id, username),
  unique(user_email)  -- Email must be unique across all tenants for admin lookups
);

-- Index for fast email lookups (used by admin functions)
create index if not exists idx_users_user_email on public.users(user_email);

create table if not exists public.products (
  product_id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete restrict,
  created_by uuid not null references public.users(user_id) on delete restrict
);

create table if not exists public.product_user_map (
  product_id uuid not null references public.products(product_id) on delete cascade,
  user_id uuid not null references public.users(user_id) on delete cascade,
  primary key (product_id, user_id)
);

comment on table public.tenants is 'Organizations (tenants).';
comment on table public.users is 'App users; user_id = auth.uid(). Admins manage by email. user_email must match auth.users.email.';
comment on table public.products is 'Products belong to a tenant; created_by is the owner.';
comment on table public.product_user_map is 'Which users can access which products (creator + shared).';
