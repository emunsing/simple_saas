-- Step 1: Create tenants (with fixed IDs for predictability)
insert into public.tenants (id) values
  ('00000000-0000-0000-0000-000000000001'::uuid),
  ('00000000-0000-0000-0000-000000000002'::uuid)
on conflict (id) do nothing;

-- Step 2: Admin workflow - Add users by email (they'll be linked when they sign in)
-- Option A: Pre-create users (they'll be linked when they sign in with matching email)
-- This requires knowing the auth.uid() first (sign in once, then get UUID from Dashboard)

-- Tenant 1 users:
insert into public.users (user_id, tenant_id, username, user_email)
values
  ('<REPLACE_WITH_AUTH_UID_FOR_USER1>'::uuid, '00000000-0000-0000-0000-000000000001'::uuid, 'name1', 'email1'),
  ('<REPLACE_WITH_AUTH_UID_FOR_USER2>'::uuid, '00000000-0000-0000-0000-000000000001'::uuid, 'name2', 'email2')
on conflict (user_id) do update set
  tenant_id = excluded.tenant_id,
  username = excluded.username,
  user_email = excluded.user_email;

-- Tenant 2 users:
insert into public.users (user_id, tenant_id, username, user_email)
values
  ('<REPLACE_WITH_AUTH_UID_FOR_USER3>'::uuid, '00000000-0000-0000-0000-000000000002'::uuid, 'name3', 'email3'),
  ('<REPLACE_WITH_AUTH_UID_FOR_USER4>'::uuid, '00000000-0000-0000-0000-000000000002'::uuid, 'name4', 'email4')
on conflict (user_id) do update set
  tenant_id = excluded.tenant_id,
  username = excluded.username,
  user_email = excluded.user_email;

-- Option B: Post-signin workflow (after users sign in, link them by email)
-- After a user signs in with Google/Microsoft/email, run:
-- update public.users set tenant_id = '00000000-0000-0000-0000-000000000001'::uuid, username = 'eric.munsing'
-- where user_email = 'eric.munsing@gmail.com' and user_id = (select id from auth.users where email = 'eric.munsing@gmail.com');

-- Helper queries for admin:
-- Find auth.uid() for an email: select id, email from auth.users where email = 'eric.munsing@gmail.com';
-- Find tenant for an email: select public.tenant_id_from_email('eric.munsing@gmail.com');
-- List all users in a tenant: select user_email, username from public.users where tenant_id = '00000000-0000-0000-0000-000000000001'::uuid;