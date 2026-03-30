-- Sample data for local development / testing
-- SaasCo is the platform tenant; TenantA and TenantB are clients.

-- Step 1: Create tenants with fixed IDs for predictability
INSERT INTO public.tenants (id, name) VALUES
  ('00000000-0000-0000-0000-000000000000'::uuid, 'SaasCo'),
  ('00000000-0000-0000-0000-000000000001'::uuid, 'TenantA'),
  ('00000000-0000-0000-0000-000000000002'::uuid, 'TenantB')
ON CONFLICT (id) DO NOTHING;

-- Step 2: Pre-populate the email allowlist so users can sign in for the first time.
-- Replace the placeholder emails with real Google-authenticated addresses.
INSERT INTO public.tenant_email_allowlist (email, tenant_id, role) VALUES
  ('SAASCO_SUPERUSER_EMAIL',  '00000000-0000-0000-0000-000000000000', 'saasco_superuser'),
  ('SAASCO_EMPLOYEE_EMAIL',   '00000000-0000-0000-0000-000000000000', 'saasco_employee'),
  ('TENANT_A_SUPERUSER_EMAIL','00000000-0000-0000-0000-000000000001', 'tenant_superuser'),
  ('TENANT_A_ADMIN_EMAIL',    '00000000-0000-0000-0000-000000000001', 'tenant_admin'),
  ('TENANT_A_USER_EMAIL',     '00000000-0000-0000-0000-000000000001', 'user'),
  ('TENANT_B_USER_EMAIL',     '00000000-0000-0000-0000-000000000002', 'user')
ON CONFLICT (email) DO NOTHING;
