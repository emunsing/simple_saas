-- Sample data for local development / testing
-- SaasCo is the platform tenant; TenantA and TenantB are clients.

-- Step 1: Create tenants with fixed IDs for predictability
INSERT INTO public.tenants (id, name) VALUES
  ('00000000-0000-0000-0000-000000000000'::uuid, 'SaasCo'),
ON CONFLICT (id) DO NOTHING;

-- Step 2: Pre-populate the email allowlist so users can sign in for the first time.
-- Replace the placeholder emails with real Google-authenticated addresses.
INSERT INTO public.tenant_email_allowlist (email, username, tenant_id, role) VALUES
  ('SAASCO_SUPERUSER_EMAIL', 'SAASCO_SUPERUSER_USERNAME', '00000000-0000-0000-0000-000000000000', 'saasco_superuser'),
ON CONFLICT (email) DO NOTHING;
