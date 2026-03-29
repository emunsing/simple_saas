-- Step 1: Create tenants (with fixed IDs for predictability)
insert into public.tenants (id) values
  ('00000000-0000-0000-0000-000000000001'::uuid),
  ('00000000-0000-0000-0000-000000000002'::uuid)
on conflict (id) do nothing;

INSERT INTO "private"."tenant_email_allowlist" ("email", "tenant_id")
VALUES
('EMAIL_FOR_USER_IN_TENANT_1', '00000000-0000-0000-0000-000000000001'),
('EMAIL_FOR_USER_IN_TENANT_2', '00000000-0000-0000-0000-000000000002')
