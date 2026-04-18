# Demo 4: Multi-Tenant Impersonation

Extends demo 3 with support for admin users impersonating lower-privileged users for
technical support purposes. Includes an audit trail, CSRF protection, and HMAC-signed
audit headers.

## Setup

```bash
# Apply migrations in order in the Supabase SQL editor:
#   migration1.sql
#   migration2_impersonation.sql
#   migration3_hmac_audit.sql

# After migration3, store the HMAC secret in Supabase Vault:
SELECT vault.create_secret('your-secret-here', 'impersonation_hmac_secret');
# Generate the secret with: openssl rand -hex 32
#
# To rotate later:
#   SELECT id FROM vault.secrets WHERE name = 'impersonation_hmac_secret';
#   SELECT vault.update_secret('<uuid>', 'new-secret-here');
```

Required `.env` variables:

```
SUPABASE_APP_URL=...
SUPABASE_API_KEY=...
SUPABASE_SERVICE_ROLE_KEY=...
IMPERSONATION_HMAC_SECRET=...   # must match app.impersonation_hmac_secret set above
SESSION_SECRET_KEY=...          # openssl rand -hex 32
```

## Architecture Notes

### Impersonation flow

1. Admin clicks **Impersonate** link (includes CSRF token).
2. Server validates CSRF token, role-on-role permission, and rate limit.
3. Server calls Supabase admin `generate_link` → exchanges token for a real JWT
   where `auth.uid()` is the target user's UUID.
4. JWT is stored in **process memory only** (never in the database).
   The `impersonation_sessions` table records the audit metadata (who, who, when, why)
   but not the credential.
5. All data operations during impersonation use the target user's JWT so RLS applies
   correctly. The `x-impersonator-id` header is HMAC-signed so PostgreSQL can attribute
   mutations to the real actor without trusting an unsigned client header.
6. On **Stop impersonation**: Supabase session is revoked via `admin.sign_out(scope="local")`,
   the in-memory JWT is evicted, and the session cookie is cleared.

### Security properties implemented

- **CSRF protection** on `/auth/impersonate/{id}` and `/auth/stop-impersonation` via
  per-session token stored in the signed cookie and passed as a query parameter.
- **HMAC-signed audit header** (`x-impersonator-id`): PostgreSQL's
  `current_impersonator_id()` verifies the signature before trusting the UUID,
  preventing external clients from forging audit attribution.
- **In-memory token cache**: impersonation JWTs are never written to the database.
  A server restart ends all active impersonation sessions (by design).
- **Rate limiting**: 10 impersonation attempts per 60 seconds per admin user ID.
- **Token revocation**: Supabase session is revoked at stop-impersonation, not just
  evicted from the in-memory cache.
- **Audit triggers** on `public.tenants`, `public.users`, `public.tenant_email_allowlist`,
  and `public.impersonation_sessions` — including the audit log itself.

### Known limitations (TODOs for production hardening)

**Reason enforcement (SOC-2 CC7)**
The `reason` field is accepted but not enforced to be non-empty. For production:
- Add `CHECK (length(reason) > 0)` to the `impersonation_sessions` table.
- Add a confirmation UI step that collects a documented business justification
  before the impersonation link is generated.

**Step-up authentication (SOC-2 CC6.3)**
A valid session cookie is currently sufficient to initiate impersonation. For production:
- Require a TOTP challenge or re-authentication immediately before the impersonation
  endpoint is reachable.
- Consider integrating with Supabase MFA (`supabase.auth.mfa`).

**Tenant notification (SOC-2 CC9)**
Customers are not notified when SaasCo staff impersonates one of their users. For production:
- Send an email to the `tenant_superuser` on each impersonation start.
- Optionally expose an impersonation log view to tenant admins in the tenant admin panel.

**Magic-link email delivery**
The Supabase admin `generate_link` API returns the token directly without sending an email
by default. If your project uses a custom SMTP hook, verify that it does not forward
admin-generated magic links to end users.

**Multi-process / multi-instance deployments**
The in-memory token cache is per-process. In a multi-worker or horizontally scaled
deployment, impersonation sessions started on one instance will not be visible to others.
Migrate the cache to Redis (with TTL matching the 1-hour session window) before deploying
behind a load balancer.
