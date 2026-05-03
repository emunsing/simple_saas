## Architecture Review Notes

*Review date: 2026-04-18 — SOC-2 compliance + principal architecture review*

### What's solid

The overall approach is sound for an early-stage architecture:

- **Impersonation via real JWT** is the right call. By minting a real token for the
  target user, all existing RLS policies apply without modification. This avoids
  the fragile alternative of "RLS bypass with an admin flag" which invariably
  leads to policy gaps as the schema evolves.
- **HMAC-signed audit header** closes the obvious forgery vector where an authenticated
  client sets `x-impersonator-id` directly on a REST call. The Vault-based secret
  storage and 60-second TTL are appropriate.
- **In-memory token cache** is a defensible choice for a single-process MVP. The
  security property (server restart = forced session termination) is a feature,
  not a limitation, at this stage.
- **Nested impersonation prevention** is correctly enforced.
- **Audit triggers on the audit table itself** (impersonation_sessions) catches
  tampering attempts — a detail many teams miss.

### Critical issues (must fix before any production traffic)

**1. Allowlist DELETE policy lacks role-on-role enforcement (privilege escalation path)**
`allowlist_delete_admin` lets a `tenant_admin` delete allowlist entries for any role in
their tenant, including `tenant_superuser`. Combined with the existing INSERT policy
(which restricts `tenant_admin` to inserting `role = 'user'` only), this creates a
two-step privilege manipulation: delete a `tenant_superuser` allowlist entry, then
re-add the same email as `user`. While the original user's `public.users` row is
unaffected, this corrupts the onboarding pipeline and could misdirect a future re-signup.
- **Fix:** Add role-on-role checks to the DELETE policy, mirroring the INSERT policy
  structure. A `tenant_admin` should only be able to delete entries with `role = 'user'`.

**1. `handle_new_user()` trigger missing `SET search_path` (search-path injection)**
The `handle_new_user()` function is `SECURITY DEFINER` but does not set `search_path`.
A user who can create objects in a schema earlier in `search_path` could shadow
`public.tenant_email_allowlist` or `public.users` and intercept the INSERT/DELETE.
This is [a known Supabase/PostgreSQL hardening item](https://supabase.com/docs/guides/database/hardening).
- **Fix:** Add `SET search_path = public` to the function definition (same pattern
  already used by `sync_user_tenant_map`, `current_user_role`, etc.).

**1. CSRF token in URL query parameters (token leakage)**
The CSRF token is passed as `?csrf_token=...` in impersonation links rendered in the
Panel UI. Query parameters leak via:
- Server access logs (Uvicorn, reverse proxy, CDN)
- Browser history and session restore
- `Referer` headers on subsequent navigation
- Any client-side error/analytics reporting

This means the CSRF token is likely persisted in plaintext in multiple locations and
could be harvested to forge impersonation requests.
- **Fix:** Switch to `POST` requests with the token in the request body. This requires
  changing the Panel links to forms or using JavaScript fetch calls, but it eliminates
  all four leakage vectors. At minimum, set `Referrer-Policy: no-referrer` on responses.

**1. No admin session token refresh flow**
There is no `refresh_token` exchange anywhere in the request lifecycle. Supabase access
tokens have a default 1-hour TTL. After expiry, the admin's session silently fails —
all data calls return empty/error results with no redirect to login. During impersonation
this is doubly confusing: the admin sees failures but cannot tell whether the admin token
or the impersonation token expired.
- **Fix:** Add token refresh logic to `AuthContextMiddleware` (check JWT `exp` claim,
  call `supabase.auth.refresh_session()` when within a refresh window, update the
  session cookie). Store `refresh_token` in the session (it's already saved in
  `auth_callback` but never used).

### Significant issues (fix before SOC-2 audit engagement)

**1. Audit log has no immutability guarantee (SOC-2 CC7.2)**
`public.audit_log` has no protection against
deletion — a compromised superuser could `DELETE FROM audit_log` via the service role
(or even via a future RLS policy gap). SOC-2 requires that audit logs be tamper-resistant.
- **Fix:** Remove DELETE and UPDATE grants on `audit_log` from all roles
  including the service role. Consider an append-only design using `pg_partman` for
  rotation, or replicate to an external SIEM/log store that the application cannot modify.

**1. `access_token` column still exists on `impersonation_sessions`**
Migration 3 makes the column nullable, but the column remains in the schema. The stated
design is "JWT never touches the database," but the column's presence invites future
developers to populate it. The audit trigger on this table would then capture the JWT
in `audit_log.new_data` as a JSONB snapshot — a credential stored in plaintext in an
append-only log.
- **Fix:** Drop the `access_token` column entirely in a follow-up migration. If there
  are existing rows with non-null values, scrub them first.

**1. HMAC comparison in PL/pgSQL is not constant-time**
`current_impersonator_id()` uses `sig != expected` (standard string comparison) to
verify the HMAC. This is theoretically vulnerable to timing side-channels. The 60-second
TTL and network jitter make exploitation impractical today, but this is the kind of
finding an auditor will flag.
- **Fix:** Use `digest(sig, 'sha256') = digest(expected, 'sha256')` to compare hashes
  of hashes, which makes the comparison length-independent. Or compare using
  `hmac(sig::bytea, 'constant'::bytea, 'sha256') = hmac(expected::bytea, 'constant'::bytea, 'sha256')`.



### Moderate issues (address during buildout)

**1. No RLS UPDATE policies on core tables**
`public.users`, `public.tenants`, and `public.projects` have no UPDATE policies. This
means no authenticated user (including the service role via RLS) can update these rows
through PostgREST. This is intentional for now, but as you add profile editing, tenant
settings, or project renaming, you'll need UPDATE policies with proper role-on-role
constraints. Plan these before building the features — retrofitting RLS is error-prone.

**1. ReBAC access check is in application code, not RLS**
`list_accessible_projects()` implements the "owned OR shared" access check in Python.
RLS provides only tenant isolation. This means:
- Any new API endpoint that queries `projects` must remember to apply the same filter.
- A direct PostgREST call (bypassing the Python layer) would return all tenant projects.
- **Recommendation:** Consider an RLS policy that checks `created_by = auth.uid() OR
  EXISTS (SELECT 1 FROM project_roles WHERE project_id = id AND user_id = auth.uid())`.
  This makes the access boundary enforceable at the database level regardless of how the
  query arrives. The tradeoff is more complex RLS, but it eliminates an entire class of
  authorization bypass bugs.

**1. Impersonation metadata in the session cookie is verbose**
The `impersonation` dict stored in the cookie includes `user_info` (full target user
record with email, role, tenant_id), `impersonator_id`, `session_id`, and `expires_at`.
Starlette's `SessionMiddleware` signs but does not encrypt the cookie. Anyone who can
read the cookie (browser extensions, XSS, network inspection without HTTPS) can see
who is impersonating whom and the target's role/tenant membership.
- **Fix:** Store only the `session_id` in the cookie. Look up the rest from the
  in-memory cache or from the `impersonation_sessions` table on each request.

**1. No HTTPS enforcement or Secure cookie flag**
The application does not set `Secure`, `HttpOnly`, or `SameSite` attributes on the
session cookie, and there is no HTTPS redirect. In production, session cookies must be
`Secure; HttpOnly; SameSite=Lax` at minimum, and all HTTP traffic must redirect to HTTPS.
Starlette's `SessionMiddleware` supports `https_only=True`.