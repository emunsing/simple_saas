-- ============================================================
-- MIGRATION 3: HMAC-signed impersonation header + token column cleanup
--
-- Changes:
--   1. Enable pgcrypto for HMAC verification.
--   2. Replace current_impersonator_id() with a version that verifies
--      the HMAC-SHA256 signature on the x-impersonator-id header before
--      returning the UUID.  This prevents any authenticated client from
--      forging audit attribution by setting the header on direct REST calls.
--   3. Make impersonation_sessions.access_token nullable — the JWT is no
--      longer stored in the database; it lives in process memory only.
--
-- Prerequisites:
--   Run migration1.sql and migration2_impersonation.sql first.
--
-- One-time manual step (run in Supabase SQL editor or psql):
--   ALTER DATABASE postgres
--     SET app.impersonation_hmac_secret = '<your-secret>';
--
--   Use the same value as the IMPERSONATION_HMAC_SECRET env var in your
--   Python application.  Generate with: openssl rand -hex 32
-- ============================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================================
-- Make access_token optional — token is no longer stored in DB.
-- Existing rows keep their values; new rows will have NULL.
-- ============================================================
ALTER TABLE public.impersonation_sessions
  ALTER COLUMN access_token DROP NOT NULL,
  ALTER COLUMN access_token SET DEFAULT NULL;

-- ============================================================
-- Updated current_impersonator_id()
--
-- Expects x-impersonator-id header in the format:
--   <uuid>.<unix_timestamp>.<hmac_sha256_hex>
--
-- Rejects the claim if:
--   - It is missing or malformed (not exactly 3 dot-separated parts)
--   - The timestamp is more than 60 seconds old (prevents replay)
--   - The HMAC does not match (prevents forgery)
--   - app.impersonation_hmac_secret is not configured
-- ============================================================
CREATE OR REPLACE FUNCTION public.current_impersonator_id()
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
STABLE
AS $$
DECLARE
  raw      text;
  parts    text[];
  imp_uuid text;
  ts_str   text;
  sig      text;
  expected text;
  secret   text;
  max_age  int := 60; -- seconds; header is minted fresh on every request
BEGIN
  raw := current_setting('request.headers', true)::json->>'x-impersonator-id';
  IF raw IS NULL OR raw = '' THEN
    RETURN NULL;
  END IF;

  -- Expected format: uuid.timestamp.hmac  (UUIDs contain hyphens, not dots)
  parts := string_to_array(raw, '.');
  IF array_length(parts, 1) != 3 THEN
    RETURN NULL;
  END IF;

  imp_uuid := parts[1];
  ts_str   := parts[2];
  sig      := parts[3];

  -- Reject stale claims
  IF abs(extract(epoch from now())::bigint - ts_str::bigint) > max_age THEN
    RETURN NULL;
  END IF;

  -- Read the HMAC secret from Supabase Vault.
  -- SECURITY DEFINER is required because vault.decrypted_secrets is not
  -- accessible to the authenticated role.
  -- To create the secret:  SELECT vault.create_secret('your-secret', 'impersonation_hmac_secret');
  -- To rotate the secret:  SELECT vault.update_secret('<uuid>', 'new-secret');
  SELECT decrypted_secret INTO secret
  FROM vault.decrypted_secrets
  WHERE name = 'impersonation_hmac_secret'
  LIMIT 1;

  IF secret IS NULL THEN
    RETURN NULL;
  END IF;

  -- Verify HMAC-SHA256
  expected := encode(
    hmac(
      (imp_uuid || '.' || ts_str)::bytea,
      secret::bytea,
      'sha256'
    ),
    'hex'
  );

  IF sig != expected THEN
    RETURN NULL;
  END IF;

  RETURN imp_uuid::uuid;
EXCEPTION
  WHEN others THEN
    -- Catches Vault unavailability, invalid UUID cast, or any unexpected error.
    RETURN NULL;
END;
$$;

-- ============================================================
-- AUDIT TRIGGERS: extend coverage to previously unaudited tables
--
-- public.tenants: tenant creation/deletion — previously unaudited,
--   meaning a superuser could create or drop a tenant with no record.
--   actor_user_id captures the authenticated user; impersonator_id
--   captures any active impersonation context.
--
-- public.impersonation_sessions: audit the audit trail itself.
--   Rows are written by the service role so actor_user_id will be NULL
--   (same as the existing users trigger behaviour on first login).
--   This ensures that any manual edits to the impersonation log are
--   themselves recorded.
-- ============================================================

CREATE OR REPLACE TRIGGER audit_tenants
  AFTER INSERT OR UPDATE OR DELETE ON public.tenants
  FOR EACH ROW EXECUTE FUNCTION public.audit_trigger_fn();

CREATE OR REPLACE TRIGGER audit_impersonation_sessions
  AFTER INSERT OR UPDATE OR DELETE ON public.impersonation_sessions
  FOR EACH ROW EXECUTE FUNCTION public.audit_trigger_fn();

-- ============================================================
-- DROP private.auth_debug_log
-- This table was created during development to capture full auth
-- hook payloads (including JWT claims).  It has no RLS and no TTL.
-- It is no longer referenced in code and must be removed.
-- ============================================================

DROP TABLE IF EXISTS private.auth_debug_log;
