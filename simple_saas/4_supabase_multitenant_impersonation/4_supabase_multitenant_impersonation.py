from __future__ import annotations

"""
Multi-tenant ReBAC MVP: Supabase + FastAPI + Panel.

- Auth: Supabase Google OAuth; session in cookie.
- Data: tenants, users; RLS enforces access.
- Roles: saasco_superuser, saasco_employee, tenant_superuser, tenant_admin, user
- Panel apps:
    /panel       — user view (org member list)
    /admin       — tenant admin/superuser: manage users in their tenant
    /tenantadmin — SaasCo staff: manage tenants and all tenant users
- Impersonation:
    /auth/impersonate/{user_id} — admin starts impersonating a user
    /auth/stop-impersonation    — return to admin's own session

Run: uvicorn 3_supabase_multitenant_admin:app --reload --port 8000
Set SUPABASE_APP_URL, SUPABASE_API_KEY, SUPABASE_SERVICE_ROLE_KEY in .env.
Optional: AUTH_REDIRECT_URL, SESSION_SECRET_KEY (openssl rand -hex 32).
Apply migration1.sql then migration2_impersonation.sql in Supabase before running.
"""

import hashlib
import hmac as _hmac
import logging
import os
import secrets
import time
from collections import defaultdict
from contextvars import ContextVar, copy_context
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import panel as pn
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from panel.io.fastapi import add_application
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware
from supabase import Client, ClientOptions, create_client

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

pn.extension()

# ---------------------------------------------------------------------------
# Config & Supabase
# ---------------------------------------------------------------------------
SUPABASE_URL = os.environ["SUPABASE_APP_URL"].rstrip("/")
SUPABASE_ANON_KEY = os.environ["SUPABASE_API_KEY"]
SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
AUTH_REDIRECT_URL = os.environ.get("AUTH_REDIRECT_URL", "http://127.0.0.1:8000/auth/callback")
SESSION_SECRET_KEY = os.environ.get("SESSION_SECRET_KEY", os.urandom(32).hex())
# Secret used to HMAC-sign the x-impersonator-id header value.
# Must also be set in PostgreSQL: ALTER DATABASE postgres SET app.impersonation_hmac_secret = '...';
IMPERSONATION_HMAC_SECRET = os.environ.get("IMPERSONATION_HMAC_SECRET", "")
if not os.environ.get("SESSION_SECRET_KEY"):
    logger.warning(
        "SESSION_SECRET_KEY not set; using a random value. Sessions will not persist across restarts."
    )
if not SUPABASE_SERVICE_ROLE_KEY:
    logger.warning(
        "SUPABASE_SERVICE_ROLE_KEY not set; impersonation will not work."
    )
if not IMPERSONATION_HMAC_SECRET:
    logger.warning(
        "IMPERSONATION_HMAC_SECRET not set; impersonation audit headers will be rejected by the database."
    )

# Request-scoped auth (set by middleware)
# access_token_ctx: effective token — impersonation token when active, else admin's token
access_token_ctx: ContextVar[Optional[str]] = ContextVar("access_token", default=None)
# admin_token_ctx: always the logged-in admin's real token, even during impersonation
admin_token_ctx: ContextVar[Optional[str]] = ContextVar("admin_token", default=None)
user_email_ctx: ContextVar[Optional[str]] = ContextVar("user_email", default=None)
# impersonated_user_ctx: set when impersonation is active; contains target user's info dict
impersonated_user_ctx: ContextVar[Optional[dict]] = ContextVar("impersonated_user", default=None)
# impersonator_id_ctx: the admin's user_id when impersonation is active; used to set x-impersonator-id header
impersonator_id_ctx: ContextVar[Optional[str]] = ContextVar("impersonator_id", default=None)
# csrf_token_ctx: per-session CSRF token used to authenticate impersonation/stop-impersonation links
csrf_token_ctx: ContextVar[Optional[str]] = ContextVar("csrf_token", default=None)

# Roles that can access /admin (tenant-level admin)
TENANT_ADMIN_ROLES = {"saasco_superuser", "saasco_employee", "tenant_superuser", "tenant_admin"}
# Roles that can access /tenantadmin (SaasCo staff only)
SAASCO_STAFF_ROLES = {"saasco_superuser", "saasco_employee"}

# Which roles each admin role may impersonate (role-on-role constraints)
_IMPERSONATABLE_ROLES: dict[str, set[str]] = {
    "saasco_superuser": {"saasco_superuser", "saasco_employee", "tenant_superuser", "tenant_admin", "user"},
    "saasco_employee":  {"tenant_superuser", "tenant_admin", "user"},
    "tenant_superuser": {"tenant_admin", "user"},
    "tenant_admin":     {"user"},
}


# ---------------------------------------------------------------------------
# Impersonation token cache
# Stores impersonation JWTs in process memory keyed by session UUID.
# The JWT never touches the database — only the audit metadata does.
# Sessions are evicted on stop-impersonation or natural TTL expiry.
# ---------------------------------------------------------------------------
_impersonation_token_cache: dict[str, tuple[str, datetime]] = {}


def _store_impersonation_token(session_id: str, token: str, expires_at: datetime) -> None:
    _impersonation_token_cache[session_id] = (token, expires_at)


def _fetch_impersonation_token(session_id: str) -> Optional[str]:
    entry = _impersonation_token_cache.get(session_id)
    if not entry:
        return None
    token, expires_at = entry
    if datetime.now(timezone.utc) >= expires_at:
        _impersonation_token_cache.pop(session_id, None)
        return None
    return token


def _evict_impersonation_token(session_id: str) -> None:
    _impersonation_token_cache.pop(session_id, None)


# ---------------------------------------------------------------------------
# Impersonation rate limiter
# Keyed by admin user_id; limits impersonation attempts to prevent enumeration.
# ---------------------------------------------------------------------------
_impersonation_attempts: dict[str, list[float]] = defaultdict(list)
_RATE_LIMIT_MAX = 10       # attempts allowed per window
_RATE_LIMIT_WINDOW = 60.0  # seconds


def _is_rate_limited(admin_user_id: str) -> bool:
    """Return True (and log) if this admin has exceeded the impersonation rate limit."""
    now = time.time()
    cutoff = now - _RATE_LIMIT_WINDOW
    recent = [t for t in _impersonation_attempts[admin_user_id] if t > cutoff]
    _impersonation_attempts[admin_user_id] = recent
    if len(recent) >= _RATE_LIMIT_MAX:
        logger.warning(
            "auth_impersonate: rate limit exceeded for admin_user_id=%s (%d attempts in %ds)",
            admin_user_id, len(recent), int(_RATE_LIMIT_WINDOW),
        )
        return True
    _impersonation_attempts[admin_user_id].append(now)
    return False


def _sign_impersonator_claim(impersonator_id: str) -> str:
    """Return a signed value for the x-impersonator-id request header.

    Format: <uuid>.<unix_timestamp>.<hmac_sha256_hex>

    PostgreSQL's current_impersonator_id() verifies the HMAC and timestamp
    before trusting the UUID, preventing external clients from forging
    audit attribution by setting the header directly on Supabase REST calls.
    """
    if not IMPERSONATION_HMAC_SECRET:
        raise RuntimeError(
            "IMPERSONATION_HMAC_SECRET is not set. Cannot sign impersonator claim."
        )
    ts = str(int(time.time()))
    msg = f"{impersonator_id}.{ts}".encode()
    sig = _hmac.new(IMPERSONATION_HMAC_SECRET.encode(), msg, hashlib.sha256).hexdigest()
    return f"{impersonator_id}.{ts}.{sig}"


def _supabase_auth_client() -> Client:
    """Client with PKCE flow for login."""
    return create_client(SUPABASE_URL, SUPABASE_ANON_KEY, ClientOptions(flow_type="pkce"))


def get_supabase_for_user(
    access_token: Optional[str],
    impersonator_id: Optional[str] = None,
) -> Client:
    """Supabase client with user JWT so RLS applies.

    When impersonator_id is set, attaches a signed x-impersonator-id header.
    The value is HMAC-SHA256 signed (uuid.timestamp.sig) so PostgreSQL's
    current_impersonator_id() can reject forgeries from external clients
    before trusting the UUID for audit attribution.
    """
    opts = ClientOptions()
    headers: dict[str, str] = {}
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"
    if impersonator_id:
        headers["x-impersonator-id"] = _sign_impersonator_claim(impersonator_id)
    if headers:
        opts.headers = headers
    return create_client(SUPABASE_URL, SUPABASE_ANON_KEY, options=opts)


def get_supabase_admin() -> Client:
    """Service-role client — bypasses RLS. Use only for privileged server-side operations."""
    if not SUPABASE_SERVICE_ROLE_KEY:
        raise RuntimeError(
            "SUPABASE_SERVICE_ROLE_KEY is not set. Cannot perform admin operations."
        )
    return create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)


# ---------------------------------------------------------------------------
# Auth middleware
# ---------------------------------------------------------------------------
class AuthContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        session = getattr(request, "session", None)
        admin_token = request.session.get("access_token") if session else None
        email = request.session.get("email") if session else None
        impersonation = request.session.get("impersonation") if session else None

        # Ensure every authenticated session has a CSRF token.
        # Generated lazily here (rather than only in auth_callback) so that
        # sessions created before this change also get a token on next request.
        csrf_token = request.session.get("csrf_token") if session else None
        if admin_token and not csrf_token:
            csrf_token = secrets.token_urlsafe(32)
            if session:
                request.session["csrf_token"] = csrf_token

        # Auto-expire impersonation sessions whose token TTL has passed.
        # This prevents stale impersonation tokens from reaching Panel callbacks
        # when the admin returns to a tab after a long absence.
        if impersonation:
            expires_at_raw = impersonation.get("expires_at")
            if expires_at_raw:
                try:
                    expires_at = datetime.fromisoformat(expires_at_raw)
                    if datetime.now(timezone.utc) >= expires_at:
                        logger.info(
                            "Impersonation token expired for target=%s; auto-clearing",
                            impersonation.get("user_info", {}).get("user_email"),
                        )
                        request.session.pop("impersonation", None)
                        impersonation = None
                except ValueError:
                    pass  # malformed date; leave impersonation intact

        # Effective token: look up from in-memory cache when impersonation is active.
        effective_token: Optional[str] = admin_token
        if impersonation:
            session_id = impersonation.get("session_id")
            if session_id:
                effective_token = _fetch_impersonation_token(session_id)
                if effective_token is None:
                    # Cache miss — session expired or server restarted; clear cookie state.
                    logger.info(
                        "middleware: impersonation token not in cache for session %s; clearing",
                        session_id,
                    )
                    request.session.pop("impersonation", None)
                    impersonation = None
        impersonated_user = impersonation.get("user_info") if impersonation else None
        impersonator_id = impersonation.get("impersonator_id") if impersonation else None

        t_ctx = access_token_ctx.set(effective_token)
        a_ctx = admin_token_ctx.set(admin_token)
        e_ctx = user_email_ctx.set(email)
        i_ctx = impersonated_user_ctx.set(impersonated_user)
        imp_id_ctx = impersonator_id_ctx.set(impersonator_id)
        c_ctx = csrf_token_ctx.set(csrf_token)
        try:
            return await call_next(request)
        finally:
            access_token_ctx.reset(t_ctx)
            admin_token_ctx.reset(a_ctx)
            user_email_ctx.reset(e_ctx)
            impersonated_user_ctx.reset(i_ctx)
            impersonator_id_ctx.reset(imp_id_ctx)
            csrf_token_ctx.reset(c_ctx)


# ---------------------------------------------------------------------------
# FastAPI app & auth routes
# ---------------------------------------------------------------------------
app = FastAPI(title="Multi-tenant ReBAC (Supabase)")
app.add_middleware(AuthContextMiddleware)
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET_KEY)


@app.get("/auth/login")
async def auth_login(request: Request):
    supabase = _supabase_auth_client()
    resp = supabase.auth.sign_in_with_oauth(
        {"provider": "google", "options": {"redirect_to": AUTH_REDIRECT_URL}}
    )
    storage_key = f"{supabase.auth._storage_key}-code-verifier"
    request.session["code_verifier"] = supabase.auth._storage.get_item(storage_key)
    return RedirectResponse(resp.url)


@app.get("/auth/callback")
async def auth_callback(request: Request, code: str | None = None):
    if not code:
        return RedirectResponse("/login")

    code_verifier = request.session.pop("code_verifier", None)
    if not code_verifier:
        return RedirectResponse("/login")

    supabase = _supabase_auth_client()
    auth_resp = supabase.auth.exchange_code_for_session(
        {"auth_code": code, "code_verifier": code_verifier}
    )
    if auth_resp.user is None or auth_resp.user.email is None:
        logger.error("auth_callback: OAuth response missing user or email")
        return RedirectResponse("/auth/login", status_code=302)
    request.session["email"] = auth_resp.user.email
    request.session["access_token"] = auth_resp.session.access_token
    request.session["refresh_token"] = auth_resp.session.refresh_token
    request.session["csrf_token"] = secrets.token_urlsafe(32)
    return RedirectResponse("/panel", status_code=302)


@app.get("/auth/logout")
async def auth_logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/", status_code=302)


@app.get("/auth/impersonate/{user_id}")
async def auth_impersonate(request: Request, user_id: str, reason: str = "", csrf_token: str = ""):
    """Start impersonating a user. Validates permissions, generates a session token
    for the target user via magic link, then stores it in the session cookie.

    # TODO(security): Enforce a minimum non-empty reason string for SOC-2 audit trails.
    #   The DB column is NOT NULL DEFAULT '' — change to NOT NULL with a CHECK (length > 0)
    #   and add a confirmation UI step that collects a business justification.
    # TODO(security): Require MFA / step-up authentication before impersonation is permitted.
    #   The current flow requires only a valid session cookie. For production, require a
    #   TOTP challenge or re-authentication before this endpoint is reachable.
    # TODO(compliance): Notify the affected tenant when one of their users is impersonated.
    #   Options: email to tenant_superuser, in-app notification on next login, webhook.
    """
    admin_token = request.session.get("access_token")
    if not admin_token:
        return RedirectResponse("/auth/login")

    # CSRF check: token in query param must match the session token.
    stored_csrf = request.session.get("csrf_token", "")
    if not stored_csrf or not secrets.compare_digest(csrf_token, stored_csrf):
        logger.warning("auth_impersonate: CSRF token mismatch for user_id=%s", user_id)
        return RedirectResponse("/panel")

    # Prevent nested impersonation
    if request.session.get("impersonation"):
        logger.warning("Attempted to start impersonation while already impersonating")
        return RedirectResponse("/panel")

    # Get admin's own info using their real token
    try:
        admin_info = _get_user_info_by_token_and_email(
            admin_token, request.session.get("email", "")
        )
    except Exception:
        logger.exception("auth_impersonate: failed to get admin info")
        return RedirectResponse("/panel")

    if not admin_info or admin_info.get("role") not in TENANT_ADMIN_ROLES:
        return RedirectResponse("/panel")

    if _is_rate_limited(admin_info["user_id"]):
        return RedirectResponse("/panel")

    # Look up target user via service role (admin may be in a different tenant)
    try:
        target_info = _get_user_by_id_admin(user_id)
    except Exception:
        logger.exception("auth_impersonate: failed to get target user")
        return RedirectResponse("/panel")

    if not target_info:
        logger.warning("auth_impersonate: target user %s not found", user_id)
        return RedirectResponse("/panel")

    if not can_impersonate(admin_info, target_info):
        logger.warning(
            "auth_impersonate: %s (role=%s) not permitted to impersonate %s (role=%s)",
            admin_info.get("user_id"),
            admin_info.get("role"),
            user_id,
            target_info.get("role"),
        )
        return RedirectResponse("/panel")

    # Obtain a real JWT for the target user via magic link exchange
    try:
        impersonation_token = _generate_impersonation_token(target_info["user_email"])
    except Exception:
        logger.exception("auth_impersonate: failed to generate impersonation token")
        return RedirectResponse("/panel")

    # Insert audit row (no JWT stored in DB); cache the token in process memory.
    expires_at_dt = datetime.now(timezone.utc) + timedelta(hours=1)
    try:
        session_id = _record_impersonation_session(admin_info, target_info, reason)
    except Exception:
        logger.exception("auth_impersonate: failed to record audit log")
        return RedirectResponse("/panel")

    _store_impersonation_token(session_id, impersonation_token, expires_at_dt)

    request.session["impersonation"] = {
        "session_id": session_id,
        "user_info": target_info,
        "impersonator_id": admin_info["user_id"],
        "expires_at": expires_at_dt.isoformat(),
    }
    logger.info(
        "Impersonation started: %s -> %s",
        admin_info.get("user_email", admin_info["user_id"]),
        target_info["user_email"],
    )
    return RedirectResponse("/panel", status_code=302)


@app.get("/auth/stop-impersonation")
async def auth_stop_impersonation(request: Request, csrf_token: str = ""):
    """End impersonation and return to admin's normal session."""
    stored_csrf = request.session.get("csrf_token", "")
    if not stored_csrf or not secrets.compare_digest(csrf_token, stored_csrf):
        logger.warning("auth_stop_impersonation: CSRF token mismatch")
        return RedirectResponse("/panel")

    impersonation = request.session.pop("impersonation", None)
    if impersonation:
        session_id = impersonation.get("session_id")
        if session_id:
            # Revoke the impersonation JWT at Supabase (scope="local" revokes only
            # this session, not any real sessions the target user may have open).
            token = _fetch_impersonation_token(session_id)
            if token:
                try:
                    get_supabase_admin().auth.admin.sign_out(token, scope="local")
                except Exception:
                    logger.exception("stop_impersonation: failed to revoke impersonation JWT (non-fatal)")
            _evict_impersonation_token(session_id)
        # Mark session as ended in the audit log
        try:
            supabase_admin = get_supabase_admin()
            if session_id:
                supabase_admin.table("impersonation_sessions").update(
                    {"ended_at": datetime.now(timezone.utc).isoformat()}
                ).eq("id", session_id).execute()
        except Exception:
            logger.exception("stop_impersonation: failed to update audit log (non-fatal)")

        logger.info(
            "Impersonation ended: impersonator=%s target=%s",
            impersonation["impersonator_id"],
            impersonation["user_info"].get("user_email"),
        )
    return RedirectResponse("/panel", status_code=302)


@app.get("/")
async def root():
    return RedirectResponse(url="/panel", status_code=302)


# ---------------------------------------------------------------------------
# Token helpers
# ---------------------------------------------------------------------------
def _token() -> Optional[str]:
    """Effective token: impersonation token when active, otherwise admin's token."""
    return access_token_ctx.get()


def _require_token() -> str:
    t = _token()
    if not t:
        raise PermissionError("Not authenticated. Go to /auth/login")
    return t


def _admin_token() -> Optional[str]:
    """The real logged-in admin's token, unaffected by impersonation."""
    return admin_token_ctx.get()


def _require_admin_token() -> str:
    t = _admin_token()
    if not t:
        raise PermissionError("Not authenticated. Go to /auth/login")
    return t


def _get_supabase_effective() -> Client:
    """The single authorised way to obtain a Supabase client for user-facing
    data operations.

    - Uses the effective token (impersonation JWT when active, admin JWT otherwise),
      so RLS is enforced as the correct effective user.
    - Attaches x-impersonator-id when impersonation is active so that
      PostgreSQL audit triggers can record both the effective user (auth.uid())
      and the real actor (current_impersonator_id()).

    Admin-only operations (allowlist management, tenant creation, etc.) should
    continue to call get_supabase_for_user(_require_admin_token()) directly —
    those actions are performed as the admin and need no impersonation header.
    """
    return get_supabase_for_user(
        _require_token(),
        impersonator_id=impersonator_id_ctx.get(),
    )


# ---------------------------------------------------------------------------
# Impersonation helpers
# ---------------------------------------------------------------------------
def can_impersonate(admin_info: dict, target_info: dict) -> bool:
    """Return True if admin_info's role may impersonate target_info's role/tenant."""
    admin_role = admin_info.get("role", "")
    target_role = target_info.get("role", "")

    # Prevent self-impersonation
    if admin_info.get("user_id") == target_info.get("user_id"):
        return False

    allowed_roles = _IMPERSONATABLE_ROLES.get(admin_role, set())
    if target_role not in allowed_roles:
        return False

    # Tenant-scoped admins may only impersonate within their own tenant
    if admin_role in ("tenant_superuser", "tenant_admin"):
        return admin_info.get("tenant_id") == target_info.get("tenant_id")

    return True


def _generate_impersonation_token(target_email: str) -> str:
    """Use the admin API to mint a magic-link OTP, then exchange it for a real
    access token for the target user.  The resulting JWT has auth.uid() ==
    target user's UUID, so all existing RLS policies work unchanged.

    Note on email delivery: the admin generate_link API returns the token directly
    and does NOT send an email to the target user by default.  Supabase only sends
    email when the client-facing sign_in_with_otp() call is used.  If your project
    has a custom SMTP hook that intercepts all OTP events, verify that it does not
    forward admin-generated links.
    """
    supabase_admin = get_supabase_admin()
    link_resp = supabase_admin.auth.admin.generate_link(
        {"type": "magiclink", "email": target_email}
    )
    hashed_token = link_resp.properties.hashed_token

    anon_client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
    # hashed_token from generate_link is already the stored hash.
    # Pass it as token_hash (not token) so GoTrue looks it up directly
    # rather than hashing it again.  Type must be "email" — that is how
    # GoTrue stores magic-link OTPs internally regardless of the link type
    # requested via generate_link.
    otp_resp = anon_client.auth.verify_otp(
        {"token_hash": hashed_token, "type": "email"}
    )
    if otp_resp.session is None:
        raise RuntimeError(
            f"verify_otp succeeded but returned no session for {target_email}. "
            "This usually means Supabase requires email confirmation for this user."
        )
    return otp_resp.session.access_token


def _record_impersonation_session(
    admin_info: dict, target_info: dict, reason: str
) -> str:
    """Insert an audit row and return the new session UUID.

    The impersonation JWT is NOT stored in the database — it lives only in
    _impersonation_token_cache for the lifetime of this server process.
    """
    supabase_admin = get_supabase_admin()
    r = supabase_admin.table("impersonation_sessions").insert(
        {
            "impersonator_id": admin_info["user_id"],
            "target_user_id": target_info["user_id"],
            "target_email": target_info["user_email"],
            "target_tenant_id": target_info["tenant_id"],
            "reason": reason,
        }
    ).execute()
    return r.data[0]["id"]


# ---------------------------------------------------------------------------
# Data helpers (user-facing — use effective token; RLS applies as target user)
# ---------------------------------------------------------------------------
def list_org_users() -> list[dict[str, Any]]:
    """Users in the current user's tenant (RLS-scoped).
    During impersonation this shows what the target user sees, and the
    x-impersonator-id header is attached for audit attribution."""
    supabase = _get_supabase_effective()
    r = supabase.table("users").select("user_id, username, user_email, tenant_id, role").execute()
    return list(r.data or [])


def get_current_user_info() -> Optional[dict[str, Any]]:
    """Returns {user_id, role, tenant_id} for the *effective* user.
    During impersonation this is the target user's info."""
    token = _token()
    if not token:
        return None

    impersonated = impersonated_user_ctx.get()
    if impersonated:
        # Use target's known email to query via the impersonation token
        email = impersonated.get("user_email", "")
    else:
        email = user_email_ctx.get() or ""

    if not email:
        return None
    try:
        supabase = _get_supabase_effective()
        r = supabase.table("users").select("user_id, role, tenant_id").eq("user_email", email).execute()
        return r.data[0] if r.data else None
    except Exception:
        logger.exception("get_current_user_info")
        return None


# ---------------------------------------------------------------------------
# Data helpers (admin-facing — use admin token; RLS applies as the real admin)
# ---------------------------------------------------------------------------
def get_admin_user_info() -> Optional[dict[str, Any]]:
    """Returns {user_id, role, tenant_id} for the real logged-in admin.
    Unaffected by impersonation state."""
    token = _admin_token()
    email = user_email_ctx.get()
    if not token or not email:
        return None
    try:
        supabase = get_supabase_for_user(token)
        r = supabase.table("users").select("user_id, role, tenant_id, user_email").eq("user_email", email).execute()
        return r.data[0] if r.data else None
    except Exception:
        logger.exception("get_admin_user_info")
        return None


def _get_user_info_by_token_and_email(token: str, email: str) -> Optional[dict[str, Any]]:
    """Look up a user row using a specific token + email (used during HTTP routes
    where ContextVars are not yet set)."""
    if not token or not email:
        return None
    try:
        supabase = get_supabase_for_user(token)
        r = supabase.table("users").select("user_id, role, tenant_id, user_email").eq("user_email", email).execute()
        return r.data[0] if r.data else None
    except Exception:
        logger.exception("_get_user_info_by_token_and_email")
        return None


def _get_user_by_id_admin(user_id: str) -> Optional[dict[str, Any]]:
    """Fetch a user row by user_id using the service role (bypasses RLS).
    Required when the admin and target are in different tenants."""
    supabase_admin = get_supabase_admin()
    r = (
        supabase_admin.table("users")
        .select("user_id, username, user_email, role, tenant_id")
        .eq("user_id", user_id)
        .execute()
    )
    return r.data[0] if r.data else None


def list_tenants() -> list[dict[str, Any]]:
    """All tenants visible to the real admin (RLS-scoped via admin token)."""
    supabase = get_supabase_for_user(_require_admin_token())
    r = supabase.table("tenants").select("id, name").order("name").execute()
    return list(r.data or [])


def list_users_for_tenant(tenant_id: str) -> list[dict[str, Any]]:
    """Active (logged-in) users for a specific tenant. Uses admin token so RLS
    allows cross-tenant access for SaasCo staff."""
    supabase = get_supabase_for_user(_require_admin_token())
    r = (
        supabase.table("users")
        .select("user_id, username, user_email, role, tenant_id, tenants(name)")
        .eq("tenant_id", tenant_id)
        .order("username")
        .execute()
    )
    return list(r.data or [])


def list_all_accessible_users() -> list[dict[str, Any]]:
    """All active users visible to the admin via RLS on the admin token.
    SaasCo staff see every tenant; tenant admins/superusers see their own tenant.
    Includes tenant name via an embedded join for display."""
    supabase = get_supabase_for_user(_require_admin_token())
    r = (
        supabase.table("users")
        .select("user_id, username, user_email, role, tenant_id, tenants(name)")
        .order("tenant_id")
        .order("username")
        .execute()
    )
    return list(r.data or [])


def admin_create_tenant(name: str) -> str:
    """Create a new tenant (RLS restricts to SaasCo staff). Returns new tenant id."""
    supabase = get_supabase_for_user(_require_admin_token())
    r = supabase.table("tenants").insert({"name": name}).execute()
    return r.data[0]["id"]


def admin_add_to_allowlist(email: str, tenant_id: str, role: str, username: str) -> None:
    """Upsert an allowlist entry. RLS enforces role-on-role constraints.

    Raises ValueError if (tenant_id, username) is already taken in users or the allowlist.
    """
    supabase = get_supabase_for_user(_require_admin_token())
    available = supabase.rpc(
        "check_username_available",
        {"p_tenant_id": tenant_id, "p_username": username, "p_exclude_email": email.lower()},
    ).execute()
    if not available.data:
        raise ValueError(f"Username '{username}' is already taken in this tenant.")
    supabase.table("tenant_email_allowlist").upsert(
        {"email": email.lower(), "tenant_id": tenant_id, "username": username, "role": role}
    ).execute()


def admin_remove_from_allowlist(email: str) -> None:
    supabase = get_supabase_for_user(_require_admin_token())
    supabase.table("tenant_email_allowlist").delete().eq("email", email.lower()).execute()


def admin_list_allowlist(tenant_id: Optional[str] = None) -> list[dict[str, Any]]:
    """List allowlist entries. RLS scopes results to what the admin may see."""
    supabase = get_supabase_for_user(_require_admin_token())
    query = supabase.table("tenant_email_allowlist").select("email, username, tenant_id, role, created_at")
    if tenant_id:
        query = query.eq("tenant_id", tenant_id)
    r = query.execute()
    return list(r.data or [])


# ---------------------------------------------------------------------------
# REST API
# ---------------------------------------------------------------------------
@app.get("/api/users/org")
async def api_list_org_users():
    try:
        return list_org_users()
    except PermissionError as e:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail=str(e))


# ---------------------------------------------------------------------------
# Shared Panel component: impersonation banner
# ---------------------------------------------------------------------------
def make_impersonation_banner() -> Optional[pn.viewable.Viewable]:
    """Returns a warning banner when impersonation is active, else None."""
    impersonated = impersonated_user_ctx.get()
    if not impersonated:
        return None
    email = impersonated.get("user_email", "unknown")
    role = impersonated.get("role", "")
    csrf = csrf_token_ctx.get() or ""
    return pn.pane.Markdown(
        f"**Impersonation active** — viewing as **{email}** (`{role}`) "
        f"&nbsp;&nbsp;[Stop impersonation](/auth/stop-impersonation?csrf_token={csrf})",
        styles={
            "background-color": "#fff3cd",
            "border": "1px solid #ffc107",
            "border-radius": "4px",
            "padding": "8px 12px",
        },
        sizing_mode="stretch_width",
    )


# ---------------------------------------------------------------------------
# Shared Panel component: "Users Awaiting Login" (allowlist entries)
# ---------------------------------------------------------------------------
def make_pending_users_panel(tenant_id: Optional[str], on_refresh, ctx) -> pn.Column:
    """
    Returns a Panel Column listing allowlist entries for *tenant_id* with a
    Remove button on each row.  Call on_refresh() after a removal to rebuild.

    ctx must be the copy_context() snapshot from the parent Panel app so that
    Remove-button callbacks (fired by Bokeh outside any ctx.run) can reach
    Supabase via _require_admin_token().
    """
    try:
        entries = admin_list_allowlist(tenant_id)
    except Exception as e:
        return pn.Column(pn.pane.Markdown(f"_Error loading pending users: {e}_"))

    if not entries:
        return pn.Column(pn.pane.Markdown("_No users awaiting login._"))

    rows = []
    for entry in entries:
        email = entry["email"]
        username = entry.get("username") or "—"
        role = entry["role"]
        remove_btn = pn.widgets.Button(name="Remove", button_type="danger", width=90)

        def _on_remove(event, _email=email):
            def _inner():
                try:
                    admin_remove_from_allowlist(_email)
                except Exception:
                    logger.exception("admin_remove_from_allowlist")
                on_refresh()
            ctx.run(_inner)

        remove_btn.on_click(_on_remove)
        rows.append(
            pn.Row(
                pn.pane.Markdown(f"**{email}** (`{username}`) — `{role}`", width=440),
                remove_btn,
            )
        )

    return pn.Column(*rows)


# ---------------------------------------------------------------------------
# Shared Panel component: "Active Users" with impersonate buttons
# ---------------------------------------------------------------------------
def make_active_users_panel(
    admin_info: dict,
    tenant_id: Optional[str] = None,
) -> pn.Column:
    """Lists active (logged-in) users with Impersonate links.

    If tenant_id is given, shows only that tenant's users.
    If omitted, shows every user visible to the admin via RLS — useful for
    SaasCo staff who need to impersonate across tenants for async debugging.
    Tenant name is included in each row when showing the full cross-tenant list.
    """
    show_tenant = tenant_id is None
    try:
        users = list_all_accessible_users() if show_tenant else list_users_for_tenant(tenant_id)
    except Exception as e:
        return pn.Column(pn.pane.Markdown(f"_Error loading active users: {e}_"))

    if not users:
        return pn.Column(pn.pane.Markdown("_No active users found._"))

    csrf = csrf_token_ctx.get() or ""
    rows = []
    for u in users:
        uid = u["user_id"]
        email = u.get("user_email", "—")
        username = u.get("username") or "—"
        role = u.get("role", "")
        tenant_name = (u.get("tenants") or {}).get("name", "") if show_tenant else ""

        identity = f"**{username}** — {email} `{role}`"
        if tenant_name:
            identity += f" · _{tenant_name}_"

        if can_impersonate(admin_info, u):
            action = pn.pane.Markdown(
                f"[Impersonate](/auth/impersonate/{uid}?csrf_token={csrf})", width=150
            )
        else:
            action = pn.pane.Markdown("_(self or higher role)_", width=150)

        rows.append(pn.Row(pn.pane.Markdown(identity, width=460), action))

    return pn.Column(*rows)


# ---------------------------------------------------------------------------
# Panel app: user view — login link or org member list
# ---------------------------------------------------------------------------
@add_application("/panel", app=app, title="Organization")
def create_panel_app():
    # Capture ContextVars (access_token, email) from the HTTP request that
    # initialises this Panel session.  Button-click callbacks run via
    # Bokeh/Tornado's IO loop in a different context, so we restore the
    # snapshot with ctx.run() on every callback that touches Supabase.

    ctx = copy_context()

    banner = make_impersonation_banner()

    main_md = pn.pane.Markdown("", sizing_mode="stretch_width")
    refresh_btn = pn.widgets.Button(name="Refresh members", button_type="primary")
    logout_md = pn.pane.Markdown("[Log out](/auth/logout)")
    tenant_admin_md = pn.pane.Markdown("[Tenant Admin](/tenantadmin)")
    user_admin_md = pn.pane.Markdown("[User Admin](/admin)")

    def update_view(event=None):
        if not _token():
            main_md.object = "[Log in with Google](/auth/login)"
            refresh_btn.visible = False
            logout_md.visible = False
            tenant_admin_md.visible = False
            user_admin_md.visible = False
            return

        # Admin links use the effective-user role (hidden during impersonation)
        user_info = get_current_user_info()
        effective_role = user_info.get("role") if user_info else None
        tenant_admin_md.visible = effective_role in SAASCO_STAFF_ROLES
        user_admin_md.visible = effective_role in TENANT_ADMIN_ROLES

        refresh_btn.visible = True
        logout_md.visible = True

        impersonated = impersonated_user_ctx.get()
        display_email = impersonated["user_email"] if impersonated else (user_email_ctx.get() or "—")

        try:
            rows = list_org_users()
        except PermissionError:
            main_md.object = (
                f"**Signed in as:** {display_email}\n\n"
                "_Could not load members (not authenticated)._\n\n"
                "[Log in with Google](/auth/login)"
            )
            return
        except Exception as e:
            logger.exception("list_org_users in panel")
            main_md.object = f"**Signed in as:** {display_email}\n\n_Error loading members: {e}_"
            return

        lines = [
            f"**Signed in as:** {display_email}",
            "",
            "### Users in your organization",
            "",
        ]
        if not rows:
            lines.append(
                "_No users returned (check RLS and that your account exists in `public.users`)._"
            )
        else:
            for u in rows:
                name = u.get("username") or u.get("user_id") or "—"
                mail = u.get("user_email") or ""
                role = u.get("role") or ""
                lines.append(f"- **{name}** — {mail or '—'} `{role}`")
        main_md.object = "\n".join(lines)

    refresh_btn.on_click(lambda e: ctx.run(update_view, e))
    ctx.run(update_view)

    components: list[Any] = []
    if banner:
        components.append(banner)
    components += [
        main_md,
        pn.Row(tenant_admin_md, user_admin_md),
        pn.Row(refresh_btn, logout_md),
    ]
    return pn.Column(*components, sizing_mode="stretch_width")


# ---------------------------------------------------------------------------
# Panel app: /admin — tenant superuser / tenant admin view
# ---------------------------------------------------------------------------
@add_application("/admin", app=app, title="Tenant Admin")
def create_admin_app():
    ctx = copy_context()

    if not _admin_token():
        return pn.Column(pn.pane.Markdown("[Log in with Google](/auth/login)"))

    # Always use admin's real info for access control, even during impersonation
    user_info = get_admin_user_info()
    if not user_info or user_info.get("role") not in TENANT_ADMIN_ROLES:
        return pn.Column(
            pn.pane.Markdown(
                "**Access denied.** This page requires a tenant admin role or higher.\n\n"
                "[Back to app](/panel)"
            )
        )

    caller_role = user_info["role"]
    tenant_id = user_info["tenant_id"]

    # Role options depend on the caller's role
    if caller_role in SAASCO_STAFF_ROLES:
        available_roles = ["tenant_superuser", "tenant_admin", "user"]
    elif caller_role == "tenant_superuser":
        available_roles = ["tenant_admin", "user"]
    else:  # tenant_admin
        available_roles = ["user"]

    email_input = pn.widgets.TextInput(name="Email", placeholder="user@example.com", width=300)
    username_input = pn.widgets.TextInput(name="Username", placeholder="user1", width=200)
    role_select = pn.widgets.Select(name="Role", options=available_roles, value="user", width=160)
    add_btn = pn.widgets.Button(name="Add to Allowlist", button_type="primary")
    status_md = pn.pane.Markdown("")
    pending_col = pn.Column()
    active_users_col = pn.Column()

    def refresh_pending(*_):
        pending_col.objects = [make_pending_users_panel(tenant_id, refresh_pending, ctx)]

    def refresh_active_users(*_):
        def _inner():
            active_users_col.objects = [make_active_users_panel(user_info, tenant_id=tenant_id)]
        ctx.run(_inner)

    def on_add(event=None):
        def _inner():
            email = email_input.value.strip()
            username = username_input.value.strip()
            if not email:
                status_md.object = "_Please enter an email address._"
                return
            if not username:
                status_md.object = "_Please enter a username._"
                return
            try:
                admin_add_to_allowlist(email, tenant_id, role_select.value, username)
                status_md.object = f"Added **{email}** (`{username}`) with role `{role_select.value}`."
                email_input.value = ""
                username_input.value = ""
                refresh_pending()
            except Exception as e:
                status_md.object = f"_Error: {e}_"
        ctx.run(_inner)

    add_btn.on_click(on_add)
    ctx.run(refresh_pending)
    refresh_active_users()  # already calls ctx.run(_inner) internally; must not be double-wrapped

    banner = make_impersonation_banner()
    components: list[Any] = []
    if banner:
        components.append(banner)
    components += [
        "## Admin",
        "### Add User to Allowlist",
        pn.Row(email_input, username_input, role_select, add_btn),
        status_md,
        pn.layout.Divider(),
        "### Users Awaiting Login",
        pending_col,
        pn.layout.Divider(),
        "### Active Users",
        active_users_col,
        pn.layout.Divider(),
        pn.pane.Markdown("[Back to app](/panel) | [Log out](/auth/logout)"),
    ]
    return pn.Column(*components, sizing_mode="stretch_width")


# ---------------------------------------------------------------------------
# Panel app: /tenantadmin — SaasCo staff view
# ---------------------------------------------------------------------------
@add_application("/tenantadmin", app=app, title="SaasCo Admin")
def create_tenantadmin_app():
    ctx = copy_context()

    if not _admin_token():
        return pn.Column(pn.pane.Markdown("[Log in with Google](/auth/login)"))

    # Always use admin's real info for access control
    user_info = get_admin_user_info()
    if not user_info or user_info.get("role") not in SAASCO_STAFF_ROLES:
        return pn.Column(
            pn.pane.Markdown(
                "**Access denied.** This page is for SaasCo staff only.\n\n"
                "[Back to app](/panel)"
            )
        )

    caller_role = user_info["role"]

    # All roles a SaasCo employee/superuser may assign
    if caller_role == "saasco_superuser":
        available_roles = ["saasco_superuser", "saasco_employee", "tenant_superuser", "tenant_admin", "user"]
    else:  # saasco_employee
        available_roles = ["saasco_employee", "tenant_superuser", "tenant_admin", "user"]

    # ---- Create Tenant section ----
    tenant_name_input = pn.widgets.TextInput(
        name="Tenant name", placeholder="e.g. TenantC", width=280
    )
    create_tenant_btn = pn.widgets.Button(name="Create Tenant", button_type="success")
    create_tenant_status = pn.pane.Markdown("")

    # ---- Select Tenant section ----
    def _tenant_options():
        tenants = list_tenants()
        return {(t["name"] or t["id"]): t["id"] for t in tenants}

    tenant_select = pn.widgets.Select(
        name="Tenant", options=_tenant_options(), width=280
    )

    # ---- Add User section ----
    email_input = pn.widgets.TextInput(
        name="Email", placeholder="user@example.com", width=300
    )
    username_input = pn.widgets.TextInput(
        name="Username", placeholder="user1", width=200
    )
    role_select = pn.widgets.Select(
        name="Role", options=available_roles, value="user", width=180
    )
    add_user_btn = pn.widgets.Button(name="Add to Allowlist", button_type="primary")
    add_user_status = pn.pane.Markdown("")

    # ---- Pending + Active Users sections (reactive on tenant selection) ----
    pending_col = pn.Column()
    active_users_col = pn.Column()

    def refresh_pending(*_):
        tid = tenant_select.value
        pending_col.objects = [make_pending_users_panel(tid, refresh_pending, ctx)]

    def refresh_active_users(*_):
        def _inner():
            # Show all users accessible to this admin regardless of the tenant
            # currently selected in the management dropdown.
            active_users_col.objects = [make_active_users_panel(user_info)]
        ctx.run(_inner)

    def on_create_tenant(event=None):
        def _inner():
            name = tenant_name_input.value.strip()
            if not name:
                create_tenant_status.object = "_Please enter a tenant name._"
                return
            try:
                new_id = admin_create_tenant(name)
                create_tenant_status.object = f"Created **{name}** (`{new_id}`)"
                tenant_name_input.value = ""
                tenant_select.options = _tenant_options()
            except Exception as e:
                create_tenant_status.object = f"_Error: {e}_"
        ctx.run(_inner)

    def on_add_user(event=None):
        def _inner():
            email = email_input.value.strip()
            username = username_input.value.strip()
            tid = tenant_select.value
            if not email or not tid:
                add_user_status.object = "_Please select a tenant and enter an email._"
                return
            if not username:
                add_user_status.object = "_Please enter a username._"
                return
            try:
                admin_add_to_allowlist(email, tid, role_select.value, username)
                add_user_status.object = f"Added **{email}** (`{username}`) with role `{role_select.value}`."
                email_input.value = ""
                username_input.value = ""
                refresh_pending()
            except Exception as e:
                add_user_status.object = f"_Error: {e}_"
        ctx.run(_inner)

    def on_tenant_change(event=None):
        ctx.run(refresh_pending)
        refresh_active_users()

    create_tenant_btn.on_click(on_create_tenant)
    add_user_btn.on_click(on_add_user)
    tenant_select.param.watch(on_tenant_change, "value")
    ctx.run(refresh_pending)
    refresh_active_users()

    banner = make_impersonation_banner()
    components: list[Any] = []
    if banner:
        components.append(banner)
    components += [
        "## SaasCo Admin",
        pn.layout.Divider(),
        "### Create New Tenant",
        pn.Row(tenant_name_input, create_tenant_btn),
        create_tenant_status,
        pn.layout.Divider(),
        "### Manage Tenant Users",
        tenant_select,
        "#### Add User to Allowlist",
        pn.Row(email_input, username_input, role_select, add_user_btn),
        add_user_status,
        "#### Users Awaiting Login",
        pending_col,
        "#### Active Users",
        active_users_col,
        pn.layout.Divider(),
        pn.pane.Markdown("[Back to app](/panel) | [Log out](/auth/logout)"),
    ]
    return pn.Column(*components, sizing_mode="stretch_width")
