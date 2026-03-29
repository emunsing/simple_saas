from __future__ import annotations

"""
Multi-tenant ReBAC MVP: Supabase + FastAPI + Panel.

- Auth: Supabase Google OAuth; session in cookie.
- Data: tenants, users; RLS enforces access.
- Panel: Login link when anonymous; when authenticated, email and org user list.

Run: uvicorn 2_supabase_multitenant_users:app --reload --port 8000
Set SUPABASE_URL, SUPABASE_ANON_KEY in .env. Optional: AUTH_REDIRECT_URL, SESSION_SECRET_KEY.
SESSION_SECRET_KEY: use a stable secret so sessions persist across restarts (e.g. openssl rand -hex 32).
Configure Google OAuth in Supabase Dashboard and add redirect URL: http://127.0.0.1:8000/auth/callback
Apply migrations in Supabase (SQL Editor or supabase db push).
"""

"""
MAIN PROMPT:
I want to build a multi-tenant relation-based access control (ReBAC) web app as an MVP for understanding how to use Supabase, FastAPI, and holoviz Panel together to create a very basic multi-tenant fully-python web app.

As an MVP, let's just have our web app allow users to see other people in their organization/tenant.  
- When the user isn't logged in, they should just see a login button.  
- When they are logged in, they should see their own email/userID, and a list of other users in their tenant organization.

I would expect our database to have the following tables:
- Tenants (fields: just the id)
- Users (fields: user_id, tenant, username, user_email)

Assume that we will define the list of users and their tenant organizations directly in the database.

Right now, let's fully utilize Supabase for the database migrations, setting up RLS rules, authentication via Google OAuth, and authorization.
"""


import logging
import os
from contextvars import ContextVar
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
AUTH_REDIRECT_URL = os.environ.get("AUTH_REDIRECT_URL", "http://127.0.0.1:8000/auth/callback")
# Stable secret for session cookie (required for session to persist across server restarts)
SESSION_SECRET_KEY = os.environ.get("SESSION_SECRET_KEY", os.urandom(32).hex())
if not os.environ.get("SESSION_SECRET_KEY"):
    logger.warning(
        "SESSION_SECRET_KEY not set; using a random value. Sessions will not persist across restarts."
    )

# Request-scoped auth (set by middleware)
access_token_ctx: ContextVar[Optional[str]] = ContextVar("access_token", default=None)
user_email_ctx: ContextVar[Optional[str]] = ContextVar("user_email", default=None)


def _supabase_auth_client() -> Client:
    """Client with PKCE flow for login; generates and stores code_verifier when sign_in_with_oauth is called."""
    return create_client(
        SUPABASE_URL,
        SUPABASE_ANON_KEY,
        ClientOptions(flow_type="pkce"),
    )


def get_supabase_for_user(access_token: Optional[str]) -> Client:
    """Supabase client with user JWT so RLS applies. Use anon key + Authorization header."""
    opts = ClientOptions()
    if access_token:
        opts.headers = {"Authorization": f"Bearer {access_token}"}
    return create_client(SUPABASE_URL, SUPABASE_ANON_KEY, options=opts)


# ---------------------------------------------------------------------------
# Auth middleware: set access_token from session (set in /auth/callback)
# ---------------------------------------------------------------------------
class AuthContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        session = getattr(request, "session", None)
        token = request.session.get("access_token") if session else None
        email = request.session.get("email") if session else None
        token_ctx = access_token_ctx.set(token)
        email_ctx = user_email_ctx.set(email)
        try:
            return await call_next(request)
        finally:
            access_token_ctx.reset(token_ctx)
            user_email_ctx.reset(email_ctx)


# ---------------------------------------------------------------------------
# FastAPI app & auth routes
# ---------------------------------------------------------------------------
app = FastAPI(title="Multi-tenant ReBAC (Supabase)")
# Last-added middleware runs first (outermost). SessionMiddleware must run before AuthContextMiddleware
# so request.session is available when we read access_token.
app.add_middleware(AuthContextMiddleware)
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET_KEY)


@app.get("/auth/login")
async def auth_login(request: Request):
    """
    Redirect to Supabase Google OAuth. Uses client's PKCE (flow_type='pkce'); the code_verifier
    is stored in the client's in-memory storage, so we copy it to request.session so it survives
    the redirect. Relies on supabase.auth internal storage key; see _supabase_auth_client().
    """
    supabase = _supabase_auth_client()
    resp = supabase.auth.sign_in_with_oauth(
        {"provider": "google", "options": {"redirect_to": AUTH_REDIRECT_URL}}
    )
    # Persist the PKCE code verifier in the session so it survives the redirect
    storage_key = f"{supabase.auth._storage_key}-code-verifier"
    request.session["code_verifier"] =  supabase.auth._storage.get_item(storage_key)
    return RedirectResponse(resp.url)


@app.get("/auth/callback")
async def auth_callback(request: Request, code: str | None = None):
    if not code:
        return RedirectResponse("/login")

    code_verifier = request.session.pop("code_verifier", None)
    if not code_verifier:
        print("No code verifier found")
        return RedirectResponse("/login")
    else:
        print("Successful code verifier found")

    supabase = _supabase_auth_client()
    auth_resp = supabase.auth.exchange_code_for_session(
        {"auth_code": code, "code_verifier": code_verifier}
    )
    print("Raw User dict")
    print(auth_resp.user.dict())
    print("User ID:", auth_resp.user.id)

    assert auth_resp.user is not None and auth_resp.user.email is not None, "Expected auth response to have user & email"
    # Note: The auth_resp.user objects contains a number of datetimes, which aren't serializable
    # The auth_resp.user is also larger than the 2kb cookie limit, so we have to choose a subset to store.
    request.session["email"] = auth_resp.user.email
    print("Session after login callback:", request.session)
    print("Access token:", auth_resp.session.access_token)
    request.session["access_token"] = auth_resp.session.access_token
    request.session["refresh_token"] = auth_resp.session.refresh_token
    print("Made it through to the redirect!")
    return RedirectResponse("/panel", status_code=302)


@app.get("/auth/logout")
async def auth_logout(request: Request):
    """Clear session and redirect home."""
    request.session.clear()
    return RedirectResponse(url="/", status_code=302)


@app.get("/")
async def root():
    """Link to login or panel."""
    return RedirectResponse(url="/panel", status_code=302)


# ---------------------------------------------------------------------------
# Data helpers (use context token; called from Panel or API)
# ---------------------------------------------------------------------------
def _token() -> Optional[str]:
    return access_token_ctx.get()


def _require_token() -> str:
    t = _token()
    if not t:
        raise PermissionError("Not authenticated. Go to /auth/login")
    return t

def list_org_users() -> list[dict[str, Any]]:
    """Users in the current user's tenant (RLS-scoped)."""
    supabase = get_supabase_for_user(_require_token())
    r = supabase.table("users").select("user_id, username, user_email, tenant_id").execute()
    return list(r.data or [])


# ---------------------------------------------------------------------------
# REST API (optional; Panel can call Python helpers via context)
# ---------------------------------------------------------------------------

@app.get("/api/users/org")
async def api_list_org_users():
    try:
        return list_org_users()
    except PermissionError as e:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail=str(e))


# ---------------------------------------------------------------------------
# Panel app: login link, or email + org members (refresh on demand)
# ---------------------------------------------------------------------------
# Panel runs on the server; middleware sets access_token_ctx and user_email_ctx.


@add_application("/panel", app=app, title="Organization")
def create_panel_app():
    main_md = pn.pane.Markdown("", sizing_mode="stretch_width")
    refresh_btn = pn.widgets.Button(name="Refresh members", button_type="primary")
    logout_md = pn.pane.Markdown("[Log out](/auth/logout)")

    def update_view(event=None):
        if not _token():
            main_md.object = "[Log in with Google](/auth/login)"
            refresh_btn.visible = False
            logout_md.visible = False
            return
        refresh_btn.visible = True
        logout_md.visible = True
        email = user_email_ctx.get() or "—"
        try:
            rows = list_org_users()
        except PermissionError:
            main_md.object = (
                f"**Signed in as:** {email}\n\n"
                "_Could not load members (not authenticated)._\n\n"
                "[Log in with Google](/auth/login)"
            )
            return
        except Exception as e:
            logger.exception("list_org_users in panel")
            main_md.object = f"**Signed in as:** {email}\n\n_Error loading members: {e}_"
            return
        if not isinstance(rows, list):
            rows = [rows] if rows else []
        lines = [
            f"**Signed in as:** {email}",
            "",
            "### Users in your organization",
            "",
        ]
        if not rows:
            lines.append("_No users returned (check RLS and that your account exists in `public.users`)._")
        else:
            for u in rows:
                name = u.get("username") or u.get("user_id") or "—"
                mail = u.get("user_email") or ""
                lines.append(f"- **{name}** — {mail or '—'}")
        main_md.object = "\n".join(lines)

    refresh_btn.on_click(update_view)
    update_view()

    return pn.Column(
        main_md,
        pn.Row(refresh_btn, logout_md),
        sizing_mode="stretch_width",
    )
