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

Run: uvicorn 3_supabase_multitenant_admin:app --reload --port 8000
Set SUPABASE_APP_URL, SUPABASE_API_KEY in .env.
Optional: AUTH_REDIRECT_URL, SESSION_SECRET_KEY (openssl rand -hex 32).
Apply migration1.sql in Supabase before running.
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
SESSION_SECRET_KEY = os.environ.get("SESSION_SECRET_KEY", os.urandom(32).hex())
if not os.environ.get("SESSION_SECRET_KEY"):
    logger.warning(
        "SESSION_SECRET_KEY not set; using a random value. Sessions will not persist across restarts."
    )

# Request-scoped auth (set by middleware)
access_token_ctx: ContextVar[Optional[str]] = ContextVar("access_token", default=None)
user_email_ctx: ContextVar[Optional[str]] = ContextVar("user_email", default=None)

# Roles that can access /admin (tenant-level admin)
TENANT_ADMIN_ROLES = {"saasco_superuser", "saasco_employee", "tenant_superuser", "tenant_admin"}
# Roles that can access /tenantadmin (SaasCo staff only)
SAASCO_STAFF_ROLES = {"saasco_superuser", "saasco_employee"}


def _supabase_auth_client() -> Client:
    """Client with PKCE flow for login."""
    return create_client(SUPABASE_URL, SUPABASE_ANON_KEY, ClientOptions(flow_type="pkce"))


def get_supabase_for_user(access_token: Optional[str]) -> Client:
    """Supabase client with user JWT so RLS applies."""
    opts = ClientOptions()
    if access_token:
        opts.headers = {"Authorization": f"Bearer {access_token}"}
    return create_client(SUPABASE_URL, SUPABASE_ANON_KEY, options=opts)


# ---------------------------------------------------------------------------
# Auth middleware
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
    assert auth_resp.user is not None and auth_resp.user.email is not None
    request.session["email"] = auth_resp.user.email
    request.session["access_token"] = auth_resp.session.access_token
    request.session["refresh_token"] = auth_resp.session.refresh_token
    return RedirectResponse("/panel", status_code=302)


@app.get("/auth/logout")
async def auth_logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/", status_code=302)


@app.get("/")
async def root():
    return RedirectResponse(url="/panel", status_code=302)


# ---------------------------------------------------------------------------
# Data helpers
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
    r = supabase.table("users").select("user_id, username, user_email, tenant_id, role").execute()
    return list(r.data or [])


def get_current_user_info() -> Optional[dict[str, Any]]:
    """Returns {user_id, role, tenant_id} for the current user, or None."""
    token = _token()
    email = user_email_ctx.get()
    if not token or not email:
        return None
    try:
        supabase = get_supabase_for_user(token)
        r = supabase.table("users").select("user_id, role, tenant_id").eq("user_email", email).execute()
        return r.data[0] if r.data else None
    except Exception:
        logger.exception("get_current_user_info")
        return None


def list_tenants() -> list[dict[str, Any]]:
    """All tenants visible to the current user (RLS-scoped)."""
    supabase = get_supabase_for_user(_require_token())
    r = supabase.table("tenants").select("id, name").order("name").execute()
    return list(r.data or [])


def admin_create_tenant(name: str) -> str:
    """Create a new tenant (RLS restricts to SaasCo staff). Returns new tenant id."""
    supabase = get_supabase_for_user(_require_token())
    r = supabase.table("tenants").insert({"name": name}).execute()
    return r.data[0]["id"]


def admin_add_to_allowlist(email: str, tenant_id: str, role: str) -> None:
    """Upsert an allowlist entry. RLS enforces role-on-role constraints."""
    supabase = get_supabase_for_user(_require_token())
    supabase.table("tenant_email_allowlist").upsert(
        {"email": email.lower(), "tenant_id": tenant_id, "role": role}
    ).execute()


def admin_remove_from_allowlist(email: str) -> None:
    supabase = get_supabase_for_user(_require_token())
    supabase.table("tenant_email_allowlist").delete().eq("email", email.lower()).execute()


def admin_list_allowlist(tenant_id: Optional[str] = None) -> list[dict[str, Any]]:
    """List allowlist entries. RLS scopes results to what the caller may see."""
    supabase = get_supabase_for_user(_require_token())
    query = supabase.table("tenant_email_allowlist").select("email, tenant_id, role, created_at")
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
# Shared Panel component: "Users Awaiting Login" (allowlist entries)
# ---------------------------------------------------------------------------
def make_pending_users_panel(tenant_id: Optional[str], on_refresh) -> pn.Column:
    """
    Returns a Panel Column listing allowlist entries for *tenant_id* with a
    Remove button on each row.  Call on_refresh() after a removal to rebuild.
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
        role = entry["role"]
        remove_btn = pn.widgets.Button(name="Remove", button_type="danger", width=90)

        def _on_remove(event, _email=email):
            try:
                admin_remove_from_allowlist(_email)
            except Exception as exc:
                logger.exception("admin_remove_from_allowlist")
            on_refresh()

        remove_btn.on_click(_on_remove)
        rows.append(
            pn.Row(
                pn.pane.Markdown(f"**{email}** — `{role}`", width=420),
                remove_btn,
            )
        )

    return pn.Column(*rows)


# ---------------------------------------------------------------------------
# Panel app: user view — login link or org member list
# ---------------------------------------------------------------------------
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

        lines = [
            f"**Signed in as:** {email}",
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

    refresh_btn.on_click(update_view)
    update_view()

    return pn.Column(
        main_md,
        pn.Row(refresh_btn, logout_md),
        sizing_mode="stretch_width",
    )


# ---------------------------------------------------------------------------
# Panel app: /admin — tenant superuser / tenant admin view
# ---------------------------------------------------------------------------
@add_application("/admin", app=app, title="Tenant Admin")
def create_admin_app():
    if not _token():
        return pn.Column(pn.pane.Markdown("[Log in with Google](/auth/login)"))

    user_info = get_current_user_info()
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
    role_select = pn.widgets.Select(name="Role", options=available_roles, value="user", width=160)
    add_btn = pn.widgets.Button(name="Add to Allowlist", button_type="primary")
    status_md = pn.pane.Markdown("")
    pending_col = pn.Column()

    def refresh_pending(*_):
        pending_col.objects = [make_pending_users_panel(tenant_id, refresh_pending)]

    def on_add(event=None):
        email = email_input.value.strip()
        if not email:
            status_md.object = "_Please enter an email address._"
            return
        try:
            admin_add_to_allowlist(email, tenant_id, role_select.value)
            status_md.object = f"Added **{email}** with role `{role_select.value}`."
            email_input.value = ""
            refresh_pending()
        except Exception as e:
            status_md.object = f"_Error: {e}_"

    add_btn.on_click(on_add)
    refresh_pending()

    return pn.Column(
        "## Tenant Admin",
        "### Add User to Allowlist",
        pn.Row(email_input, role_select, add_btn),
        status_md,
        pn.layout.Divider(),
        "### Users Awaiting Login",
        pending_col,
        pn.layout.Divider(),
        pn.pane.Markdown("[Back to app](/panel) | [Log out](/auth/logout)"),
        sizing_mode="stretch_width",
    )


# ---------------------------------------------------------------------------
# Panel app: /tenantadmin — SaasCo staff view
# ---------------------------------------------------------------------------
@add_application("/tenantadmin", app=app, title="SaasCo Admin")
def create_tenantadmin_app():
    if not _token():
        return pn.Column(pn.pane.Markdown("[Log in with Google](/auth/login)"))

    user_info = get_current_user_info()
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
    role_select = pn.widgets.Select(
        name="Role", options=available_roles, value="user", width=180
    )
    add_user_btn = pn.widgets.Button(name="Add to Allowlist", button_type="primary")
    add_user_status = pn.pane.Markdown("")

    # ---- Pending Users section (reactive on tenant selection) ----
    pending_col = pn.Column()

    def refresh_pending(*_):
        tid = tenant_select.value
        pending_col.objects = [make_pending_users_panel(tid, refresh_pending)]

    def on_create_tenant(event=None):
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

    def on_add_user(event=None):
        email = email_input.value.strip()
        tid = tenant_select.value
        if not email or not tid:
            add_user_status.object = "_Please select a tenant and enter an email._"
            return
        try:
            admin_add_to_allowlist(email, tid, role_select.value)
            add_user_status.object = f"Added **{email}** with role `{role_select.value}`."
            email_input.value = ""
            refresh_pending()
        except Exception as e:
            add_user_status.object = f"_Error: {e}_"

    def on_tenant_change(event=None):
        refresh_pending()

    create_tenant_btn.on_click(on_create_tenant)
    add_user_btn.on_click(on_add_user)
    tenant_select.param.watch(on_tenant_change, "value")
    refresh_pending()

    return pn.Column(
        "## SaasCo Admin",
        pn.layout.Divider(),
        "### Create New Tenant",
        pn.Row(tenant_name_input, create_tenant_btn),
        create_tenant_status,
        pn.layout.Divider(),
        "### Manage Tenant Users",
        tenant_select,
        "#### Add User to Allowlist",
        pn.Row(email_input, role_select, add_user_btn),
        add_user_status,
        "#### Users Awaiting Login",
        pending_col,
        pn.layout.Divider(),
        pn.pane.Markdown("[Back to app](/panel) | [Log out](/auth/logout)"),
        sizing_mode="stretch_width",
    )
