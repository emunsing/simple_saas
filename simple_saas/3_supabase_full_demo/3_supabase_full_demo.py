from __future__ import annotations

"""
Multi-tenant ReBAC MVP: Supabase + FastAPI + Panel.

- Auth: Supabase Google OAuth; session in cookie.
- Data: tenants, users, products, product_user_map; RLS enforces access.
- Panel: Create Product, Share Product with org member, View products (refresh on change).

Run: uvicorn webscenarios.12_supabase_full_demo:app --reload --port 8000
Set SUPABASE_URL, SUPABASE_ANON_KEY in .env. Optional: AUTH_REDIRECT_URL, SESSION_SECRET_KEY.
SESSION_SECRET_KEY: use a stable secret so sessions persist across restarts (e.g. openssl rand -hex 32).
Configure Google OAuth in Supabase Dashboard and add redirect URL: http://127.0.0.1:8000/auth/callback
Apply migrations in Supabase (SQL Editor or supabase db push).
"""

"""
MAIN PROMPT:
I want to build a multi-tenant relation-based access control (ReBAC) web app as an MVP for understanding how to use Supabase, FastAPI, and holoviz Panel together to create a fully-featured fully-python web app.

As an MVP, let's just have our web app allow users to create a new "Product", and share that Product with other Users within their organization.  So our Panel app will just have 3 functions:
- Create a Product (just a button)
- Share a Product with a member of your organization (from a drop-down of users in your organization)
- View a list of products available to you (should refresh on change)

I would expect our database to have the following tables:
- Tenants (fields: just the id)
- Users (fields: user_id, tenant, username, user_email)
- product_user_map (fields: product_id, user_id)
- Products (fields: product_id)

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

# Request-scoped access token (set by middleware)
access_token_ctx: ContextVar[Optional[str]] = ContextVar("access_token", default=None)


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
        print("Middleware session:", request.session)
        print("Middleware Context token:", _token())
        token = request.session.get("access_token") if request.session else None
        print("Middleware access token:", token)
        token_ctx = access_token_ctx.set(token)
        try:
            return await call_next(request)
        finally:
            access_token_ctx.reset(token_ctx)


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

def prep_for_json(obj: dict) -> Any:
    if isinstance(obj, dict):
        return {k: prep_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [prep_for_json(item) for item in obj]
    elif hasattr(obj, "isoformat"):  # Handle datetime objects
        return obj.isoformat()
    else:
        return obj


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
    # request.session["user"] = prep_for_json(auth_resp.user.dict())
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


def list_products() -> list[dict[str, Any]]:
    """Products visible to current user (RLS)."""
    supabase = get_supabase_for_user(_require_token())
    r = supabase.table("products").select("product_id, tenant_id, created_by").execute()
    return list(r.data or [])


def list_org_users() -> list[dict[str, Any]]:
    """Users in the current user's tenant (for share dropdown)."""
    supabase = get_supabase_for_user(_require_token())
    r = supabase.table("users").select("user_id, username, user_email, tenant_id").execute()
    return list(r.data or [])


def create_product() -> dict[str, Any]:
    """Create a product and grant creator access via product_user_map."""
    supabase = get_supabase_for_user(_require_token())
    # Get current user row for tenant_id and user_id
    me = supabase.table("users").select("user_id, tenant_id").eq("user_id", _require_token()).single().execute()
    if not me.data:
        raise PermissionError("Your user is not in the app users table. Add your auth.uid() to public.users.")
    user_id = me.data["user_id"]
    tenant_id = me.data["tenant_id"]

    product = (
        supabase.table("products")
        .insert({"tenant_id": tenant_id, "created_by": user_id})
        .select("product_id, tenant_id, created_by")
        .execute()
    )
    if not product.data or len(product.data) != 1:
        raise RuntimeError("Product insert failed")
    row = product.data[0]
    product_id = row["product_id"]

    supabase.table("product_user_map").insert({"product_id": product_id, "user_id": user_id}).execute()
    return row


def share_product(product_id: str, user_id: str) -> None:
    """Add user to product_user_map (RLS: only product creator can insert)."""
    supabase = get_supabase_for_user(_require_token())
    supabase.table("product_user_map").insert({"product_id": product_id, "user_id": user_id}).execute()


# ---------------------------------------------------------------------------
# REST API (optional; Panel can call Python helpers via context)
# ---------------------------------------------------------------------------
@app.get("/api/products")
async def api_list_products():
    try:
        return list_products()
    except PermissionError as e:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail=str(e))


@app.post("/api/products", status_code=201)
async def api_create_product():
    try:
        return create_product()
    except PermissionError as e:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail=str(e))
    except RuntimeError as e:
        from fastapi import HTTPException
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/products/{product_id}/share")
async def api_share_product(product_id: str, user_id: str):
    try:
        share_product(product_id, user_id)
        return {"ok": True}
    except PermissionError as e:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/users/org")
async def api_list_org_users():
    try:
        return list_org_users()
    except PermissionError as e:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail=str(e))


# ---------------------------------------------------------------------------
# Panel app: Create Product, Share Product, View products (refresh on change)
# ---------------------------------------------------------------------------
# Panel runs on the server; middleware sets access_token_ctx from cookie, so
# callbacks use list_products() / create_product() / share_product() directly.


@add_application("/panel", app=app, title="Products (ReBAC)")
def create_panel_app():
    status = pn.pane.Markdown("", width=400)
    products_md = pn.pane.Markdown("_Loading…_", width=500)

    def load_products():
        print("In load_products, Context token:", _token())
        try:
            if not _token():
                products_md.object = "**Not logged in.** [Log in with Google](/auth/login) first."
                return
            data = list_products()
            if not isinstance(data, list):
                data = [data] if data else []
            if not data:
                products_md.object = "_No products yet. Create one below._"
                return
            lines = ["**Products you can access:**", ""]
            for p in data:
                pid = p.get("product_id")
                lines.append(f"- `{pid}`")
            products_md.object = "\n".join(lines)
        except PermissionError:
            products_md.object = "**Not logged in.** [Log in with Google](/auth/login) first."
        except Exception as e:
            products_md.object = f"Error loading products: {e}"
            logger.exception("load_products")

    def load_org_users():
        try:
            if not _token():
                return [], []
            data = list_org_users()
            if not isinstance(data, list):
                data = [data] if data else []
            labels = [f"{u.get('username')} ({u.get('user_email') or u.get('user_id')})" for u in data]
            return labels, data
        except Exception as e:
            logger.exception("load_org_users")
            return [], []

    # Widgets
    create_btn = pn.widgets.Button(name="Create a product", button_type="primary")
    share_product_select = pn.widgets.Select(name="Product to share", options=[], value=None)
    share_user_select = pn.widgets.Select(name="Share with user", options=[], value=None)
    share_btn = pn.widgets.Button(name="Share product", button_type="default")
    refresh_btn = pn.widgets.Button(name="Refresh list", button_type="default")

    # Store raw data for mapping selection -> id
    products_data: list[dict] = []
    users_data: list[dict] = []

    def sync_dropdowns():
        nonlocal products_data, users_data
        if not _token():
            share_user_select.options = []
            share_product_select.options = []
            return
        try:
            products_data = list_products()
        except Exception:
            products_data = []
        if not isinstance(products_data, list):
            products_data = [products_data] if products_data else []
        opts, users_data = load_org_users()
        share_user_select.options = opts
        share_user_select.value = opts[0] if opts else None
        product_opts = [str(p.get("product_id")) for p in products_data]
        share_product_select.options = product_opts
        share_product_select.value = product_opts[0] if product_opts else None

    def on_create(event):
        try:
            create_product()
            status.object = "Product created."
            sync_dropdowns()
            load_products()
        except PermissionError:
            status.object = "Not logged in. Use the link above to log in."
        except Exception as e:
            status.object = f"Error: {e}"
            logger.exception("on_create")

    def on_share(event):
        try:
            product_id = share_product_select.value
            if not product_id:
                status.object = "Select a product first."
                return
            label = share_user_select.value
            if not label or not users_data:
                status.object = "Select a user first."
                return
            opts = share_user_select.options or []
            idx = opts.index(label) if label in opts else 0
            user_id = str(users_data[idx]["user_id"]) if idx < len(users_data) else None
            if not user_id:
                status.object = "Could not resolve user."
                return
            share_product(product_id, user_id)
            status.object = "Product shared."
            load_products()
        except PermissionError:
            status.object = "Not logged in."
        except Exception as e:
            status.object = f"Error: {e}"
            logger.exception("on_share")

    def on_refresh(event):
        sync_dropdowns()
        load_products()
        status.object = "List refreshed."

    create_btn.on_click(on_create)
    share_btn.on_click(on_share)
    refresh_btn.on_click(on_refresh)

    # Initial load (token may be in context from middleware)
    load_products()
    sync_dropdowns()

    layout = pn.Column(
        pn.pane.Markdown("## Products (ReBAC MVP)"),
        pn.Row(pn.Column(pn.pane.Markdown("[Log in with Google](/auth/login) · [Log out](/auth/logout)"), refresh_btn)),
        pn.Spacer(height=10),
        pn.Row(create_btn, status),
        pn.pane.Markdown("---"),
        products_md,
        pn.Spacer(height=10),
        pn.pane.Markdown("**Share a product with someone in your organization:**"),
        pn.Row(share_product_select, share_user_select, share_btn),
    )
    return layout
