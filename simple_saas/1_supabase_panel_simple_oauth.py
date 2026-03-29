"""
Minimal test: Panel + FastAPI + Supabase Google OAuth.

Verifies that Panel WebSocket, session middleware, and Supabase auth
all work together. No database access — just login/logout/display email.

Run:  uvicorn test_panel_supabase_auth:app --port 8000
Env:  SUPABASE_APP_URL, SUPABASE_API_KEY (in .env or exported)
"""

import os
from contextvars import ContextVar
from typing import Optional

import panel as pn
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from panel.io.fastapi import add_application
from starlette.middleware.sessions import SessionMiddleware
from supabase import Client, ClientOptions, create_client

load_dotenv()
pn.extension()

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SUPABASE_URL = os.environ["SUPABASE_APP_URL"]
SUPABASE_KEY = os.environ["SUPABASE_API_KEY"]
REDIRECT_URI = os.environ.get(
    "AUTH_REDIRECT_URL", "http://127.0.0.1:8000/auth/callback"
)
SESSION_SECRET = os.environ.get("SESSION_SECRET_KEY", os.urandom(32).hex())

# ---------------------------------------------------------------------------
# Request-scoped context (set by middleware, read by Panel callbacks)
# ---------------------------------------------------------------------------
user_email_ctx: ContextVar[Optional[str]] = ContextVar("user_email", default=None)


def _supabase_client() -> Client:
    return create_client(
        SUPABASE_URL, SUPABASE_KEY, ClientOptions(flow_type="pkce")
    )


# ---------------------------------------------------------------------------
# ASGI middleware (works with both HTTP and WebSocket)
# ---------------------------------------------------------------------------
class AuthContextMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            session = scope.get("session", {})
            ctx = user_email_ctx.set(session.get("email"))
            try:
                await self.app(scope, receive, send)
            finally:
                user_email_ctx.reset(ctx)
        else:
            await self.app(scope, receive, send)


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(title="Panel + Supabase Auth Test")
app.add_middleware(AuthContextMiddleware)
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)


@app.get("/")
async def root():
    return RedirectResponse("/panel")


@app.get("/auth/login")
async def login(request: Request):
    supabase = _supabase_client()
    resp = supabase.auth.sign_in_with_oauth(
        {"provider": "google", "options": {"redirect_to": REDIRECT_URI}}
    )
    storage_key = f"{supabase.auth._storage_key}-code-verifier"
    request.session["code_verifier"] = supabase.auth._storage.get_item(storage_key)
    return RedirectResponse(resp.url)


@app.get("/auth/callback")
async def auth_callback(request: Request, code: str | None = None):
    if not code:
        return RedirectResponse("/auth/login")

    code_verifier = request.session.pop("code_verifier", None)
    if not code_verifier:
        return RedirectResponse("/auth/login")

    supabase = _supabase_client()
    auth_resp = supabase.auth.exchange_code_for_session(
        {"auth_code": code, "code_verifier": code_verifier}
    )

    request.session["email"] = (
        auth_resp.user.email if auth_resp.user else "unknown"
    )
    return RedirectResponse("/panel", status_code=302)


@app.get("/auth/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/panel", status_code=302)


# ---------------------------------------------------------------------------
# Panel app
# ---------------------------------------------------------------------------
@add_application("/panel", app=app, title="Auth Test")
def create_panel_app():
    status_md = pn.pane.Markdown("", sizing_mode="stretch_width")

    def render(event=None):
        email = user_email_ctx.get()
        if email:
            status_md.object = (
                f"### Logged in as **{email}**\n\n"
                f"[Log out](/auth/logout)"
            )
        else:
            status_md.object = (
                "### Not logged in\n\n"
                "[Log in with Google](/auth/login)"
            )

    refresh_btn = pn.widgets.Button(name="Refresh", button_type="default")
    refresh_btn.on_click(render)

    render()

    return pn.Column(
        pn.pane.Markdown("## Panel + Supabase Auth Test"),
        status_md,
        refresh_btn,
        sizing_mode="stretch_width",
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)