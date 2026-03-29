# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A set of progressive skill-building tutorials for building a multi-tenant SaaS application in Python. The goal is a ReBAC (relationship-based access control) system with multiple tenants, multiple users per tenant, and shared resources.

**Stack:** Panel (frontend), FastAPI + Uvicorn (backend), Supabase (auth + DB), SQLAlchemy/SQLModel (data model)

## Commands

### Setup
```bash
poetry install
```

### Running a demo
```bash
# Either of these work:
python simple_saas/<demo>/<script>.py
uvicorn simple_saas.<demo>.<script>:app --reload --port 8000
```

### Linting
```bash
ruff check .
ruff format .
```

## Demo Progression

Each demo is a self-contained FastAPI app with its own SQL migrations:

1. **`0_supabase_simple_oauth.py`** — Basic PKCE OAuth with Supabase (no Panel)
2. **`1_supabase_multitenant_users/`** — Multi-tenant users; Panel app shows org members
3. **`2_supabase_full_demo/`** — Adds products with create/share/view via Panel

## Architecture Patterns

### Auth Flow (PKCE)
- `/auth/login`: Creates a Supabase client with `flow_type="pkce"`, initiates OAuth, saves `code_verifier` to session before redirect
- `/auth/callback`: Retrieves `code_verifier` from session, exchanges code for session, stores `access_token` + `email` in cookie session
- The Supabase client's internal storage key for the verifier: `f"{supabase.auth._storage_key}-code-verifier"`

### Request-Scoped Auth Context
Auth tokens are propagated to Panel (which runs server-side) via `ContextVar`:
```python
access_token_ctx: ContextVar[Optional[str]]
user_email_ctx: ContextVar[Optional[str]]
```
`AuthContextMiddleware` (BaseHTTPMiddleware) reads from `request.session` and sets these vars on each request.

**Middleware order matters:** `SessionMiddleware` must be added after `AuthContextMiddleware` so it runs first (last-added = outermost):
```python
app.add_middleware(AuthContextMiddleware)
app.add_middleware(SessionMiddleware, secret_key=...)
```

### Supabase Client Per-Request
Two client types:
- `_supabase_auth_client()`: PKCE flow, used only during login
- `get_supabase_for_user(access_token)`: Sets `Authorization: Bearer <token>` header so Supabase enforces RLS using the user's JWT

### Panel Integration
Panel apps are mounted via `panel.io.fastapi.add_application`:
```python
@add_application("/panel", app=app, title="...")
def create_panel_app():
    ...
```
Panel callbacks read `access_token_ctx.get()` / `user_email_ctx.get()` directly (no HTTP request object available).

### Database / RLS (Supabase)
Migrations are plain SQL files in each demo directory. Key pattern: helper functions with `SECURITY DEFINER` to avoid RLS recursion when policies need to look up the current user's tenant:
```sql
create function public.current_user_tenant_id() returns uuid
language sql security definer set search_path = public stable as $$
  select tenant_id from public.users where user_id = auth.uid() limit 1;
$$;
```

## Environment Variables

Required in `.env`:
- `SUPABASE_APP_URL` — Supabase project URL
- `SUPABASE_API_KEY` — Supabase anon/publishable key

Optional:
- `SESSION_SECRET_KEY` — Stable session secret (use `openssl rand -hex 32`); if unset, sessions don't survive server restarts
- `AUTH_REDIRECT_URL` — OAuth callback URL (default: `http://127.0.0.1:8000/auth/callback`)
- `DATABASE_URL` — Postgres URL for non-Supabase demos

## Gotchas

- **Websocket cookie size**: If the Panel app silently fails to load, you may have too many `localhost` cookies. Try `127.0.0.1` or clear site cookies.
- **Session size**: Supabase `User` objects contain datetimes and exceed the 2KB cookie limit — store only `email`, `access_token`, and `refresh_token` in the session.
- **Microsoft OAuth**: Must be configured via Azure, not Entra.
- **Mac + Flask OAuth**: `localhost` may resolve to IPv6 `::1`; use `127.0.0.1` explicitly.
