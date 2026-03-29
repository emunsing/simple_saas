# Webscenarios

Context: This is a set of skill-building tutorials for creating a software-as-a-service (SaaS) application, working
primarily in Python.  

Key components of our stack:
- Panel for the front-end, which is a Python library for creating web apps and dashboards.
- Uvicorn for the back-end server
- Supabase for user authentication (optionally also database hosting)
- SQLAlchemy / SQLModel for the data model and database interactions

The goal is to be able to have a relationship-based access control (ReBAC) system with multiple tenants (companies), 
each of whom has multiple users, and users may share projects.

The core idea builds off of the [webscenarios]() repository, specifically 
[10_uvicorn_panel_db_reader_with_users.py](https://github.com/emunsing/webscenarios/blob/main/webscenarios/10_uvicorn_panel_db_reader_with_users.py), 
which demonstrates a simple relationship-based access control system with users and shared projects, but which doesn't 
attempt to implement authentication or multi-tenant support.

The uvicorn+panel demos can be run like `python <scriptname>.py` or `uvicorn <scriptname>:app --reload --port 8000`
- IMPORTANT: See the below note about websocket gotchas when running Panel with Uvicorn
- These require a postgres server to be running, and if the default Postgres URL isn't used, the URL should be overriden with the environment variable `DATABASE_URL`.

The demos go in the following order:
- `0_supabase_simple_oauth.py`: Basic PKCE OAuth with Supabase client
- `1_supabase_full_demo`: Full multi-tenant database access, relying on Supabase data
- `2_supabase_postgres_demo`: Use Supabase for auth, but a separate Postgres database not hosted on Supabase.

# Auth lessons

## OAuth lessons

`supabase.auth.sign_in_with_oauth(...)` will redirect the user to the oauth sign-in page.  When the user returns to 
our server, we need to be able to identify them. To do this, we set the code verifier in the session state.
Without this, the system will not be able to recognize that the user has previously been sent off on the oauth flow.

`supabase.auth.exchange_code_for_session` returns a comprehensive dict with the user's oauth info, 

# Multi-tenant lessons:

Supabase authentication creates a JWT which contains the user's 


## Panel + Uvicorn Gotchas

### Versioning

Starlette 1.0 created significant issues for the compatability with Bokeh/Panel.  Currently, 
we pin `[starlette, fastapi, bokeh-fastapi, bokeh, panel]` to ensure that we are compatible. 
If you get a persistent 403 error and are sure that your app isn't getting any other backend issues, it's likely a 
versioning issue.  

**To test that your Panel + Starlette is working,** run the 1_supabase_panel_simple_oauth.py - this doesn't rely on 
a database, so if you aren't able to render any Panel page for this app, you probably have a version issue.

### Cookie size
Websocket has a limited cookie capacity.  If you have been using `localhost` for a lot of development, you may have
accumulated many cookies, to the point that Bokeh/Websocket will refuse to parse the cookies when the HTTP request is
handed from Uvicorn to Bokeh. **This can result in a silent failure which produces no logs but the app doesn't load.**

To diagnose this:
- Check whether you are able to run successfully from 0.0.0.0 or 127.0.0.1 instead of localhost
- Try clearing the local site cookies (Chrome Inspect -> Applications -> Cookies)

### Notes on Google OAuth setup
[This Youtube Video was helpful](https://www.youtube.com/watch?v=OK_j05bxmH4) for a live walk-through of how to create
an OAuth client on the Google Cloud Platform.  This worked smoothly for me.

### Notes on Microsoft Azure OAuth setup
**Important note:** This must be set up from Microsoft **Azure**, not Microsoft Entra. Setting up on Entra kept me in an 
infinite authentication loop and never went back to the target app.

I used the "Quickstart" sample code which implements a Flask app. Two general notes about this Quicktart example:
1. You need to set the environment variables in the .env file within the quickstart app.
2. See the below note on Flask and OAuth

### Flask and OAuth on Mac
A critical but subtle note: Your redirect URI needs to be on localhost, but flask generally supports IPv4, 
and listens to 127.0.0.1 as the directory loop for `localhost`. On Mac, localhost can resolve to the IPv6 loopback 
address `::1` if the IPv4 port isn't responsive. This can result in a 403 error "Access to localhost was denied", 
while Flask doesn't provide any error messages.

To debug this: 
- Without Flask running, confirm whether there are any processes listening to localhost:5000 by running `$ lsof -i :5000`.
- **If you see any other processes listening to localhost:5000, change the port which Flask is being served on to something free

## Supabase, auth, and RLS
[Helpful blog post by dob about RLS in SqlAlchemy](https://dobken.nl/posts/rls-postgres/)

## 12_supabase_full_demo

Flow for this:
- 