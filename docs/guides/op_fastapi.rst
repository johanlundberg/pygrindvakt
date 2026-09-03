OpenID Provider on FastAPI
==========================

This guide builds the five OP endpoints as FastAPI routes. The runnable
version is ``examples/fastapi-op/app.py`` in the repository; run it with
``cd examples/fastapi-op && ../../.venv/bin/uvicorn app:app --port 5000``.

pygrindvakt's API is synchronous: each provider call blocks the calling
thread (with the GIL released) until grindvakt's async work completes. In an
ASGI application that means every provider call goes through
``run_in_threadpool``, so the event loop stays free while the native side
works. Never call a provider method directly from a coroutine on the event
loop; it would stall every other request for the duration.

The adapters
------------

Starlette's ``Request`` exposes the raw body only through an awaitable, so
the request adapter is ``async``. The example parses the form body itself
with :func:`urllib.parse.parse_qsl` rather than ``request.form()``, which
would pull in ``python-multipart``:

.. code-block:: python

   from urllib.parse import parse_qsl

   import fastapi
   from fastapi import Request
   from pygrindvakt.http import HttpRequestData, Response

   async def request_data(request: Request) -> HttpRequestData:
       body = await request.body()
       headers = {k.lower(): v for k, v in request.headers.items()}
       form: dict[str, str] = {}
       if headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
           form = dict(parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True))
       return HttpRequestData(
           path=request.url.path.lstrip("/"),
           method=request.method,
           uri=str(request.url),
           query=dict(request.query_params),
           form=form,
           body=body,
           headers=headers,
           cookies=dict(request.cookies),
       )

   def to_fastapi(resp: Response) -> fastapi.Response:
       out = fastapi.Response(content=resp.body, status_code=resp.status)
       for name, value in resp.headers:
           out.headers.append(name, value)      # keeps multi-valued headers
       return out

The provider
------------

Build it once per process at import time from configuration, and derive the
token URL from the same issuer setting:

.. code-block:: python

   import os
   from fastapi import FastAPI
   from starlette.concurrency import run_in_threadpool

   from pygrindvakt import OAuthError
   from pygrindvakt.request import AuthorizationRequest

   ISSUER = os.environ.get("OP_ISSUER", "http://127.0.0.1:5000")
   TOKEN_URL = f"{ISSUER}/token"          # from configuration, never from the Host header
   OP = build_provider(ISSUER)            # see the Flask guide for build_provider
   app = FastAPI(title="pygrindvakt demo OP")

Under ``uvicorn --workers N`` each worker imports the module after fork, so
import-time construction is safe. If you switch to a shared token-use store,
a lifespan handler is the equivalent of gunicorn's ``post_fork``.

The routes
----------

Discovery and JWKS return static dicts; the example still routes them
through the threadpool for uniformity, though they do no I/O:

.. code-block:: python

   @app.get("/.well-known/openid-configuration")
   async def discovery():
       return to_fastapi(Response.json(await run_in_threadpool(OP.discovery_document)))

   @app.get("/jwks")
   async def jwks():
       return to_fastapi(Response.json(await run_in_threadpool(OP.jwks_document)))

The authorization endpoint needs to remember the pending request between
the login page and the credential POST. The example keeps it in a cookie
signed with ``itsdangerous`` (Starlette's ``SessionMiddleware`` works just
as well); the cookie is deleted once the POST has consumed it.

.. code-block:: python

   from itsdangerous import BadSignature, URLSafeTimedSerializer

   AUTHZ_COOKIE = "op_authz"
   _signer = URLSafeTimedSerializer(os.environ["OP_SECRET_KEY"], salt="authz")

   def save_authz(value: dict) -> str:
       return _signer.dumps(value)

   def load_authz(cookie: str) -> dict | None:
       try:
           return _signer.loads(cookie, max_age=600)
       except BadSignature:
           return None

   @app.get("/authorization")
   async def authorization(request: Request):
       data = await request_data(request)
       try:
           req = AuthorizationRequest.from_params(data.query)
           await run_in_threadpool(OP.validate_authorization_request, req)
       except OAuthError as e:
           # The redirect_uri is not trusted until validation succeeds: never redirect here.
           return to_fastapi(e.to_response())
       out = to_fastapi(Response.html(render_login_form(req.client_id)))
       out.set_cookie(AUTHZ_COOKIE, save_authz(req.to_dict()), httponly=True, samesite="lax")
       return out

   @app.post("/authorization")
   async def login(request: Request):
       data = await request_data(request)
       stored = load_authz(data.cookies.get(AUTHZ_COOKIE, ""))
       if stored is None:
           return to_fastapi(OAuthError("invalid_request", "no pending authorization request").to_response())
       req = AuthorizationRequest.from_dict(stored)
       claims = authenticate(data.form.get("username", ""), data.form.get("password", ""))
       if claims is None:
           err = OAuthError("access_denied", "wrong username or password", req.state)
           out = to_fastapi(err.to_redirect(req.redirect_uri))       # validated on the GET
       else:
           try:
               out = to_fastapi(await run_in_threadpool(OP.authorization_redirect, req, data.form["username"], claims))
           except OAuthError as e:
               out = to_fastapi(e.to_redirect(req.redirect_uri))
       out.delete_cookie(AUTHZ_COOKIE)
       return out

Parsing (``from_params``, ``from_dict``) is pure CPU and runs inline;
``validate_authorization_request`` and ``authorization_redirect`` consult
the client store, which may be a Python object doing database I/O, so they
go through the threadpool.

Token and userinfo are the calls that block longest (client store, token-use
store, possibly Redis):

.. code-block:: python

   @app.post("/token")
   async def token(request: Request):
       data = await request_data(request)
       try:
           tr = await run_in_threadpool(OP.handle_token_request, data.form, TOKEN_URL,
                                        auth_header=data.authorization())
       except OAuthError as e:
           return to_fastapi(e.to_response())
       return to_fastapi(tr.to_response())

   @app.api_route("/userinfo", methods=["GET", "POST"])     # OIDC Core 5.3 allows both
   async def userinfo(request: Request):
       access_token = (await request_data(request)).bearer_token()
       if access_token is None:
           return to_fastapi(OAuthError("access_denied", "missing bearer token").to_response())
       try:
           return to_fastapi(Response.json(await run_in_threadpool(OP.userinfo, access_token)))
       except OAuthError as e:
           return to_fastapi(e.to_response())

Accept both methods at userinfo: OIDC Core allows either, and
:func:`pygrindvakt.rp.fetch_userinfo` sends a POST.

Threads and the runtime
-----------------------

``run_in_threadpool`` uses AnyIO's default worker pool (40 threads). Each
provider call releases the GIL while it waits on grindvakt, so the pool's
threads genuinely run in parallel and the event loop stays responsive. The
provider object is safe to share between them.

Python protocol adapters (a custom ``ClientStore`` or ``TokenUseStore``) run
on the threadpool thread that made the call, not on the event loop, so they
must be synchronous code. An ``async`` ORM cannot be used from inside an
adapter directly; use a synchronous client (see :doc:`stores`).

Multi-process deployment
------------------------

Under ``uvicorn --workers N`` or gunicorn with uvicorn workers, each worker is
a separate process. Use :class:`~pygrindvakt.provider.RedisStore` constructed
in the worker (a lifespan handler runs after fork and is a good place) or a
Python-backed store; see :doc:`stores`.
