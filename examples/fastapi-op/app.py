"""A minimal OpenID Provider on FastAPI, driven by pygrindvakt.

Run::

    cd examples/fastapi-op && ../../.venv/bin/uvicorn app:app --port 5000

The ``Provider`` methods are blocking (they release the GIL while the native
side works), so every call goes through ``run_in_threadpool``. The pending
authorization request is kept in a signed cookie (``itsdangerous``) or, when
that package is missing, in a module-level dict keyed by a random cookie
value. DEMO ONLY.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from urllib.parse import parse_qsl

import fastapi
from fastapi import FastAPI, Request
from starlette.concurrency import run_in_threadpool

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # examples/, for ``common``
from common.op_config import authenticate, build_provider, render_login_form  # noqa: E402

from pygrindvakt import OAuthError, util  # noqa: E402
from pygrindvakt.http import HttpRequestData, Response  # noqa: E402
from pygrindvakt.request import AuthorizationRequest  # noqa: E402

ISSUER = os.environ.get("OP_ISSUER", "http://127.0.0.1:5000")
TOKEN_URL = f"{ISSUER}/token"  # from configuration, never from the Host header
SECRET_KEY = os.environ.get("OP_SECRET_KEY", "dev-only-fastapi-secret")
AUTHZ_COOKIE = "op_authz"

OP = build_provider(ISSUER)  # once per process
app = FastAPI(title="pygrindvakt demo OP")


# --- adapters ---------------------------------------------------------------


async def request_data(request: Request) -> HttpRequestData:
    """Normalize a Starlette request into an ``HttpRequestData``.

    The form body is parsed here (like the tunnelbana adapter does) so the
    example does not need ``python-multipart``, which ``request.form()`` requires.
    """
    body = await request.body()
    headers = {k.lower(): v for k, v in request.headers.items()}
    form: list[tuple[str, str]] = []
    if headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
        form = parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True)
    return HttpRequestData(
        path=request.url.path.lstrip("/"),
        method=request.method,
        uri=str(request.url),
        query=list(request.query_params.multi_items()),
        form=form,
        body=body,
        headers=headers,
        cookies=dict(request.cookies),
    )


def to_fastapi(resp: Response) -> fastapi.Response:
    """Turn a pygrindvakt ``Response`` into a FastAPI / Starlette response."""
    out = fastapi.Response(content=resp.body, status_code=resp.status)
    for name, value in resp.headers:
        out.headers.append(name, value)
    return out


# --- pending authorization request storage ---------------------------------

try:
    from itsdangerous import BadSignature, URLSafeTimedSerializer

    _signer = URLSafeTimedSerializer(SECRET_KEY, salt="authz")

    def save_authz(value: dict) -> str:
        return _signer.dumps(value)

    def load_authz(cookie: str) -> dict | None:
        try:
            return _signer.loads(cookie, max_age=600)
        except BadSignature:
            return None

except ImportError:  # pragma: no cover - fallback when itsdangerous is absent
    _pending: dict[str, dict] = {}

    def save_authz(value: dict) -> str:
        sid = util.random_token()
        _pending[sid] = value
        return sid

    def load_authz(cookie: str) -> dict | None:
        return _pending.pop(cookie, None)


# --- endpoints --------------------------------------------------------------


@app.get("/.well-known/openid-configuration")
async def discovery():
    return to_fastapi(Response.json(await run_in_threadpool(OP.discovery_document)))


@app.get("/jwks")
async def jwks():
    return to_fastapi(Response.json(await run_in_threadpool(OP.jwks_document)))


@app.get("/authorization")
async def authorization(request: Request):
    data = await request_data(request)
    try:
        req = AuthorizationRequest.from_params(data.query_pairs)
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
        out = to_fastapi(err.to_redirect(req.redirect_uri, "fragment" if req.use_fragment() else "query"))
    else:
        try:
            out = to_fastapi(await run_in_threadpool(OP.authorization_redirect, req, data.form["username"], claims))
        except OAuthError as e:
            out = to_fastapi(e.to_redirect(req.redirect_uri, "fragment" if req.use_fragment() else "query"))
    out.delete_cookie(AUTHZ_COOKIE)
    return out


@app.post("/token")
async def token(request: Request):
    data = await request_data(request)
    try:
        tr = await run_in_threadpool(OP.handle_token_request, data.form_pairs, TOKEN_URL, auth_header=data.authorization())
    except OAuthError as e:
        return to_fastapi(e.to_response())
    return to_fastapi(tr.to_response())


@app.api_route("/userinfo", methods=["GET", "POST"])  # OIDC Core 5.3 allows both
async def userinfo(request: Request):
    access_token = (await request_data(request)).bearer_token()
    if access_token is None:
        return to_fastapi(OAuthError("access_denied", "missing bearer token").to_response())
    try:
        return to_fastapi(Response.json(await run_in_threadpool(OP.userinfo, access_token)))
    except OAuthError as e:
        return to_fastapi(e.to_response())
