"""A minimal OpenID Provider on Flask, driven by pygrindvakt.

Run::

    .venv/bin/python examples/flask-op/app.py        # listens on 127.0.0.1:5000

Endpoints: ``/.well-known/openid-configuration``, ``/jwks``, ``/authorization``
(GET shows a login form, POST checks the credentials and redirects back to the
client), ``/token`` and ``/userinfo``. The two adapters ``request_data`` and
``to_flask`` are the only Flask-specific glue; the views work on
pygrindvakt's framework-agnostic ``HttpRequestData`` / ``Response``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import flask
from flask import Flask, session

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # examples/, for ``common``
from common.op_config import authenticate, build_provider, render_login_form  # noqa: E402

from pygrindvakt import OAuthError  # noqa: E402
from pygrindvakt.http import HttpRequestData, Response  # noqa: E402
from pygrindvakt.request import AuthorizationRequest  # noqa: E402

ISSUER = os.environ.get("OP_ISSUER", "http://127.0.0.1:5000")


# --- adapters ---------------------------------------------------------------


def request_data() -> HttpRequestData:
    """Normalize the current ``flask.request`` into an ``HttpRequestData``."""
    r = flask.request
    return HttpRequestData(
        path=r.path.lstrip("/"),
        method=r.method,
        uri=r.url,
        query=list(r.args.items(multi=True)),
        form=list(r.form.items(multi=True)),
        body=r.get_data(),
        headers={k.lower(): v for k, v in r.headers.items()},
        cookies=r.cookies.to_dict(),
    )


def to_flask(resp: Response) -> flask.Response:
    """Turn a pygrindvakt ``Response`` into a Flask response."""
    return flask.Response(resp.body, status=resp.status, headers=list(resp.headers))


# --- application ------------------------------------------------------------


def create_app(issuer: str = ISSUER) -> Flask:
    app = Flask(__name__)
    app.secret_key = os.environ.get("OP_SECRET_KEY", "dev-only-flask-secret")
    app.config["SESSION_COOKIE_NAME"] = "op_session"  # the demo RP also runs on 127.0.0.1

    op = build_provider(issuer)
    token_url = f"{issuer}/token"  # from configuration, never from the Host header

    @app.get("/.well-known/openid-configuration")
    def discovery():
        return to_flask(Response.json(op.discovery_document()))

    @app.get("/jwks")
    def jwks():
        return to_flask(Response.json(op.jwks_document()))

    @app.get("/authorization")
    def authorization():
        data = request_data()
        try:
            req = AuthorizationRequest.from_params(data.query_pairs)
            op.validate_authorization_request(req)
        except OAuthError as e:
            # The redirect_uri is not trusted until validation succeeds: never redirect here.
            return to_flask(e.to_response())
        session["authz"] = req.to_dict()
        return render_login_form(req.client_id)

    @app.post("/authorization")
    def login():
        stored = session.pop("authz", None)
        if stored is None:
            return to_flask(OAuthError("invalid_request", "no pending authorization request").to_response())
        req = AuthorizationRequest.from_dict(stored)
        form = request_data().form
        claims = authenticate(form.get("username", ""), form.get("password", ""))
        if claims is None:
            err = OAuthError("access_denied", "wrong username or password", req.state)
            return to_flask(err.to_redirect(req.redirect_uri, "fragment" if req.use_fragment() else "query"))
        try:
            return to_flask(op.authorization_redirect(req, form["username"], claims))
        except OAuthError as e:
            return to_flask(e.to_redirect(req.redirect_uri, "fragment" if req.use_fragment() else "query"))

    @app.post("/token")
    def token():
        data = request_data()
        try:
            tr = op.handle_token_request(data.form_pairs, token_url, auth_header=data.authorization())
        except OAuthError as e:
            return to_flask(e.to_response())
        return to_flask(tr.to_response())

    @app.route("/userinfo", methods=["GET", "POST"])  # OIDC Core 5.3 allows both
    def userinfo():
        access_token = request_data().bearer_token()
        if access_token is None:
            return to_flask(OAuthError("access_denied", "missing bearer token").to_response())
        try:
            return to_flask(Response.json(op.userinfo(access_token)))
        except OAuthError as e:
            return to_flask(e.to_response())

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=True)
