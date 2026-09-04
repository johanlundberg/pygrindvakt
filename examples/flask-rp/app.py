"""A minimal OpenID Connect Relying Party on Flask, driven by ``pygrindvakt.rp``.

Run (with one of the OP examples listening on port 5000)::

    .venv/bin/python examples/flask-rp/app.py        # listens on 127.0.0.1:5001

then open http://127.0.0.1:5001/login. ``/login`` discovers the OP and
redirects the browser to its authorization endpoint (code flow with PKCE);
``/callback`` exchanges the code, verifies the id_token, fetches userinfo and
shows the claims. DEMO ONLY: dev secrets, discovery on every request.
"""

from __future__ import annotations

import html
import json
import os

import flask
from flask import Flask, abort, session

from pygrindvakt import GrindvaktError, pkce, rp, util
from pygrindvakt.http import ReqwestClient

OP_ISSUER = os.environ.get("OP_ISSUER", "http://127.0.0.1:5000")
CLIENT = rp.RpClient(
    "demo",
    "http://127.0.0.1:5001/callback",
    client_secret=os.environ.get("RP_CLIENT_SECRET", "demo-secret"),
    scope="openid email profile",
)
# Outbound HTTP: never follows redirects, bounded timeouts and body size.
# Anything implementing ``pygrindvakt.http.HttpClientProtocol`` works here.
HTTP_CLIENT = ReqwestClient()


def provider_info() -> rp.ProviderInfo:
    """Discover the OP (a real RP would cache this)."""
    return rp.ProviderInfo.from_metadata(rp.discover(HTTP_CLIENT, OP_ISSUER))


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = os.environ.get("RP_SECRET_KEY", "dev-only-rp-secret")
    app.config["SESSION_COOKIE_NAME"] = "rp_session"  # the demo OP also runs on 127.0.0.1

    @app.get("/")
    def index():
        return '<a href="/login">Log in with the demo OP</a>'

    @app.get("/login")
    def login():
        prov = provider_info()
        state, nonce, verifier = util.random_token(), util.random_token(), util.random_token(48)
        session["oidc"] = {"state": state, "nonce": nonce, "verifier": verifier}
        return flask.redirect(rp.authorization_url(prov, CLIENT, state, nonce, pkce.s256_challenge(verifier)))

    @app.get("/callback")
    def callback():
        pending = session.pop("oidc", None)
        args = flask.request.args
        if pending is None or args.get("state") != pending["state"]:
            abort(400, "state mismatch")
        if "error" in args:
            return f"<p>The OP refused: <b>{html.escape(args['error'])}</b> {html.escape(args.get('error_description', ''))}", 403
        code = args.get("code")
        if not code:
            abort(400, "missing code")
        try:
            prov = provider_info()
            tokens = rp.exchange_code(HTTP_CLIENT, prov, CLIENT, code, pending["verifier"])
            jwks = rp.fetch_jwks(HTTP_CLIENT, prov.jwks_uri, prov.issuer)
            id_claims = rp.verify_id_token(
                jwks, tokens.id_token, prov.issuer, CLIENT.client_id,
                pending["nonce"], ["ES256"],
            )
            userinfo = rp.fetch_userinfo(
                HTTP_CLIENT, prov.userinfo_endpoint, tokens.access_token,
                id_claims["sub"], prov.issuer,
            )
        except GrindvaktError as e:
            # Error details stay in the server log; never echo str(e) to the browser.
            app.logger.warning("login failed: %s", e)
            return "<p>Login failed; please try again.", 502
        return (
            f"<h1>Signed in as {html.escape(id_claims['sub'])}</h1>"
            f"<h2>id_token claims</h2><pre>{html.escape(json.dumps(id_claims, indent=2))}</pre>"
            f"<h2>userinfo</h2><pre>{html.escape(json.dumps(userinfo, indent=2))}</pre>"
        )

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5001, debug=True)
