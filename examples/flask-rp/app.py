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
from pygrindvakt import BadRequestError, ConfigError, GrindvaktError, rp
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
# Whether the OP puts ``iss`` on the authorization response (RFC 9207). The demo
# OP does not, so this is False here. Production RPs must set it from the OP's
# metadata: True when it advertises authorization_response_iss_parameter_supported,
# and then ``matches_iss(required=True)`` (fail closed) is the safe default.
OP_SENDS_ISS = False


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
        url, state, nonce, verifier = rp.begin(prov, CLIENT)
        session["oidc"] = {"state": state, "nonce": nonce, "verifier": verifier}
        return flask.redirect(url)

    @app.get("/callback")
    def callback():
        # Popped first. This demo uses Flask's signed-cookie session, so an older
        # cookie can restore the entry and concurrent callbacks can both pass the
        # state check. For strict single use keep the entry server-side and
        # consume it atomically.
        pending = session.pop("oidc", None)
        try:
            # items(multi=True) keeps duplicates; a plain dict would hide them.
            resp = rp.parse_authorization_response(list(flask.request.args.items(multi=True)))
        except BadRequestError as e:
            app.logger.warning("bad callback: %s", e.log_summary)
            abort(400, "malformed callback")
        # The parse proves nothing: state and iss are still ours to check.
        if pending is None or not resp.matches_state(pending["state"]):
            abort(400, "state mismatch")
        if not resp.matches_iss(OP_ISSUER, required=OP_SENDS_ISS):
            abort(400, "wrong issuer")
        if resp.is_error:
            # Log only the escaped text; no provider-supplied text goes on the page.
            app.logger.warning("OP refused login: %s %s", resp.error, resp.error_description_safe)
            return "<p>The OP refused the login.", 403
        code = resp.code
        try:
            prov = provider_info()
            tokens = rp.exchange_code(HTTP_CLIENT, prov, CLIENT, code, pending["verifier"])
            jwks = rp.fetch_jwks(HTTP_CLIENT, prov.jwks_uri, prov.issuer)
            id_claims = rp.verify_id_token(
                jwks,
                tokens.id_token,
                prov.issuer,
                CLIENT.client_id,
                pending["nonce"],
                ["ES256"],
            )
            userinfo = rp.fetch_userinfo(
                HTTP_CLIENT,
                prov.userinfo_endpoint,
                tokens.access_token,
                id_claims["sub"],
                prov.issuer,
            )
        except ConfigError as e:
            # A deployment fault, not a failed login: log it and let it surface
            # as a 500 instead of a user-visible 4xx/503.
            app.logger.error("RP misconfigured: %s", e.log_summary)
            raise
        except GrindvaktError as e:
            # Error details stay in the server log; never echo them to the browser.
            # The status is for monitors and clients only.
            app.logger.warning("login failed: %s", e.log_summary)
            if e.retryable:  # OP or network trouble
                return "<p>The sign-in service is unavailable; please try again shortly.", 503
            return "<p>Login failed; please start again.", 401 if e.auth_failure else 400
        return (
            f"<h1>Signed in as {html.escape(id_claims['sub'])}</h1>"
            f"<h2>id_token claims</h2><pre>{html.escape(json.dumps(id_claims, indent=2))}</pre>"
            f"<h2>userinfo</h2><pre>{html.escape(json.dumps(userinfo, indent=2))}</pre>"
        )

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5001, debug=True)
