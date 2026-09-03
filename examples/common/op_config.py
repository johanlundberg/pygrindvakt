"""OpenID Provider configuration shared by the Flask, Django and FastAPI examples.

DEMO ONLY: two static clients, a single hard-coded user, an in-memory
token-use store and development secrets. Replace every piece of this module
before running anything like it in production.
"""

from __future__ import annotations

import hmac
import html
import json
import os
from pathlib import Path

from pygrindvakt import client, keys, metadata, provider, tokens

RP_REDIRECT_URI = "http://127.0.0.1:5001/callback"

# username -> password + the claims the OP asserts about them. ``claims`` is in
# the ``external_claims`` shape ``Provider.authorization_redirect`` expects:
# claim name -> list of string values.
USERS = {
    "alice": {
        "password": "alice",
        "claims": {"email": ["alice@example.com"], "email_verified": ["true"], "name": ["Alice"]},
    },
}

LOGIN_FORM_HTML = """<!doctype html>
<title>Demo OP - sign in</title>
<h1>Sign in</h1>
<p>Client <b>{client_id}</b> asks you to sign in (try <code>alice</code> / <code>alice</code>).</p>
<form method="post">
  {hidden}
  <label>Username <input name="username" autofocus></label><br>
  <label>Password <input name="password" type="password"></label><br>
  <button type="submit">Sign in</button>
</form>
"""


def render_login_form(client_id: str, hidden: str = "") -> str:
    """The login page; ``hidden`` is extra markup for the form (a CSRF token)."""
    return LOGIN_FORM_HTML.format(client_id=html.escape(client_id), hidden=hidden)


def authenticate(username: str, password: str) -> dict[str, list[str]] | None:
    """Check a username / password against ``USERS``; return the user's claims or None."""
    user = USERS.get(username)
    if user is None or not hmac.compare_digest(user["password"], password):
        return None
    return user["claims"]


def load_signing_key() -> keys.SigningKey:
    """The OP's ES256 signing key.

    Taken from the ``OP_SIGNING_JWK`` environment variable (a private JWK as
    JSON) if set; otherwise loaded from ``OP_KEY_FILE`` (default
    ``op-key.json`` in the current directory), which is generated on first run
    so the key survives restarts and the RP's cached JWKS stays valid.
    """
    raw = os.environ.get("OP_SIGNING_JWK")
    if raw:
        jwk = json.loads(raw)
    else:
        path = Path(os.environ.get("OP_KEY_FILE", "op-key.json"))
        if path.exists():
            jwk = json.loads(path.read_text())
        else:
            jwk = keys.generate_ec_jwk("P-256")
            path.write_text(json.dumps(jwk))
            path.chmod(0o600)
    return keys.signing_key_from_jwk(jwk, alg="ES256", kid=jwk.get("kid", "op-1"))


def build_provider(issuer: str) -> provider.Provider:
    """Build the demo ``Provider`` for ``issuer`` (the OP's public base URL).

    Build it once per process and share it across requests. Every endpoint URL
    (token endpoint, userinfo, JWKS) is derived from ``issuer``, never from the
    incoming ``Host`` header.
    """
    demo_rp = client.Client(
        "demo",
        client_secret="demo-secret",
        redirect_uris=[RP_REDIRECT_URI],
        grant_types=["authorization_code", "refresh_token"],
        client_name="Demo RP",
    )
    service = client.Client(
        "svc",
        client_secret="svc-secret",
        grant_types=["client_credentials"],
        token_endpoint_auth_method="client_secret_post",
        scope="read write",
    )
    return provider.Provider(
        metadata.ProviderMetadata(issuer),
        load_signing_key(),
        client.InMemoryClientStore([demo_rp, service]),
        tokens.TokenCodec(os.environ.get("OP_SECRET", "dev-only-secret")),
        token_use_store=provider.InMemoryTokenUseStore(),
    )
