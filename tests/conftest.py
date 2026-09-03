"""Shared pytest fixtures for the pygrindvakt test suite.

Provides generated signing keys, an in-process OpenID Provider, a fake outbound
HTTP client that routes requests to that provider, OpenSSL-generated PEM keys,
an optional SoftHSM2 token (PKCS#11 tests self-skip without the tooling), and
an optional Redis URL (redis-marked tests self-skip without ``REDIS_URL``).
"""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
import textwrap
from urllib.parse import parse_qs, urlparse

import pytest

from pygrindvakt import OAuthError, client, keys, metadata, provider, tokens

ISSUER = "https://op.example.com"
TOKEN_URL = f"{ISSUER}/token"
USERINFO_URL = f"{ISSUER}/userinfo"
REDIRECT_URI = "https://rp.example.com/cb"

SOFTHSM_MODULE_CANDIDATES = [
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/local/lib/softhsm/libsofthsm2.so",
]


def _have(cmd):
    return shutil.which(cmd) is not None


def basic_auth(client_id: str, secret: str) -> str:
    return "Basic " + base64.b64encode(f"{client_id}:{secret}".encode()).decode()


def code_from_redirect(resp) -> str:
    """Extract the ``code`` parameter from a 302 authorization response."""
    assert resp.status == 302, resp
    loc = resp.header("location")
    return parse_qs(urlparse(loc).query)["code"][0]


@pytest.fixture(scope="session")
def op_key():
    """A P-256 signing key with kid ``op-1``."""
    return keys.signing_key_from_jwk(keys.generate_ec_jwk("P-256"), alg="ES256", kid="op-1")


@pytest.fixture(scope="session")
def rp_key():
    """A second P-256 key, used as an RP's private_key_jwt key."""
    return keys.signing_key_from_jwk(keys.generate_ec_jwk("P-256"), alg="ES256", kid="rp-1")


@pytest.fixture
def demo_client():
    return client.Client(
        "demo",
        client_secret="s3cret",
        redirect_uris=[REDIRECT_URI],
        grant_types=["authorization_code", "refresh_token"],
        client_name="Demo RP",
    )


@pytest.fixture
def op(op_key, rp_key, demo_client):
    """A fresh in-process OpenID Provider with three clients:

    * ``demo`` - confidential, client_secret_basic, code + refresh
    * ``svc`` - client_credentials via client_secret_post, scope ``read write``
    * ``jwt-rp`` - private_key_jwt with ``rp_key``'s public JWKS
    """
    svc = client.Client(
        "svc",
        client_secret="svc-secret",
        grant_types=["client_credentials"],
        token_endpoint_auth_method="client_secret_post",
        scope="read write",
    )
    jwt_rp = client.Client(
        "jwt-rp",
        redirect_uris=[REDIRECT_URI],
        token_endpoint_auth_method="private_key_jwt",
        jwks=rp_key.to_public_jwks(),
    )
    md = metadata.ProviderMetadata(ISSUER)
    return provider.Provider(
        md,
        op_key,
        client.InMemoryClientStore([demo_client, svc, jwt_rp]),
        tokens.TokenCodec("op-secret"),
        token_use_store=provider.InMemoryTokenUseStore(),
    )


class FakeHttpClient:
    """An ``HttpClient`` protocol implementation that serves an in-process
    ``Provider`` and any extra ``routes`` (url -> (status, body, content_type)).
    """

    def __init__(self, op=None, routes=None):
        self.op = op
        self.routes = dict(routes or {})
        self.calls: list[tuple[str, str]] = []

    @staticmethod
    def _json(obj, status=200):
        import json

        return status, json.dumps(obj).encode(), "application/json"

    def get(self, url):
        self.calls.append(("GET", url))
        if url in self.routes:
            return self.routes[url]
        if self.op is not None:
            if url == f"{ISSUER}/.well-known/openid-configuration":
                return self._json(self.op.discovery_document())
            if url == f"{ISSUER}/jwks":
                return self._json(self.op.jwks_document())
        return 404, b"not found", "text/plain"

    def post_form(self, url, form, headers):
        self.calls.append(("POST", url))
        if url in self.routes:
            return self.routes[url]
        if self.op is None:
            return 404, b"not found", "text/plain"
        hdrs = {k.lower(): v for k, v in headers}
        if url == TOKEN_URL:
            try:
                tr = self.op.handle_token_request(dict(form), TOKEN_URL, auth_header=hdrs.get("authorization"))
            except OAuthError as e:
                r = e.to_response()
                return r.status, r.body, "application/json"
            return self._json(tr.to_dict())
        if url == USERINFO_URL:
            auth = hdrs.get("authorization", "")
            try:
                return self._json(self.op.userinfo(auth.split(" ", 1)[1]))
            except OAuthError as e:
                r = e.to_response()
                return r.status, r.body, "application/json"
        return 404, b"not found", "text/plain"


@pytest.fixture
def fake_http(op):
    return FakeHttpClient(op)


@pytest.fixture(scope="session")
def rsa_pem(tmp_path_factory):
    """An RSA-2048 private key in PKCS#8 PEM, generated with openssl."""
    if not _have("openssl"):
        pytest.skip("openssl not available")
    d = tmp_path_factory.mktemp("keys")
    key = d / "rsa.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(key)],
        check=True,
        capture_output=True,
    )
    return key.read_bytes()


@pytest.fixture(scope="session")
def ec_pem(tmp_path_factory):
    """A P-256 private key in PKCS#8 PEM, generated with openssl."""
    if not _have("openssl"):
        pytest.skip("openssl not available")
    d = tmp_path_factory.mktemp("keys-ec")
    key = d / "ec.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(key)],
        check=True,
        capture_output=True,
    )
    return key.read_bytes()


@pytest.fixture(scope="session")
def softhsm(tmp_path_factory):
    """Provision a SoftHSM2 token with an EC P-256 key; return (module, pin, label).

    Skips when SoftHSM2 tooling is unavailable.
    """
    module = next((m for m in SOFTHSM_MODULE_CANDIDATES if os.path.exists(m)), None)
    if module is None or not _have("softhsm2-util") or not _have("pkcs11-tool"):
        pytest.skip("SoftHSM2 / pkcs11-tool not available")

    base = tmp_path_factory.mktemp("softhsm")
    tokens_dir = base / "tokens"
    tokens_dir.mkdir()
    conf = base / "softhsm2.conf"
    conf.write_text(
        textwrap.dedent(
            f"""\
            directories.tokendir = {tokens_dir}
            objectstore.backend = file
            log.level = ERROR
            """
        )
    )
    os.environ["SOFTHSM2_CONF"] = str(conf)

    pin, label = "1234", "op-signing-key"
    subprocess.run(
        ["softhsm2-util", "--init-token", "--slot", "0", "--label", "op", "--so-pin", "0000", "--pin", pin],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["pkcs11-tool", "--module", module, "--login", "--pin", pin, "--keypairgen",
         "--key-type", "EC:prime256v1", "--label", label],
        check=True,
        capture_output=True,
    )
    return module, pin, label


@pytest.fixture(scope="session")
def redis_url():
    url = os.environ.get("REDIS_URL")
    if not url:
        pytest.skip("REDIS_URL not set")
    return url
