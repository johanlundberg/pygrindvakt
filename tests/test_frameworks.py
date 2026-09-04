"""End-to-end tests for the framework examples under ``examples/``.

Each OP example (Flask, Django, FastAPI) is driven through its framework's own
test client with a full authorization-code flow: discovery, JWKS, login form,
credentials, code exchange with PKCE and client_secret_basic, userinfo. The
Flask RP example is exercised end to end by routing its outbound HTTP client
into the Flask OP's test client. Frameworks that are not installed skip.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import threading
from pathlib import Path
from typing import NamedTuple
from urllib.parse import parse_qs, parse_qsl, urlencode, urlsplit

import pytest

from conftest import basic_auth
from pygrindvakt import keys, pkce, rp, util

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
OP_ISSUER = "http://127.0.0.1:5000"
REDIRECT_URI = "http://127.0.0.1:5001/callback"
AUTHZ_PARAMS = {
    "client_id": "demo",
    "response_type": "code",
    "redirect_uri": REDIRECT_URI,
    "scope": "openid email",
    "state": "st-1",
    "nonce": "n-1",
}

# The examples read their signing key from the environment when it is set, so
# importing them never writes an ``op-key.json`` into the working directory.
os.environ.setdefault("OP_SIGNING_JWK", json.dumps(keys.generate_ec_jwk("P-256")))


def load_module(name: str, path: Path):
    """Import ``path`` as module ``name`` (the examples are all called ``app``)."""
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def in_thread(fn, *args, **kwargs):
    """Run ``fn`` on a fresh thread; see ``tests/test_rp.py`` for why."""
    box: dict = {}

    def run():
        try:
            box["value"] = fn(*args, **kwargs)
        except BaseException as e:  # noqa: BLE001 - re-raised below
            box["error"] = e

    t = threading.Thread(target=run)
    t.start()
    t.join()
    if "error" in box:
        raise box["error"]
    return box["value"]


# --- one interface over three test clients -----------------------------------


class Reply(NamedTuple):
    status: int
    headers: dict[str, str]  # lower-cased names
    body: bytes

    def json(self):
        return json.loads(self.body)

    @property
    def location(self) -> str:
        return self.headers["location"]


class FlaskDriver:
    name = "flask"

    def __init__(self, app):
        self.client = app.test_client()

    def get(self, path, params=None, headers=None):
        r = self.client.get(path, query_string=params, headers=headers)
        return Reply(r.status_code, {k.lower(): v for k, v in r.headers.items()}, r.data)

    def post(self, path, form, headers=None):
        if isinstance(form, list):
            from werkzeug.datastructures import MultiDict

            form = MultiDict(form)
        r = self.client.post(path, data=form, headers=headers)
        return Reply(r.status_code, {k.lower(): v for k, v in r.headers.items()}, r.data)


class DjangoDriver:
    name = "django"

    def __init__(self, client):
        self.client = client

    def get(self, path, params=None, headers=None):
        if params:
            path = f"{path}?{urlencode(params)}"
        r = self.client.get(path, headers=headers)
        return Reply(r.status_code, {k.lower(): v for k, v in r.headers.items()}, r.content)

    def post(self, path, form, headers=None):
        r = self.client.post(path, urlencode(form), content_type="application/x-www-form-urlencoded",
                             headers=headers)
        return Reply(r.status_code, {k.lower(): v for k, v in r.headers.items()}, r.content)


class FastapiDriver:
    name = "fastapi"

    def __init__(self, client):
        self.client = client

    def get(self, path, params=None, headers=None):
        r = self.client.get(path, params=params, headers=headers, follow_redirects=False)
        return Reply(r.status_code, {k.lower(): v for k, v in r.headers.items()}, r.content)

    def post(self, path, form, headers=None):
        if isinstance(form, list):
            headers = {**(headers or {}), "content-type": "application/x-www-form-urlencoded"}
            r = self.client.post(path, content=urlencode(form), headers=headers, follow_redirects=False)
        else:
            r = self.client.post(path, data=form, headers=headers, follow_redirects=False)
        return Reply(r.status_code, {k.lower(): v for k, v in r.headers.items()}, r.content)


# --- fixtures ----------------------------------------------------------------


@pytest.fixture
def flask_op():
    pytest.importorskip("flask")
    mod = load_module("flask_op_app", EXAMPLES / "flask-op" / "app.py")
    return FlaskDriver(mod.create_app())


@pytest.fixture(scope="session")
def django_setup():
    django = pytest.importorskip("django")
    sys.path.insert(0, str(EXAMPLES / "django-op"))
    os.environ["DJANGO_SETTINGS_MODULE"] = "opsite.settings"
    django.setup()


@pytest.fixture
def django_op(django_setup):
    from django.test import Client

    return DjangoDriver(Client())


@pytest.fixture
def fastapi_op():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    mod = load_module("fastapi_op_app", EXAMPLES / "fastapi-op" / "app.py")
    return FastapiDriver(TestClient(mod.app))


@pytest.fixture(params=["flask", "django", "fastapi"])
def op_app(request):
    """One of the three OP examples, behind the common driver interface."""
    return request.getfixturevalue(f"{request.param}_op")


# --- helpers -----------------------------------------------------------------


def start_authorization(op, params=None):
    """GET /authorization with valid parameters; return the login-form reply."""
    return op.get("/authorization", {**AUTHZ_PARAMS, **(params or {})})


def code_from_login(reply) -> str:
    assert reply.status == 302, reply
    assert reply.location.startswith(REDIRECT_URI + "?"), reply.location
    q = parse_qs(urlsplit(reply.location).query)
    assert q["state"] == ["st-1"]
    return q["code"][0]


def exchange(op, code, verifier):
    """POST /token with client_secret_basic and the PKCE verifier."""
    form = {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier}
    return op.post("/token", form, headers={"Authorization": basic_auth("demo", "demo-secret")})


# --- OP examples ---------------------------------------------------------------


def test_discovery_and_jwks(op_app):
    """Discovery names the configured issuer (not the test client's Host) and
    JWKS publishes exactly the public signing key."""
    r = op_app.get("/.well-known/openid-configuration")
    assert r.status == 200 and r.headers["content-type"].startswith("application/json")
    doc = r.json()
    assert doc["issuer"] == OP_ISSUER
    assert doc["token_endpoint"] == f"{OP_ISSUER}/token"
    assert doc["authorization_endpoint"] == f"{OP_ISSUER}/authorization"
    jwks = op_app.get("/jwks").json()
    assert [k["kid"] for k in jwks["keys"]] == ["op-1"]
    assert "d" not in jwks["keys"][0]


def test_full_code_flow(op_app):
    """Login form -> credentials -> code -> tokens (PKCE, client_secret_basic)
    -> verified id_token -> userinfo, all through the framework's test client."""
    verifier = util.random_token(48)
    r = start_authorization(op_app, {"code_challenge": pkce.s256_challenge(verifier),
                                     "code_challenge_method": "S256"})
    assert r.status == 200 and b"<form" in r.body and b"demo" in r.body

    code = code_from_login(op_app.post("/authorization", {"username": "alice", "password": "alice"}))

    r = exchange(op_app, code, verifier)
    assert r.status == 200, r.body
    assert r.headers["cache-control"] == "no-store"
    body = r.json()
    assert body["token_type"] == "Bearer" and body["access_token"] and body["refresh_token"]

    jwks = op_app.get("/jwks").json()
    claims = rp.verify_id_token(jwks, body["id_token"], OP_ISSUER, "demo", "n-1", ["ES256"])
    assert claims["sub"] == "alice" and claims["email"] == "alice@example.com"

    r = op_app.get("/userinfo", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert r.status == 200
    info = r.json()
    assert info["sub"] == "alice" and info["email"] == "alice@example.com" and info["email_verified"] is True


def test_wrong_password_redirects_with_access_denied(op_app):
    """A failed login sends the browser back to the (validated) redirect_uri
    with error=access_denied and the client's state."""
    assert start_authorization(op_app).status == 200
    r = op_app.post("/authorization", {"username": "alice", "password": "nope"})
    assert r.status == 302
    assert r.location.startswith(REDIRECT_URI + "?")
    q = parse_qs(urlsplit(r.location).query)
    assert q["error"] == ["access_denied"] and q["state"] == ["st-1"] and "code" not in q


def test_unknown_client_is_not_redirected(op_app):
    """An authorization request for an unregistered client_id is answered with
    a JSON 4xx directly: the redirect_uri cannot be trusted."""
    r = start_authorization(op_app, {"client_id": "ghost"})
    assert 400 <= r.status < 500 and "location" not in r.headers
    assert r.headers["content-type"].startswith("application/json")
    assert r.json()["error"] in ("invalid_client", "invalid_request", "unauthorized_client")


def test_duplicate_authorization_parameter_is_rejected_by_every_adapter(op_app):
    """Flask, Django, and FastAPI preserve duplicate query values for rejection."""
    params = list(AUTHZ_PARAMS.items()) + [("client_id", "attacker")]
    r = op_app.get("/authorization", params)
    assert r.status == 400
    assert r.json()["error"] == "invalid_request"


def test_duplicate_token_parameter_is_rejected_by_every_adapter(op_app):
    """Duplicate token form fields reach Provider as ordered pairs."""
    form = [("grant_type", "authorization_code"), ("grant_type", "refresh_token")]
    r = op_app.post("/token", form)
    assert r.status == 400
    assert r.json()["error"] == "invalid_request"


def test_login_without_pending_request_is_rejected(op_app):
    """POSTing credentials with no authorization request in the session fails
    with invalid_request rather than a redirect."""
    r = op_app.post("/authorization", {"username": "alice", "password": "alice"})
    assert r.status == 400 and r.json()["error"] == "invalid_request"


def test_code_replay_is_rejected(op_app):
    """Presenting the same authorization code twice yields 400 invalid_grant."""
    verifier = util.random_token(48)
    start_authorization(op_app, {"code_challenge": pkce.s256_challenge(verifier),
                                 "code_challenge_method": "S256"})
    code = code_from_login(op_app.post("/authorization", {"username": "alice", "password": "alice"}))
    assert exchange(op_app, code, verifier).status == 200
    r = exchange(op_app, code, verifier)
    assert r.status == 400 and r.json()["error"] == "invalid_grant"


def test_token_endpoint_rejects_bad_client_secret(op_app):
    """A wrong client secret is a 401 invalid_client with a WWW-Authenticate challenge."""
    r = op_app.post("/token", {"grant_type": "authorization_code", "code": "x", "redirect_uri": REDIRECT_URI},
                    headers={"Authorization": basic_auth("demo", "wrong")})
    assert r.status == 401 and r.json()["error"] == "invalid_client"
    assert "www-authenticate" in r.headers


def test_client_credentials_grant(op_app):
    """The ``svc`` client obtains an access token with client_secret_post."""
    r = op_app.post("/token", {"grant_type": "client_credentials", "client_id": "svc",
                               "client_secret": "svc-secret", "scope": "read"})
    assert r.status == 200
    body = r.json()
    assert body["scope"] == "read" and "id_token" not in body


def test_userinfo_requires_bearer_token(op_app):
    """/userinfo without a token, or with garbage, is a JSON error, not a 500."""
    r = op_app.get("/userinfo")
    assert r.status in (400, 401) and r.json()["error"]
    r = op_app.get("/userinfo", headers={"Authorization": "Bearer garbage"})
    assert r.status in (400, 401) and r.json()["error"]


# --- RP example -----------------------------------------------------------------


class OpBridge:
    """An ``HttpClientProtocol`` object that routes the RP's outbound requests
    into the Flask OP's test client, as if the OP were listening on
    ``OP_ISSUER``. Dispatches on a helper thread because the calling thread is
    driving the RP's own runtime (see ``tests/test_rp.py``)."""

    def __init__(self, op):
        self.op = op
        self.calls: list[str] = []

    def _path(self, url: str) -> str:
        assert url.startswith(OP_ISSUER + "/"), url
        return url[len(OP_ISSUER):]

    @staticmethod
    def _fetch(reply: Reply):
        return reply.status, reply.body, reply.headers.get("content-type")

    def get(self, url):
        self.calls.append(url)
        return self._fetch(in_thread(self.op.get, self._path(url)))

    def post_form(self, url, form, headers):
        self.calls.append(url)
        return self._fetch(in_thread(self.op.post, self._path(url), dict(form), dict(headers)))


def test_flask_rp_end_to_end(flask_op, monkeypatch):
    """Drive the Flask RP against the Flask OP: /login redirects to the OP's
    authorization endpoint with PKCE; the "browser" logs in there; the OP's
    redirect lands on the RP's /callback, which exchanges the code, verifies
    the id_token, fetches userinfo and renders alice's claims."""
    pytest.importorskip("flask")
    rp_mod = load_module("flask_rp_app", EXAMPLES / "flask-rp" / "app.py")
    bridge = OpBridge(flask_op)
    monkeypatch.setattr(rp_mod, "HTTP_CLIENT", bridge)
    browser = rp_mod.create_app().test_client()

    r = browser.get("/login")
    assert r.status_code == 302
    authz_url = r.headers["Location"]
    assert authz_url.startswith(f"{OP_ISSUER}/authorization?")
    params = dict(parse_qsl(urlsplit(authz_url).query))
    assert params["code_challenge_method"] == "S256" and params["client_id"] == "demo"

    assert flask_op.get("/authorization", params).status == 200
    login = flask_op.post("/authorization", {"username": "alice", "password": "alice"})
    assert login.status == 302 and login.location.startswith(REDIRECT_URI + "?")

    r = browser.get("/callback?" + urlsplit(login.location).query)
    assert r.status_code == 200, r.data
    page = r.data.decode()
    assert "Signed in as alice" in page and "alice@example.com" in page
    assert f"{OP_ISSUER}/token" in bridge.calls and f"{OP_ISSUER}/userinfo" in bridge.calls


def test_flask_rp_rejects_state_mismatch(flask_op, monkeypatch):
    """A callback whose state does not match the session is refused before
    any code exchange happens."""
    pytest.importorskip("flask")
    rp_mod = load_module("flask_rp_app", EXAMPLES / "flask-rp" / "app.py")
    bridge = OpBridge(flask_op)
    monkeypatch.setattr(rp_mod, "HTTP_CLIENT", bridge)
    browser = rp_mod.create_app().test_client()
    assert browser.get("/login").status_code == 302
    r = browser.get("/callback?code=abc&state=forged")
    assert r.status_code == 400
    assert not any(url.endswith("/token") for url in bridge.calls)
