"""Tests for ``pygrindvakt.rp`` - the relying-party side of OIDC.

An in-process ``Provider`` plays the upstream OP; a ``FakeHttpClient`` routes
the RP's outbound requests straight into it, so the full code flow
(discovery -> authorization -> code exchange -> id_token -> userinfo) runs
without any network.
"""

from __future__ import annotations

import json
import threading
import time
from urllib.parse import parse_qs, urlsplit

import pytest

from pygrindvakt import (
    AuthnError,
    BadRequestError,
    GrindvaktError,
    InternalError,
    OAuthError,
    client,
    jwt,
    keys,
    metadata,
    pkce,
    provider,
    request,
    rp,
    tokens,
    util,
)

ISSUER = "https://op.example.com"
CLIENT_ID = "demo"
CLIENT_SECRET = "s3cret"
REDIRECT_URI = "https://rp.example.com/cb"


def in_thread(fn, *args, **kwargs):
    """Run ``fn`` on a fresh thread and return its result (re-raising errors).

    Not required (pygrindvakt runs re-entrant calls on a helper thread itself;
    see ``tests/test_adapters.py``), but it mirrors the real topology: a real
    OP runs in its own process, so its endpoints run off the RP's thread here.
    """
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
ALT_REDIRECT_URI = "https://rp.example.com/alt-cb"


class FakeHttpClient:
    """An ``HttpClient`` protocol object that dispatches into an in-process OP."""

    def __init__(self, op):
        self.op = op
        self.calls: list[tuple[str, str]] = []
        self.forms: list[list[tuple[str, str]]] = []

    @staticmethod
    def _json(value, status=200):
        return status, json.dumps(value).encode(), "application/json"

    @staticmethod
    def _oauth_error(e: OAuthError):
        resp = e.to_response()
        return resp.status, resp.body, resp.header("content-type")

    def get(self, url):
        self.calls.append(("GET", url))
        if url == f"{ISSUER}/.well-known/openid-configuration":
            return self._json(self.op.discovery_document())
        if url == f"{ISSUER}/jwks":
            return self._json(self.op.jwks_document())
        return 404, b"not found", "text/plain"

    def post_form(self, url, form, headers):
        self.calls.append(("POST", url))
        self.forms.append(list(form))
        hdrs = {k.lower(): v for k, v in headers}
        if url == f"{ISSUER}/token":
            try:
                tr = in_thread(
                    self.op.handle_token_request,
                    list(form),
                    f"{ISSUER}/token",
                    auth_header=hdrs.get("authorization"),
                )
            except OAuthError as e:
                return self._oauth_error(e)
            return self._json(tr.to_dict())
        if url == f"{ISSUER}/userinfo":
            auth = hdrs.get("authorization", "")
            if not auth.startswith("Bearer "):
                return 401, b"", None
            try:
                return self._json(in_thread(self.op.userinfo, auth[len("Bearer "):]))
            except OAuthError as e:
                return self._oauth_error(e)
        return 404, b"not found", "text/plain"


class RaisingHttpClient:
    """An ``HttpClient`` whose every request raises."""

    def get(self, url):
        raise RuntimeError("boom: network is down")

    def post_form(self, url, form, headers):
        raise RuntimeError("boom: network is down")


@pytest.fixture
def op_key():
    jwk = keys.generate_ec_jwk("P-256")
    return keys.signing_key_from_jwk(jwk, alg="ES256", kid="op-1")


@pytest.fixture
def op(op_key):
    md = metadata.ProviderMetadata(ISSUER)
    c = client.Client(CLIENT_ID, client_secret=CLIENT_SECRET, redirect_uris=[REDIRECT_URI, ALT_REDIRECT_URI])
    return provider.Provider(
        md, op_key, client.InMemoryClientStore([c]), tokens.TokenCodec("op-secret"),
        token_use_store=provider.InMemoryTokenUseStore(),
    )


@pytest.fixture
def http(op):
    return FakeHttpClient(op)


@pytest.fixture
def prov(http):
    return rp.ProviderInfo.from_metadata(rp.discover(http, ISSUER))


@pytest.fixture
def rpc():
    return rp.RpClient(CLIENT_ID, REDIRECT_URI, client_secret=CLIENT_SECRET)


@pytest.fixture
def rp_key():
    jwk = keys.generate_ec_jwk("P-256")
    return keys.signing_key_from_jwk(jwk, alg="ES256", kid="rp-1")


def run_authorization(op, prov, rpc, state, nonce, verifier, sub="alice", claims=None):
    """Drive the OP side of the flow and return the authorization code."""
    url = rp.authorization_url(prov, rpc, state, nonce, pkce.s256_challenge(verifier))
    params = {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}
    req = request.AuthorizationRequest.from_params(list(params.items()))
    op.validate_authorization_request(req)
    resp = op.authorization_redirect(req, sub, claims or {"email": ["a@b"]})
    assert resp.status in (302, 303)
    location = resp.header("location")
    assert location.startswith(REDIRECT_URI)
    q = parse_qs(urlsplit(location).query)
    assert q["state"] == [state]
    return q["code"][0]


# --- discovery ----------------------------------------------------------------


def test_discover_returns_metadata_for_issuer(http):
    """``discover`` fetches the discovery document and returns ProviderMetadata."""
    md = rp.discover(http, ISSUER)
    assert isinstance(md, metadata.ProviderMetadata)
    assert md.issuer == ISSUER
    assert http.calls == [("GET", f"{ISSUER}/.well-known/openid-configuration")]


def test_discover_with_trailing_slash(http):
    """Issuer identifiers differing by a trailing slash are not conflated."""
    with pytest.raises(AuthnError):
        rp.discover(http, ISSUER + "/")


def test_discover_rejects_plain_http_before_fetching(http):
    """Plain-http issuers (non-loopback) are refused without any request."""
    with pytest.raises(GrindvaktError):
        rp.discover(http, "http://op.example.com")
    assert http.calls == []


@pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
def test_discover_fails_closed_when_http_client_raises():
    """A raising HttpClient surfaces as InternalError carrying the message.

    The adapter's traceback is also routed through ``sys.unraisablehook`` so
    operators can see it; pytest reports that as a warning, ignored here.
    """
    with pytest.raises(InternalError, match="network is down"):
        rp.discover(RaisingHttpClient(), ISSUER)


def test_discover_rejects_issuer_mismatch(op):
    """The issuer in the returned document must match the requested one."""

    class Liar(FakeHttpClient):
        def get(self, url):
            doc = self.op.discovery_document()
            doc["issuer"] = "https://evil.example.com"
            return self._json(doc)

    with pytest.raises(AuthnError, match="does not match"):
        rp.discover(Liar(op), ISSUER)


def test_fetch_jwks_returns_one_key(http, prov):
    """``fetch_jwks`` returns the JWKS dict with the OP's single signing key."""
    jwks = rp.fetch_jwks(http, prov.jwks_uri, prov.issuer)
    assert isinstance(jwks, dict)
    assert len(jwks["keys"]) == 1
    assert jwks["keys"][0]["kid"] == "op-1"
    assert "d" not in jwks["keys"][0]


# --- ProviderInfo -----------------------------------------------------------------


def test_provider_info_from_metadata(op):
    """``from_metadata`` copies the endpoints, including userinfo and jwks."""
    md = op.metadata
    p = rp.ProviderInfo.from_metadata(md)
    assert p.issuer == ISSUER
    assert p.authorization_endpoint == md.authorization_endpoint
    assert p.token_endpoint == md.token_endpoint
    assert p.userinfo_endpoint == md.userinfo_endpoint
    assert p.jwks_uri == md.jwks_uri
    assert "ProviderInfo(" in repr(p) and ISSUER in repr(p)


def test_provider_info_constructor_defaults():
    """Optional endpoints default to None."""
    p = rp.ProviderInfo(ISSUER, f"{ISSUER}/authz", f"{ISSUER}/token")
    assert p.userinfo_endpoint is None
    assert p.jwks_uri is None
    assert "userinfo_endpoint=None" in repr(p)
    p2 = rp.ProviderInfo(ISSUER, f"{ISSUER}/authz", f"{ISSUER}/token", jwks_uri=f"{ISSUER}/jwks")
    assert p2.jwks_uri == f"{ISSUER}/jwks"


# --- RpClient -------------------------------------------------------------------


def test_rp_client_defaults():
    """Default scope, auth_method inferred from the presence of a secret."""
    c = rp.RpClient(CLIENT_ID, REDIRECT_URI)
    assert c.client_id == CLIENT_ID
    assert c.redirect_uri == REDIRECT_URI
    assert c.scope == "openid profile email"
    assert c.auth_method == "none"
    c2 = rp.RpClient(CLIENT_ID, REDIRECT_URI, client_secret=CLIENT_SECRET, scope="openid")
    assert c2.auth_method == "client_secret_basic"
    assert c2.scope == "openid"


def test_rp_client_explicit_methods(rp_key):
    """Every explicit auth_method is accepted with its matching credential."""
    assert (
        rp.RpClient(CLIENT_ID, REDIRECT_URI, client_secret="x", auth_method="client_secret_post").auth_method
        == "client_secret_post"
    )
    assert (
        rp.RpClient(CLIENT_ID, REDIRECT_URI, auth_method="private_key_jwt", signing_key=rp_key).auth_method
        == "private_key_jwt"
    )
    assert rp.RpClient(CLIENT_ID, REDIRECT_URI, auth_method="none").auth_method == "none"


def test_rp_client_repr_hides_secret():
    """The secret never appears in repr()."""
    c = rp.RpClient(CLIENT_ID, REDIRECT_URI, client_secret=CLIENT_SECRET)
    r = repr(c)
    assert CLIENT_SECRET not in r
    assert "client_secret_basic" in r and CLIENT_ID in r


@pytest.mark.parametrize(
    "kwargs",
    [
        {"auth_method": "private_key_jwt"},
        {"auth_method": "client_secret_basic"},
        {"auth_method": "client_secret_post"},
        {"auth_method": "bogus"},
        {"auth_method": "none", "client_secret": "x"},
        {"client_secret": ""},
    ],
)
def test_rp_client_rejects_inconsistent_combinations(kwargs):
    """Inconsistent method / credential combinations raise ValueError."""
    with pytest.raises(ValueError):
        rp.RpClient(CLIENT_ID, REDIRECT_URI, **kwargs)


def test_rp_client_rejects_unused_signing_key(rp_key):
    """A signing_key that the resolved method would ignore is rejected."""
    with pytest.raises(ValueError, match="private_key_jwt"):
        rp.RpClient(CLIENT_ID, REDIRECT_URI, signing_key=rp_key)
    with pytest.raises(ValueError):
        rp.RpClient(CLIENT_ID, REDIRECT_URI, client_secret="x", signing_key=rp_key)
    with pytest.raises(ValueError):
        rp.RpClient(
            CLIENT_ID, REDIRECT_URI, auth_method="private_key_jwt", signing_key=rp_key, client_secret="x"
        )


# --- authorization_url ------------------------------------------------------------


def test_authorization_url_contains_parameters(prov, rpc):
    """state, nonce, PKCE challenge and extra params are all present."""
    challenge = pkce.s256_challenge("v" * 43)
    url = rp.authorization_url(prov, rpc, "st-1", "n-1", challenge, extra={"prompt": "login"})
    assert url.startswith(prov.authorization_endpoint + "?")
    q = parse_qs(urlsplit(url).query)
    assert q["response_type"] == ["code"]
    assert q["client_id"] == [CLIENT_ID]
    assert q["redirect_uri"] == [REDIRECT_URI]
    assert q["scope"] == ["openid profile email"]
    assert q["state"] == ["st-1"]
    assert q["nonce"] == ["n-1"]
    assert q["code_challenge"] == [challenge]
    assert q["code_challenge_method"] == ["S256"]
    assert q["prompt"] == ["login"]


def test_authorization_url_extra_as_list_and_no_pkce(prov, rpc):
    """extra may be a list of tuples; without a challenge no PKCE params appear."""
    url = rp.authorization_url(prov, rpc, "st", "n", extra=[("acr_values", "mfa"), ("prompt", "none")])
    q = parse_qs(urlsplit(url).query)
    assert q["acr_values"] == ["mfa"]
    assert q["prompt"] == ["none"]
    assert "code_challenge" not in q
    with pytest.raises((ValueError, TypeError)):
        rp.authorization_url(prov, rpc, "st", "n", extra="prompt=login")


def test_authorization_url_appends_to_existing_query(rpc):
    """An authorization endpoint that already has a query gets '&'."""
    p = rp.ProviderInfo(ISSUER, f"{ISSUER}/authz?tenant=x", f"{ISSUER}/token")
    url = rp.authorization_url(p, rpc, "st", "n")
    assert url.startswith(f"{ISSUER}/authz?tenant=x&response_type=code")


def test_provider_info_rejects_unsafe_endpoints_and_reserved_query(rpc):
    for endpoint in ["http://example.com/token", "file:///tmp/token", "https://u:p@example.com/token",
                     "https://example.com/token#fragment", "http://127.0.0.1:8000/token"]:
        with pytest.raises(GrindvaktError):
            rp.ProviderInfo(ISSUER, f"{ISSUER}/authorization", endpoint)
    with pytest.raises(GrindvaktError, match="library-controlled"):
        rp.ProviderInfo(ISSUER, f"{ISSUER}/authorization?client_id=attacker", f"{ISSUER}/token")
    # Separate HTTPS endpoint origins remain legitimate. Loopback HTTP is a
    # development exception only when the issuer is itself loopback HTTP.
    rp.ProviderInfo(ISSUER, "https://login.example.net/authorization", "https://tokens.example.net/token")
    rp.ProviderInfo("http://127.0.0.1:8000", "http://127.0.0.1:8000/authorization",
                    "http://localhost:8000/token")


def test_direct_endpoint_fetches_bind_loopback_http_to_issuer():
    """A remote issuer cannot send credential-bearing fetches to loopback."""
    with pytest.raises(GrindvaktError, match="absolute https URL"):
        rp.fetch_jwks(
            RaisingHttpClient(),
            "http://127.0.0.1:8000/jwks",
            "https://remote.example",
        )
    with pytest.raises(GrindvaktError, match="absolute https URL"):
        rp.fetch_userinfo(
            RaisingHttpClient(),
            "http://127.0.0.1:8000/userinfo",
            "access-token",
            "alice",
            "https://remote.example",
        )


def test_public_rp_requires_pkce_at_every_boundary(prov, rp_key):
    public = rp.RpClient("public", REDIRECT_URI, auth_method="none")
    with pytest.raises(GrindvaktError, match="PKCE"):
        rp.authorization_url(prov, public, "state", "nonce")
    with pytest.raises(GrindvaktError, match="PKCE"):
        rp.signed_request_object(prov, public, rp_key, "state", "nonce")
    with pytest.raises(GrindvaktError, match="PKCE"):
        rp.exchange_code(RaisingHttpClient(), prov, public, "code")


def test_authorization_url_rejects_reserved_and_ambiguous_extras(prov, rpc):
    with pytest.raises(GrindvaktError, match="library-controlled"):
        rp.authorization_url(prov, rpc, "state", "nonce", extra={"redirect_uri": "https://evil/cb"})
    with pytest.raises(GrindvaktError, match="duplicate"):
        rp.authorization_url(prov, rpc, "state", "nonce", extra=[("prompt", "login"), ("prompt", "none")])
    configured = rp.ProviderInfo(
        ISSUER, f"{ISSUER}/authorization?tenant=configured", f"{ISSUER}/token")
    with pytest.raises(GrindvaktError, match="duplicate"):
        rp.authorization_url(configured, rpc, "state", "nonce", extra={"tenant": "override"})
    url = rp.authorization_url(prov, rpc, "state", "nonce",
                               extra=[("resource", "https://api-1"), ("resource", "https://api-2")])
    assert len(parse_qs(urlsplit(url).query)["resource"]) == 2


# --- redirect_uri override ----------------------------------------------------------


def test_redirect_uri_override_in_authorization_url_and_jar(prov, rpc, rp_key):
    url = rp.authorization_url(prov, rpc, "st", "n", redirect_uri=ALT_REDIRECT_URI)
    assert parse_qs(urlsplit(url).query)["redirect_uri"] == [ALT_REDIRECT_URI]
    assert rpc.redirect_uri == REDIRECT_URI  # the client itself is unchanged
    jar = rp.signed_request_object(prov, rpc, rp_key, "st", "n", redirect_uri=ALT_REDIRECT_URI)
    import base64

    claims = json.loads(base64.urlsafe_b64decode(jar.split(".")[1] + "=="))
    assert claims["redirect_uri"] == ALT_REDIRECT_URI


def test_redirect_uri_override_reaches_token_request(op, http, prov, rpc):
    state, nonce, verifier = util.random_token(), util.random_token(), util.random_token(48)
    url = rp.authorization_url(
        prov, rpc, state, nonce, pkce.s256_challenge(verifier), redirect_uri=ALT_REDIRECT_URI
    )
    req = request.AuthorizationRequest.from_params(
        [(k, v[0]) for k, v in parse_qs(urlsplit(url).query).items()]
    )
    op.validate_authorization_request(req)
    resp = op.authorization_redirect(req, "alice", {"email": ["a@b"]})
    code = parse_qs(urlsplit(resp.header("location")).query)["code"][0]
    ts = rp.exchange_code(http, prov, rpc, code, verifier, redirect_uri=ALT_REDIRECT_URI)
    assert ts.id_token
    assert ("redirect_uri", ALT_REDIRECT_URI) in http.forms[-1]
    assert ("redirect_uri", REDIRECT_URI) not in http.forms[-1]


@pytest.mark.parametrize("bad", ["https://rp.example.com/cb#frag", "/relative", ""])
def test_redirect_uri_override_rejected(prov, rpc, rp_key, bad):
    with pytest.raises(BadRequestError):
        rp.authorization_url(prov, rpc, "st", "n", redirect_uri=bad)
    with pytest.raises(BadRequestError):
        rp.signed_request_object(prov, rpc, rp_key, "st", "n", redirect_uri=bad)
    with pytest.raises(BadRequestError):
        rp.exchange_code(RaisingHttpClient(), prov, rpc, "code", "v" * 43, redirect_uri=bad)
    with pytest.raises(BadRequestError):
        rp.begin(prov, rpc, redirect_uri=bad)


# --- begin ----------------------------------------------------------------------------


def test_begin_returns_url_state_nonce_verifier(prov, rpc):
    url, state, nonce, verifier = rp.begin(prov, rpc)
    q = parse_qs(urlsplit(url).query)
    assert q["state"] == [state]
    assert q["nonce"] == [nonce]
    assert q["code_challenge_method"] == ["S256"]
    assert q["code_challenge"] == [pkce.s256_challenge(verifier)]
    assert pkce.verify(verifier, q["code_challenge"][0], "S256")
    assert len(verifier) == 64
    assert len(state) == len(nonce) == 43


def test_begin_values_are_fresh(prov, rpc):
    a = rp.begin(prov, rpc)
    b = rp.begin(prov, rpc)
    for i in (1, 2, 3):
        assert a[i] != b[i]


def test_begin_extra_and_override(prov, rpc):
    url, *_ = rp.begin(prov, rpc, extra={"prompt": "login"}, redirect_uri=ALT_REDIRECT_URI)
    q = parse_qs(urlsplit(url).query)
    assert q["prompt"] == ["login"]
    assert q["redirect_uri"] == [ALT_REDIRECT_URI]


def test_begin_pkce_false(prov, rpc):
    url, _, _, verifier = rp.begin(prov, rpc, pkce=False)
    assert verifier is None
    assert "code_challenge" not in parse_qs(urlsplit(url).query)


def test_begin_pkce_false_refused_for_public_client(prov):
    public = rp.RpClient("public", REDIRECT_URI, auth_method="none")
    with pytest.raises(BadRequestError, match="PKCE"):
        rp.begin(prov, public, pkce=False)
    url, *_ = rp.begin(prov, public)
    assert "code_challenge" in parse_qs(urlsplit(url).query)


def test_begin_with_request_object(prov, rpc, rp_key):
    url, *_ = rp.begin(prov, rpc, request_object_key=rp_key)
    q = parse_qs(urlsplit(url).query)
    assert q["request"][0].count(".") == 2


def test_begin_then_exchange_code_flow(op, http, prov, rpc):
    url, state, nonce, verifier = rp.begin(prov, rpc)
    req = request.AuthorizationRequest.from_params(
        [(k, v[0]) for k, v in parse_qs(urlsplit(url).query).items()]
    )
    op.validate_authorization_request(req)
    resp = op.authorization_redirect(req, "alice", {"email": ["a@b"]})
    q = parse_qs(urlsplit(resp.header("location")).query)
    assert q["state"] == [state]
    ts = rp.exchange_code(http, prov, rpc, q["code"][0], verifier)
    jwks = rp.fetch_jwks(http, prov.jwks_uri, prov.issuer)
    claims = rp.verify_id_token(jwks, ts.id_token, ISSUER, CLIENT_ID, nonce, ["ES256"])
    assert claims["sub"] == "alice"


# --- full code flow -----------------------------------------------------------------


def test_full_code_flow(op, http, prov, rpc):
    """authorization_url -> OP -> exchange_code -> verify_id_token -> userinfo."""
    state, nonce, verifier = util.random_token(), util.random_token(), util.random_token(48)
    code = run_authorization(op, prov, rpc, state, nonce, verifier)

    ts = rp.exchange_code(http, prov, rpc, code, verifier)
    assert isinstance(ts, rp.TokenSet)
    assert ts.access_token and ts.id_token
    assert ts.token_type.lower() == "bearer"
    assert ts.raw["access_token"] == ts.access_token
    assert "expires_in" in ts.raw
    assert ts.access_token not in repr(ts) and ts.id_token not in repr(ts)
    assert 'token_type="' in repr(ts)

    jwks = rp.fetch_jwks(http, prov.jwks_uri, prov.issuer)
    claims = rp.verify_id_token(jwks, ts.id_token, ISSUER, CLIENT_ID, nonce, ["ES256"])
    assert claims["sub"] == "alice"
    assert claims["iss"] == ISSUER
    assert claims["nonce"] == nonce
    assert claims["aud"] == CLIENT_ID or CLIENT_ID in claims["aud"]

    info = rp.fetch_userinfo(
        http, prov.userinfo_endpoint, ts.access_token, claims["sub"], prov.issuer
    )
    assert info["sub"] == "alice"
    assert info["email"] == "a@b"


def test_exchange_code_with_client_secret_post(op, prov):
    """client_secret_post authenticates via the form body (OP registered for it)."""
    c = client.Client(
        CLIENT_ID,
        client_secret=CLIENT_SECRET,
        redirect_uris=[REDIRECT_URI],
        token_endpoint_auth_method="client_secret_post",
    )
    op2 = provider.Provider(
        op.metadata, op.signing_key, client.InMemoryClientStore([c]), tokens.TokenCodec("op-secret"),
        token_use_store=provider.InMemoryTokenUseStore(),
    )
    rpc = rp.RpClient(CLIENT_ID, REDIRECT_URI, client_secret=CLIENT_SECRET, auth_method="client_secret_post")
    verifier = util.random_token(48)
    code = run_authorization(op2, prov, rpc, "st", "n", verifier)
    ts = rp.exchange_code(FakeHttpClient(op2), prov, rpc, code, verifier)
    assert ts.id_token


def test_exchange_code_method_mismatch_is_refused(op, http, prov):
    """An RP using client_secret_post against a client_secret_basic registration fails."""
    rpc = rp.RpClient(CLIENT_ID, REDIRECT_URI, client_secret=CLIENT_SECRET, auth_method="client_secret_post")
    verifier = util.random_token(48)
    code = run_authorization(op, prov, rpc, "st", "n", verifier)
    with pytest.raises(AuthnError, match="invalid_client"):
        rp.exchange_code(http, prov, rpc, code, verifier)


def test_exchange_code_wrong_secret_raises_authn(op, http, prov):
    """A rejected token request surfaces as AuthnError (fail closed)."""
    good = rp.RpClient(CLIENT_ID, REDIRECT_URI, client_secret=CLIENT_SECRET)
    bad = rp.RpClient(CLIENT_ID, REDIRECT_URI, client_secret="wrong")
    verifier = util.random_token(48)
    code = run_authorization(op, prov, good, "st", "n", verifier)
    with pytest.raises(AuthnError, match="token endpoint returned"):
        rp.exchange_code(http, prov, bad, code, verifier)


def test_exchange_code_wrong_verifier_raises(op, http, prov, rpc):
    """A PKCE verifier mismatch is rejected by the OP and raised here."""
    code = run_authorization(op, prov, rpc, "st", "n", util.random_token(48))
    with pytest.raises(AuthnError):
        rp.exchange_code(http, prov, rpc, code, util.random_token(48))


# --- verify_id_token ----------------------------------------------------------------


@pytest.fixture
def issued(op, http, prov, rpc):
    """An (id_token, jwks, nonce) triple from a completed flow."""
    nonce, verifier = util.random_token(), util.random_token(48)
    code = run_authorization(op, prov, rpc, "st", nonce, verifier)
    ts = rp.exchange_code(http, prov, rpc, code, verifier)
    return ts.id_token, rp.fetch_jwks(http, prov.jwks_uri, prov.issuer), nonce


def test_verify_id_token_nonce_mismatch(issued):
    """A wrong expected nonce is rejected."""
    id_token, jwks, _nonce = issued
    with pytest.raises(GrindvaktError, match="nonce"):
        rp.verify_id_token(jwks, id_token, ISSUER, CLIENT_ID, "not-the-nonce", ["ES256"])


def test_verify_id_token_wrong_audience_and_issuer(issued):
    """Audience and issuer are enforced."""
    id_token, jwks, nonce = issued
    with pytest.raises(GrindvaktError):
        rp.verify_id_token(jwks, id_token, ISSUER, "other-client", nonce, ["ES256"])
    with pytest.raises(GrindvaktError):
        rp.verify_id_token(jwks, id_token, "https://other.example.com", CLIENT_ID, nonce, ["ES256"])


def test_verify_id_token_wrong_key(issued):
    """A JWKS that does not contain the signing key is rejected."""
    id_token, _jwks, nonce = issued
    other = keys.signing_key_from_jwk(keys.generate_ec_jwk("P-256"), alg="ES256", kid="op-1")
    with pytest.raises(GrindvaktError):
        rp.verify_id_token(other.to_public_jwks(), id_token, ISSUER, CLIENT_ID, nonce, ["ES256"])


def test_verify_id_token_requires_nonce_by_default(issued):
    """expected_nonce=None without the unsafe flag raises AuthnError."""
    id_token, jwks, _nonce = issued
    with pytest.raises(AuthnError, match="expected_nonce is required"):
        rp.verify_id_token(jwks, id_token, ISSUER, CLIENT_ID, None, ["ES256"])


def test_verify_id_token_unsafe_skip_warns(issued):
    """unsafe_skip_nonce_check=True skips the check and emits a UserWarning."""
    id_token, jwks, _nonce = issued
    with pytest.warns(UserWarning, match="nonce check skipped"):
        claims = rp.verify_id_token(jwks, id_token, ISSUER, CLIENT_ID, None, ["ES256"], unsafe_skip_nonce_check=True)
    assert claims["sub"] == "alice"


def test_verify_id_token_unsafe_flag_with_nonce_still_checks(issued):
    """The flag only matters when no nonce is given; a given nonce is enforced."""
    id_token, jwks, nonce = issued
    claims = rp.verify_id_token(jwks, id_token, ISSUER, CLIENT_ID, nonce, ["ES256"], unsafe_skip_nonce_check=True)
    assert claims["nonce"] == nonce
    with pytest.raises(GrindvaktError, match="nonce"):
        rp.verify_id_token(jwks, id_token, ISSUER, CLIENT_ID, "wrong", ["ES256"], unsafe_skip_nonce_check=True)


def test_verify_id_token_subject_audience_azp_and_algorithm_policy(op_key):
    now = int(time.time())
    base = {"iss": ISSUER, "sub": "alice", "aud": CLIENT_ID, "iat": now, "exp": now + 300,
            "nonce": "n"}
    jwks = op_key.to_public_jwks()

    missing_sub = {key: value for key, value in base.items() if key != "sub"}
    with pytest.raises(GrindvaktError, match="sub"):
        rp.verify_id_token(jwks, jwt.sign(op_key, missing_sub), ISSUER, CLIENT_ID, "n", ["ES256"])

    single_array = {**base, "aud": [CLIENT_ID]}
    assert rp.verify_id_token(
        jwks, jwt.sign(op_key, single_array), ISSUER, CLIENT_ID, "n", ["ES256"]
    )["sub"] == "alice"
    with pytest.raises(GrindvaktError, match="azp"):
        rp.verify_id_token(
            jwks,
            jwt.sign(op_key, {**single_array, "azp": "another-client"}),
            ISSUER,
            CLIENT_ID,
            "n",
            ["ES256"],
        )

    multi = {**base, "aud": [CLIENT_ID, "https://api.example"]}
    with pytest.raises(GrindvaktError, match="untrusted audience"):
        rp.verify_id_token(jwks, jwt.sign(op_key, multi), ISSUER, CLIENT_ID, "n", ["ES256"])
    with pytest.raises(GrindvaktError, match="azp"):
        rp.verify_id_token(jwks, jwt.sign(op_key, multi), ISSUER, CLIENT_ID, "n", ["ES256"],
                           ["https://api.example"])
    accepted = {**multi, "azp": CLIENT_ID}
    assert rp.verify_id_token(jwks, jwt.sign(op_key, accepted), ISSUER, CLIENT_ID, "n", ["ES256"],
                              ["https://api.example"])["sub"] == "alice"
    with pytest.raises(GrindvaktError):
        rp.verify_id_token(jwks, jwt.sign(op_key, base), ISSUER, CLIENT_ID, "n", ["RS256"])
    with pytest.raises(GrindvaktError, match="allowed"):
        rp.verify_id_token(jwks, jwt.sign(op_key, base), ISSUER, CLIENT_ID, "n", [])


# --- userinfo -------------------------------------------------------------------


def test_fetch_userinfo_bad_token_raises(http, prov):
    """A rejected access token surfaces as AuthnError."""
    with pytest.raises(AuthnError, match="userinfo returned"):
        rp.fetch_userinfo(
            http, prov.userinfo_endpoint, "garbage", "expected-sub", prov.issuer
        )


def test_fetch_userinfo_requires_matching_subject():
    class UserInfoHttp:
        def get(self, url):
            raise AssertionError("unexpected GET")

        def post_form(self, url, form, headers):
            return 200, b'{"sub":"mallory","email":"m@example.test"}', "application/json"

    with pytest.raises(AuthnError, match="subject"):
        rp.fetch_userinfo(
            UserInfoHttp(), f"{ISSUER}/userinfo", "access-token", "alice", ISSUER
        )


@pytest.mark.parametrize("payload", [
    {"id_token": "i", "token_type": "Bearer"},
    {"access_token": "a", "token_type": "Bearer"},
    {"access_token": "a", "id_token": "i"},
    {"access_token": "", "id_token": "i", "token_type": "Bearer"},
])
def test_exchange_code_rejects_partial_success(payload):
    class TokenHttp:
        def get(self, url):
            raise AssertionError("unexpected GET")

        def post_form(self, url, form, headers):
            return 200, json.dumps(payload).encode(), "application/json"

    info = rp.ProviderInfo(ISSUER, f"{ISSUER}/authorization", f"{ISSUER}/token")
    confidential = rp.RpClient(CLIENT_ID, REDIRECT_URI, client_secret=CLIENT_SECRET)
    with pytest.raises(AuthnError, match="missing"):
        rp.exchange_code(TokenHttp(), info, confidential, "code")


def test_exchange_code_rejects_unknown_token_type():
    """An RP must not use an access-token scheme it does not implement."""
    class TokenHttp:
        def get(self, url):
            raise AssertionError("unexpected GET")

        def post_form(self, url, form, headers):
            payload = {"access_token": "a", "id_token": "i", "token_type": "Unknown"}
            return 200, json.dumps(payload).encode(), "application/json"

    info = rp.ProviderInfo(ISSUER, f"{ISSUER}/authorization", f"{ISSUER}/token")
    confidential = rp.RpClient(CLIENT_ID, REDIRECT_URI, client_secret=CLIENT_SECRET)
    with pytest.raises(AuthnError, match="unsupported token_type"):
        rp.exchange_code(TokenHttp(), info, confidential, "code")


# --- client assertions / request objects ----------------------------------------


def test_build_client_assertion(rp_key):
    """The assertion is a JWT with iss == sub == client_id and aud == audience."""
    aud = f"{ISSUER}/token"
    jws = rp.build_client_assertion(rp_key, CLIENT_ID, aud)
    claims = jwt.peek_claims_unverified(jws)
    assert claims["iss"] == CLIENT_ID
    assert claims["sub"] == CLIENT_ID
    assert claims["aud"] == aud
    assert claims["jti"]
    assert 0 < claims["exp"] - claims["iat"] <= 300
    assert jwt.peek_header(jws)["kid"] == "rp-1"
    v = jwt.Validation().with_issuer(CLIENT_ID).with_audience(aud).require_exp()
    assert jwt.verify_with_jwks(rp_key.to_public_jwks(), jws, v)["sub"] == CLIENT_ID


def test_private_key_jwt_client_authenticates(op, http, prov, rp_key):
    """private_key_jwt sends a client_assertion; a mismatched key is refused."""
    # Register a private_key_jwt client on the OP with the RP's public key.
    c = client.Client(
        "jwt-client",
        redirect_uris=[REDIRECT_URI],
        token_endpoint_auth_method="private_key_jwt",
        jwks=rp_key.to_public_jwks(),
    )
    op2 = provider.Provider(
        op.metadata, op.signing_key, client.InMemoryClientStore([c]), tokens.TokenCodec("op-secret"),
        token_use_store=provider.InMemoryTokenUseStore(),
    )
    http2 = FakeHttpClient(op2)
    rpc = rp.RpClient("jwt-client", REDIRECT_URI, auth_method="private_key_jwt", signing_key=rp_key)
    verifier = util.random_token(48)
    code = run_authorization(op2, prov, rpc, "st", "n", verifier)
    ts = rp.exchange_code(http2, prov, rpc, code, verifier)
    assert ts.id_token

    other = keys.signing_key_from_jwk(keys.generate_ec_jwk("P-256"), alg="ES256", kid="rp-1")
    bad = rp.RpClient("jwt-client", REDIRECT_URI, auth_method="private_key_jwt", signing_key=other)
    code = run_authorization(op2, prov, rpc, "st", "n", verifier)
    with pytest.raises(AuthnError):
        rp.exchange_code(http2, prov, bad, code, verifier)


def test_signed_request_object(prov, rpc, rp_key):
    """The request object carries the authorization parameters, signed by key."""
    challenge = pkce.s256_challenge("v" * 43)
    jar = rp.signed_request_object(prov, rpc, rp_key, "st-1", "n-1", challenge)
    v = jwt.Validation().with_issuer(CLIENT_ID).with_audience(ISSUER)
    claims = jwt.verify_with_jwks(rp_key.to_public_jwks(), jar, v)
    assert claims["client_id"] == CLIENT_ID
    assert claims["redirect_uri"] == REDIRECT_URI
    assert claims["response_type"] == "code"
    assert claims["state"] == "st-1"
    assert claims["nonce"] == "n-1"
    assert claims["code_challenge"] == challenge
    assert claims["code_challenge_method"] == "S256"
    assert claims["jti"]
    plain = jwt.peek_claims_unverified(rp.signed_request_object(prov, rpc, rp_key, "st", "n"))
    assert "code_challenge" not in plain


# --- claims_to_attributes ---------------------------------------------------------


def test_claims_to_attributes_shape():
    """Strings, lists, numbers and bools map to string lists; the rest is dropped."""
    out = rp.claims_to_attributes(
        {"a": "x", "b": ["y", "z"], "n": 3, "t": True, "obj": {"k": "v"}, "none": None, "empty": []}
    )
    assert out == {"a": ["x"], "b": ["y", "z"], "n": ["3"], "t": ["true"]}
    assert rp.claims_to_attributes({}) == {}
