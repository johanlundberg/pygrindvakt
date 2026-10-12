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
    ConfigError,
    CryptoError,
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
                return self._json(in_thread(self.op.userinfo, auth[len("Bearer ") :]))
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
    c = client.Client(
        CLIENT_ID,
        client_secret=CLIENT_SECRET,
        redirect_uris=[REDIRECT_URI, ALT_REDIRECT_URI],
    )
    return provider.Provider(
        md,
        op_key,
        client.InMemoryClientStore([c]),
        tokens.TokenCodec("op-secret"),
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
    return rp.RpClient(
        CLIENT_ID,
        REDIRECT_URI,
        client_secret=CLIENT_SECRET,
        redirect_uris=[ALT_REDIRECT_URI],
    )


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
            CLIENT_ID,
            REDIRECT_URI,
            auth_method="private_key_jwt",
            signing_key=rp_key,
            client_secret="x",
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
    for endpoint in [
        "http://example.com/token",
        "file:///tmp/token",
        "https://u:p@example.com/token",
        "https://example.com/token#fragment",
        "http://127.0.0.1:8000/token",
    ]:
        with pytest.raises(GrindvaktError):
            rp.ProviderInfo(ISSUER, f"{ISSUER}/authorization", endpoint)
    with pytest.raises(GrindvaktError, match="library-controlled"):
        rp.ProviderInfo(ISSUER, f"{ISSUER}/authorization?client_id=attacker", f"{ISSUER}/token")
    # Separate HTTPS endpoint origins remain legitimate. Loopback HTTP is a
    # development exception only when the issuer is itself loopback HTTP.
    rp.ProviderInfo(
        ISSUER,
        "https://login.example.net/authorization",
        "https://tokens.example.net/token",
    )
    rp.ProviderInfo(
        "http://127.0.0.1:8000",
        "http://127.0.0.1:8000/authorization",
        "http://localhost:8000/token",
    )


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
    configured = rp.ProviderInfo(ISSUER, f"{ISSUER}/authorization?tenant=configured", f"{ISSUER}/token")
    with pytest.raises(GrindvaktError, match="duplicate"):
        rp.authorization_url(configured, rpc, "state", "nonce", extra={"tenant": "override"})
    url = rp.authorization_url(
        prov,
        rpc,
        "state",
        "nonce",
        extra=[("resource", "https://api-1"), ("resource", "https://api-2")],
    )
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
    state, nonce, verifier = (
        util.random_token(),
        util.random_token(),
        util.random_token(48),
    )
    url = rp.authorization_url(
        prov,
        rpc,
        state,
        nonce,
        pkce.s256_challenge(verifier),
        redirect_uri=ALT_REDIRECT_URI,
    )
    req = request.AuthorizationRequest.from_params([(k, v[0]) for k, v in parse_qs(urlsplit(url).query).items()])
    op.validate_authorization_request(req)
    resp = op.authorization_redirect(req, "alice", {"email": ["a@b"]})
    code = parse_qs(urlsplit(resp.header("location")).query)["code"][0]
    ts = rp.exchange_code(http, prov, rpc, code, verifier, redirect_uri=ALT_REDIRECT_URI)
    assert ts.id_token
    assert ("redirect_uri", ALT_REDIRECT_URI) in http.forms[-1]
    assert ("redirect_uri", REDIRECT_URI) not in http.forms[-1]


def _all_overrides(prov, client, rp_key, uri):
    """Run every per-call override entry point; yield one callable each."""
    return [
        lambda: rp.authorization_url(prov, client, "st", "n", redirect_uri=uri),
        lambda: rp.signed_request_object(prov, client, rp_key, "st", "n", redirect_uri=uri),
        lambda: rp.begin(prov, client, redirect_uri=uri),
        lambda: rp.exchange_code(RaisingHttpClient(), prov, client, "code", "v" * 43, redirect_uri=uri),
    ]


@pytest.mark.parametrize(
    "bad",
    [
        "https://evil.example/steal",
        "http://evil.example/cb",
        REDIRECT_URI + "/",
        REDIRECT_URI.upper(),
        ALT_REDIRECT_URI + "/",
        ALT_REDIRECT_URI + "?x=1",
        ALT_REDIRECT_URI.replace("rp.example.com", "rp.example.com:8443"),
        ALT_REDIRECT_URI.replace("https://rp", "https://RP"),
    ],
)
def test_unregistered_redirect_uri_override_rejected(prov, rpc, rp_key, bad):
    for call in _all_overrides(prov, rpc, rp_key, bad):
        with pytest.raises(BadRequestError, match="redirect_uris"):
            call()


def test_unregistered_override_error_names_escape_hatch(prov, rpc):
    with pytest.raises(BadRequestError, match="allow_unregistered_redirect_uri"):
        rp.authorization_url(prov, rpc, "st", "n", redirect_uri="https://evil.example/steal")


def test_configured_redirect_uri_override_is_noop(prov, rpc, rp_key):
    plain = rp.RpClient(CLIENT_ID, REDIRECT_URI, client_secret=CLIENT_SECRET)
    url = rp.authorization_url(prov, plain, "st", "n", redirect_uri=REDIRECT_URI)
    assert parse_qs(urlsplit(url).query)["redirect_uri"] == [REDIRECT_URI]
    rp.signed_request_object(prov, plain, rp_key, "st", "n", redirect_uri=REDIRECT_URI)
    rp.begin(prov, plain, redirect_uri=REDIRECT_URI)


def test_redirect_uris_properties_and_repr():
    c = rp.RpClient("c", REDIRECT_URI, redirect_uris=[ALT_REDIRECT_URI])
    assert c.redirect_uris == (ALT_REDIRECT_URI,)
    assert c.allow_unregistered_redirect_uri is False
    assert "redirect_uris=" in repr(c)
    d = rp.RpClient("c", REDIRECT_URI, allow_unregistered_redirect_uri=True)
    assert d.redirect_uris == ()
    assert d.allow_unregistered_redirect_uri is True
    assert "allow_unregistered_redirect_uri=True" in repr(d)


def test_allow_unregistered_redirect_uri_accepts_valid_https(prov, rp_key):
    c = rp.RpClient(
        CLIENT_ID,
        REDIRECT_URI,
        client_secret=CLIENT_SECRET,
        allow_unregistered_redirect_uri=True,
    )
    uri = "https://other.example/dyn"
    url = rp.authorization_url(prov, c, "st", "n", redirect_uri=uri)
    assert parse_qs(urlsplit(url).query)["redirect_uri"] == [uri]
    rp.signed_request_object(prov, c, rp_key, "st", "n", redirect_uri=uri)
    rp.begin(prov, c, redirect_uri=uri)
    for bad in (
        "https://other.example/dyn#frag",
        "http://other.example/cb",
        "/relative",
        "",
    ):
        for call in _all_overrides(prov, c, rp_key, bad):
            with pytest.raises(BadRequestError):
                call()
    url = rp.authorization_url(prov, c, "st", "n", redirect_uri="http://127.0.0.1:8080/cb")
    assert "127.0.0.1" in url


def test_loopback_http_registered_override_accepted(prov):
    c = rp.RpClient(
        CLIENT_ID,
        REDIRECT_URI,
        client_secret=CLIENT_SECRET,
        redirect_uris=[
            "http://localhost:8080/cb",
            "http://[::1]:9/cb",
            "com.example.app:/oauth2redirect",
        ],
    )
    for uri in c.redirect_uris:
        url = rp.authorization_url(prov, c, "st", "n", redirect_uri=uri)
        assert parse_qs(urlsplit(url).query)["redirect_uri"] == [uri]


@pytest.mark.parametrize(
    "bad",
    [
        "https://rp.example.com/cb#frag",
        "/relative",
        "",
        "http://rp.example.com/cb",
        "http://10.0.0.1/cb",
    ],
)
def test_redirect_uris_validated_at_construction(bad):
    with pytest.raises(GrindvaktError):
        rp.RpClient(CLIENT_ID, REDIRECT_URI, redirect_uris=[bad])


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
    req = request.AuthorizationRequest.from_params([(k, v[0]) for k, v in parse_qs(urlsplit(url).query).items()])
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
    state, nonce, verifier = (
        util.random_token(),
        util.random_token(),
        util.random_token(48),
    )
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

    info = rp.fetch_userinfo(http, prov.userinfo_endpoint, ts.access_token, claims["sub"], prov.issuer)
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
        op.metadata,
        op.signing_key,
        client.InMemoryClientStore([c]),
        tokens.TokenCodec("op-secret"),
        token_use_store=provider.InMemoryTokenUseStore(),
    )
    rpc = rp.RpClient(
        CLIENT_ID,
        REDIRECT_URI,
        client_secret=CLIENT_SECRET,
        auth_method="client_secret_post",
    )
    verifier = util.random_token(48)
    code = run_authorization(op2, prov, rpc, "st", "n", verifier)
    ts = rp.exchange_code(FakeHttpClient(op2), prov, rpc, code, verifier)
    assert ts.id_token


def test_exchange_code_method_mismatch_is_refused(op, http, prov):
    """An RP using client_secret_post against a client_secret_basic registration fails."""
    rpc = rp.RpClient(
        CLIENT_ID,
        REDIRECT_URI,
        client_secret=CLIENT_SECRET,
        auth_method="client_secret_post",
    )
    verifier = util.random_token(48)
    code = run_authorization(op, prov, rpc, "st", "n", verifier)
    with pytest.raises(AuthnError, match="token endpoint returned 401") as ei:
        rp.exchange_code(http, prov, rpc, code, verifier)
    assert ei.value.code == "invalid_client"
    assert ei.value.upstream_status == 401


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
        claims = rp.verify_id_token(
            jwks,
            id_token,
            ISSUER,
            CLIENT_ID,
            None,
            ["ES256"],
            unsafe_skip_nonce_check=True,
        )
    assert claims["sub"] == "alice"


def test_verify_id_token_unsafe_flag_with_nonce_still_checks(issued):
    """The flag only matters when no nonce is given; a given nonce is enforced."""
    id_token, jwks, nonce = issued
    claims = rp.verify_id_token(
        jwks,
        id_token,
        ISSUER,
        CLIENT_ID,
        nonce,
        ["ES256"],
        unsafe_skip_nonce_check=True,
    )
    assert claims["nonce"] == nonce
    with pytest.raises(GrindvaktError, match="nonce"):
        rp.verify_id_token(
            jwks,
            id_token,
            ISSUER,
            CLIENT_ID,
            "wrong",
            ["ES256"],
            unsafe_skip_nonce_check=True,
        )


def test_verify_id_token_subject_audience_azp_and_algorithm_policy(op_key):
    now = int(time.time())
    base = {
        "iss": ISSUER,
        "sub": "alice",
        "aud": CLIENT_ID,
        "iat": now,
        "exp": now + 300,
        "nonce": "n",
    }
    jwks = op_key.to_public_jwks()

    missing_sub = {key: value for key, value in base.items() if key != "sub"}
    with pytest.raises(GrindvaktError, match="sub"):
        rp.verify_id_token(jwks, jwt.sign(op_key, missing_sub), ISSUER, CLIENT_ID, "n", ["ES256"])

    single_array = {**base, "aud": [CLIENT_ID]}
    assert rp.verify_id_token(jwks, jwt.sign(op_key, single_array), ISSUER, CLIENT_ID, "n", ["ES256"])["sub"] == "alice"
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
        rp.verify_id_token(
            jwks,
            jwt.sign(op_key, multi),
            ISSUER,
            CLIENT_ID,
            "n",
            ["ES256"],
            ["https://api.example"],
        )
    accepted = {**multi, "azp": CLIENT_ID}
    assert (
        rp.verify_id_token(
            jwks,
            jwt.sign(op_key, accepted),
            ISSUER,
            CLIENT_ID,
            "n",
            ["ES256"],
            ["https://api.example"],
        )["sub"]
        == "alice"
    )
    with pytest.raises(GrindvaktError):
        rp.verify_id_token(jwks, jwt.sign(op_key, base), ISSUER, CLIENT_ID, "n", ["RS256"])
    with pytest.raises(GrindvaktError, match="allowed"):
        rp.verify_id_token(jwks, jwt.sign(op_key, base), ISSUER, CLIENT_ID, "n", [])


# --- userinfo -------------------------------------------------------------------


def test_fetch_userinfo_bad_token_raises(http, prov):
    """A rejected access token surfaces as AuthnError."""
    with pytest.raises(AuthnError, match="userinfo returned"):
        rp.fetch_userinfo(http, prov.userinfo_endpoint, "garbage", "expected-sub", prov.issuer)


def test_fetch_userinfo_requires_matching_subject():
    class UserInfoHttp:
        def get(self, url):
            raise AssertionError("unexpected GET")

        def post_form(self, url, form, headers):
            return (
                200,
                b'{"sub":"mallory","email":"m@example.test"}',
                "application/json",
            )

    with pytest.raises(AuthnError, match="subject"):
        rp.fetch_userinfo(UserInfoHttp(), f"{ISSUER}/userinfo", "access-token", "alice", ISSUER)


@pytest.mark.parametrize(
    "payload",
    [
        {"id_token": "i", "token_type": "Bearer"},
        {"access_token": "a", "token_type": "Bearer"},
        {"access_token": "a", "id_token": "i"},
        {"access_token": "", "id_token": "i", "token_type": "Bearer"},
    ],
)
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
        op.metadata,
        op.signing_key,
        client.InMemoryClientStore([c]),
        tokens.TokenCodec("op-secret"),
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
        {
            "a": "x",
            "b": ["y", "z"],
            "n": 3,
            "t": True,
            "obj": {"k": "v"},
            "none": None,
            "empty": [],
        }
    )
    assert out == {"a": ["x"], "b": ["y", "z"], "n": ["3"], "t": ["true"]}
    assert rp.claims_to_attributes({}) == {}


# --- userinfo: GET, signed JWT, endpoint policy --------------------------------

UI_URL = f"{ISSUER}/userinfo"


class UserinfoRecorder:
    """Python client with header support on ``get``; records every request."""

    def __init__(self, status=200, body=b'{"sub":"alice","name":"A"}', ctype="application/json"):
        self.calls = []
        self.resp = (status, body, ctype)

    def get(self, url, headers=None):
        self.calls.append(("GET", url, headers))
        return self.resp

    def post_form(self, url, form, headers):
        self.calls.append(("POST", url, form, headers))
        return self.resp


def ui(http, **kw):
    return rp.fetch_userinfo(http, UI_URL, "tok", "alice", ISSUER, **kw)


def test_userinfo_post_default_unchanged():
    c = UserinfoRecorder()
    assert ui(c)["name"] == "A"
    assert c.calls == [("POST", UI_URL, [], [("authorization", "Bearer tok")])]


def test_userinfo_get_sends_authorization_header():
    c = UserinfoRecorder()
    assert ui(c, method="GET")["sub"] == "alice"
    assert c.calls == [("GET", UI_URL, [("authorization", "Bearer tok")])]


def test_userinfo_get_with_get_with_headers_preferred():
    class Both(UserinfoRecorder):
        def get_with_headers(self, url, headers):
            self.calls.append(("GWH", url, headers))
            return self.resp

    c = Both()
    ui(c, method="GET")
    assert c.calls == [("GWH", UI_URL, [("authorization", "Bearer tok")])]


def test_userinfo_get_with_kwargs_get():
    class Kw:
        def get(self, url, **kwargs):
            self.kw = kwargs
            return 200, b'{"sub":"alice"}', "application/json"

        def post_form(self, *a):
            raise AssertionError

    c = Kw()
    ui(c, method="GET")
    assert c.kw == {"headers": [("authorization", "Bearer tok")]}


def test_userinfo_get_client_without_header_support_is_config_error():
    from pygrindvakt import ConfigError

    class Plain:
        called = False

        def get(self, url):
            Plain.called = True
            return 200, b'{"sub":"alice"}', "application/json"

        def post_form(self, url, form, headers):
            return 200, b'{"sub":"alice"}', "application/json"

    with pytest.raises(ConfigError, match="request headers"):
        ui(Plain(), method="GET")
    assert not Plain.called  # decided up front, never call-and-fall-back
    assert ui(Plain())["sub"] == "alice"  # POST still fine


def test_userinfo_get_positional_only_or_var_positional_headers_is_unsupported():
    """`headers` must be passable by keyword; the adapter calls get(url, headers=...)."""
    from pygrindvakt import ConfigError

    class PosOnly:
        called = False

        def get(self, url, headers=None, /):
            PosOnly.called = True
            return 200, b'{"sub":"alice"}', "application/json"

        def post_form(self, *a):
            raise AssertionError

    class VarPos:
        called = False

        def get(self, url, *headers):
            VarPos.called = True
            return 200, b'{"sub":"alice"}', "application/json"

        def post_form(self, *a):
            raise AssertionError

    for cls in (PosOnly, VarPos):
        with pytest.raises(ConfigError, match="request headers"):
            ui(cls(), method="GET")
        assert not cls.called


def test_userinfo_get_keyword_only_and_var_keyword_named_headers_are_supported():
    class KwOnly:
        def get(self, url, *, headers=None):
            self.h = headers
            return 200, b'{"sub":"alice"}', "application/json"

        def post_form(self, *a):
            raise AssertionError

    class VarKwHeaders:
        def get(self, url, **headers):
            self.h = headers
            return 200, b'{"sub":"alice"}', "application/json"

        def post_form(self, *a):
            raise AssertionError

    for cls in (KwOnly, VarKwHeaders):
        c = cls()
        ui(c, method="GET")
        h = c.h["headers"] if cls is VarKwHeaders else c.h
        assert h == [("authorization", "Bearer tok")]


def test_userinfo_get_typeerror_inside_client_is_not_swallowed():
    class Boom:
        def get(self, url, headers=None):
            raise TypeError("inside client")

        def post_form(self, *a):
            raise AssertionError

    with pytest.raises(InternalError) as e:
        ui(Boom(), method="GET")
    assert e.value.code == "transport"


def test_userinfo_invalid_method_and_trust_values():
    c = UserinfoRecorder()
    with pytest.raises(ValueError, match="method"):
        ui(c, method="PUT")
    with pytest.raises(ValueError, match="trust"):
        ui(c, trust="bogus")
    with pytest.raises(ValueError, match="requires typ"):
        ui(c, trust="typed")
    with pytest.raises(ValueError, match="only used"):
        ui(c, trust="dedicated_keys", typ="userinfo+jwt")


def test_userinfo_endpoint_none_is_config_error():
    from pygrindvakt import ConfigError

    with pytest.raises(ConfigError, match="does not advertise a userinfo_endpoint"):
        rp.fetch_userinfo(UserinfoRecorder(), None, "tok", "alice", ISSUER)


def test_userinfo_get_real_server_sends_authorization():
    import http.server as hs

    seen = []

    class H(hs.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            seen.append(self.headers.get("Authorization"))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"sub":"alice"}')

    srv = hs.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        out = rp.fetch_userinfo(None, f"{base}/userinfo", "tok", "alice", base, method="GET")
        assert out == {"sub": "alice"} and seen == ["Bearer tok"]
    finally:
        srv.shutdown()


def _jwt_claims(**over):
    now = int(time.time())
    claims = {"iss": ISSUER, "sub": "alice", "aud": CLIENT_ID, "iat": now, "name": "A"}
    claims.update(over)
    return {k: v for k, v in claims.items() if v is not None}


def _signed(op_key, claims, typ=None):
    return UserinfoRecorder(body=jwt.sign(op_key, claims, typ).encode(), ctype="application/jwt")


def _verify(c, op_key, trust="dedicated_keys", typ=None, **kw):
    return ui(
        c,
        jwks=op_key.to_public_jwks(),
        client_id=CLIENT_ID,
        allowed_algorithms=["ES256"],
        trust=trust,
        typ=typ,
        **kw,
    )


def test_userinfo_signed_jwt_accepted_per_trust_mode(op_key):
    claims = _jwt_claims()
    for method in ("POST", "GET"):
        out = _verify(_signed(op_key, claims), op_key, "dedicated_keys", method=method)
        assert out["name"] == "A" and out["sub"] == "alice"
    assert _verify(_signed(op_key, claims), op_key, "untyped_shared_key_compat")["sub"] == "alice"
    typed = _signed(op_key, claims, "userinfo+jwt")
    assert _verify(typed, op_key, "typed", "userinfo+jwt")["sub"] == "alice"


def test_userinfo_typed_rejects_wrong_or_missing_typ(op_key):
    with pytest.raises(GrindvaktError):
        _verify(_signed(op_key, _jwt_claims(), "other+jwt"), op_key, "typed", "userinfo+jwt")
    with pytest.raises(GrindvaktError):
        _verify(_signed(op_key, _jwt_claims()), op_key, "typed", "userinfo+jwt")
    # typ must identify UserInfo specifically
    with pytest.raises(GrindvaktError):
        _verify(_signed(op_key, _jwt_claims(), "JWT"), op_key, "typed", "JWT")


@pytest.mark.parametrize("missing", ["jwks", "client_id", "allowed_algorithms", "trust"])
def test_userinfo_signed_jwt_fails_closed_without_verification_inputs(op_key, missing):
    kw = {
        "jwks": op_key.to_public_jwks(),
        "client_id": CLIENT_ID,
        "allowed_algorithms": ["ES256"],
        "trust": "dedicated_keys",
    }
    del kw[missing]
    with pytest.raises(AuthnError) as e:
        ui(_signed(op_key, _jwt_claims()), **kw)
    assert e.value.code == "userinfo_unverifiable"
    assert missing in str(e.value)
    # an empty algorithm list is also unverifiable
    if missing == "allowed_algorithms":
        with pytest.raises(AuthnError) as e:
            ui(
                _signed(op_key, _jwt_claims()),
                allowed_algorithms=[],
                jwks=kw["jwks"],
                client_id=CLIENT_ID,
                trust="dedicated_keys",
            )
        assert e.value.code == "userinfo_unverifiable"


def test_userinfo_signed_jwt_rejections(op_key):
    other = keys.signing_key_from_jwk(keys.generate_ec_jwk("P-256"), alg="ES256", kid="op-1")
    cases = {
        "bad signature": _signed(other, _jwt_claims()),
        "wrong iss": _signed(op_key, _jwt_claims(iss="https://evil.example")),
        "wrong aud": _signed(op_key, _jwt_claims(aud="someone-else")),
        "multi aud": _signed(op_key, _jwt_claims(aud=[CLIENT_ID, "api"])),
        "sub mismatch": _signed(op_key, _jwt_claims(sub="mallory")),
        "expired": _signed(op_key, _jwt_claims(exp=int(time.time()) - 3600)),
        "stale iat": _signed(op_key, _jwt_claims(iat=int(time.time()) - 3600)),
        "no iat": _signed(op_key, _jwt_claims(iat=None)),
        "nonce": _signed(op_key, _jwt_claims(nonce="n")),
        "at_hash": _signed(op_key, _jwt_claims(at_hash="h")),
        "c_hash": _signed(op_key, _jwt_claims(c_hash="h")),
        "id_token typ": _signed(op_key, _jwt_claims(), "id_token+jwt"),
    }
    for name, c in cases.items():
        with pytest.raises(GrindvaktError):
            _verify(c, op_key, "untyped_shared_key_compat")
            pytest.fail(f"{name} was accepted")
    # require_exp: a token without exp is refused only when asked
    assert _verify(_signed(op_key, _jwt_claims()), op_key)["sub"] == "alice"
    with pytest.raises(GrindvaktError):
        _verify(_signed(op_key, _jwt_claims()), op_key, require_exp=True)
    ok_exp = _jwt_claims(exp=int(time.time()) + 300)
    assert _verify(_signed(op_key, ok_exp), op_key, require_exp=True)["sub"] == "alice"


def test_userinfo_wrong_content_type_for_signed_body_is_not_trusted(op_key):
    """A JWT served as JSON is not accepted as claims (no sub in the body)."""
    body = jwt.sign(op_key, _jwt_claims()).encode()
    with pytest.raises(GrindvaktError):
        ui(UserinfoRecorder(body=body, ctype="application/json"))


def test_userinfo_max_age_default_and_disabled(op_key):
    old = _jwt_claims(iat=int(time.time()) - 3600)
    with pytest.raises(GrindvaktError):
        _verify(_signed(op_key, old), op_key)
    assert _verify(_signed(op_key, old), op_key, max_age=7200)["sub"] == "alice"
    undated = _jwt_claims(iat=None)
    with pytest.raises(GrindvaktError):
        _verify(_signed(op_key, undated), op_key)
    assert _verify(_signed(op_key, undated), op_key, max_age=None)["sub"] == "alice"
    assert _verify(_signed(op_key, old), op_key, max_age=None)["sub"] == "alice"


def test_userinfo_jwe_rejected():
    jwe = b"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.a.b.c.d"
    with pytest.raises(AuthnError, match="encrypted") as e:
        ui(UserinfoRecorder(body=jwe, ctype="application/jwt"))
    assert e.value.code == "userinfo_encrypted"


def test_userinfo_jwks_must_be_a_jwks_dict(op_key):
    with pytest.raises(TypeError):
        ui(
            _signed(op_key, _jwt_claims()),
            jwks="not-a-jwks",
            client_id=CLIENT_ID,
            allowed_algorithms=["ES256"],
            trust="dedicated_keys",
        )


# --- RP-Initiated Logout ------------------------------------------------------


@pytest.fixture
def lprov():
    return rp.ProviderInfo(
        ISSUER,
        f"{ISSUER}/authorization",
        f"{ISSUER}/token",
        end_session_endpoint=f"{ISSUER}/logout",
    )


def test_provider_info_carries_end_session_endpoint_from_discovery(op, op_key):
    md = metadata.ProviderMetadata(ISSUER)
    md.end_session_endpoint = f"{ISSUER}/logout"
    op2 = provider.Provider(
        md,
        op_key,
        client.InMemoryClientStore([]),
        tokens.TokenCodec("s"),
        token_use_store=provider.InMemoryTokenUseStore(),
    )
    discovered = rp.discover(FakeHttpClient(op2), ISSUER)
    assert discovered.end_session_endpoint == f"{ISSUER}/logout"
    assert discovered.raw is not None and discovered.raw["end_session_endpoint"] == f"{ISSUER}/logout"
    info = rp.ProviderInfo.from_metadata(discovered)
    assert info.end_session_endpoint == f"{ISSUER}/logout"
    assert "end_session_endpoint" in repr(info)


def test_provider_info_without_end_session_endpoint(prov):
    assert prov.end_session_endpoint is None
    with pytest.raises(ConfigError):
        rp.end_session_url(prov)


def test_discover_raw_is_response_body(http):
    md = rp.discover(http, ISSUER)
    assert md.raw == http.op.discovery_document()


def test_provider_info_rejects_unsafe_end_session_endpoint():
    for bad in [
        "http://op.example.com/l",
        f"{ISSUER}/l#frag",
        "https://u:p@op.example.com/l",
    ]:
        with pytest.raises(GrindvaktError):
            rp.ProviderInfo(
                ISSUER,
                f"{ISSUER}/authorization",
                f"{ISSUER}/token",
                end_session_endpoint=bad,
            )


def test_from_metadata_drops_unsafe_end_session_endpoint():
    """Login must not depend on logout: a bad advertised endpoint becomes None."""
    for bad in [
        "http://evil.example/l",
        f"{ISSUER}/l#frag",
        "https://u:p@op.example.com/l",
        "not a url",
    ]:
        import json

        body = json.dumps(metadata.ProviderMetadata(ISSUER).to_dict() | {"end_session_endpoint": bad}).encode()

        class Http:
            def get(self, url, body=body):
                return 200, body, "application/json"

            def post_form(self, url, form, headers):
                raise AssertionError

        md = rp.discover(Http(), ISSUER)
        info = rp.ProviderInfo.from_metadata(md)
        assert info.end_session_endpoint is None
        assert info.token_endpoint == f"{ISSUER}/token"
        with pytest.raises(ConfigError, match="different origin than the issuer"):
            rp.end_session_url(info)


def _pi(endpoint, issuer=ISSUER, **kw):
    return rp.ProviderInfo(
        issuer,
        f"{issuer}/authorization",
        f"{issuer}/token",
        end_session_endpoint=endpoint,
        **kw,
    )


def _md_with(endpoint, issuer=ISSUER):
    return metadata.ProviderMetadata.from_dict(
        metadata.ProviderMetadata(issuer).to_dict() | {"end_session_endpoint": endpoint}
    )


SAME_ORIGIN = [
    "https://op.example.com/l",
    "https://op.example.com:443/l",
    "https://OP.Example.COM/l",
    "HTTPS://op.example.com/l?x=1",
]
CROSS_ORIGIN = [
    "https://evil.example/logout",
    "https://sub.op.example.com/l",
    "https://op.example.com:8443/l",
    "https://op.example.com./l",
    "https://op.example.com@evil.example/l",
    "https://op.example.com.evil.example/l",
    "https://evil.example/https://op.example.com/l",
]


@pytest.mark.parametrize("ep", SAME_ORIGIN)
def test_end_session_same_origin_accepted(ep):
    assert _pi(ep).end_session_endpoint == ep
    assert rp.ProviderInfo.from_metadata(_md_with(ep)).end_session_endpoint == ep


@pytest.mark.parametrize("ep", CROSS_ORIGIN)
def test_end_session_cross_origin_rejected_and_dropped(ep):
    with pytest.raises(GrindvaktError):
        _pi(ep)
    info = rp.ProviderInfo.from_metadata(_raw_md(ep))
    assert info.end_session_endpoint is None
    with pytest.raises(ConfigError, match="different origin than the issuer"):
        rp.end_session_url(info, id_token_hint="tok")


def test_from_metadata_warns_when_dropping_end_session():
    import warnings

    with pytest.warns(
        UserWarning,
        match="different origin than the issuer.*allow_cross_origin_end_session=True",
    ):
        info = rp.ProviderInfo.from_metadata(_raw_md("https://evil.example/logout"))
    assert info.end_session_endpoint is None
    with pytest.warns(UserWarning, match="unsafe"):
        rp.ProviderInfo.from_metadata(_raw_md("https://op.example.com/l#frag"))
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        # a warnings filter of "error" must not make login depend on logout
        dropped = rp.ProviderInfo.from_metadata(_raw_md("https://evil.example/logout"))
        assert dropped.end_session_endpoint is None
        rp.ProviderInfo.from_metadata(_raw_md("https://op.example.com/l"))
        rp.ProviderInfo.from_metadata(_raw_md("https://evil.example/l"), allow_cross_origin_end_session=True)
        rp.ProviderInfo.from_metadata(rp.discover(_NoEndSession(), ISSUER))


class _NoEndSession:
    def get(self, url):
        return (
            200,
            json.dumps(metadata.ProviderMetadata(ISSUER).to_dict()).encode(),
            "application/json",
        )

    def post_form(self, url, form, headers):
        raise AssertionError


def test_end_session_constructor_error_says_cross_origin():
    with pytest.raises(BadRequestError, match="different origin"):
        _pi("https://evil.example/logout")


def test_end_session_explicit_default_port_issuer():
    iss = "https://op.example.com:443"
    assert _pi("https://op.example.com/l", issuer=iss).end_session_endpoint == "https://op.example.com/l"


def test_end_session_loopback_http_issuer_origin_binding():
    iss = "http://localhost:8000"
    assert _pi("http://localhost:8000/l", issuer=iss).end_session_endpoint
    for bad in [
        "http://localhost:9000/l",
        "http://127.0.0.1:8000/l",
        "http://localhost/l",
    ]:
        with pytest.raises(GrindvaktError):
            _pi(bad, issuer=iss)
    # scheme differs: https on the loopback host/port is still another origin
    with pytest.raises(GrindvaktError):
        _pi("https://localhost:8000/l", issuer=iss)
    v6 = "http://[::1]:8000"
    assert _pi("http://[::1]:8000/l", issuer=v6).end_session_endpoint
    with pytest.raises(GrindvaktError):
        _pi("http://[::1]:8001/l", issuer=v6)


def test_end_session_review_poc_now_config_error():
    md = metadata.ProviderMetadata.from_dict(
        metadata.ProviderMetadata(ISSUER).to_dict() | {"end_session_endpoint": "https://evil.example/logout"}
    )
    info = rp.ProviderInfo.from_metadata(md)
    with pytest.raises(ConfigError):
        rp.end_session_url(info, id_token_hint="secret-id-token")


def test_end_session_cross_origin_opt_in():
    ep = "https://logout.other.example/l"
    info = _pi(ep, allow_cross_origin_end_session=True)
    assert info.end_session_endpoint == ep
    info2 = rp.ProviderInfo.from_metadata(_md_with(ep), allow_cross_origin_end_session=True)
    assert info2.end_session_endpoint == ep
    url = rp.end_session_url(info2, id_token_hint="tok")
    assert url.startswith("https://logout.other.example/l?") and "id_token_hint=tok" in url


def test_end_session_opt_in_still_validates_unsafe():
    for bad in [
        "http://evil.example/l",
        "https://evil.example/l#f",
        "https://u:p@evil.example/l",
    ]:
        with pytest.raises(GrindvaktError):
            _pi(bad, allow_cross_origin_end_session=True)
        info = rp.ProviderInfo.from_metadata(_raw_md(bad), allow_cross_origin_end_session=True)
        assert info.end_session_endpoint is None


def _raw_md(bad):
    class Http:
        def get(self, url):
            return (
                200,
                json.dumps(metadata.ProviderMetadata(ISSUER).to_dict() | {"end_session_endpoint": bad}).encode(),
                "application/json",
            )

        def post_form(self, url, form, headers):
            raise AssertionError

    return rp.discover(Http(), ISSUER)


def _logout_client(*uris):
    return rp.RpClient(CLIENT_ID, REDIRECT_URI, post_logout_redirect_uris=list(uris))


def test_end_session_url_params_and_encoding(lprov):
    rpc = _logout_client("https://rp.example.com/after?x=1&y=2")
    url = rp.end_session_url(
        lprov,
        id_token_hint="a.b.c",
        client=rpc,
        post_logout_redirect_uri="https://rp.example.com/after?x=1&y=2",
        state="s t&",
        logout_hint="al ice",
        ui_locales="sv en",
        extra={"foo": "b ar"},
    )
    parts = urlsplit(url)
    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == f"{ISSUER}/logout"
    q = parse_qs(parts.query)
    assert q == {
        "id_token_hint": ["a.b.c"],
        "client_id": [CLIENT_ID],
        "post_logout_redirect_uri": ["https://rp.example.com/after?x=1&y=2"],
        "state": ["s t&"],
        "logout_hint": ["al ice"],
        "ui_locales": ["sv en"],
        "foo": ["b ar"],
    }
    assert "x=1&y=2" not in parts.query  # the nested URL is percent-encoded


def test_end_session_url_minimal_and_existing_query():
    p = rp.ProviderInfo(
        ISSUER,
        f"{ISSUER}/a",
        f"{ISSUER}/token",
        end_session_endpoint=f"{ISSUER}/logout?tenant=x",
    )
    assert rp.end_session_url(p) == f"{ISSUER}/logout?tenant=x"
    url = rp.end_session_url(p, id_token_hint="h")
    assert url == f"{ISSUER}/logout?tenant=x&id_token_hint=h"
    assert rp.end_session_url(p, extra=[("a", "1"), ("a", "2")]).endswith("?tenant=x&a=1&a=2")


AFTER = "https://rp.example.com/after"


def test_end_session_url_registered_post_logout_accepted(lprov):
    c = _logout_client(AFTER, "https://rp.example.com/other")
    assert c.post_logout_redirect_uris == (AFTER, "https://rp.example.com/other")
    assert "post_logout_redirect_uris" in repr(c)
    url = rp.end_session_url(lprov, client=c, post_logout_redirect_uri=AFTER)
    assert parse_qs(urlsplit(url).query)["post_logout_redirect_uri"] == [AFTER]
    rp.end_session_url(lprov, client=c, id_token_hint="h", post_logout_redirect_uri=AFTER)


def test_end_session_url_unregistered_post_logout_rejected(lprov):
    c = _logout_client(AFTER)
    with pytest.raises(BadRequestError, match="registered on the client"):
        rp.end_session_url(lprov, client=c, post_logout_redirect_uri="https://evil.example/")


@pytest.mark.parametrize(
    "near",
    [
        AFTER + "/",
        AFTER.replace("rp.", "RP."),
        "HTTPS://rp.example.com/after",
        AFTER + "?next=1",
        AFTER + " ",
    ],
)
def test_end_session_url_near_miss_rejected(lprov, near):
    with pytest.raises(BadRequestError, match="registered on the client"):
        rp.end_session_url(lprov, client=_logout_client(AFTER), post_logout_redirect_uri=near)


def test_end_session_url_hint_only_post_logout_rejected(lprov):
    with pytest.raises(BadRequestError, match="registered on the client"):
        rp.end_session_url(lprov, id_token_hint="h", post_logout_redirect_uri=AFTER)
    with pytest.raises(BadRequestError, match="registered on the client"):
        rp.end_session_url(lprov, post_logout_redirect_uri=AFTER)


def test_end_session_url_empty_registration_rejects_all(lprov, rpc):
    assert rpc.post_logout_redirect_uris == ()
    for c in (rpc, _logout_client()):
        with pytest.raises(BadRequestError, match="registered on the client"):
            rp.end_session_url(lprov, client=c, id_token_hint="h", post_logout_redirect_uri=AFTER)


def test_end_session_url_request_value_cannot_bypass(lprov):
    request_args = {"next": "https://evil.example/steal"}
    with pytest.raises(BadRequestError, match="registered on the client"):
        rp.end_session_url(
            lprov,
            id_token_hint="h",
            client=_logout_client(AFTER),
            post_logout_redirect_uri=request_args["next"],
        )


def test_end_session_url_post_logout_syntax_still_validated(lprov):
    with pytest.raises(BadRequestError):
        _logout_client(AFTER + "#frag")
    with pytest.raises(BadRequestError):
        _logout_client("relative/path")
    # Without post_logout_redirect_uri nothing changes.
    rp.end_session_url(lprov, client=_logout_client(AFTER), id_token_hint="h")


def test_end_session_url_rejects_reserved_extras_and_empty(lprov):
    for key in [
        "id_token_hint",
        "client_id",
        "post_logout_redirect_uri",
        "state",
        "logout_hint",
        "ui_locales",
    ]:
        with pytest.raises(BadRequestError, match="library-controlled"):
            rp.end_session_url(lprov, extra={key: "x"})
    with pytest.raises(BadRequestError):
        rp.end_session_url(lprov, state="")
    p = rp.ProviderInfo(
        ISSUER,
        f"{ISSUER}/a",
        f"{ISSUER}/token",
        end_session_endpoint=f"{ISSUER}/logout?state=x",
    )
    with pytest.raises(BadRequestError, match="library-controlled"):
        rp.end_session_url(p)


# --- verify_id_token options ----------------------------------------------------


def _half_hash(value: str, algo: str = "sha256") -> str:
    import base64
    import hashlib

    digest = hashlib.new(algo, value.encode()).digest()
    return base64.urlsafe_b64encode(digest[: len(digest) // 2]).rstrip(b"=").decode()


def _co(**extra):
    now = int(time.time())
    return {
        "iss": ISSUER,
        "sub": "alice",
        "aud": CLIENT_ID,
        "iat": now,
        "exp": now + 300,
        "nonce": "n",
        **extra,
    }


def _vo(op_key, claims, *args, **kw):
    token = jwt.sign(op_key, claims)
    return rp.verify_id_token(op_key.to_public_jwks(), token, ISSUER, CLIENT_ID, "n", ["ES256"], *args, **kw)


def test_verify_options_default_behaviour_unchanged(op_key):
    """at_hash / c_hash without values to check stay ignored, as before."""
    claims = _co(at_hash="x", c_hash="y", auth_time=1, acr="whatever")
    assert _vo(op_key, claims)["sub"] == "alice"


def test_verify_strict_hashes(op_key):
    at = "the-access-token"
    claims = _co(at_hash=_half_hash(at))
    with pytest.raises(AuthnError, match="at_hash"):
        _vo(op_key, claims, strict_hashes=True)
    assert _vo(op_key, claims, access_token=at, strict_hashes=True)["sub"] == "alice"
    with pytest.raises(AuthnError, match="c_hash"):
        _vo(op_key, _co(c_hash="x"), strict_hashes=True)
    # No values and no hash claims: nothing required, no BadRequestError.
    assert _vo(op_key, _co(), strict_hashes=True)["sub"] == "alice"
    # Default unchanged.
    assert _vo(op_key, claims)["sub"] == "alice"
    assert _vo(op_key, _co(), access_token=at)["sub"] == "alice"


def test_verify_strict_hashes_requires_claims_when_values_given(op_key):
    at, code = "the-access-token", "the-code"
    # Value passed, claim absent: required.
    with pytest.raises(AuthnError, match="missing at_hash"):
        _vo(op_key, _co(), access_token=at, strict_hashes=True)
    with pytest.raises(AuthnError, match="missing c_hash"):
        _vo(op_key, _co(), authorization_code=code, strict_hashes=True)
    # Only one claim present while both values are passed.
    with pytest.raises(AuthnError, match="missing c_hash"):
        _vo(
            op_key,
            _co(at_hash=_half_hash(at)),
            access_token=at,
            authorization_code=code,
            strict_hashes=True,
        )
    # Both valid.
    both = _co(at_hash=_half_hash(at), c_hash=_half_hash(code))
    assert _vo(op_key, both, access_token=at, authorization_code=code, strict_hashes=True)["sub"] == "alice"
    # Wrong value still mismatches.
    with pytest.raises(AuthnError, match="at_hash mismatch"):
        _vo(
            op_key,
            both,
            access_token="other",
            authorization_code=code,
            strict_hashes=True,
        )
    # Only access_token passed: c_hash claim is unverifiable, at_hash required.
    with pytest.raises(AuthnError, match="id_token carries c_hash but no value was supplied"):
        _vo(op_key, both, access_token=at, strict_hashes=True)
    only_at = _co(at_hash=_half_hash(at))
    assert _vo(op_key, only_at, access_token=at, strict_hashes=True)["sub"] == "alice"
    # Explicit require_* combos still work.
    assert _vo(op_key, only_at, access_token=at, require_at_hash=True, strict_hashes=True)["sub"] == "alice"
    with pytest.raises(AuthnError, match="missing at_hash"):
        _vo(op_key, _co(), access_token=at, require_at_hash=True, strict_hashes=True)
    with pytest.raises(BadRequestError, match="require_at_hash needs an access_token"):
        _vo(op_key, _co(), require_at_hash=True, strict_hashes=True)
    # strict_hashes off: absent claim still accepted.
    assert _vo(op_key, _co(), access_token=at, authorization_code=code)["sub"] == "alice"


def test_verify_leeway_makes_expired_token_pass(op_key):
    now = int(time.time())
    expired = _co(iat=now - 400, exp=now - 100)
    with pytest.raises(GrindvaktError):
        _vo(op_key, expired)  # default leeway is 60s
    with pytest.raises(GrindvaktError):
        _vo(op_key, expired, leeway=30)
    assert _vo(op_key, expired, leeway=200)["sub"] == "alice"


def test_verify_leeway_above_300_rejected(op_key):
    assert _vo(op_key, _co(), leeway=300)["sub"] == "alice"
    with pytest.raises(BadRequestError, match="leeway"):
        _vo(op_key, _co(), leeway=301)
    with pytest.raises(ValueError, match="negative"):
        _vo(op_key, _co(), leeway=-1)


def test_verify_max_age_uses_auth_time(op_key):
    now = int(time.time())
    assert _vo(op_key, _co(auth_time=now - 10), max_age=60)["sub"] == "alice"
    with pytest.raises(AuthnError, match="older than max_age"):
        _vo(op_key, _co(auth_time=now - 120), max_age=60)
    # iat is fresh but irrelevant: auth_time decides.
    with pytest.raises(AuthnError, match="older than max_age"):
        _vo(op_key, _co(iat=now, auth_time=now - 1000), max_age=60)
    # Float auth_time is accepted; future auth_time beyond leeway is not.
    assert _vo(op_key, _co(auth_time=float(now - 5)), max_age=60)["sub"] == "alice"
    with pytest.raises(AuthnError, match="future"):
        _vo(op_key, _co(auth_time=now + 3600), max_age=60)


def test_verify_max_age_requires_auth_time(op_key):
    with pytest.raises(AuthnError, match="auth_time"):
        _vo(op_key, _co(), max_age=60)
    with pytest.raises(AuthnError, match="auth_time"):
        _vo(op_key, _co(auth_time="soon"), max_age=60)
    with pytest.raises(ValueError, match="negative"):
        _vo(op_key, _co(auth_time=1), max_age=-5)


def test_verify_acr_allow_list(op_key):
    assert _vo(op_key, _co(acr="mfa"), acr_values=["pwd", "mfa"])["acr"] == "mfa"
    with pytest.raises(AuthnError, match="acr"):
        _vo(op_key, _co(acr="pwd"), acr_values=["mfa"])
    with pytest.raises(AuthnError, match="acr"):
        _vo(op_key, _co(), acr_values=["mfa"])
    with pytest.raises(BadRequestError, match="acr_values"):
        _vo(op_key, _co(acr="mfa"), acr_values=[])


def test_verify_at_hash(op_key):
    at = "the-access-token"
    claims = _co(at_hash=_half_hash(at))
    assert _vo(op_key, claims, access_token=at)["sub"] == "alice"
    with pytest.raises(AuthnError, match="at_hash mismatch"):
        _vo(op_key, claims, access_token="another-token")
    # Present but not checkable by default is still accepted (historic behaviour).
    assert _vo(op_key, claims)["sub"] == "alice"


def test_verify_require_at_hash(op_key):
    at = "the-access-token"
    with pytest.raises(AuthnError, match="missing at_hash"):
        _vo(op_key, _co(), access_token=at, require_at_hash=True)
    # Without the claim and without the requirement the token is not bound.
    assert _vo(op_key, _co(), access_token=at)["sub"] == "alice"
    assert _vo(op_key, _co(at_hash=_half_hash(at)), access_token=at, require_at_hash=True)["sub"] == "alice"


def test_verify_require_at_hash_without_access_token_is_bad_request(op_key):
    with pytest.raises(BadRequestError, match="require_at_hash"):
        _vo(op_key, _co(at_hash="x"), require_at_hash=True)
    with pytest.raises(BadRequestError, match="require_c_hash"):
        _vo(op_key, _co(c_hash="x"), require_c_hash=True)


def test_verify_c_hash(op_key):
    code = "the-auth-code"
    claims = _co(c_hash=_half_hash(code))
    assert _vo(op_key, claims, authorization_code=code)["sub"] == "alice"
    with pytest.raises(AuthnError, match="c_hash mismatch"):
        _vo(op_key, claims, authorization_code="other-code")
    with pytest.raises(AuthnError, match="missing c_hash"):
        _vo(op_key, _co(), authorization_code=code, require_c_hash=True)
    assert _vo(op_key, claims, authorization_code=code, require_c_hash=True)["sub"] == "alice"


def test_verify_hash_with_eddsa(op_key):
    """EdDSA has no OIDC hash function: a hash claim cannot be checked."""
    ed = keys.signing_key_from_jwk(keys.generate_ed25519_jwk(), alg="EdDSA", kid="ed-1")
    jwks = ed.to_public_jwks()

    def verify(claims, **kw):
        return rp.verify_id_token(jwks, jwt.sign(ed, claims), ISSUER, CLIENT_ID, "n", ["EdDSA"], **kw)

    # No hash claim in the token: access_token alone is harmless...
    assert verify(_co(), access_token="at")["sub"] == "alice"
    # ...but requiring it is impossible to satisfy.
    with pytest.raises(AuthnError, match="missing at_hash"):
        verify(_co(), access_token="at", require_at_hash=True)
    # A hash claim present with a supplied value cannot be checked.
    with pytest.raises(CryptoError, match="token-hash"):
        verify(_co(at_hash="x"), access_token="at")
    # strict_hashes + value: claim required, which EdDSA cannot provide.
    with pytest.raises(AuthnError, match="missing at_hash"):
        verify(_co(), access_token="at", strict_hashes=True)
    with pytest.raises(CryptoError, match="token-hash"):
        verify(_co(at_hash="x"), access_token="at", strict_hashes=True)
    # strict_hashes without values: unchanged.
    assert verify(_co(), strict_hashes=True)["sub"] == "alice"


def test_verify_trusted_additional_audience_keyword(op_key):
    multi = _co(aud=[CLIENT_ID, "https://api.example"], azp=CLIENT_ID)
    with pytest.raises(AuthnError, match="untrusted audience"):
        _vo(op_key, multi)
    assert _vo(op_key, multi, trusted_additional_audiences=["https://api.example"])["sub"] == "alice"
