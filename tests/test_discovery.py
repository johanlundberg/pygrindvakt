"""Tests for ``pygrindvakt.discovery`` (home-organization discovery and
OpenID Connect Core §4 Third-Party Initiated Login).

Ported from the unit tests in ``grindvakt/src/discovery.rs``.
"""

import time
from urllib.parse import parse_qsl, urlsplit

import pytest

import pygrindvakt
from pygrindvakt import discovery, jwt, keys
from pygrindvakt.errors import OAuthError  # noqa: F401  (ensures package import side effects)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


class FakeHttpClient:
    """An ``HttpClient`` serving one canned entity configuration for any GET.

    Records the URLs it was asked for so tests can assert on the
    ``.well-known/openid-federation`` path.
    """

    def __init__(self, body: str, status: int = 200):
        self.body = body
        self.status = status
        self.urls: list[str] = []

    def get(self, url: str):
        self.urls.append(url)
        return (self.status, self.body.encode(), "application/entity-statement+jwt")

    def post_form(self, url, form, headers):
        return (404, b"", None)


def rp_signing_key():
    """A fresh ES256 signing key with a kid, like the upstream test helper."""
    jwk = keys.generate_ec_jwk("P-256")
    jwk["alg"] = "ES256"
    return keys.signing_key_from_jwk(jwk, "ES256", "rp")


def rp_entity_configuration(entity_id: str, rp_metadata: dict, lifetime: int = 3600) -> str:
    """Build a self-signed entity configuration JWT for ``entity_id``.

    Prefers ``pygrindvakt.federation.build_entity_configuration`` when it is
    available; otherwise signs the equivalent claims directly with
    ``pygrindvakt.jwt.sign`` (typ ``entity-statement+jwt``), which is what
    the upstream builder does.
    """
    key = rp_signing_key()
    metadata = {"openid_relying_party": rp_metadata}
    build = getattr(pygrindvakt.federation, "build_entity_configuration", None)
    if build is not None:
        return build(key, entity_id, key.to_public_jwks(), [], metadata, [], lifetime)
    now = int(time.time())
    claims = {
        "iss": entity_id,
        "sub": entity_id,
        "iat": now,
        "exp": now + lifetime,
        "jwks": key.to_public_jwks(),
        "metadata": metadata,
    }
    return jwt.sign(key, claims, "entity-statement+jwt")


def query_of(url: str) -> dict:
    """The decoded query parameters of ``url`` as a dict."""
    return dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))


# ---------------------------------------------------------------------------
# validate_entity_id
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "entity_id",
    ["https://rp.example.com", "https://rp.example.com/oidc", "https://rp.example.com/"],
)
def test_validate_entity_id_accepts_https_urls(entity_id):
    """Plain https URLs with a host, with or without a path, are valid entity ids."""
    assert discovery.validate_entity_id(entity_id) is None


@pytest.mark.parametrize(
    "entity_id",
    [
        "http://rp.example.com",
        "https://rp.example.com/?x=1",
        "https://rp.example.com/#frag",
        "not a url",
        "javascript:alert(1)",
        "",
    ],
)
def test_validate_entity_id_rejects_non_https_query_fragment_and_garbage(entity_id):
    """http, query strings, fragments, garbage and non-URL schemes raise BadRequestError."""
    with pytest.raises(pygrindvakt.BadRequestError):
        discovery.validate_entity_id(entity_id)


def test_validate_entity_id_error_is_a_grindvakt_error():
    """BadRequestError is a GrindvaktError with a 400 status hint."""
    with pytest.raises(pygrindvakt.GrindvaktError) as ei:
        discovery.validate_entity_id("http://rp.example.com")
    assert ei.type.status_hint == 400
    assert "https" in str(ei.value)


# ---------------------------------------------------------------------------
# discovery_request_url
# ---------------------------------------------------------------------------


def test_discovery_request_url_encodes_params():
    """All three parameters are appended, percent-encoded, in the fixed order."""
    url = discovery.discovery_request_url(
        "https://discovery.example.com/discovery",
        "https://rp.example.com/oidc",
        "https://op.example.com",
        "https://app.example.com/deep?x=1&y=2",
    )
    assert url == (
        "https://discovery.example.com/discovery"
        "?entity_id=https%3A%2F%2Frp.example.com%2Foidc"
        "&hint=https%3A%2F%2Fop.example.com"
        "&target_link_uri=https%3A%2F%2Fapp.example.com%2Fdeep%3Fx%3D1%26y%3D2"
    )
    assert query_of(url) == {
        "entity_id": "https://rp.example.com/oidc",
        "hint": "https://op.example.com",
        "target_link_uri": "https://app.example.com/deep?x=1&y=2",
    }


def test_discovery_request_url_keyword_arguments():
    """op_hint and target_link_uri are optional keyword arguments."""
    url = discovery.discovery_request_url(
        "https://discovery.example.com/discovery",
        "https://rp.example.com",
        target_link_uri="https://app.example.com/",
    )
    assert query_of(url) == {
        "entity_id": "https://rp.example.com",
        "target_link_uri": "https://app.example.com/",
    }
    url = discovery.discovery_request_url(
        "https://discovery.example.com/discovery",
        "https://rp.example.com",
        op_hint="https://op.example.com",
    )
    assert query_of(url) == {
        "entity_id": "https://rp.example.com",
        "hint": "https://op.example.com",
    }


def test_discovery_request_url_joins_existing_query():
    """An endpoint that already has a query string gets ``&`` rather than ``?``."""
    url = discovery.discovery_request_url(
        "https://discovery.example.com/?ui=compact", "https://rp.example.com"
    )
    assert url == "https://discovery.example.com/?ui=compact&entity_id=https%3A%2F%2Frp.example.com"


def test_discovery_request_url_places_query_before_fragment():
    """A fragment on the endpoint stays after the appended query."""
    url = discovery.discovery_request_url(
        "https://discovery.example.com/discovery#chooser", "https://rp.example.com"
    )
    assert url == "https://discovery.example.com/discovery?entity_id=https%3A%2F%2Frp.example.com#chooser"


def test_discovery_request_url_rejects_invalid_endpoint():
    """A discovery endpoint that is not a URL raises BadRequestError."""
    with pytest.raises(pygrindvakt.BadRequestError):
        discovery.discovery_request_url("not a url", "https://rp.example.com")


def test_discovery_request_url_rejects_bad_ids():
    """Both the RP entity id and the OP hint are validated as entity ids."""
    with pytest.raises(pygrindvakt.BadRequestError):
        discovery.discovery_request_url("https://d.example", "http://rp.example")
    with pytest.raises(pygrindvakt.BadRequestError):
        discovery.discovery_request_url("https://d.example", "https://rp.example", "not a url")


# ---------------------------------------------------------------------------
# ThirdPartyInitiatedLogin / parse_third_party_initiated_login
# ---------------------------------------------------------------------------


def test_parse_third_party_initiated_login_required_and_optional_params():
    """iss is required; login_hint and target_link_uri are optional and passed through."""
    login = discovery.parse_third_party_initiated_login(
        {"iss": "https://op.example.com", "target_link_uri": "https://app.example.com/x"}
    )
    assert isinstance(login, discovery.ThirdPartyInitiatedLogin)
    assert login.iss == "https://op.example.com"
    assert login.login_hint is None
    assert login.target_link_uri == "https://app.example.com/x"

    login = discovery.parse_third_party_initiated_login(
        {"iss": "https://op.example.com", "login_hint": "alice@example.com"}
    )
    assert login.login_hint == "alice@example.com"
    assert login.target_link_uri is None


def test_parse_third_party_initiated_login_ignores_unknown_and_empty_params():
    """Unrelated parameters are ignored and empty optional values count as absent."""
    login = discovery.parse_third_party_initiated_login(
        {
            "iss": "https://op.example.com",
            "login_hint": "",
            "target_link_uri": "",
            "state": "whatever",
        }
    )
    assert login.login_hint is None
    assert login.target_link_uri is None


def test_parse_third_party_initiated_login_requires_iss():
    """A missing or empty iss raises BadRequestError."""
    with pytest.raises(pygrindvakt.BadRequestError):
        discovery.parse_third_party_initiated_login({})
    with pytest.raises(pygrindvakt.BadRequestError):
        discovery.parse_third_party_initiated_login({"iss": ""})
    with pytest.raises(pygrindvakt.BadRequestError):
        discovery.parse_third_party_initiated_login({"login_hint": "alice"})


def test_parse_third_party_initiated_login_requires_https_iss():
    """iss must be a valid https entity identifier."""
    with pytest.raises(pygrindvakt.BadRequestError):
        discovery.parse_third_party_initiated_login({"iss": "http://op.example.com"})
    with pytest.raises(pygrindvakt.BadRequestError):
        discovery.parse_third_party_initiated_login({"iss": "https://op.example.com/?x=1"})


def test_parse_third_party_initiated_login_rejects_non_string_values():
    """Parameters must be a str -> str mapping."""
    with pytest.raises(TypeError):
        discovery.parse_third_party_initiated_login({"iss": 1})
    with pytest.raises(TypeError):
        discovery.parse_third_party_initiated_login("iss=https://op.example.com")


def test_third_party_initiated_login_constructor_eq_hash_repr():
    """The class can be built directly, compares by value, hashes and has a repr."""
    a = discovery.ThirdPartyInitiatedLogin("https://op.example.com")
    b = discovery.parse_third_party_initiated_login({"iss": "https://op.example.com"})
    c = discovery.ThirdPartyInitiatedLogin(
        "https://op.example.com", login_hint="alice", target_link_uri="https://app.example.com/"
    )
    assert a == b
    assert hash(a) == hash(b)
    assert a != c
    assert a != "https://op.example.com"
    assert len({a, b, c}) == 2
    assert c.login_hint == "alice"
    assert c.target_link_uri == "https://app.example.com/"
    r = repr(c)
    assert r.startswith("ThirdPartyInitiatedLogin(")
    assert 'iss="https://op.example.com"' in r
    assert "alice" in r and "https://app.example.com/" in r
    assert "login_hint=None" in repr(a)


def test_third_party_initiated_login_is_frozen():
    """Attributes are read-only."""
    login = discovery.ThirdPartyInitiatedLogin("https://op.example.com")
    with pytest.raises(AttributeError):
        login.iss = "https://other.example.com"


# ---------------------------------------------------------------------------
# initiate_login_uri
# ---------------------------------------------------------------------------


def test_initiate_login_uri_extraction():
    """The RP's initiate_login_uri is read from metadata.openid_relying_party."""
    metadata = {
        "openid_relying_party": {
            "client_name": "Test RP",
            "initiate_login_uri": "https://rp.example.com/initiate",
        }
    }
    assert discovery.initiate_login_uri(metadata) == "https://rp.example.com/initiate"


@pytest.mark.parametrize(
    "metadata",
    [
        {"openid_relying_party": {}},
        {},
        {"openid_relying_party": {"initiate_login_uri": ""}},
        {"openid_relying_party": {"initiate_login_uri": "http://rp.example.com/initiate"}},
        {"openid_relying_party": {"initiate_login_uri": "https://rp.example.com/i#frag"}},
        {"openid_relying_party": {"initiate_login_uri": "not a url"}},
        {"openid_relying_party": {"initiate_login_uri": 42}},
        {"openid_relying_party": "https://rp.example.com/initiate"},
        {"openid_provider": {"initiate_login_uri": "https://rp.example.com/initiate"}},
    ],
)
def test_initiate_login_uri_rejects_missing_non_https_or_fragmented(metadata):
    """Missing, empty, non-string, non-https, or fragmented URIs raise AuthnError."""
    with pytest.raises(pygrindvakt.AuthnError):
        discovery.initiate_login_uri(metadata)


def test_initiate_login_uri_keeps_query():
    """A query string on the initiate_login_uri is allowed and preserved."""
    metadata = {"openid_relying_party": {"initiate_login_uri": "https://rp.example.com/i?v=2"}}
    assert discovery.initiate_login_uri(metadata) == "https://rp.example.com/i?v=2"


# ---------------------------------------------------------------------------
# third_party_login_url
# ---------------------------------------------------------------------------


def test_third_party_login_url_keeps_target_verbatim():
    """target_link_uri is appended percent-encoded and round-trips through parsing."""
    target = "https://app.example.com/deep?x=1&y=2"
    url = discovery.third_party_login_url(
        "https://rp.example.com/initiate", "https://op.example.com", target_link_uri=target
    )
    assert url == (
        "https://rp.example.com/initiate"
        "?iss=https%3A%2F%2Fop.example.com"
        "&target_link_uri=https%3A%2F%2Fapp.example.com%2Fdeep%3Fx%3D1%26y%3D2"
    )
    # Round-trip: the RP parsing the return call sees the exact value.
    login = discovery.parse_third_party_initiated_login(query_of(url))
    assert login.iss == "https://op.example.com"
    assert login.target_link_uri == target


def test_third_party_login_url_login_hint_and_existing_query():
    """login_hint is encoded and an existing query on the URI is joined with ``&``."""
    url = discovery.third_party_login_url(
        "https://rp.example.com/initiate?v=2",
        "https://op.example.com",
        "alice+bob@example.com",
        "https://app.example.com/",
    )
    assert url.startswith("https://rp.example.com/initiate?v=2&iss=")
    assert query_of(url) == {
        "v": "2",
        "iss": "https://op.example.com",
        "login_hint": "alice+bob@example.com",
        "target_link_uri": "https://app.example.com/",
    }
    login = discovery.parse_third_party_initiated_login(query_of(url))
    assert login.login_hint == "alice+bob@example.com"


def test_third_party_login_url_minimal():
    """Without optional parameters only iss is appended."""
    url = discovery.third_party_login_url("https://rp.example.com/initiate", "https://op.example.com")
    assert url == "https://rp.example.com/initiate?iss=https%3A%2F%2Fop.example.com"


# ---------------------------------------------------------------------------
# self_published_rp / self_published_initiate_login_uri
# ---------------------------------------------------------------------------


def test_self_published_initiate_login_uri_roundtrip():
    """A self-signed entity configuration served at .well-known yields the initiate_login_uri."""
    body = rp_entity_configuration(
        "https://rp.example.com", {"initiate_login_uri": "https://rp.example.com/initiate"}
    )
    http = FakeHttpClient(body)
    assert (
        discovery.self_published_initiate_login_uri(http, "https://rp.example.com")
        == "https://rp.example.com/initiate"
    )
    assert http.urls == ["https://rp.example.com/.well-known/openid-federation"]


def test_self_published_rp_exposes_metadata_and_exp():
    """The richer form exposes the full metadata dict and the statement's exp."""
    body = rp_entity_configuration(
        "https://rp.example.com", {"initiate_login_uri": "https://rp.example.com/initiate"}
    )
    rp = discovery.self_published_rp(FakeHttpClient(body), "https://rp.example.com")
    assert isinstance(rp, discovery.SelfPublishedRp)
    assert rp.metadata["openid_relying_party"]["initiate_login_uri"] == "https://rp.example.com/initiate"
    now = int(time.time())
    assert rp.exp is not None
    assert now < rp.exp <= now + 3600
    assert discovery.initiate_login_uri(rp.metadata) == "https://rp.example.com/initiate"
    r = repr(rp)
    assert r.startswith("SelfPublishedRp(")
    assert "openid_relying_party" in r
    assert str(rp.exp) in r


def test_self_published_rp_trailing_slash_entity_id():
    """A trailing slash on the entity id does not double the slash in the well-known URL."""
    body = rp_entity_configuration(
        "https://rp.example.com/", {"initiate_login_uri": "https://rp.example.com/initiate"}
    )
    http = FakeHttpClient(body)
    discovery.self_published_rp(http, "https://rp.example.com/")
    assert http.urls == ["https://rp.example.com/.well-known/openid-federation"]


def test_self_published_rp_must_be_issued_by_requested_entity():
    """A statement issued by a different entity than the one asked for is rejected."""
    body = rp_entity_configuration(
        "https://rp.example.com", {"initiate_login_uri": "https://rp.example.com/initiate"}
    )
    with pytest.raises(pygrindvakt.AuthnError):
        discovery.self_published_initiate_login_uri(FakeHttpClient(body), "https://other.example.com")
    with pytest.raises(pygrindvakt.AuthnError):
        discovery.self_published_rp(FakeHttpClient(body), "https://other.example.com")


def test_self_published_requires_initiate_login_uri():
    """A valid RP without an initiate_login_uri has metadata but no login URI."""
    body = rp_entity_configuration("https://rp.example.com", {})
    with pytest.raises(pygrindvakt.AuthnError):
        discovery.self_published_initiate_login_uri(FakeHttpClient(body), "https://rp.example.com")
    # The richer form still succeeds; it is the extraction that fails.
    rp = discovery.self_published_rp(FakeHttpClient(body), "https://rp.example.com")
    assert rp.metadata == {"openid_relying_party": {}}


def test_self_published_rp_validates_entity_id_before_fetching():
    """An invalid entity id raises BadRequestError without any HTTP request."""
    http = FakeHttpClient("unused")
    with pytest.raises(pygrindvakt.BadRequestError):
        discovery.self_published_rp(http, "http://rp.example.com")
    assert http.urls == []


def test_self_published_rp_rejects_bad_signature():
    """A statement whose signature does not verify against its own jwks is rejected."""
    body = rp_entity_configuration(
        "https://rp.example.com", {"initiate_login_uri": "https://rp.example.com/initiate"}
    )
    head, payload, sig = body.split(".")
    tampered = ".".join([head, payload, sig[:-4] + ("AAAA" if not sig.endswith("AAAA") else "BBBB")])
    with pytest.raises(pygrindvakt.GrindvaktError):
        discovery.self_published_rp(FakeHttpClient(tampered), "https://rp.example.com")


def test_self_published_rp_rejects_non_200():
    """A non-200 fetch is reported as an error."""
    with pytest.raises(pygrindvakt.GrindvaktError):
        discovery.self_published_rp(FakeHttpClient("", status=404), "https://rp.example.com")


def test_self_published_rp_rejects_object_without_http_protocol():
    """An http argument lacking get/post_form is rejected with TypeError."""
    with pytest.raises(TypeError):
        discovery.self_published_rp(object(), "https://rp.example.com")


# ---------------------------------------------------------------------------
# initiate_login_uri_from_resolved / promote_hint (need pygrindvakt.federation)
# ---------------------------------------------------------------------------


def _ops():
    """Three CollectionEntity values a, b, c (skips if federation is not built yet)."""
    federation = pytest.importorskip("pygrindvakt.federation")
    if not hasattr(federation, "CollectionEntity"):
        pytest.skip("pygrindvakt.federation.CollectionEntity is not available yet")

    def op(entity_id):
        return federation.CollectionEntity(entity_id=entity_id, display_name=entity_id)

    return [op("https://a.example"), op("https://b.example"), op("https://c.example")]


def test_promote_hint_no_match_keeps_order():
    """A hint naming no entity returns False and the unchanged list."""
    ops = _ops()
    found, out = discovery.promote_hint(ops, "https://nope.example")
    assert found is False
    assert [e.entity_id for e in out] == ["https://a.example", "https://b.example", "https://c.example"]


def test_promote_hint_moves_match_to_front():
    """A matching hint (trailing slash normalized) moves that entity to the front."""
    ops = _ops()
    found, out = discovery.promote_hint(ops, "https://c.example/")
    assert found is True
    assert [e.entity_id for e in out] == ["https://c.example", "https://a.example", "https://b.example"]
    assert len(out) == 3
    # The input list is not mutated.
    assert [e.entity_id for e in ops] == ["https://a.example", "https://b.example", "https://c.example"]


def test_promote_hint_already_first_still_matches():
    """An entity already at the front still counts as a hint match."""
    ops = _ops()
    found, out = discovery.promote_hint(ops, "https://a.example")
    assert found is True
    assert [e.entity_id for e in out] == ["https://a.example", "https://b.example", "https://c.example"]


def test_promote_hint_empty_list():
    """An empty list yields (False, [])."""
    _ops()
    assert discovery.promote_hint([], "https://a.example") == (False, [])


class RoutedHttpClient:
    """An ``HttpClient`` that serves canned bodies keyed by URL (query ignored)."""

    def __init__(self, routes: dict):
        self.routes = routes
        self.urls: list[str] = []

    def get(self, url: str):
        self.urls.append(url)
        base = url.split("?", 1)[0]
        if base in self.routes:
            return (200, self.routes[base].encode(), "application/jwt")
        return (404, b"not found", "text/plain")

    def post_form(self, url, form, headers):
        return (404, b"", None)


TA_ID = "https://ta.example"
RP_ID = "https://rp.example.com"


def resolved_rp_entity(rp_metadata: dict):
    """A ``ResolvedEntity`` for ``RP_ID`` obtained through a real (fake-HTTP) resolve.

    Builds a one-intermediate-free chain: the RP's self-signed entity
    configuration, the trust anchor's subordinate statement about the RP, and
    the trust anchor's own entity configuration; then a resolve response
    signed by the trust anchor that carries ``rp_metadata`` and that chain.
    """
    federation = pytest.importorskip("pygrindvakt.federation")
    if not hasattr(federation, "ResolvedEntity"):
        pytest.skip("pygrindvakt.federation.ResolvedEntity is not available yet")
    ta_key = keys.signing_key_from_jwk(keys.generate_ec_jwk("P-256"), alg="ES256", kid="ta")
    rp_key = rp_signing_key()
    now = int(time.time())
    metadata = {"openid_relying_party": rp_metadata}
    rp_ec = federation.build_entity_configuration(
        rp_key, RP_ID, rp_key.to_public_jwks(), [TA_ID], metadata, None, 3600
    )
    ta_ec = federation.build_entity_configuration(
        ta_key,
        TA_ID,
        ta_key.to_public_jwks(),
        [],
        {"federation_entity": {"federation_resolve_endpoint": f"{TA_ID}/resolve"}},
        None,
        3600,
    )
    subordinate = jwt.sign(
        ta_key,
        {"iss": TA_ID, "sub": RP_ID, "iat": now, "exp": now + 3600, "jwks": rp_key.to_public_jwks()},
        "entity-statement+jwt",
    )
    resolve_response = jwt.sign(
        ta_key,
        {
            "iss": TA_ID,
            "sub": RP_ID,
            "iat": now,
            "exp": now + 600,
            "metadata": metadata,
            "trust_chain": [rp_ec, subordinate, ta_ec],
        },
        "resolve-response+jwt",
    )
    http = RoutedHttpClient(
        {
            f"{TA_ID}/.well-known/openid-federation": ta_ec,
            f"{TA_ID}/resolve": resolve_response,
        }
    )
    return federation.resolve_via_trust_anchors(http, RP_ID, {TA_ID: ta_key.to_public_jwks()})


def test_initiate_login_uri_from_resolved():
    """initiate_login_uri_from_resolved reads the resolved entity's metadata."""
    entity = resolved_rp_entity({"initiate_login_uri": f"{RP_ID}/initiate"})
    assert entity.subject == RP_ID
    assert discovery.initiate_login_uri_from_resolved(entity) == f"{RP_ID}/initiate"
    assert discovery.initiate_login_uri(entity.metadata) == f"{RP_ID}/initiate"


def test_initiate_login_uri_from_resolved_rejects_missing_or_http():
    """A resolved RP without a valid https initiate_login_uri raises AuthnError."""
    with pytest.raises(pygrindvakt.AuthnError):
        discovery.initiate_login_uri_from_resolved(resolved_rp_entity({}))
    with pytest.raises(pygrindvakt.AuthnError):
        discovery.initiate_login_uri_from_resolved(
            resolved_rp_entity({"initiate_login_uri": "http://rp.example.com/initiate"})
        )


def test_initiate_login_uri_from_resolved_requires_resolved_entity():
    """A plain dict is not accepted in place of a ResolvedEntity."""
    with pytest.raises(TypeError):
        discovery.initiate_login_uri_from_resolved(
            {"metadata": {"openid_relying_party": {"initiate_login_uri": f"{RP_ID}/initiate"}}}
        )


def test_promote_hint_requires_collection_entities():
    """Items must be CollectionEntity instances."""
    _ops()
    with pytest.raises(TypeError):
        discovery.promote_hint(["https://a.example"], "https://a.example")


# ---------------------------------------------------------------------------
# module surface
# ---------------------------------------------------------------------------


def test_module_surface_and_docs():
    """Every public name is exposed under pygrindvakt.discovery with a docstring."""
    assert discovery.__name__ == "pygrindvakt.discovery"
    for name in [
        "validate_entity_id",
        "discovery_request_url",
        "ThirdPartyInitiatedLogin",
        "parse_third_party_initiated_login",
        "initiate_login_uri",
        "initiate_login_uri_from_resolved",
        "SelfPublishedRp",
        "self_published_rp",
        "self_published_initiate_login_uri",
        "third_party_login_url",
        "promote_hint",
    ]:
        obj = getattr(discovery, name)
        assert obj.__doc__, name
    assert discovery.ThirdPartyInitiatedLogin.__module__ == "pygrindvakt.discovery"
    assert discovery.SelfPublishedRp.__module__ == "pygrindvakt.discovery"
