"""Tests for ``pygrindvakt.testing`` - the shipped test helpers."""

from __future__ import annotations

import ast
import json
import subprocess
import sys
import threading
import time
import warnings
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from pygrindvakt import (
    AuthnError,
    CryptoError,
    OAuthError,
    client,
    jwt,
    keys,
    metadata,
    pkce,
    provider,
    request,
    rp,
    testing,
    tokens,
    util,
)
from pygrindvakt import http as gv_http
from pygrindvakt.testing import ProviderHttpClient, RecordedRequest, StaticHttpClient, mint_id_token

ISSUER = "https://op.example.com"
CLIENT_ID = "demo"
CLIENT_SECRET = "s3cret"
REDIRECT_URI = "https://rp.example.com/cb"
JWKS_URI = f"{ISSUER}/jwks"
DISCOVERY_URL = f"{ISSUER}/.well-known/openid-configuration"


def _headerless(record):
    """Recorded warnings that are the one-time 'reports no response headers' one."""
    return [w for w in record if "reports no response headers" in str(w.message)]


@pytest.fixture
def op_key():
    return keys.signing_key_from_jwk(keys.generate_ec_jwk("P-256"), alg="ES256", kid="op-1")


@pytest.fixture
def op(op_key):
    c = client.Client(CLIENT_ID, client_secret=CLIENT_SECRET, redirect_uris=[REDIRECT_URI])
    return provider.Provider(
        metadata.ProviderMetadata(ISSUER),
        op_key,
        client.InMemoryClientStore([c]),
        tokens.TokenCodec("op-secret"),
        token_use_store=provider.InMemoryTokenUseStore(),
    )


@pytest.fixture
def rpc():
    return rp.RpClient(CLIENT_ID, REDIRECT_URI, client_secret=CLIENT_SECRET)


# --- StaticHttpClient -------------------------------------------------------------


def test_static_routes_default_and_recording():
    c = StaticHttpClient({"https://a/x": (200, b"hi", "text/plain", (("X-Y", "1"),))})
    assert c.get("https://a/x") == (200, b"hi", "text/plain", [("x-y", "1")])
    assert c.get("https://a/missing") == (404, b"", "text/plain", [])
    assert c.post_form("https://a/x", [("k", "v")], [("Authorization", "Bearer t")])[0] == 200
    assert c.calls == [
        RecordedRequest("GET", "https://a/x", None, ()),
        RecordedRequest("GET", "https://a/missing", None, ()),
        RecordedRequest("POST", "https://a/x", (("k", "v"),), (("Authorization", "Bearer t"),)),
    ]
    assert c.calls[2].header("authorization") == "Bearer t"
    assert c.calls[0].header("authorization") is None


def test_static_custom_default():
    c = StaticHttpClient({}, default=(503, b"x", None, ()))
    assert c.get("https://a/")[:3] == (503, b"x", None)


def test_static_method_keys_win_over_url_keys():
    c = StaticHttpClient(
        {
            "https://a/x": (200, b"any", None, ()),
            ("POST", "https://a/x"): (201, b"post", None, ()),
        }
    )
    assert c.get("https://a/x")[1] == b"any"
    assert c.post_form("https://a/x", [], [])[1] == b"post"


def test_static_callable_route_sees_request():
    seen: list[RecordedRequest] = []

    def route(req: RecordedRequest):
        seen.append(req)
        return 200, req.url.encode(), None, ()

    c = StaticHttpClient({"https://a/x": route})
    assert c.get("https://a/x", [("Authorization", "Bearer t")])[1] == b"https://a/x"
    assert seen[0].header("AUTHORIZATION") == "Bearer t"


def test_static_from_json():
    c = StaticHttpClient.from_json({"https://a/x": {"k": [1]}})
    status, body, ctype, headers = c.get("https://a/x")
    assert (status, json.loads(body), ctype, headers) == (
        200,
        {"k": [1]},
        "application/json",
        [("cache-control", "max-age=300")],
    )


def test_static_redirect_is_returned_verbatim_not_followed():
    c = StaticHttpClient(
        {
            "https://a/start": (302, b"", None, (("Location", "https://a/final"),)),
            "https://a/final": (200, b"final", None, ()),
        }
    )
    status, body, _, headers = c.get("https://a/start")
    assert (status, body, headers) == (302, b"", [("location", "https://a/final")])
    assert [r.url for r in c.calls] == ["https://a/start"]
    status, _, _, _ = c.post_form("https://a/start", [], [])
    assert status == 302
    assert [r.url for r in c.calls] == ["https://a/start", "https://a/start"]


def test_static_supports_get_with_headers(op):
    assert gv_http.supports_get_with_headers(StaticHttpClient({})) is True
    assert gv_http.supports_get_with_headers(ProviderHttpClient(op, ISSUER)) is True


def test_static_get_with_headers_records_headers():
    c = StaticHttpClient({"https://a/x": (200, b"", None, ())})
    c.get_with_headers("https://a/x", [("Authorization", "Bearer t")])
    assert c.calls[0].headers == (("Authorization", "Bearer t"),)


def test_static_with_fetch_jwks_and_jwks_cache_no_warning(op_key):
    http = StaticHttpClient.from_json({JWKS_URI: op_key.to_public_jwks()})
    with warnings.catch_warnings(record=True) as rec:
        warnings.simplefilter("always")
        assert rp.fetch_jwks(http, JWKS_URI, ISSUER)["keys"][0]["kid"] == "op-1"
        cache = rp.JwksCache(http, JWKS_URI, ISSUER)
        token = mint_id_token(op_key, issuer=ISSUER, client_id=CLIENT_ID, nonce="n")
        claims = cache.verify_id_token(token, CLIENT_ID, "n", ["ES256"])
    assert claims["sub"] == "alice"
    assert [str(w.message) for w in rec] == []


def test_static_with_discovery_cache_no_warning(op):
    http = StaticHttpClient.from_json({DISCOVERY_URL: op.discovery_document(), JWKS_URI: op.jwks_document()})
    with warnings.catch_warnings(record=True) as rec:
        warnings.simplefilter("always")
        cache = rp.DiscoveryCache(http, ISSUER)
        assert cache.metadata().issuer == ISSUER
        assert cache.jwks() is not None
        cache.jwks().verify_id_token(
            mint_id_token(op.signing_key, issuer=ISSUER, client_id=CLIENT_ID, nonce="n"), CLIENT_ID, "n", ["ES256"]
        )
    assert _headerless(rec) == []


def _recorded(fn):
    with warnings.catch_warnings(record=True) as rec:
        warnings.simplefilter("always")
        fn()
    return rec


class _Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def test_provider_client_default_no_headerless_warning(op):
    http = ProviderHttpClient(op, ISSUER)
    rec = _recorded(
        lambda: (rp.JwksCache(http, JWKS_URI, ISSUER).jwks(), rp.DiscoveryCache(http, ISSUER).jwks().jwks())
    )
    assert _headerless(rec) == []
    assert http.get(JWKS_URI)[3] == [("cache-control", "max-age=300")]
    assert http.get(DISCOVERY_URL)[3] == [("cache-control", "max-age=300")]


def test_provider_client_cache_control_none_is_headerless_and_warns_once(op):
    http = ProviderHttpClient(op, ISSUER, cache_control=None)
    assert http.get(JWKS_URI)[3] == [] and http.get(DISCOVERY_URL)[3] == []
    jwks_cache = rp.JwksCache(http, JWKS_URI, ISSUER)
    assert len(_headerless(_recorded(jwks_cache.jwks))) == 1
    disc = rp.DiscoveryCache(http, ISSUER)
    assert len(_headerless(_recorded(disc.metadata))) == 1


def test_provider_client_custom_cache_control(op):
    http = ProviderHttpClient(op, ISSUER, cache_control="no-store")
    assert http.get(JWKS_URI)[3] == [("cache-control", "no-store")]


def test_static_from_json_default_no_headerless_warning(op):
    http = StaticHttpClient.from_json({DISCOVERY_URL: op.discovery_document(), JWKS_URI: op.jwks_document()})
    rec = _recorded(lambda: (rp.JwksCache(http, JWKS_URI, ISSUER).jwks(), rp.DiscoveryCache(http, ISSUER).metadata()))
    assert _headerless(rec) == []


def test_static_from_json_cache_control_none_and_legacy_three_tuple_warn_once(op):
    docs = {DISCOVERY_URL: op.discovery_document(), JWKS_URI: op.jwks_document()}
    none = StaticHttpClient.from_json(docs, cache_control=None)
    assert len(_headerless(_recorded(rp.JwksCache(none, JWKS_URI, ISSUER).jwks))) == 1
    assert len(_headerless(_recorded(rp.DiscoveryCache(none, ISSUER).metadata))) == 1
    legacy = StaticHttpClient({JWKS_URI: (200, json.dumps(op.jwks_document()).encode(), "application/json")})
    assert len(_headerless(_recorded(rp.JwksCache(legacy, JWKS_URI, ISSUER).jwks))) == 1
    with_empty = StaticHttpClient({JWKS_URI: (200, json.dumps(op.jwks_document()).encode(), "application/json", ())})
    assert len(_headerless(_recorded(rp.JwksCache(with_empty, JWKS_URI, ISSUER).jwks))) == 1
    four = StaticHttpClient(
        {
            JWKS_URI: (
                200,
                json.dumps(op.jwks_document()).encode(),
                "application/json",
                (("Cache-Control", "max-age=60"),),
            )
        }
    )
    assert _headerless(_recorded(rp.JwksCache(four, JWKS_URI, ISSUER).jwks)) == []


def test_from_json_cache_control_value_is_served():
    http = StaticHttpClient.from_json({"https://a/x": {}}, cache_control="max-age=5")
    assert http.get("https://a/x")[3] == [("cache-control", "max-age=5")]


def test_provider_client_cache_control_drives_discovery_ttl(op):
    clock = _Clock()
    http = ProviderHttpClient(op, ISSUER, cache_control="max-age=300")
    cache = rp.DiscoveryCache(http, ISSUER, min_ttl=1, _now=clock)
    cache.metadata()
    n = len(http.calls)
    clock.t += 299
    cache.metadata()
    assert len(http.calls) == n
    clock.t += 2
    cache.metadata()
    assert len(http.calls) == n + 1


def test_provider_client_cache_control_drives_jwks_ttl(op):
    clock = _Clock()
    http = ProviderHttpClient(op, ISSUER, cache_control="max-age=300")
    cache = rp.JwksCache(http, JWKS_URI, ISSUER, min_ttl=1, _now=clock)
    cache.jwks()
    clock.t += 299
    cache.jwks()
    assert len(http.calls) == 1
    clock.t += 2
    cache.jwks()
    assert len(http.calls) == 2


def test_static_userinfo_over_get_with_headers():
    def route(req: RecordedRequest):
        assert req.header("authorization") == "Bearer tok"
        return 200, json.dumps({"sub": "alice"}).encode(), "application/json", ()

    c = StaticHttpClient({"https://op.example.com/userinfo": route})
    got = rp.fetch_userinfo(c, "https://op.example.com/userinfo", "tok", "alice", ISSUER, method="GET")
    assert got["sub"] == "alice"


def test_static_accepts_legacy_three_tuple_and_four_tuple():
    c = StaticHttpClient(
        {
            "https://a/3": (200, b"x", "text/plain"),
            "https://a/4": (200, b"y", None, [("K", "V")]),
            "https://a/f": lambda req: (201, b"z", None),
        },
        default=(500, b"", None),
    )
    assert c.get("https://a/3") == (200, b"x", "text/plain", [])
    assert c.get("https://a/4") == (200, b"y", None, [("k", "V")])
    assert c.get("https://a/f") == (201, b"z", None, [])
    assert c.get("https://a/none") == (500, b"", None, [])


@pytest.mark.parametrize(
    "bad",
    [
        (200, b"x"),
        (200, b"x", None, (), "extra"),
        "200",
        [200, b"x", None],
        None,
        ("200", b"x", None),
        (True, b"x", None),
        (200, "text", None),
        (200, b"x", 5),
        (200, b"x", None, "hdrs"),
        (200, b"x", None, [("a",)]),
        (200, b"x", None, [("a", 1)]),
    ],
)
def test_static_bad_route_shape_is_a_type_error_naming_key_and_request(bad):
    with pytest.raises(TypeError, match=r"https://a/x"):
        StaticHttpClient({"https://a/x": bad})
    with pytest.raises(TypeError, match=r"POST.*https://a/x"):
        StaticHttpClient({"https://a/x": lambda req: bad}).post_form("https://a/x", [], [])
    with pytest.raises(TypeError, match="default"):
        StaticHttpClient({}, default=bad)
    with pytest.raises(TypeError, match=r"\(\"GET\", \"https://a/x\"\)|'GET', 'https://a/x'"):
        StaticHttpClient({("GET", "https://a/x"): bad})


@pytest.mark.parametrize("key", [5, None, ("GET",), ("GET", "u", "x"), (1, "u"), b"https://a"])
def test_static_bad_route_key_is_a_type_error(key):
    with pytest.raises(TypeError, match="route key"):
        StaticHttpClient({key: (200, b"", None, ())})


def test_static_accepts_annotated_dicts_of_either_key_type():
    ok: testing.FetchResult = (200, b"", None, ())
    by_url: dict[str, testing.FetchResult] = {"https://a/x": ok}
    by_pair: dict[tuple[str, str], testing.FetchResult] = {("GET", "https://a/y"): ok}
    mixed: dict[str | tuple[str, str], testing.FetchResult] = {"https://a/x": ok, ("POST", "https://a/y"): ok}
    assert StaticHttpClient(by_url).get("https://a/x")[0] == 200
    assert StaticHttpClient(by_pair).get("https://a/y")[0] == 200
    assert StaticHttpClient(mixed).post_form("https://a/y", [], [])[0] == 200


# --- ProviderHttpClient -----------------------------------------------------------


def authorize(op, prov, rpc, nonce, verifier):
    url = rp.authorization_url(prov, rpc, "st", nonce, pkce.s256_challenge(verifier))
    req = request.AuthorizationRequest.from_params([(k, v[0]) for k, v in parse_qs(urlsplit(url).query).items()])
    op.validate_authorization_request(req)
    resp = op.authorization_redirect(req, "alice", {"email": ["a@b"]})
    return resp.header("location")


def test_provider_client_full_flow(op, rpc):
    http = ProviderHttpClient(op, ISSUER)
    with warnings.catch_warnings(record=True) as rec:
        warnings.simplefilter("always")
        prov = rp.ProviderInfo.from_metadata(rp.discover(http, ISSUER))
        verifier = util.random_token(48)
        location = authorize(op, prov, rpc, "n1", verifier)
        resp = rp.parse_authorization_response(parse_qs(urlsplit(location).query))
        assert resp.matches_state("st")
        assert resp.code is not None
        ts = rp.exchange_code(http, prov, rpc, resp.code, verifier)
        cache = rp.JwksCache(http, prov.jwks_uri, ISSUER)
        claims = cache.verify_id_token(
            ts.id_token, CLIENT_ID, "n1", ["ES256"], access_token=ts.access_token, require_at_hash=True
        )
        assert claims["sub"] == "alice"
        post = rp.fetch_userinfo(http, prov.userinfo_endpoint, ts.access_token, "alice", ISSUER)
        get = rp.fetch_userinfo(http, prov.userinfo_endpoint, ts.access_token, "alice", ISSUER, method="GET")
    assert post["sub"] == get["sub"] == "alice"
    assert [str(w.message) for w in rec] == []
    methods = [(r.method, r.url) for r in http.calls]
    assert methods[0] == ("GET", DISCOVERY_URL)
    assert ("POST", f"{ISSUER}/token") in methods
    assert ("GET", JWKS_URI) in methods
    assert ("code", resp.code) in http.forms[0]
    assert http.calls[-1].header("authorization") == f"Bearer {ts.access_token}"


def test_provider_client_oauth_error_is_mapped(op, rpc):
    http = ProviderHttpClient(op, ISSUER)
    prov = rp.ProviderInfo.from_metadata(rp.discover(http, ISSUER))
    status, body, _, _ = http.post_form(
        prov.token_endpoint, [("grant_type", "authorization_code"), ("code", "bogus")], []
    )
    assert status in (400, 401)
    assert json.loads(body)["error"] in {"invalid_client", "invalid_grant", "invalid_request"}
    with pytest.raises(AuthnError):
        rp.exchange_code(http, prov, rpc, "bogus", util.random_token(48))
    status, _, _, _ = http.get(f"{ISSUER}/userinfo", [("Authorization", "Bearer nope")])
    assert status in (400, 401, 403)
    assert http.get(f"{ISSUER}/userinfo")[0] == 401


def test_provider_client_forwards_oauth_error_headers(op):
    http = ProviderHttpClient(op, ISSUER)
    resp = OAuthError("invalid_client", "bad").to_response()
    status, body, ctype, headers = http.post_form(
        f"{ISSUER}/token",
        [("grant_type", "authorization_code"), ("code", "c"), ("client_id", CLIENT_ID), ("client_secret", "wrong")],
        [],
    )
    assert status == 401
    got = dict(headers)
    expected = {k.lower(): v for k, v in resp.headers}
    assert expected, "to_response() carries headers"
    assert {k: got[k] for k in expected} == expected
    assert "cache-control" in got and "www-authenticate" in got
    assert ctype == "application/json" and json.loads(body)["error"] == "invalid_client"
    assert all(k == k.lower() for k, _ in headers)
    # Same bridge on the UserInfo path.
    status, _, _, headers = http.get(f"{ISSUER}/userinfo", [("Authorization", "Bearer nope")])
    assert status in (400, 401, 403) and ("cache-control", "no-store") in headers


# NOTE: a DPoP "use_dpop_nonce" challenge is not covered: the in-process
# Provider cannot cheaply be made to produce a dpop-nonce header, and
# OAuthError carries no custom headers. Forwarding is generic (all
# to_response() headers), as the test above shows.


@pytest.mark.parametrize("auth", ["bearer {t}", "BEARER {t}", "BeArEr {t}"])
def test_provider_client_userinfo_bearer_scheme_is_case_insensitive(op, rpc, auth):
    http = ProviderHttpClient(op, ISSUER)
    token = op_access_token(op, http, rpc)
    for send in (
        lambda h: http.get(f"{ISSUER}/userinfo", h),
        lambda h: http.post_form(f"{ISSUER}/userinfo", [], h),
    ):
        status, body, _, _ = send([("Authorization", auth.format(t=token))])
        assert status == 200 and json.loads(body)["sub"] == "alice"


@pytest.mark.parametrize("auth", [None, "", "Bearer", "Bearer ", "bearer   ", "Basic abc", "Bearertok"])
def test_provider_client_userinfo_missing_or_blank_token_is_401(op, auth):
    http = ProviderHttpClient(op, ISSUER)
    hdrs = [] if auth is None else [("Authorization", auth)]
    assert http.get(f"{ISSUER}/userinfo", hdrs)[0] == 401
    assert http.post_form(f"{ISSUER}/userinfo", [], hdrs)[0] == 401


def test_provider_client_token_success_has_no_store_headers(op, rpc):
    seen: list[tuple[str, tuple[tuple[str, str], ...]]] = []

    class Spy(ProviderHttpClient):
        def _answer(self, request):
            resp = super()._answer(request)
            seen.append((request.url, tuple(resp[3])))
            return resp

    http = Spy(op, ISSUER)
    op_access_token(op, http, rpc)
    (headers,) = [h for url, h in seen if url == f"{ISSUER}/token"]
    assert ("cache-control", "no-store") in headers and ("pragma", "no-cache") in headers


def _userinfo_posts(op, rpc):
    http = ProviderHttpClient(op, ISSUER)
    return http, op_access_token(op, http, rpc)


def test_provider_client_userinfo_form_access_token(op, rpc):
    http, token = _userinfo_posts(op, rpc)
    status, body, _, _ = http.post_form(f"{ISSUER}/userinfo", [("access_token", token)], [])
    assert status == 200 and json.loads(body)["sub"] == "alice"


def test_provider_client_userinfo_header_present_never_falls_back_to_form(op, rpc):
    http, token = _userinfo_posts(op, rpc)
    # A whitespace-only Authorization header is present: with a form token it is
    # the 400 invalid_request conflict, never a silent fall back to the form.
    status, _, _, _ = http.post_form(f"{ISSUER}/userinfo", [("access_token", token)], [("Authorization", " ")])
    assert status == 400
    # Header alone still works (precedence over absent form).
    status, _, _, _ = http.post_form(f"{ISSUER}/userinfo", [], [("Authorization", f"Bearer {token}")])
    assert status == 200


def test_provider_client_userinfo_both_methods_is_400_invalid_request(op, rpc):
    http, token = _userinfo_posts(op, rpc)
    status, body, ctype, headers = http.post_form(
        f"{ISSUER}/userinfo", [("access_token", token)], [("Authorization", f"Bearer {token}")]
    )
    assert status == 400 and ctype == "application/json"
    assert json.loads(body) == {"error": "invalid_request"}
    assert ("www-authenticate", 'Bearer error="invalid_request"') in headers
    # Even when the header is a different scheme.
    assert http.post_form(f"{ISSUER}/userinfo", [("access_token", token)], [("Authorization", "Basic abc")])[0] == 400
    # Repeated form parameter.
    assert http.post_form(f"{ISSUER}/userinfo", [("access_token", token), ("access_token", token)], [])[0] == 400


def test_provider_client_userinfo_bad_and_blank_form_token(op):
    http = ProviderHttpClient(op, ISSUER)
    assert http.post_form(f"{ISSUER}/userinfo", [("access_token", "nope")], [])[0] in (400, 401, 403)
    status, _, _, headers = http.post_form(f"{ISSUER}/userinfo", [("access_token", "")], [])
    assert status == 401 and ("www-authenticate", "Bearer") in headers


@pytest.mark.parametrize(
    "pad", ["Bearer  {t}", "Bearer {t} ", " Bearer {t}", "Bearer {t}\t", "Bearer  {t} ", " ", "   "]
)
def test_provider_client_userinfo_padded_or_blank_header_is_401(op, rpc, pad):
    http = ProviderHttpClient(op, ISSUER)
    token = op_access_token(op, http, rpc)
    hdrs = [("Authorization", pad.format(t=token))]
    for resp in (http.get(f"{ISSUER}/userinfo", hdrs), http.post_form(f"{ISSUER}/userinfo", [], hdrs)):
        assert resp[0] == 401 and ("www-authenticate", "Bearer") in resp[3]
    # Present-but-invalid header does not fall back to a valid form token.
    assert http.post_form(f"{ISSUER}/userinfo", [("access_token", token)], hdrs)[0] == 400


@pytest.mark.parametrize("auth", [None, "", "Bearer", "Bearer ", "bearer   ", "Basic abc", "Bearertok"])
def test_provider_client_userinfo_401_carries_www_authenticate_bearer(op, auth):
    http = ProviderHttpClient(op, ISSUER)
    hdrs = [] if auth is None else [("Authorization", auth)]
    for resp in (http.get(f"{ISSUER}/userinfo", hdrs), http.post_form(f"{ISSUER}/userinfo", [], hdrs)):
        assert resp[0] == 401 and ("www-authenticate", "Bearer") in resp[3]


@pytest.mark.parametrize("name", ["DPoP", "dpop", "DPOP"])
@pytest.mark.parametrize("which", ["token", "userinfo-post", "userinfo-get"])
def test_provider_client_dpop_header_raises_not_implemented(op, name, which):
    http = ProviderHttpClient(op, ISSUER)
    with pytest.raises(NotImplementedError, match="does not support DPoP"):
        if which == "token":
            http.post_form(f"{ISSUER}/token", [("grant_type", "authorization_code")], [(name, "proof")])
        elif which == "userinfo-post":
            http.post_form(f"{ISSUER}/userinfo", [], [(name, "proof"), ("Authorization", "Bearer t")])
        else:
            http.get(f"{ISSUER}/userinfo", [(name, "proof"), ("Authorization", "Bearer t")])


@pytest.mark.parametrize("auth", ["DPoP tok", "dpop tok", "DPOP tok"])
def test_provider_client_authorization_dpop_scheme_raises_not_implemented(op, auth):
    http = ProviderHttpClient(op, ISSUER)
    with pytest.raises(NotImplementedError, match="does not support DPoP"):
        http.get(f"{ISSUER}/userinfo", [("Authorization", auth)])
    with pytest.raises(NotImplementedError, match="does not support DPoP"):
        http.post_form(f"{ISSUER}/userinfo", [], [("Authorization", auth)])
    with pytest.raises(NotImplementedError, match="does not support DPoP"):
        http.post_form(f"{ISSUER}/token", [], [("Authorization", auth)])


def test_provider_client_dpop_header_on_discovery_is_ignored(op):
    assert ProviderHttpClient(op, ISSUER).get(DISCOVERY_URL, [("DPoP", "x")])[0] == 200


def test_static_method_key_is_case_normalised():
    ok = (200, b"x", "text/plain", (("cache-control", "max-age=1"),))
    http = StaticHttpClient({("post", "https://a/x"): ok, ("Get", "https://a/y"): ok})
    assert http.post_form("https://a/x", [], [])[0] == 200
    assert http.get("https://a/x")[0] == 404
    assert http.get("https://a/y")[0] == 200
    assert http.post_form("https://a/y", [], [])[0] == 404


def test_static_empty_method_and_duplicate_normalised_keys_are_type_errors():
    ok = (200, b"x", "text/plain", ())
    with pytest.raises(TypeError, match="empty"):
        StaticHttpClient({("", "https://a/x"): ok})
    with pytest.raises(TypeError, match="duplicate"):
        StaticHttpClient({("get", "https://a/x"): ok, ("GET", "https://a/x"): ok})


def op_access_token(op, http, rpc):
    prov = rp.ProviderInfo.from_metadata(rp.discover(http, ISSUER))
    verifier = util.random_token(48)
    location = authorize(op, prov, rpc, "n1", verifier)
    code = rp.parse_authorization_response(parse_qs(urlsplit(location).query)).code
    assert code is not None
    return rp.exchange_code(http, prov, rpc, code, verifier).access_token


def test_provider_client_subclass_hooks_answer_and_keeps_plumbing(op):
    class Tweaked(ProviderHttpClient):
        def _answer(self, request):
            if request.url == JWKS_URI:
                return 200, b'{"keys": []}', "application/json", ()
            return super()._answer(request)

    http = Tweaked(op, ISSUER)
    assert http.get_with_headers(JWKS_URI, [("X", "1")])[1] == b'{"keys": []}'
    assert http.get(DISCOVERY_URL)[0] == 200
    assert [r.url for r in http.calls] == [JWKS_URI, DISCOVERY_URL]
    assert gv_http.supports_get_with_headers(http) is True


def test_provider_client_forms_property(op):
    http = ProviderHttpClient(op, ISSUER)
    http.get(JWKS_URI)
    http.post_form(f"{ISSUER}/nope", [("a", "1")], [])
    assert http.forms == [[("a", "1")]]


def test_provider_client_unknown_url_and_custom_paths(op):
    http = ProviderHttpClient(op, ISSUER + "/", jwks_path="/keys")
    assert http.get(f"{ISSUER}/nope")[0] == 404
    assert http.post_form(f"{ISSUER}/nope", [], [])[0] == 404
    assert http.get(f"{ISSUER}/jwks")[0] == 404
    assert http.get(f"{ISSUER}/keys")[0] == 200


# --- mint_id_token ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("make", "alg"),
    [
        (lambda: keys.generate_ec_jwk("P-256"), "ES256"),
        (lambda: keys.generate_rsa_jwk(2048), "RS256"),
    ],
)
def test_mint_round_trip_with_hashes(make, alg):
    key = keys.signing_key_from_jwk(make(), alg=alg, kid="k1")
    token = mint_id_token(
        key,
        issuer=ISSUER,
        client_id=CLIENT_ID,
        nonce="nn",
        access_token="at-123",
        code="code-123",
        extra={"acr": "urn:x", "email": "a@b"},
    )
    claims = rp.verify_id_token(
        key.to_public_jwks(),
        token,
        ISSUER,
        CLIENT_ID,
        "nn",
        [alg],
        access_token="at-123",
        require_at_hash=True,
        authorization_code="code-123",
        require_c_hash=True,
        strict_hashes=True,
    )
    assert claims["at_hash"] == jwt.oidc_token_hash(alg, "at-123")
    assert claims["c_hash"] == jwt.oidc_token_hash(alg, "code-123")
    assert claims["aud"] == CLIENT_ID
    assert claims["exp"] - claims["iat"] == 300
    assert (claims["acr"], claims["email"], claims["nonce"]) == ("urn:x", "a@b", "nn")


def test_mint_minimal_claims_and_options(op_key):
    now = int(time.time()) - 5
    token = mint_id_token(op_key, issuer=ISSUER, client_id=CLIENT_ID, sub="bob", lifetime=60, iat=now)
    validation = jwt.Validation().with_issuer(ISSUER).with_audience(CLIENT_ID).with_allowed_algorithms(["ES256"])
    claims = jwt.verify_with_jwks(op_key.to_public_jwks(), token, validation)
    assert claims == {"iss": ISSUER, "sub": "bob", "aud": CLIENT_ID, "iat": now, "exp": now + 60}


@pytest.mark.parametrize("claim", ["iss", "sub", "aud", "exp", "iat", "nonce", "at_hash", "c_hash"])
def test_mint_refuses_protocol_claim_override(op_key, claim):
    with pytest.raises(ValueError, match=claim):
        mint_id_token(op_key, issuer=ISSUER, client_id=CLIENT_ID, extra={claim: "x"})


@pytest.mark.parametrize("lifetime", [0, -1, True, 1.5, "60", None])
def test_mint_rejects_bad_lifetime(op_key, lifetime):
    with pytest.raises(ValueError, match="lifetime"):
        mint_id_token(op_key, issuer=ISSUER, client_id=CLIENT_ID, lifetime=lifetime)  # type: ignore[arg-type]


@pytest.mark.parametrize("iat", [True, False, -1, 1.5, "1"])
def test_mint_rejects_bad_iat(op_key, iat):
    with pytest.raises(ValueError, match="iat"):
        mint_id_token(op_key, issuer=ISSUER, client_id=CLIENT_ID, iat=iat)  # type: ignore[arg-type]


def test_mint_accepts_iat_zero(op_key):
    assert mint_id_token(op_key, issuer=ISSUER, client_id=CLIENT_ID, iat=0, lifetime=1)


def test_mint_collision_check_runs_before_hashing():
    key = keys.signing_key_from_jwk(keys.generate_ed25519_jwk(), alg="EdDSA", kid="ed")
    with pytest.raises(ValueError, match="nonce"):
        mint_id_token(key, issuer=ISSUER, client_id=CLIENT_ID, access_token="at", extra={"nonce": "x"})
    with pytest.raises(ValueError, match="c_hash"):
        mint_id_token(key, issuer=ISSUER, client_id=CLIENT_ID, code="c", extra={"c_hash": "x"})


def test_mint_extra_allows_azp_auth_time_jti_acr_amr(op_key):
    extra = {"azp": "demo", "auth_time": 123, "jti": "j-1", "acr": "urn:x", "amr": ["pwd"]}
    token = mint_id_token(op_key, issuer=ISSUER, client_id=CLIENT_ID, nonce="n", extra=extra)
    claims = rp.verify_id_token(op_key.to_public_jwks(), token, ISSUER, CLIENT_ID, "n", ["ES256"])
    assert {k: claims[k] for k in extra} == extra


def test_mint_eddsa_with_hash_raises_crypto_error():
    key = keys.signing_key_from_jwk(keys.generate_ed25519_jwk(), alg="EdDSA", kid="ed")
    with pytest.raises(CryptoError):
        mint_id_token(key, issuer=ISSUER, client_id=CLIENT_ID, access_token="at")
    with pytest.raises(CryptoError):
        mint_id_token(key, issuer=ISSUER, client_id=CLIENT_ID, code="c")
    assert mint_id_token(key, issuer=ISSUER, client_id=CLIENT_ID)


# --- packaging / isolation --------------------------------------------------------


def test_import_pygrindvakt_does_not_import_testing():
    code = "import sys, pygrindvakt; print('pygrindvakt.testing' in sys.modules)"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "False"


def test_testing_has_no_third_party_imports():
    tree = ast.parse(Path(testing.__file__).read_text())
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    assert roots <= set(sys.stdlib_module_names) | {"__future__"}, roots


def test_public_names():
    assert set(testing.__all__) == {
        "FetchResult",
        "ProviderHttpClient",
        "RecordedRequest",
        "StaticHttpClient",
        "mint_id_token",
    }


# --- re-entrancy / threading ------------------------------------------------------
# tests/test_adapters.py already covers a re-entrant in-process HttpClient
# (test_reentrant_http_client_drives_in_process_provider) and a re-entrant
# store adapter; neither drives the client from a worker thread or calls
# rp.* again from inside the client's own get(). This does both.


class ReentrantProviderClient(ProviderHttpClient):
    """On the first JWKS GET, re-enters pygrindvakt (a nested ``rp.fetch_jwks``
    through the same client) from inside the native HTTP callback."""

    nested: dict | None = None
    _inside = False

    def _answer(self, request):
        if request.url == JWKS_URI and not self._inside:
            self._inside = True
            try:
                self.nested = rp.fetch_jwks(self, JWKS_URI, ISSUER)
            finally:
                self._inside = False
        return super()._answer(request)


@pytest.mark.filterwarnings("ignore:this HttpClient reports no response headers")
def test_provider_client_flow_from_worker_thread_with_reentrant_callback(op, rpc):
    http = ReentrantProviderClient(op, ISSUER)
    out: dict = {}

    def work():
        try:
            prov = rp.ProviderInfo.from_metadata(rp.discover(http, ISSUER))
            verifier = util.random_token(48)
            location = authorize(op, prov, rpc, "n1", verifier)
            code = rp.parse_authorization_response(parse_qs(urlsplit(location).query)).code
            ts = rp.exchange_code(http, prov, rpc, code, verifier)
            cache = rp.JwksCache(http, prov.jwks_uri, ISSUER)
            out["claims"] = cache.verify_id_token(ts.id_token, CLIENT_ID, "n1", ["ES256"])
            out["jwks"] = rp.fetch_jwks(http, JWKS_URI, ISSUER)
        except BaseException as e:  # noqa: BLE001 - surfaced in the main thread
            out["error"] = e

    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(30)
    assert not t.is_alive(), "deadlock: flow did not finish within 30s"
    assert "error" not in out, out.get("error")
    assert out["claims"]["sub"] == "alice"
    assert out["jwks"]["keys"][0]["kid"] == "op-1"
    assert http.nested is not None and http.nested["keys"][0]["kid"] == "op-1"


_SECRETS = ("sek-bearer", "sek-cs", "sek-code", "sek-ver", "sek-at", "sek-cookie")


def _sensitive_request() -> RecordedRequest:
    return RecordedRequest(
        "POST",
        "https://op.example.com/token",
        (
            ("grant_type", "authorization_code"),
            ("client_secret", "sek-cs"),
            ("code", "sek-code"),
            ("code_verifier", "sek-ver"),
            ("access_token", "sek-at"),
            ("redirect_uri", REDIRECT_URI),
        ),
        (("Authorization", "Bearer sek-bearer"), ("cookie", "sek-cookie"), ("Accept", "application/json")),
    )


def test_recorded_request_repr_redacts_credentials_keeps_names_and_plain_values():
    r = repr(_sensitive_request())
    for secret in _SECRETS:
        assert secret not in r
    for shown in ("client_secret", "code_verifier", "Authorization", "cookie", "<redacted>"):
        assert shown in r
    for plain in ("authorization_code", REDIRECT_URI, "application/json", "https://op.example.com/token", "POST"):
        assert plain in r


def test_recorded_request_attributes_and_equality_are_unredacted():
    req = _sensitive_request()
    assert req.header("authorization") == "Bearer sek-bearer"
    assert ("client_secret", "sek-cs") in (req.form or ())
    assert req == _sensitive_request()
    assert req != req.redacted()


def test_recorded_request_redaction_is_case_insensitive():
    req = RecordedRequest(
        "POST",
        "u",
        (("CLIENT_SECRET", "s1"), ("Code", "s2"), ("Refresh_Token", "s3"), ("state", "plain")),
        (
            ("AUTHORIZATION", "s4"),
            ("Proxy-Authorization", "s5"),
            ("DPoP", "s6"),
            ("X-API-Key", "s7"),
            ("Set-Cookie", "s8"),
        ),
    )
    r = repr(req)
    for i in range(1, 9):
        assert f"s{i}'" not in r
    assert "plain" in r
    assert all(v == "<redacted>" for k, v in req.redacted().headers) and req.redacted().form is not None


def test_recorded_request_redacted_get_has_no_form():
    req = RecordedRequest("GET", "u", None, (("Authorization", "x"),)).redacted()
    assert req.form is None and req.headers == (("Authorization", "<redacted>"),)


def test_client_calls_repr_is_redacted(op, rpc):
    http = ProviderHttpClient(op, ISSUER)
    http.post_form(
        f"{ISSUER}/token", [("client_secret", "sek-cs"), ("code", "sek-code")], [("Authorization", "Bearer sek-bearer")]
    )
    http.get(f"{ISSUER}/userinfo", [("Authorization", "Bearer sek-bearer")])
    static = StaticHttpClient({})
    static.post_form("https://x/t", [("access_token", "sek-at")], [("Authorization", "Bearer sek-bearer")])
    for text in (repr(http.calls), str(http.calls), repr(static.calls), f"{http.calls[0]}"):
        for secret in ("sek-cs", "sek-code", "sek-bearer", "sek-at"):
            assert secret not in text
    assert http.forms[0][0] == ("client_secret", "sek-cs")
    try:
        assert http.calls == []
    except AssertionError as e:
        assert "sek-cs" not in str(e) and "sek-bearer" not in str(e)


_BAD_PAIRS = [
    pytest.param([(b"k", "v")], id="bytes-name"),
    pytest.param([("k", 1)], id="int-value"),
    pytest.param([("k", None)], id="none-value"),
    pytest.param(["kv"], id="non-pair-str"),
    pytest.param([("k", "v", "x")], id="triple"),
    pytest.param([None], id="none-entry"),
]


def _clients(op):
    return [StaticHttpClient({}), ProviderHttpClient(op, ISSUER)]


@pytest.mark.parametrize("bad", _BAD_PAIRS)
@pytest.mark.parametrize("which", ["get", "get_with_headers", "post_form-headers", "post_form-form"])
@pytest.mark.parametrize("kind", [0, 1])
def test_clients_reject_non_str_request_pairs(op, kind, which, bad):
    c = _clients(op)[kind]
    url = f"{ISSUER}/userinfo"
    with pytest.raises(TypeError, match=r"(GET|POST) https://op\.example\.com/userinfo: (headers|form) must be"):
        if which == "get":
            c.get(url, bad)
        elif which == "get_with_headers":
            c.get_with_headers(url, bad)
        elif which == "post_form-headers":
            c.post_form(url, [], bad)
        else:
            c.post_form(url, bad, [])
    assert c.calls == []
