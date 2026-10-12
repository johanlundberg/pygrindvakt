"""Tests for ``rp.JwksCache`` and ``UnknownKeyError``.

Most tests use a scripted Python ``HttpClient`` and an injected clock (the
private ``_now`` constructor hook). A Python client cannot report response
headers unless it returns them; the ``Cache-Control`` / ``Age`` tests run both
against a loopback HTTP server through the built-in client and against a
scripted client that reports headers.
"""

from __future__ import annotations

import json
import threading
import time
import warnings
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from pygrindvakt import (
    AuthnError,
    BadRequestError,
    GrindvaktError,
    InternalError,
    JoseError,
    UnknownKeyError,
    jwt,
    keys,
    rp,
)
from pygrindvakt import http as rp_http
from pygrindvakt.http import ReqwestClient

ISSUER = "https://op.example.com"
JWKS_URI = f"{ISSUER}/jwks"
CLIENT_ID = "demo"


def make_key(kid):
    return keys.signing_key_from_jwk(keys.generate_ec_jwk("P-256"), alg="ES256", kid=kid)


def jwks_doc(*signing_keys):
    return {"keys": [k.public_jwk() for k in signing_keys]}


def id_token(key, issuer=ISSUER, **extra):
    now = int(time.time())
    claims = {"iss": issuer, "sub": "alice", "aud": CLIENT_ID, "iat": now, "exp": now + 300,
              "nonce": "n", **extra}
    return jwt.sign(key, claims)


def verify(cache, token, **kw):
    return cache.verify_id_token(token, CLIENT_ID, "n", ["ES256"], **kw)


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


class ScriptedHttp:
    """Serves ``doc`` at the JWKS URI and counts fetches."""

    def __init__(self, doc, delay=0.0):
        self.doc = doc
        self.delay = delay
        self.status = 200
        self.error = None
        self.headers = None  # None -> 3-tuple (no headers)
        self.as_response = False
        self.calls = 0
        self._lock = threading.Lock()

    def get(self, url):
        with self._lock:
            self.calls += 1
        if self.delay:
            time.sleep(self.delay)
        if self.error is not None:
            raise self.error
        if url != JWKS_URI:
            return 404, b"", "text/plain"
        body = json.dumps(self.doc).encode()
        if self.as_response:
            return rp_http.HttpFetchResponse(
                self.status, body, "application/json", self.headers
            )
        if self.headers is not None:
            return self.status, body, "application/json", self.headers
        return self.status, body, "application/json"

    def post_form(self, url, form, headers):
        return 404, b"", "text/plain"


def make_cache(http, clock=None, **kw):
    clock = clock or Clock()
    return rp.JwksCache(http, JWKS_URI, ISSUER, _now=clock, **kw), clock


# --- construction ---------------------------------------------------------------


def test_exception_class():
    assert issubclass(UnknownKeyError, JoseError)
    assert UnknownKeyError.code == "unknown_kid"
    assert UnknownKeyError.status_hint == 401
    assert UnknownKeyError("x").code == "unknown_kid"


def test_constructor_validation():
    http = ScriptedHttp({"keys": []})
    cache = rp.JwksCache(http, JWKS_URI, ISSUER)
    assert cache.jwks_uri == JWKS_URI and cache.issuer == ISSUER
    assert "JwksCache" in repr(cache) and JWKS_URI in repr(cache)
    with pytest.raises(GrindvaktError):
        rp.JwksCache(http, "http://op.example.com/jwks", "http://op.example.com")
    with pytest.raises(GrindvaktError):
        rp.JwksCache(http, "ftp://op.example.com/jwks", ISSUER)
    with pytest.raises(ValueError, match="min_ttl"):
        rp.JwksCache(http, JWKS_URI, ISSUER, min_ttl=100, max_ttl=10)
    with pytest.raises(ValueError, match="negative"):
        rp.JwksCache(http, JWKS_URI, ISSUER, default_ttl=-1)
    with pytest.raises(Exception):
        rp.JwksCache(object(), JWKS_URI, ISSUER)
    assert http.calls == 0  # nothing is fetched at construction


def test_cache_is_frozen():
    cache = rp.JwksCache(ScriptedHttp({"keys": []}), JWKS_URI, ISSUER)
    with pytest.raises(AttributeError):
        cache.issuer = "x"  # type: ignore[misc]


# --- fetching and TTL -----------------------------------------------------------


def test_fetch_once_within_default_ttl_then_refetch_on_expiry():
    k1 = make_key("k1")
    http = ScriptedHttp(jwks_doc(k1))
    cache, clock = make_cache(http)
    assert cache.jwks() == jwks_doc(k1)
    cache.jwks()
    assert verify(cache, id_token(k1))["sub"] == "alice"
    assert http.calls == 1
    clock.advance(3599)
    cache.jwks()
    assert http.calls == 1
    clock.advance(2)
    cache.jwks()
    assert http.calls == 2


def test_jwks_returns_independent_dicts():
    k1 = make_key("k1")
    cache, _ = make_cache(ScriptedHttp(jwks_doc(k1)))
    cache.jwks()["keys"].clear()
    assert len(cache.jwks()["keys"]) == 1


def test_default_ttl_is_clamped():
    http = ScriptedHttp({"keys": []})
    cache, clock = make_cache(http, default_ttl=5, min_ttl=60)
    cache.jwks()
    clock.advance(59)
    cache.jwks()
    assert http.calls == 1
    clock.advance(2)
    cache.jwks()
    assert http.calls == 2
    http2 = ScriptedHttp({"keys": []})
    cache2, clock2 = make_cache(http2, default_ttl=10**6, max_ttl=100)
    cache2.jwks()
    clock2.advance(101)
    cache2.jwks()
    assert http2.calls == 2


class _JwksHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        srv = self.server
        srv.hits += 1
        body = json.dumps(srv.doc).encode()
        self.send_response(srv.status)
        self.send_header("Content-Type", "application/json")
        for k, v in srv.extra_headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def jwks_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _JwksHandler)
    srv.daemon_threads = True
    srv.hits = 0
    srv.doc = {"keys": []}
    srv.status = 200
    srv.extra_headers = {}
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    srv.issuer = f"http://127.0.0.1:{srv.server_address[1]}"
    yield srv
    srv.shutdown()
    srv.server_close()


def server_cache(srv, **kw):
    clock = Clock()
    cache = rp.JwksCache(ReqwestClient(), f"{srv.issuer}/jwks", srv.issuer, _now=clock, **kw)
    return cache, clock


def test_cache_control_max_age_honoured(jwks_server):
    jwks_server.extra_headers = {"Cache-Control": "public, max-age=120"}
    cache, clock = server_cache(jwks_server)
    cache.jwks()
    clock.advance(119)
    cache.jwks()
    assert jwks_server.hits == 1
    clock.advance(2)
    cache.jwks()
    assert jwks_server.hits == 2


def test_age_header_is_subtracted(jwks_server):
    jwks_server.extra_headers = {"Cache-Control": "max-age=120", "Age": "100"}
    cache, clock = server_cache(jwks_server, min_ttl=1)
    cache.jwks()
    clock.advance(19)
    cache.jwks()
    assert jwks_server.hits == 1
    clock.advance(2)
    cache.jwks()
    assert jwks_server.hits == 2


def test_max_age_clamped_to_bounds(jwks_server):
    jwks_server.extra_headers = {"Cache-Control": "max-age=31536000"}
    cache, clock = server_cache(jwks_server, max_ttl=300)
    cache.jwks()
    clock.advance(301)
    cache.jwks()
    assert jwks_server.hits == 2
    jwks_server.extra_headers = {"Cache-Control": "max-age=5"}
    cache2, clock2 = server_cache(jwks_server, min_ttl=60)
    cache2.jwks()
    hits = jwks_server.hits
    clock2.advance(59)
    cache2.jwks()
    assert jwks_server.hits == hits


@pytest.mark.parametrize("header", ["no-store", "no-cache", "max-age=0"])
def test_no_store_is_floored_by_min_ttl(jwks_server, header):
    """no-store / no-cache / max-age=0 give a TTL of 0, raised to ``min_ttl``."""
    jwks_server.extra_headers = {"Cache-Control": header}
    cache, clock = server_cache(jwks_server, min_ttl=60)
    cache.jwks()
    clock.advance(30)
    cache.jwks()
    assert jwks_server.hits == 1
    clock.advance(31)
    cache.jwks()
    assert jwks_server.hits == 2


@pytest.mark.parametrize("header", ["no-store", "no-cache"])
def test_no_store_with_zero_min_ttl_never_caches(jwks_server, header):
    jwks_server.extra_headers = {"Cache-Control": header}
    cache, _ = server_cache(jwks_server, min_ttl=0)
    cache.jwks()
    cache.jwks()
    cache.jwks()
    assert jwks_server.hits == 3


def test_python_client_without_headers_warns_once_and_uses_default_ttl():
    http = ScriptedHttp({"keys": []})
    cache, clock = make_cache(http, default_ttl=100, min_ttl=1)
    with pytest.warns(UserWarning, match=r"reports no response headers.*default_ttl \(100s\)"):
        cache.jwks()
    clock.advance(99)
    cache.jwks()
    assert http.calls == 1
    clock.advance(2)  # expired: refetch must not warn again
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        cache.jwks()
    assert http.calls == 2
    # Another cache warns for itself.
    other, _ = make_cache(ScriptedHttp({"keys": []}))
    with pytest.warns(UserWarning):
        other.jwks()


def test_builtin_client_does_not_warn(jwks_server):
    cache, _ = server_cache(jwks_server)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        cache.jwks()


@pytest.mark.parametrize("as_response", [False, True])
def test_python_client_with_headers_honours_cache_control(as_response):
    http = ScriptedHttp({"keys": []})
    http.as_response = as_response
    http.headers = [("Cache-Control", "public, max-age=120"), ("Age", "100")]
    cache, clock = make_cache(http, min_ttl=1)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        cache.jwks()
        clock.advance(19)
        cache.jwks()
        assert http.calls == 1
        clock.advance(2)  # 120 - 100 = 20s lifetime
        cache.jwks()
    assert http.calls == 2


def test_python_client_headers_clamped_and_no_store_floored():
    http = ScriptedHttp({"keys": []})
    http.headers = [("cache-control", "max-age=31536000")]
    cache, clock = make_cache(http, max_ttl=300)
    cache.jwks()
    clock.advance(301)
    cache.jwks()
    assert http.calls == 2

    http2 = ScriptedHttp({"keys": []})
    http2.headers = [("Cache-Control", "no-store")]
    cache2, clock2 = make_cache(http2, min_ttl=60)
    cache2.jwks()
    clock2.advance(59)
    cache2.jwks()
    assert http2.calls == 1
    clock2.advance(2)
    cache2.jwks()
    assert http2.calls == 2

    http3 = ScriptedHttp({"keys": []})
    http3.headers = [("Cache-Control", "no-store")]
    cache3, _ = make_cache(http3, min_ttl=0)
    cache3.jwks()
    cache3.jwks()
    assert http3.calls == 2


def test_fetch_response_headers_attribute():
    r = rp_http.HttpFetchResponse(200, b"", None, [("Cache-Control", "x"), ("Set-Cookie", "a"), ("set-cookie", "b")])
    assert r.headers == [("cache-control", "x"), ("set-cookie", "a"), ("set-cookie", "b")]
    assert rp_http.HttpFetchResponse(200, b"").headers == []


@pytest.mark.parametrize("bad", [[("a",)], "x", [1, 2], [("a", 1)]])
def test_bad_headers_shape_is_an_adapter_error(bad):
    http = ScriptedHttp({"keys": []})
    http.headers = bad
    cache, _ = make_cache(http)
    with pytest.raises(InternalError):
        cache.jwks()


# --- failures -------------------------------------------------------------------


def test_transport_failure_surfaces_with_cause():
    http = ScriptedHttp({"keys": []})
    http.error = RuntimeError("network down")
    cache, _ = make_cache(http)
    with pytest.raises(InternalError) as ei:
        cache.jwks()
    assert ei.value.code == "transport"
    assert isinstance(ei.value.__cause__, RuntimeError)


def test_upstream_failure_surfaces_upstream_attributes():
    http = ScriptedHttp({"keys": []})
    http.status = 503
    cache, _ = make_cache(http)
    with pytest.raises(InternalError) as ei:
        cache.jwks()
    assert ei.value.code == "upstream_http"
    assert ei.value.upstream_status == 503
    # Errors are not cached: the next call fetches again.
    http.status = 200
    assert cache.jwks() == {"keys": []}


def test_stale_set_is_never_served_after_expiry():
    k1 = make_key("k1")
    http = ScriptedHttp(jwks_doc(k1))
    cache, clock = make_cache(http)
    cache.jwks()
    clock.advance(3601)
    http.error = RuntimeError("down")
    with pytest.raises(InternalError):
        cache.jwks()
    with pytest.raises(InternalError):
        verify(cache, id_token(k1))
    http.error = None
    assert verify(cache, id_token(k1))["sub"] == "alice"


# --- refresh() ------------------------------------------------------------------


def test_refresh_first_fetch_then_rate_limited():
    http = ScriptedHttp({"keys": []})
    cache, clock = make_cache(http, min_refresh_interval=30)
    cache.refresh()
    assert http.calls == 1
    cache.refresh()  # within the interval: no-op
    assert http.calls == 1
    clock.advance(29)
    cache.refresh()
    assert http.calls == 1
    clock.advance(2)
    cache.refresh()
    assert http.calls == 2


def test_refresh_after_failed_first_fetch_is_rate_limited():
    """A failed attempt counts: an unavailable endpoint must not be hammered."""
    http = ScriptedHttp({"keys": []})
    http.error = RuntimeError("down")
    cache, clock = make_cache(http, min_refresh_interval=30)
    with pytest.raises(InternalError):
        cache.refresh()
    assert http.calls == 1
    cache.refresh()  # no snapshot, but the failed attempt is within the interval
    assert http.calls == 1
    clock.advance(31)
    with pytest.raises(InternalError):
        cache.refresh()
    assert http.calls == 2


def test_refresh_failure_keeps_cached_set():
    k1 = make_key("k1")
    http = ScriptedHttp(jwks_doc(k1))
    cache, clock = make_cache(http)
    cache.jwks()
    clock.advance(31)
    http.error = RuntimeError("down")
    with pytest.raises(InternalError):
        cache.refresh()
    assert cache.jwks() == jwks_doc(k1)  # still within its TTL


def test_refresh_picks_up_new_keys():
    k1, k2 = make_key("k1"), make_key("k2")
    http = ScriptedHttp(jwks_doc(k1))
    cache, clock = make_cache(http)
    cache.jwks()
    http.doc = jwks_doc(k1, k2)
    clock.advance(31)
    cache.refresh()
    assert len(cache.jwks()["keys"]) == 2
    assert http.calls == 2


# --- unknown kid ----------------------------------------------------------------


def test_kid_rotation_refreshes_and_succeeds():
    k1, k2 = make_key("k1"), make_key("k2")
    http = ScriptedHttp(jwks_doc(k1))
    cache, clock = make_cache(http)
    assert verify(cache, id_token(k1))
    http.doc = jwks_doc(k1, k2)
    clock.advance(31)
    assert verify(cache, id_token(k2))["sub"] == "alice"
    assert http.calls == 2
    assert verify(cache, id_token(k2))
    assert http.calls == 2


def test_unknown_kid_after_refresh_raises_unknown_key_error():
    k1, rogue = make_key("k1"), make_key("rogue")
    http = ScriptedHttp(jwks_doc(k1))
    cache, clock = make_cache(http)
    cache.jwks()
    clock.advance(31)
    with pytest.raises(UnknownKeyError) as ei:
        verify(cache, id_token(rogue))
    assert ei.value.code == "unknown_kid"
    assert isinstance(ei.value, JoseError)
    assert http.calls == 2


def test_unknown_kid_refresh_is_rate_limited():
    k1, rogue = make_key("k1"), make_key("rogue")
    http = ScriptedHttp(jwks_doc(k1))
    cache, clock = make_cache(http, min_refresh_interval=30)
    cache.jwks()
    # Right after the first fetch a refresh would be pointless: no refetch.
    with pytest.raises(UnknownKeyError):
        verify(cache, id_token(rogue))
    assert http.calls == 1
    clock.advance(31)
    with pytest.raises(UnknownKeyError):
        verify(cache, id_token(rogue))
    assert http.calls == 2
    clock.advance(10)
    with pytest.raises(UnknownKeyError):
        verify(cache, id_token(rogue))
    assert http.calls == 2
    clock.advance(21)
    with pytest.raises(UnknownKeyError):
        verify(cache, id_token(rogue))
    assert http.calls == 3


def test_rotation_blocked_inside_interval_then_recovers():
    k1, k2 = make_key("k1"), make_key("k2")
    http = ScriptedHttp(jwks_doc(k1))
    cache, clock = make_cache(http, min_refresh_interval=30)
    cache.jwks()
    http.doc = jwks_doc(k1, k2)
    with pytest.raises(UnknownKeyError):
        verify(cache, id_token(k2))
    clock.advance(31)
    assert verify(cache, id_token(k2))


def test_refresh_failure_during_unknown_kid_raises_fetch_error():
    k1, k2 = make_key("k1"), make_key("k2")
    http = ScriptedHttp(jwks_doc(k1))
    cache, clock = make_cache(http)
    cache.jwks()
    clock.advance(31)
    http.error = RuntimeError("down")
    with pytest.raises(InternalError) as ei:
        verify(cache, id_token(k2))
    assert ei.value.code == "transport"
    # The failed attempt counts for rate limiting; the cached set still works.
    http.error = None
    assert verify(cache, id_token(k1))
    with pytest.raises(UnknownKeyError):
        verify(cache, id_token(k2))


def test_kidless_set_does_not_trigger_refresh():
    sk = make_key("k1")
    jwk = sk.public_jwk()
    jwk.pop("kid", None)
    http = ScriptedHttp({"keys": [jwk]})
    cache, clock = make_cache(http)
    # Token with a kid against a set whose keys have none: upstream behaviour.
    clock.advance(100)
    with pytest.raises(AuthnError) as ei:
        verify(cache, id_token(sk))
    assert not isinstance(ei.value, UnknownKeyError)
    assert http.calls == 1


def test_kidless_token_follows_upstream_behaviour():
    sk = keys.signing_key_from_jwk(keys.generate_ec_jwk("P-256"), alg="ES256")
    jwk = sk.public_jwk()
    jwk.pop("kid", None)
    http = ScriptedHttp({"keys": [jwk]})
    cache, _ = make_cache(http)
    assert verify(cache, id_token(sk))["sub"] == "alice"
    assert http.calls == 1
    # Several keys with kids and a kid-less token: upstream refuses, no refresh.
    k1, k2 = make_key("k1"), make_key("k2")
    http2 = ScriptedHttp(jwks_doc(k1, k2))
    cache2, clock2 = make_cache(http2)
    clock2.advance(100)
    with pytest.raises(AuthnError, match="no kid"):
        verify(cache2, id_token(sk))
    assert http2.calls == 1


def test_set_with_mixed_kid_and_kidless_keys_refreshes_for_unknown_kid():
    k1, rogue = make_key("k1"), make_key("rogue")
    plain = keys.signing_key_from_jwk(keys.generate_ec_jwk("P-256"), alg="ES256").public_jwk()
    plain.pop("kid", None)
    http = ScriptedHttp({"keys": [k1.public_jwk(), plain]})
    cache, clock = make_cache(http)
    cache.jwks()
    clock.advance(31)
    with pytest.raises(UnknownKeyError):
        verify(cache, id_token(rogue))
    assert http.calls == 2


# --- concurrency ----------------------------------------------------------------


def run_threads(n, fn):
    barrier = threading.Barrier(n)
    results = [None] * n

    def work(i):
        barrier.wait()
        try:
            results[i] = fn()
        except BaseException as e:  # noqa: BLE001
            results[i] = e

    threads = [threading.Thread(target=work, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
        assert not t.is_alive(), "deadlock"
    return results


def test_concurrent_callers_share_one_fetch():
    k1 = make_key("k1")
    http = ScriptedHttp(jwks_doc(k1), delay=0.1)
    cache, _ = make_cache(http)
    token = id_token(k1)
    results = run_threads(16, lambda: verify(cache, token))
    assert all(isinstance(r, dict) and r["sub"] == "alice" for r in results), results
    assert http.calls == 1


def test_concurrent_rotation_refreshes_once():
    k1, k2 = make_key("k1"), make_key("k2")
    http = ScriptedHttp(jwks_doc(k1), delay=0.1)
    cache, clock = make_cache(http)
    cache.jwks()
    http.doc = jwks_doc(k1, k2)
    clock.advance(31)
    token = id_token(k2)
    results = run_threads(16, lambda: verify(cache, token))
    assert all(isinstance(r, dict) for r in results), results
    assert http.calls == 2


def test_concurrent_failure_does_not_deadlock():
    http = ScriptedHttp({"keys": []}, delay=0.02)
    http.error = RuntimeError("down")
    cache, _ = make_cache(http)
    results = run_threads(16, cache.jwks)
    assert all(isinstance(r, InternalError) for r in results)


def test_concurrent_with_reentrant_python_client():
    """The fetching thread needs the GIL inside the adapter while others wait."""
    k1 = make_key("k1")
    http = ScriptedHttp(jwks_doc(k1), delay=0.05)
    cache, _ = make_cache(http)
    results = run_threads(16, cache.jwks)
    assert all(r == jwks_doc(k1) for r in results)
    assert http.calls == 1


# --- integration with verify_id_token / fetch_userinfo -----------------------------


def test_rp_verify_id_token_accepts_cache():
    k1, k2 = make_key("k1"), make_key("k2")
    http = ScriptedHttp(jwks_doc(k1))
    cache, clock = make_cache(http)
    out = rp.verify_id_token(cache, id_token(k1), ISSUER, CLIENT_ID, "n", ["ES256"])
    assert out["sub"] == "alice"
    http.doc = jwks_doc(k1, k2)
    clock.advance(31)
    assert rp.verify_id_token(cache, id_token(k2), ISSUER, CLIENT_ID, "n", ["ES256"])
    with pytest.raises(UnknownKeyError):
        clock.advance(31)
        rp.verify_id_token(cache, id_token(make_key("zzz")), ISSUER, CLIENT_ID, "n", ["ES256"])


def test_rp_verify_id_token_with_cache_rejects_issuer_mismatch():
    """A cache is bound to its issuer: keys of A must not vouch for issuer B."""
    k1 = make_key("k1")
    http = ScriptedHttp(jwks_doc(k1))
    cache, _ = make_cache(http)
    other = "https://other.example.com"
    # Token claims iss == other and is signed by the cache's key.
    with pytest.raises(BadRequestError, match="issuer"):
        rp.verify_id_token(cache, id_token(k1, issuer=other), other, CLIENT_ID, "n", ["ES256"])
    # Rejected before any fetch.
    assert http.calls == 0


def test_rp_verify_id_token_with_cache_checks_iss_claim():
    k1 = make_key("k1")
    cache, _ = make_cache(ScriptedHttp(jwks_doc(k1)))
    with pytest.raises(GrindvaktError):
        rp.verify_id_token(cache, id_token(k1, issuer="https://other.example.com"), ISSUER, CLIENT_ID, "n", ["ES256"])


def test_cache_verify_options_are_forwarded():
    k1 = make_key("k1")
    cache, _ = make_cache(ScriptedHttp(jwks_doc(k1)))
    now = int(time.time())
    assert verify(cache, id_token(k1, auth_time=now), max_age=60)
    with pytest.raises(AuthnError, match="auth_time"):
        verify(cache, id_token(k1), max_age=60)
    with pytest.raises(AuthnError, match="acr"):
        verify(cache, id_token(k1, acr="pwd"), acr_values=["mfa"])
    with pytest.raises(AuthnError, match="at_hash mismatch"):
        verify(cache, id_token(k1, at_hash="AAAAAAAAAAAAAAAAAAAAAA"), access_token="x")
    assert verify(cache, id_token(k1), leeway=300)


def test_cache_strict_hashes_is_forwarded():
    k1 = make_key("k1")
    cache, _ = make_cache(ScriptedHttp(jwks_doc(k1)))
    tok = id_token(k1, at_hash="AAAAAAAAAAAAAAAAAAAAAA")
    assert verify(cache, tok)  # default: ignored
    with pytest.raises(AuthnError, match="at_hash"):
        verify(cache, tok, strict_hashes=True)


def test_cache_argument_errors_do_not_fetch():
    k1 = make_key("k1")
    http = ScriptedHttp(jwks_doc(k1))
    cache, _ = make_cache(http)
    tok = id_token(k1)
    with pytest.raises(AuthnError, match="expected_nonce is required"):
        cache.verify_id_token(tok, CLIENT_ID, None, ["ES256"])
    with pytest.raises(BadRequestError, match="leeway"):
        verify(cache, tok, leeway=301)
    with pytest.raises(BadRequestError, match="require_at_hash"):
        verify(cache, tok, require_at_hash=True)
    with pytest.raises(BadRequestError, match="acr_values"):
        verify(cache, tok, acr_values=[])
    with pytest.raises(ValueError, match="algorithm"):
        cache.verify_id_token(tok, CLIENT_ID, "n", ["nope"])
    assert http.calls == 0


class UserinfoHttp(ScriptedHttp):
    def __init__(self, doc, body):
        super().__init__(doc)
        self.body = body

    def post_form(self, url, form, headers):
        if url == f"{ISSUER}/userinfo":
            return 200, self.body.encode(), "application/jwt"
        return 404, b"", "text/plain"


def test_fetch_userinfo_signed_path_accepts_cache_and_refreshes_on_rotation():
    k1, k2 = make_key("k1"), make_key("k2")
    now = int(time.time())
    claims = {"iss": ISSUER, "sub": "alice", "aud": CLIENT_ID, "iat": now, "name": "A"}
    http = UserinfoHttp(jwks_doc(k1), jwt.sign(k2, claims))
    cache, clock = make_cache(http)
    cache.jwks()
    http.doc = jwks_doc(k1, k2)
    clock.advance(31)

    def call():
        return rp.fetch_userinfo(
            http, f"{ISSUER}/userinfo", "tok", "alice", ISSUER, jwks=cache,
            client_id=CLIENT_ID, allowed_algorithms=["ES256"], trust="dedicated_keys",
        )

    assert call()["name"] == "A"
    assert http.calls == 2
    # Unknown kid in the response: UnknownKeyError once the refresh yields nothing.
    http.body = jwt.sign(make_key("zzz"), claims)
    clock.advance(31)
    with pytest.raises(UnknownKeyError):
        call()


def test_fetch_userinfo_json_does_not_touch_cache():
    class JsonHttp(ScriptedHttp):
        def post_form(self, url, form, headers):
            return 200, b'{"sub":"alice"}', "application/json"

    http = JsonHttp({"keys": []})
    cache, _ = make_cache(http)
    out = rp.fetch_userinfo(http, f"{ISSUER}/userinfo", "tok", "alice", ISSUER, jwks=cache)
    assert out["sub"] == "alice"
    assert http.calls == 0


def test_fetch_userinfo_with_cache_rejects_issuer_mismatch():
    """The cache's issuer must equal the issuer argument, before any fetch."""
    k1 = make_key("k1")
    now = int(time.time())
    other = "https://other.example.com"
    claims = {"iss": other, "sub": "alice", "aud": CLIENT_ID, "iat": now}
    http = UserinfoHttp(jwks_doc(k1), jwt.sign(k1, claims))
    cache, _ = make_cache(http)
    with pytest.raises(BadRequestError, match="issuer"):
        rp.fetch_userinfo(
            http, f"{other}/userinfo", "tok", "alice", other, jwks=cache,
            client_id=CLIENT_ID, allowed_algorithms=["ES256"], trust="dedicated_keys",
        )
    assert http.calls == 0  # rejected before any request


def test_unknown_kid_after_single_flight_never_uses_expired_snapshot():
    """A waiter must not verify with a set another thread stored already expired."""
    k1, k2 = make_key("k1"), make_key("k2")
    http = ScriptedHttp(jwks_doc(k1))
    http.headers = [("cache-control", "max-age=3600")]
    cache, _ = make_cache(http, min_ttl=0, min_refresh_interval=0)
    cache.jwks()  # E1: {k1}, valid
    assert http.calls == 1
    # From now on the OP rotates and answers no-store: with min_ttl=0 the new
    # set expires the moment it is stored.
    http.doc = jwks_doc(k1, k2)
    http.headers = [("cache-control", "no-store")]
    http.delay = 0.4
    token = id_token(k2)
    results = []

    def work():
        results.append(verify(cache, token))

    a = threading.Thread(target=work)
    b = threading.Thread(target=work)
    a.start()
    time.sleep(0.1)
    b.start()
    a.join()
    b.join()
    assert len(results) == 2
    # A fetched once; B waited, found the stored set expired and fetched again.
    assert http.calls == 3


# --- fetch_timeout (bounded wait for another thread's fetch) ---------------------


class StallingHttp(ScriptedHttp):
    """Blocks in ``get`` until ``release`` is set once ``stall`` is true."""

    def __init__(self, doc):
        super().__init__(doc)
        self.stall = False
        self.entered = threading.Event()
        self.release = threading.Event()

    def get(self, url):
        if self.stall:
            self.entered.set()
            assert self.release.wait(30), "test never released the stalled fetch"
        return super().get(url)


@pytest.fixture
def stalling():
    k1, k2 = make_key("k1"), make_key("k2")
    http = StallingHttp(jwks_doc(k1))
    http.k1, http.k2 = k1, k2
    threads = []
    yield http, threads
    http.release.set()  # always let stalled holders finish
    for t in threads:
        t.join(timeout=10)
        assert not t.is_alive()


def start_holder(http, threads, fn):
    out = {}

    def run():
        try:
            out["result"] = fn()
        except BaseException as e:  # noqa: BLE001
            out["result"] = e

    t = threading.Thread(target=run)
    threads.append(t)
    t.start()
    assert http.entered.wait(10), "holder never reached the adapter"
    return t, out


def assert_flight_timeout(fn, bound=5.0):
    start = time.monotonic()
    with pytest.raises(InternalError) as ei:
        fn()
    assert time.monotonic() - start < bound
    assert ei.value.code == "jwks_fetch_timeout"
    assert "timed out after 0.5s" in str(ei.value)
    return ei.value


def test_fetch_timeout_validation_and_default():
    http = ScriptedHttp({"keys": []})
    for bad in (0, 0.0, -1, -0.5, 1e-12, 4e-10, float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValueError, match="fetch_timeout"):
            rp.JwksCache(http, JWKS_URI, ISSUER, fetch_timeout=bad)
    rp.JwksCache(http, JWKS_URI, ISSUER, fetch_timeout=0.001)
    rp.JwksCache(http, JWKS_URI, ISSUER, fetch_timeout=1e300)
    rp.JwksCache(http, JWKS_URI, ISSUER, fetch_timeout=5)
    with pytest.raises(TypeError):
        rp.JwksCache(http, JWKS_URI, ISSUER, 30.0)  # type: ignore[call-arg, misc]
    assert rp.JwksCache(http, JWKS_URI, ISSUER).fetch_timeout == 45.0
    assert rp.JwksCache(http, JWKS_URI, ISSUER, fetch_timeout=2).fetch_timeout == 2.0
    with pytest.raises(AttributeError):
        rp.JwksCache(http, JWKS_URI, ISSUER).fetch_timeout = 1.0  # type: ignore[misc]


def test_waiter_in_jwks_times_out_and_cache_recovers(stalling):
    http, threads = stalling
    http.stall = True
    cache, _ = make_cache(http, fetch_timeout=0.5)
    a, out = start_holder(http, threads, cache.jwks)
    assert_flight_timeout(cache.jwks)
    assert_flight_timeout(cache.jwks)  # repeatable; holder still running
    assert a.is_alive()
    http.release.set()
    a.join(timeout=10)
    assert out["result"] == jwks_doc(http.k1)
    # No stale flight: later calls are served from cache without refetching.
    assert cache.jwks() == jwks_doc(http.k1)
    assert http.calls == 1
    cache.refresh()  # rate-limited no-op, must not block
    assert http.calls == 1


def test_waiter_in_verify_id_token_times_out(stalling):
    http, threads = stalling
    http.stall = True
    cache, _ = make_cache(http, fetch_timeout=0.5)
    a, _ = start_holder(http, threads, cache.jwks)
    assert_flight_timeout(lambda: verify(cache, id_token(http.k1)))
    http.release.set()
    a.join(timeout=10)
    assert verify(cache, id_token(http.k1))["sub"] == "alice"


def test_waiter_in_refresh_times_out(stalling):
    http, threads = stalling
    http.stall = True
    cache, clock = make_cache(http, fetch_timeout=0.5)
    a, _ = start_holder(http, threads, cache.jwks)
    clock.advance(31)  # no longer rate-limited, so refresh() must wait
    assert_flight_timeout(cache.refresh)
    http.release.set()
    a.join(timeout=10)
    assert cache.jwks() == jwks_doc(http.k1)


def test_unknown_kid_waiter_raises_timeout_not_unknown_key(stalling):
    http, threads = stalling
    cache, clock = make_cache(http, fetch_timeout=0.5)
    cache.jwks()  # primed with k1 only
    clock.advance(31)  # rotation refresh no longer rate-limited
    http.doc = jwks_doc(http.k1, http.k2)
    http.stall = True
    a, _ = start_holder(http, threads, cache.refresh)
    err = assert_flight_timeout(lambda: verify(cache, id_token(http.k2)))
    assert not isinstance(err, UnknownKeyError)
    http.release.set()
    a.join(timeout=10)
    assert verify(cache, id_token(http.k2))["sub"] == "alice"


def test_late_finish_wakes_remaining_waiters(stalling):
    """A waiter that timed out must not break the wake-up of later waiters."""
    http, threads = stalling
    http.stall = True
    cache, _ = make_cache(http, fetch_timeout=1.5)
    a, out = start_holder(http, threads, cache.jwks)
    results = []

    def waiter():
        try:
            results.append(cache.jwks())
        except BaseException as e:  # noqa: BLE001
            results.append(e)

    ws = [threading.Thread(target=waiter) for _ in range(3)]
    for w in ws:
        w.start()
    time.sleep(0.3)
    http.release.set()
    for w in ws:
        w.join(timeout=10)
        assert not w.is_alive()
    a.join(timeout=10)
    assert results == [jwks_doc(http.k1)] * 3
    assert http.calls == 1


def test_slow_fetch_under_default_timeout_still_single_flight():
    k1 = make_key("k1")
    http = ScriptedHttp(jwks_doc(k1), delay=0.2)
    cache, _ = make_cache(http)
    results = run_threads(6, cache.jwks)
    assert all(r == jwks_doc(k1) for r in results), results
    assert http.calls == 1


def test_refresh_within_interval_does_not_wait_for_inflight_fetch(stalling):
    http, threads = stalling
    http.stall = True
    cache, _ = make_cache(http, fetch_timeout=0.5, min_refresh_interval=30)
    a, _ = start_holder(http, threads, cache.refresh)  # sets last_attempt
    start = time.monotonic()
    cache.refresh()  # rate-limited: silent no-op, no wait, no timeout error
    assert time.monotonic() - start < 0.4
    http.release.set()
    a.join(timeout=10)
    assert http.calls == 1


def test_waiter_never_hangs_when_holder_finishes_near_deadline(stalling):
    """Holder ends around the waiter's deadline: result or timeout, never a hang."""
    http, threads = stalling
    http.stall = True
    cache, _ = make_cache(http, fetch_timeout=0.3)
    a, _ = start_holder(http, threads, cache.jwks)
    threading.Timer(0.3, http.release.set).start()
    try:
        assert cache.jwks() == jwks_doc(http.k1)
    except InternalError as e:
        assert e.code == "jwks_fetch_timeout"
    a.join(timeout=10)
    assert cache.jwks() == jwks_doc(http.k1)
    assert http.calls == 1
