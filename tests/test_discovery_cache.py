"""Tests for ``rp.DiscoveryCache`` (ADR 0008).

Modelled on ``test_jwks_cache.py``: a scripted Python ``HttpClient`` plus an
injected clock (the private ``_now`` hook) for most tests, and a loopback HTTP
server through the built-in client for the ``Cache-Control`` / ``Age`` tests.
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
    ConfigError,
    GrindvaktError,
    InternalError,
    JoseError,
    metadata,
    rp,
)
from pygrindvakt import http as rp_http
from pygrindvakt.http import ReqwestClient

ISSUER = "https://op.example.com"
DISCOVERY_URL = f"{ISSUER}/.well-known/openid-configuration"
JWKS_URI = f"{ISSUER}/jwks"
JWKS_URI_2 = f"{ISSUER}/keys-2"


def md_doc(issuer=ISSUER, **extra):
    return metadata.ProviderMetadata(issuer).to_dict() | extra


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


class ScriptedHttp:
    """Serves ``doc`` at the discovery URL and key sets at ``keys``; counts GETs."""

    def __init__(self, doc=None, delay=0.0, headerless=False):
        self.doc = md_doc() if doc is None else doc
        self.delay = delay
        self.status = 200
        self.error = None
        # Any header keeps the "reports no response headers" warning quiet
        # without influencing the TTL (no Cache-Control: default_ttl applies).
        self.headers = [("x-scripted", "1")]
        self.headerless = headerless  # True -> legacy 3-tuple, no headers at all
        self.as_response = False
        self.keys = {JWKS_URI: {"keys": []}, JWKS_URI_2: {"keys": []}}
        self.discovery_url = DISCOVERY_URL
        self.calls = 0  # discovery GETs
        self.jwks_calls = 0
        self._lock = threading.Lock()

    def get(self, url):
        if url in self.keys:
            with self._lock:
                self.jwks_calls += 1
            body = json.dumps(self.keys[url]).encode()
            if self.headerless:
                return 200, body, "application/json"
            return 200, body, "application/json", [("x-scripted", "1")]
        if url != self.discovery_url:
            return 404, b"", "text/plain"
        with self._lock:
            self.calls += 1
        if self.delay:
            time.sleep(self.delay)
        if self.error is not None:
            raise self.error
        body = json.dumps(self.doc).encode()
        if self.as_response:
            return rp_http.HttpFetchResponse(self.status, body, "application/json", self.headers)
        if self.headerless:
            return self.status, body, "application/json"
        return self.status, body, "application/json", self.headers

    def post_form(self, url, form, headers):
        return 404, b"", "text/plain"


def make_cache(http, clock=None, **kw):
    clock = clock or Clock()
    return rp.DiscoveryCache(http, ISSUER, _now=clock, **kw), clock


def recorded(fn):
    """Run ``fn``; return ``(result, [UserWarning messages])`` (filter: always)."""
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        result = fn()
    return result, [str(x.message) for x in w if issubclass(x.category, UserWarning)]


# --- construction ---------------------------------------------------------------


def test_constructor_defaults_and_properties():
    http = ScriptedHttp()
    cache = rp.DiscoveryCache(http, ISSUER)
    assert cache.issuer == ISSUER
    assert cache.failure_backoff == 10
    assert cache.fetch_timeout == 45.0
    assert rp.DiscoveryCache(http, ISSUER, failure_backoff=3, fetch_timeout=2).failure_backoff == 3
    assert http.calls == 0  # nothing is fetched at construction
    rp.DiscoveryCache(None, ISSUER)  # built-in client


def test_cache_is_frozen():
    cache = rp.DiscoveryCache(ScriptedHttp(), ISSUER)
    for attr in ("issuer", "failure_backoff", "fetch_timeout"):
        with pytest.raises(AttributeError):
            setattr(cache, attr, 1)


@pytest.mark.parametrize(
    "bad_issuer",
    [
        "http://op.example.com",  # plain http to a non-loopback host
        "ftp://op.example.com",
        "https://op.example.com\\@evil.example",  # backslash gate
        "",
        "not a url",
    ],
)
def test_bad_issuer_is_config_error(bad_issuer):
    with pytest.raises(ConfigError):
        rp.DiscoveryCache(ScriptedHttp(), bad_issuer)


def test_backslash_issuer_message_does_not_echo():
    with pytest.raises(ConfigError, match="must not contain a backslash") as ei:
        rp.DiscoveryCache(ScriptedHttp(), "https://op.example.com\\@evil.example")
    assert "evil" not in str(ei.value)


@pytest.mark.parametrize(
    ("kw", "match"),
    [
        ({"default_ttl": -1}, "default_ttl must not be negative"),
        ({"min_ttl": -1}, "min_ttl must not be negative"),
        ({"max_ttl": -1}, "max_ttl must not be negative"),
        ({"failure_backoff": -1}, "failure_backoff must not be negative"),
        ({"max_stale": -1}, "max_stale must not be negative"),
        ({"min_ttl": 100, "max_ttl": 10}, "min_ttl must not exceed max_ttl"),
    ],
)
def test_numeric_validation(kw, match):
    with pytest.raises(ConfigError, match=match):
        rp.DiscoveryCache(ScriptedHttp(), ISSUER, **kw)


def test_zero_values_are_accepted():
    """Like JwksCache, zero TTLs / back-off / max_stale are valid (``min_ttl=0`` = uncached)."""
    rp.DiscoveryCache(ScriptedHttp(), ISSUER, min_ttl=0, max_ttl=0, default_ttl=0, failure_backoff=0, max_stale=0)


@pytest.mark.parametrize("bad", [0, 0.0, -1, -0.5, 1e-12, 4e-10, float("nan"), float("inf"), float("-inf")])
def test_fetch_timeout_validation(bad):
    with pytest.raises(ConfigError, match="fetch_timeout"):
        rp.DiscoveryCache(ScriptedHttp(), ISSUER, fetch_timeout=bad)


def test_fetch_timeout_accepts_extremes_and_args_are_keyword_only():
    http = ScriptedHttp()
    rp.DiscoveryCache(http, ISSUER, fetch_timeout=0.001)
    rp.DiscoveryCache(http, ISSUER, fetch_timeout=1e300)
    with pytest.raises(TypeError):
        rp.DiscoveryCache(http, ISSUER, 3600)  # type: ignore[call-arg, misc]
    with pytest.raises(TypeError):
        rp.DiscoveryCache(object(), ISSUER)  # type: ignore[arg-type]


def test_default_ttl_outside_bounds_is_clamped_not_rejected():
    http = ScriptedHttp()
    cache, clock = make_cache(http, default_ttl=5, min_ttl=60)
    cache.metadata()
    clock.advance(59)
    cache.metadata()
    assert http.calls == 1
    clock.advance(2)
    cache.metadata()
    assert http.calls == 2
    http2 = ScriptedHttp()
    cache2, clock2 = make_cache(http2, default_ttl=10**6, max_ttl=100)
    cache2.metadata()
    clock2.advance(101)
    cache2.metadata()
    assert http2.calls == 2


# --- fetching and TTL -----------------------------------------------------------


def test_metadata_info_and_expiry_with_default_ttl():
    http = ScriptedHttp()
    cache, clock = make_cache(http)
    md = cache.metadata()
    assert isinstance(md, metadata.ProviderMetadata) and md.issuer == ISSUER
    assert md.raw is not None
    info = cache.info()
    assert isinstance(info, rp.ProviderInfo)
    assert info.issuer == ISSUER and info.jwks_uri == JWKS_URI
    assert info.metadata is not None and info.metadata.issuer == ISSUER
    assert http.calls == 1
    clock.advance(3599)
    cache.metadata()
    assert http.calls == 1
    clock.advance(2)
    cache.metadata()
    assert http.calls == 2


def test_rp_discover_is_unchanged():
    http = ScriptedHttp(md_doc(x_custom={"a": 1}))
    md = rp.discover(http, ISSUER)
    assert md.issuer == ISSUER
    assert md.raw is not None and md.raw["x_custom"] == {"a": 1}
    assert http.calls == 1


class _DiscoveryHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        srv = self.server
        srv.hits += 1
        body = json.dumps(srv.doc_for(srv.issuer)).encode()
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
def disc_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _DiscoveryHandler)
    srv.daemon_threads = True
    srv.hits = 0
    srv.status = 200
    srv.extra_headers = {}
    srv.doc_for = md_doc
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    srv.issuer = f"http://127.0.0.1:{srv.server_address[1]}"
    yield srv
    srv.shutdown()
    srv.server_close()


def server_cache(srv, **kw):
    clock = Clock()
    return rp.DiscoveryCache(ReqwestClient(), srv.issuer, _now=clock, **kw), clock


def test_cache_control_max_age_honoured(disc_server):
    disc_server.extra_headers = {"Cache-Control": "public, max-age=120"}
    cache, clock = server_cache(disc_server)
    cache.metadata()
    clock.advance(119)
    cache.metadata()
    assert disc_server.hits == 1
    clock.advance(2)
    cache.metadata()
    assert disc_server.hits == 2


def test_age_header_is_subtracted(disc_server):
    disc_server.extra_headers = {"Cache-Control": "max-age=120", "Age": "100"}
    cache, clock = server_cache(disc_server, min_ttl=1)
    cache.metadata()
    clock.advance(19)
    cache.metadata()
    assert disc_server.hits == 1
    clock.advance(2)
    cache.metadata()
    assert disc_server.hits == 2


def test_max_age_clamped_to_max_ttl(disc_server):
    disc_server.extra_headers = {"Cache-Control": "max-age=31536000"}
    cache, clock = server_cache(disc_server, max_ttl=300)
    cache.metadata()
    clock.advance(299)
    cache.metadata()
    assert disc_server.hits == 1
    clock.advance(2)
    cache.metadata()
    assert disc_server.hits == 2


def test_max_age_ceiling_is_max_ttl_not_the_jwks_default(disc_server):
    """max_ttl above 24h is honoured (the JWKS helper's own ceiling is 24h)."""
    disc_server.extra_headers = {"Cache-Control": "max-age=200000"}
    cache, clock = server_cache(disc_server, max_ttl=300000)
    cache.metadata()
    clock.advance(150000)
    cache.metadata()
    assert disc_server.hits == 1
    clock.advance(50001)
    cache.metadata()
    assert disc_server.hits == 2


def test_max_age_clamped_to_min_ttl(disc_server):
    disc_server.extra_headers = {"Cache-Control": "max-age=5"}
    cache, clock = server_cache(disc_server, min_ttl=60)
    cache.metadata()
    clock.advance(59)
    cache.metadata()
    assert disc_server.hits == 1
    clock.advance(2)
    cache.metadata()
    assert disc_server.hits == 2


@pytest.mark.parametrize("header", ["no-store", "no-cache", "max-age=0"])
def test_no_store_is_floored_by_min_ttl(disc_server, header):
    disc_server.extra_headers = {"Cache-Control": header}
    cache, clock = server_cache(disc_server, min_ttl=60)
    cache.metadata()
    clock.advance(30)
    cache.metadata()
    assert disc_server.hits == 1
    clock.advance(31)
    cache.metadata()
    assert disc_server.hits == 2


@pytest.mark.parametrize("header", ["no-store", "no-cache"])
def test_no_store_with_zero_min_ttl_never_caches(disc_server, header):
    disc_server.extra_headers = {"Cache-Control": header}
    cache, _ = server_cache(disc_server, min_ttl=0)
    cache.metadata()
    cache.metadata()
    cache.metadata()
    assert disc_server.hits == 3


def test_quote_aware_cache_control(disc_server):
    """An unbalanced quote hides later directives: fail closed to TTL 0 (floored)."""
    disc_server.extra_headers = {"Cache-Control": 'foo="bar, max-age=100000'}
    cache, clock = server_cache(disc_server, min_ttl=60)
    cache.metadata()
    clock.advance(61)
    cache.metadata()
    assert disc_server.hits == 2


def test_builtin_client_does_not_warn(disc_server):
    cache, _ = server_cache(disc_server)
    _, warned = recorded(cache.metadata)
    assert warned == []


def test_python_client_without_headers_warns_once_and_uses_default_ttl():
    http = ScriptedHttp(headerless=True)
    cache, clock = make_cache(http, default_ttl=100, min_ttl=1)
    _, warned = recorded(cache.metadata)
    assert len(warned) == 1
    assert "reports no response headers" in warned[0] and "default_ttl (100s)" in warned[0]
    assert "discovery" in warned[0]
    clock.advance(99)
    cache.metadata()
    assert http.calls == 1
    clock.advance(2)  # expired: the refetch must not warn again
    _, warned = recorded(cache.metadata)
    assert warned == []
    assert http.calls == 2
    # Another cache warns for itself.
    other, _ = make_cache(ScriptedHttp(headerless=True))
    _, warned = recorded(other.metadata)
    assert len(warned) == 1


@pytest.mark.parametrize("as_response", [False, True])
def test_python_client_with_headers_honours_cache_control(as_response):
    http = ScriptedHttp()
    http.as_response = as_response
    http.headers = [("Cache-Control", "public, max-age=120"), ("Age", "100")]
    cache, clock = make_cache(http, min_ttl=1)
    _, warned = recorded(cache.metadata)
    assert warned == []
    clock.advance(19)
    cache.metadata()
    assert http.calls == 1
    clock.advance(2)
    cache.metadata()
    assert http.calls == 2


def test_python_client_headers_clamped_and_no_store_floored():
    http = ScriptedHttp()
    http.headers = [("cache-control", "max-age=31536000")]
    cache, clock = make_cache(http, max_ttl=300)
    cache.metadata()
    clock.advance(301)
    cache.metadata()
    assert http.calls == 2

    http2 = ScriptedHttp()
    http2.headers = [("Cache-Control", "no-store")]
    cache2, clock2 = make_cache(http2, min_ttl=60)
    cache2.metadata()
    clock2.advance(59)
    cache2.metadata()
    assert http2.calls == 1
    clock2.advance(2)
    cache2.metadata()
    assert http2.calls == 2


@pytest.mark.parametrize("bad", [[("a",)], "x", [1, 2], [("a", 1)]])
def test_bad_headers_shape_is_an_adapter_error(bad, unraisable):
    http = ScriptedHttp()
    http.headers = bad
    cache, _ = make_cache(http)
    with pytest.raises(InternalError):
        cache.metadata()
    unraisable.expect(InternalError, "HttpClient method must return", count=1, adapter=ScriptedHttp)


# --- issuer binding -------------------------------------------------------------


def test_issuer_mismatch_raises_like_discover_and_is_not_cached():
    evil = md_doc("https://evil.example.com")
    http = ScriptedHttp(evil)
    with pytest.raises(AuthnError) as direct:
        rp.discover(http, ISSUER)
    cache, clock = make_cache(http)
    with pytest.raises(AuthnError) as cached:
        cache.metadata()
    assert str(cached.value) == str(direct.value)
    # Inside the back-off window the stored mismatch is the cause, not a document.
    for call in (cache.info, cache.jwks):
        with pytest.raises(InternalError) as ei:
            call()
        assert ei.value.code == "discovery_backoff"
        assert isinstance(ei.value.__cause__, AuthnError)
    # Not cached: a corrected document is fetched once the back-off passes.
    http.doc = md_doc()
    clock.advance(11)
    assert cache.metadata().issuer == ISSUER
    assert http.calls == 3  # direct discover, the failed attempt, the fix
    assert cache.info().issuer == ISSUER


def test_issuer_mismatch_never_replaces_or_is_served_after_a_good_fetch():
    http = ScriptedHttp()
    cache, clock = make_cache(http)
    cache.metadata()
    clock.advance(3601)
    http.doc = md_doc("https://evil.example.com", jwks_uri="https://evil.example.com/jwks")
    # stale_on_error: the OLD, issuer-bound document is served, never the evil one.
    md, warned = recorded(cache.metadata)
    assert md.issuer == ISSUER and md.jwks_uri == JWKS_URI
    assert len(warned) == 1 and "stale" in warned[0]
    assert cache.info().jwks_uri == JWKS_URI
    # Without stale serving the mismatch is an error.
    http2 = ScriptedHttp()
    cache2, clock2 = make_cache(http2, stale_on_error=False)
    cache2.metadata()
    clock2.advance(3601)
    http2.doc = md_doc("https://evil.example.com")
    with pytest.raises(AuthnError):
        cache2.metadata()


# --- single flight --------------------------------------------------------------


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
    http = ScriptedHttp(delay=0.1)
    cache, _ = make_cache(http)
    results = run_threads(10, cache.metadata)
    assert all(isinstance(r, metadata.ProviderMetadata) and r.issuer == ISSUER for r in results), results
    assert http.calls == 1


def test_concurrent_info_calls_share_one_fetch_and_one_warning_set():
    http = ScriptedHttp(md_doc(end_session_endpoint="https://logout.other.example/logout"), delay=0.1)
    cache, _ = make_cache(http)
    results, warned = recorded(lambda: run_threads(10, cache.info))
    assert all(isinstance(r, rp.ProviderInfo) for r in results), results
    assert http.calls == 1
    cross = [w for w in warned if "different origin" in w]
    assert len(cross) == 1, warned


def test_concurrent_jwks_calls_return_one_object():
    http = ScriptedHttp(delay=0.1)
    cache, _ = make_cache(http)
    results = run_threads(10, cache.jwks)
    assert all(isinstance(r, rp.JwksCache) for r in results), results
    assert all(r is results[0] for r in results)
    assert http.calls == 1


def test_concurrent_failure_does_not_deadlock_and_makes_one_request(unraisable):
    http = ScriptedHttp(delay=0.05)
    http.error = RuntimeError("down")
    cache, _ = make_cache(http)
    results = run_threads(10, cache.metadata)
    assert all(isinstance(r, InternalError) for r in results), results
    codes = sorted(r.code for r in results)
    assert codes == ["discovery_backoff"] * 9 + ["transport"]
    assert http.calls == 1
    unraisable.expect(RuntimeError, "down", count=1, adapter=ScriptedHttp)


class StallingHttp(ScriptedHttp):
    """Blocks in the discovery ``get`` until ``release`` is set once ``stall`` is true."""

    def __init__(self, doc=None):
        super().__init__(doc)
        self.stall = False
        self.entered = threading.Event()
        self.release = threading.Event()

    def get(self, url):
        if self.stall and url == DISCOVERY_URL:
            self.entered.set()
            assert self.release.wait(30), "test never released the stalled fetch"
        return super().get(url)


@pytest.fixture
def stalling():
    http = StallingHttp()
    threads = []
    yield http, threads
    http.release.set()
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
    assert ei.value.code == "discovery_fetch_timeout"
    assert ei.value.retryable is True
    assert "timed out after 0.5s" in str(ei.value)
    return ei.value


@pytest.mark.parametrize("method", ["metadata", "info", "jwks", "refresh"])
def test_waiter_times_out_while_fetch_completes_and_is_cached(stalling, method):
    http, threads = stalling
    http.stall = True
    cache, _ = make_cache(http, fetch_timeout=0.5)
    a, out = start_holder(http, threads, cache.metadata)
    assert_flight_timeout(getattr(cache, method))
    assert_flight_timeout(getattr(cache, method))  # repeatable; holder still running
    assert a.is_alive()
    http.release.set()
    a.join(timeout=10)
    assert out["result"].issuer == ISSUER
    # The holder's fetch was cached: no further GET.
    assert cache.metadata().issuer == ISSUER
    assert http.calls == 1


def test_waiter_timeout_does_not_affect_failure_state(stalling):
    http, threads = stalling
    http.stall = True
    cache, _ = make_cache(http, fetch_timeout=0.5)
    a, _ = start_holder(http, threads, cache.metadata)
    assert_flight_timeout(cache.metadata)
    http.release.set()
    a.join(timeout=10)
    assert cache.metadata().issuer == ISSUER  # no stored failure from the timeout


def test_late_finish_wakes_remaining_waiters(stalling):
    http, threads = stalling
    http.stall = True
    cache, _ = make_cache(http, fetch_timeout=1.5)
    a, _out = start_holder(http, threads, cache.metadata)
    results = []

    def waiter():
        try:
            results.append(cache.metadata())
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
    assert [r.issuer for r in results] == [ISSUER] * 3
    assert http.calls == 1


# --- failure policy -------------------------------------------------------------


def test_first_failure_raises_original_then_backoff_then_retry(unraisable):
    http = ScriptedHttp()
    http.error = RuntimeError("network down")
    cache, clock = make_cache(http)
    with pytest.raises(InternalError) as first:
        cache.metadata()
    assert first.value.code == "transport"
    assert isinstance(first.value.__cause__, RuntimeError)
    assert http.calls == 1
    # Inside the window: no GET, discovery_backoff chained to the original.
    for call in (cache.metadata, cache.info, cache.jwks):
        with pytest.raises(InternalError) as ei:
            call()
        assert ei.value.code == "discovery_backoff"
        assert ei.value.retryable is True
        assert ei.value.__cause__ is not None
        assert ei.value.__cause__.code == "transport"
        assert isinstance(ei.value.__cause__.__cause__, RuntimeError)
    clock.advance(9)
    with pytest.raises(InternalError) as ei:
        cache.metadata()
    assert ei.value.code == "discovery_backoff"
    assert http.calls == 1
    # After the window a new attempt is made.
    clock.advance(2)
    with pytest.raises(InternalError) as ei:
        cache.metadata()
    assert ei.value.code == "transport"
    assert http.calls == 2
    # Recovery.
    http.error = None
    with pytest.raises(InternalError):  # a new window opened by the failure above
        cache.metadata()
    clock.advance(11)
    assert cache.metadata().issuer == ISSUER
    assert http.calls == 3
    # Success clears the failure: later expiry fetches without back-off.
    clock.advance(3601)
    assert cache.metadata().issuer == ISSUER
    assert http.calls == 4
    unraisable.expect(RuntimeError, "down", count=2, adapter=ScriptedHttp)


def test_upstream_5xx_is_a_failure_with_backoff():
    http = ScriptedHttp()
    http.status = 503
    cache, _ = make_cache(http)
    with pytest.raises(InternalError) as ei:
        cache.metadata()
    assert ei.value.code == "upstream_http" and ei.value.upstream_status == 503
    with pytest.raises(InternalError) as ei2:
        cache.metadata()
    assert ei2.value.code == "discovery_backoff"
    assert http.calls == 1


def test_zero_backoff_never_suppresses_a_fetch(unraisable):
    http = ScriptedHttp()
    http.error = RuntimeError("down")
    cache, _ = make_cache(http, failure_backoff=0)
    for _ in range(3):
        with pytest.raises(InternalError) as ei:
            cache.metadata()
        assert ei.value.code == "transport"
    assert http.calls == 3
    unraisable.expect(RuntimeError, "down", count=3, adapter=ScriptedHttp)


def test_stale_metadata_served_after_failure_within_max_stale_then_recovers(unraisable):
    http = ScriptedHttp()
    cache, clock = make_cache(http)
    cache.metadata()
    clock.advance(3601)  # expired by 1s
    http.error = RuntimeError("down")
    md, warned = recorded(cache.metadata)
    assert md.issuer == ISSUER
    assert http.calls == 2  # foreground refresh attempted, failed
    assert len(warned) == 1 and "stale" in warned[0]
    # Inside the window: stale, no GET, no second warning.
    for call in (cache.metadata, cache.info):
        _, warned = recorded(call)
        assert warned == []
    assert http.calls == 2
    # After the window another attempt; still stale, still no second warning.
    clock.advance(11)
    _, warned = recorded(cache.metadata)
    assert http.calls == 3 and warned == []
    # The OP recovers: refetched, fresh content served.
    http.error = None
    http.doc = md_doc(scopes_supported=["openid", "fresh"])
    clock.advance(11)
    md = cache.metadata()
    assert http.calls == 4
    assert md.scopes_supported == ["openid", "fresh"]
    assert cache.metadata().scopes_supported == ["openid", "fresh"]
    assert http.calls == 4
    # A new outage warns again (the warning is once per outage).
    clock.advance(3601)
    http.error = RuntimeError("down again")
    _, warned = recorded(cache.metadata)
    assert len(warned) == 1
    unraisable.expect(RuntimeError, "down", count=3, adapter=ScriptedHttp)


def test_stale_serving_includes_jwks_binding_but_jwks_cache_itself_is_never_stale(unraisable):
    http = ScriptedHttp()
    cache, clock = make_cache(http)
    jwks_cache = cache.jwks()
    jwks_cache.jwks()
    clock.advance(3601)
    http.error = RuntimeError("down")
    http.keys = {}  # the JWKS endpoint is down too (404)
    stale, _ = recorded(cache.jwks)
    assert stale is jwks_cache  # stale metadata, same binding
    with pytest.raises(InternalError):
        stale.jwks()  # the key set itself is never served stale
    unraisable.expect(RuntimeError, "down", count=1, adapter=ScriptedHttp)


def test_stale_on_error_false_never_serves_expired_metadata(unraisable):
    http = ScriptedHttp()
    cache, clock = make_cache(http, stale_on_error=False)
    cache.metadata()
    clock.advance(3601)
    http.error = RuntimeError("down")
    with pytest.raises(InternalError) as first:
        cache.metadata()
    assert first.value.code == "transport"
    assert http.calls == 2
    with pytest.raises(InternalError) as second:
        cache.metadata()
    assert second.value.code == "discovery_backoff"
    assert second.value.__cause__ is not None and second.value.__cause__.code == "transport"
    assert http.calls == 2
    # Valid (unexpired) metadata is of course still served.
    http.error = None
    clock.advance(11)
    assert cache.metadata().issuer == ISSUER
    _, warned = recorded(cache.metadata)
    assert warned == []
    unraisable.expect(RuntimeError, "down", count=1, adapter=ScriptedHttp)


def test_stale_on_error_false_still_serves_unexpired_entry_after_failed_refresh(unraisable):
    http = ScriptedHttp()
    cache, clock = make_cache(http, stale_on_error=False)
    cache.metadata()
    http.error = RuntimeError("down")
    clock.advance(100)
    with pytest.raises(InternalError):
        cache.refresh()
    assert cache.metadata().issuer == ISSUER  # still within its TTL
    assert http.calls == 2
    unraisable.expect(RuntimeError, "down", count=1, adapter=ScriptedHttp)


def test_max_stale_bounds_stale_serving(unraisable):
    http = ScriptedHttp()
    cache, clock = make_cache(http, max_stale=100)
    cache.metadata()  # expires at t0 + 3600
    http.error = RuntimeError("down")
    clock.advance(3600 + 99)  # 99s past expiry: still servable
    md, _ = recorded(cache.metadata)
    assert md.issuer == ISSUER
    clock.advance(11)  # 110s past expiry (and out of the window): too old
    with pytest.raises(InternalError) as ei:
        cache.metadata()
    assert ei.value.code == "transport"
    # Now inside a fresh window the over-age entry is not served either.
    with pytest.raises(InternalError) as ei2:
        cache.metadata()
    assert ei2.value.code == "discovery_backoff"
    unraisable.expect(RuntimeError, "down", count=2, adapter=ScriptedHttp)


def test_max_stale_is_enforced_inside_the_backoff_window_too(unraisable):
    http = ScriptedHttp()
    cache, clock = make_cache(http, max_stale=100, failure_backoff=1000)
    cache.metadata()
    http.error = RuntimeError("down")
    clock.advance(3600 + 50)
    md, _ = recorded(cache.metadata)  # failure recorded, stale served
    assert md.issuer == ISSUER
    calls = http.calls
    clock.advance(60)  # 110s past expiry, still inside the 1000s window
    with pytest.raises(InternalError) as ei:
        cache.metadata()
    assert ei.value.code == "discovery_backoff"
    assert http.calls == calls
    unraisable.expect(RuntimeError, "down", count=1, adapter=ScriptedHttp)


def test_max_stale_zero_never_serves_expired(unraisable):
    http = ScriptedHttp()
    cache, clock = make_cache(http, max_stale=0)
    cache.metadata()
    clock.advance(3601)
    http.error = RuntimeError("down")
    with pytest.raises(InternalError):
        cache.metadata()
    unraisable.expect(RuntimeError, "down", count=1, adapter=ScriptedHttp)


def test_stale_warning_is_a_user_warning_and_never_raises_under_error_filter(unraisable):
    http = ScriptedHttp()
    cache, clock = make_cache(http)
    cache.metadata()
    clock.advance(3601)
    http.error = RuntimeError("down")
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        # Serving stale metadata must not turn into an exception.
        assert cache.metadata().issuer == ISSUER
    unraisable.expect(RuntimeError, "down", count=1, adapter=ScriptedHttp)


# --- jwks() ---------------------------------------------------------------------


def test_jwks_identity_survives_metadata_refresh_with_unchanged_uri():
    http = ScriptedHttp()
    http.keys[JWKS_URI] = {"keys": []}
    http.headers = [("Cache-Control", "max-age=60")]
    cache, clock = make_cache(http)
    first = cache.jwks()
    assert isinstance(first, rp.JwksCache)
    assert first.jwks_uri == JWKS_URI and first.issuer == ISSUER
    assert first.jwks() == {"keys": []}
    assert http.jwks_calls == 1
    assert cache.jwks() is first
    clock.advance(61)  # discovery document expired, keys (3600s) not
    assert cache.metadata().issuer == ISSUER
    assert http.calls == 2
    assert cache.jwks() is first
    first.jwks()
    assert http.jwks_calls == 1  # the cached keys survived the metadata refresh
    assert cache.refresh() is None
    assert http.calls == 3
    assert cache.jwks() is first


def test_jwks_cache_is_replaced_when_jwks_uri_changes_and_old_one_is_never_returned_again():
    http = ScriptedHttp()
    http.headers = [("Cache-Control", "max-age=60")]
    cache, clock = make_cache(http)
    old = cache.jwks()
    assert old.jwks_uri == JWKS_URI
    http.doc = md_doc(jwks_uri=JWKS_URI_2)
    clock.advance(61)
    new = cache.jwks()
    assert new is not old
    assert new.jwks_uri == JWKS_URI_2 and new.issuer == ISSUER
    assert old.jwks_uri == JWKS_URI  # the old object keeps its own binding
    assert cache.jwks() is new
    # Moving back yields yet another object, never the original.
    http.doc = md_doc()
    clock.advance(61)
    back = cache.jwks()
    assert back is not old and back is not new
    assert back.jwks_uri == JWKS_URI
    assert cache.jwks() is back


def test_document_without_jwks_uri_is_rejected_by_discovery():
    """``jwks_uri`` is required by the metadata schema, so ``jwks()`` always has one."""
    doc = md_doc()
    del doc["jwks_uri"]
    cache, _ = make_cache(ScriptedHttp(doc))
    with pytest.raises(GrindvaktError, match="jwks_uri"):
        cache.jwks()


def test_jwks_cache_shares_client_and_clock_and_default_ttl():
    http = ScriptedHttp(headerless=True)
    cache, clock = make_cache(http, default_ttl=10**5, max_ttl=10**5)
    with pytest.warns(UserWarning, match=r"default_ttl \(100000s\) applies to discovery"):
        jwks_cache = cache.jwks()
    _, warned = recorded(jwks_cache.jwks)  # headerless client: JwksCache warns for itself
    assert any("reports no response headers" in w for w in warned)
    assert http.jwks_calls == 1
    clock.advance(3599)  # the shared (injected) clock drives the JwksCache default TTL (3600)
    jwks_cache.jwks()
    assert http.jwks_calls == 1
    clock.advance(2)
    jwks_cache.jwks()
    assert http.jwks_calls == 2
    assert jwks_cache.fetch_timeout == cache.fetch_timeout
    cache2, _ = make_cache(http, fetch_timeout=7)
    with pytest.warns(UserWarning, match=r"default_ttl \(3600s\) applies to discovery"):
        assert cache2.jwks().fetch_timeout == 7.0


def test_jwks_cache_verifies_with_discovered_issuer():
    from pygrindvakt import jwt, keys

    key = keys.signing_key_from_jwk(keys.generate_ec_jwk("P-256"), alg="ES256", kid="k1")
    http = ScriptedHttp()
    http.keys[JWKS_URI] = {"keys": [key.public_jwk()]}
    cache, _ = make_cache(http)
    now = int(time.time())
    token = jwt.sign(key, {"iss": ISSUER, "sub": "alice", "aud": "demo", "iat": now, "exp": now + 300, "nonce": "n"})
    claims = cache.jwks().verify_id_token(token, "demo", "n", ["ES256"])
    assert claims["sub"] == "alice"
    other = jwt.sign(
        key, {"iss": "https://evil.example.com", "sub": "x", "aud": "demo", "iat": now, "exp": now + 300, "nonce": "n"}
    )
    with pytest.raises(JoseError):  # iss mismatch
        cache.jwks().verify_id_token(other, "demo", "n", ["ES256"])


# --- info() ---------------------------------------------------------------------

CROSS = "https://logout.other.example/logout"


def test_info_warnings_fire_once_per_fetch():
    http = ScriptedHttp(md_doc(end_session_endpoint=CROSS))
    cache, _ = make_cache(http)
    info, warned = recorded(cache.info)
    assert info.end_session_endpoint is None
    cross = [w for w in warned if "different origin" in w]
    assert len(cross) == 1
    # Repeated reads and the other accessors do not rebuild the info: no warning.
    for call in (cache.info, cache.info, cache.metadata, cache.jwks):
        _, warned = recorded(call)
        assert [w for w in warned if "different origin" in w] == []
    # A new fetch builds it again and warns again.
    _, warned = recorded(cache.refresh)
    assert len([w for w in warned if "different origin" in w]) == 1
    assert http.calls == 2


def test_metadata_first_then_info_warns_once():
    http = ScriptedHttp(md_doc(end_session_endpoint=CROSS))
    cache, _ = make_cache(http)
    _, warned = recorded(cache.metadata)
    assert len([w for w in warned if "different origin" in w]) == 1
    _, warned = recorded(cache.info)
    assert [w for w in warned if "different origin" in w] == []


def test_allow_cross_origin_end_session_is_passed_through():
    http = ScriptedHttp(md_doc(end_session_endpoint=CROSS))
    cache, _ = make_cache(http, allow_cross_origin_end_session=True)
    info, warned = recorded(cache.info)
    assert info.end_session_endpoint == CROSS
    assert [w for w in warned if "different origin" in w] == []


def test_info_equals_from_metadata():
    http = ScriptedHttp(md_doc(end_session_endpoint=f"{ISSUER}/logout"))
    cache, _ = make_cache(http)
    info = cache.info()
    expected = rp.ProviderInfo.from_metadata(cache.metadata())
    assert repr(info) == repr(expected)
    assert info.end_session_endpoint == f"{ISSUER}/logout"


# --- refresh() ------------------------------------------------------------------


def test_refresh_forces_a_refetch_even_when_fresh():
    http = ScriptedHttp()
    cache, _ = make_cache(http)
    cache.refresh()
    assert http.calls == 1
    cache.refresh()  # not rate-limited by success
    assert http.calls == 2
    http.doc = md_doc(scopes_supported=["openid", "new"])
    cache.refresh()
    assert cache.metadata().scopes_supported == ["openid", "new"]
    assert http.calls == 3


def test_refresh_after_failure_is_rate_limited_by_failure_backoff(unraisable):
    http = ScriptedHttp()
    http.error = RuntimeError("down")
    cache, clock = make_cache(http)
    with pytest.raises(InternalError):
        cache.refresh()
    assert http.calls == 1
    cache.refresh()  # inside the window: silent no-op
    cache.refresh()
    assert http.calls == 1
    clock.advance(9)
    cache.refresh()
    assert http.calls == 1
    clock.advance(2)
    with pytest.raises(InternalError):
        cache.refresh()
    assert http.calls == 2
    unraisable.expect(RuntimeError, "down", count=2, adapter=ScriptedHttp)


def test_failed_refresh_keeps_the_cached_document_and_opens_the_window(unraisable):
    http = ScriptedHttp()
    cache, clock = make_cache(http)
    cache.metadata()
    http.error = RuntimeError("down")
    with pytest.raises(InternalError):
        cache.refresh()
    assert cache.metadata().issuer == ISSUER  # unexpired entry kept
    cache.refresh()  # no-op inside the window
    assert http.calls == 2
    clock.advance(11)
    http.error = None
    cache.refresh()
    assert http.calls == 3
    unraisable.expect(RuntimeError, "down", count=1, adapter=ScriptedHttp)


# --- repr and clock hook --------------------------------------------------------


def test_repr_before_and_after_fetch_never_fetches():
    http = ScriptedHttp()
    cache, clock = make_cache(http)
    assert repr(cache) == f"DiscoveryCache(issuer='{ISSUER}', jwks_uri=None, expires_in=None)"
    assert http.calls == 0
    cache.metadata()
    assert repr(cache) == f"DiscoveryCache(issuer='{ISSUER}', jwks_uri='{JWKS_URI}', expires_in=3600)"
    clock.advance(100.7)
    assert f"expires_in={3600 - 101}" in repr(cache) or f"expires_in={3600 - 100}" in repr(cache)
    clock.advance(10_000)
    assert repr(cache).endswith("expires_in=0)")
    assert http.calls == 1


def test_repr_shows_nothing_else_and_escapes_untrusted_fields():
    hostile_issuer = "https://op.example.com/a'b"
    uri = "https://op.example.com/j'k"
    doc = md_doc(hostile_issuer, jwks_uri=uri, client_secret="s3cr3t-value", x_token="tok-123")
    http = ScriptedHttp(doc)
    http.discovery_url = f"{hostile_issuer}/.well-known/openid-configuration"
    cache = rp.DiscoveryCache(http, hostile_issuer, _now=Clock())
    cache.metadata()
    r = repr(cache)
    assert (
        r
        == "DiscoveryCache(issuer='https://op.example.com/a\\'b', jwks_uri='https://op.example.com/j\\'k', expires_in=3600)"
    )
    for secret in ("s3cr3t-value", "tok-123", "authorization", "token_endpoint"):
        assert secret not in r


def test_clock_hook_drives_expiry_deterministically():
    http = ScriptedHttp()
    clock = Clock(5_000_000.0)
    cache = rp.DiscoveryCache(http, ISSUER, _now=clock)
    cache.metadata()
    clock.t = 0.0  # a clock going backwards does not expire anything
    cache.metadata()
    assert http.calls == 1
    clock.t = 5_000_000.0 + 3599.9
    cache.metadata()
    assert http.calls == 1
    clock.t = 5_000_000.0 + 3600.0
    cache.metadata()
    assert http.calls == 2


def test_real_clock_does_not_expire_immediately():
    http = ScriptedHttp()
    cache = rp.DiscoveryCache(http, ISSUER)
    cache.metadata()
    cache.metadata()
    assert http.calls == 1


# --- waiter timeout applies the stale policy ------------------------------------


def _expired_cache_with_stalled_fetch(stalling, **kw):
    http, threads = stalling
    cache, clock = make_cache(http, fetch_timeout=0.5, **kw)
    cache.metadata()  # entry fetched (not stalled yet)
    clock.advance(3601)  # expired by 1s
    http.stall = True
    holder, _ = start_holder(http, threads, cache.metadata)
    return http, cache, clock, holder


def test_waiter_timeout_serves_stale_metadata_with_one_warning(stalling):
    http, cache, _, holder = _expired_cache_with_stalled_fetch(stalling)
    md, warned = recorded(cache.metadata)
    assert md.issuer == ISSUER
    assert len(warned) == 1 and "stale" in warned[0]
    _, warned = recorded(cache.info)  # repeat: still stale, no second warning
    assert warned == []
    assert cache.jwks().jwks_uri == JWKS_URI
    assert holder.is_alive()
    http.release.set()
    holder.join(timeout=10)
    assert cache.metadata().issuer == ISSUER
    assert http.calls == 2


def test_waiter_timeout_without_stale_on_error_still_raises(stalling):
    _, cache, _, _ = _expired_cache_with_stalled_fetch(stalling, stale_on_error=False)
    assert_flight_timeout(cache.metadata)


def test_waiter_timeout_beyond_max_stale_raises(stalling):
    http, threads = stalling
    cache, clock = make_cache(http, fetch_timeout=0.5, max_stale=100)
    cache.metadata()
    clock.advance(3601 + 100)  # expired for exactly max_stale
    http.stall = True
    start_holder(http, threads, cache.metadata)
    assert_flight_timeout(cache.metadata)


def test_waiter_timeout_without_any_entry_raises(stalling):
    http, threads = stalling
    http.stall = True
    cache, _ = make_cache(http, fetch_timeout=0.5)
    start_holder(http, threads, cache.metadata)
    assert_flight_timeout(cache.metadata)


def test_refresh_waiter_timeout_still_raises_even_with_stale_entry(stalling):
    _, cache, _, _ = _expired_cache_with_stalled_fetch(stalling)
    assert_flight_timeout(cache.refresh)


# --- discovery_backoff.retryable follows the stored cause -----------------------


def test_backoff_retryable_follows_a_transient_cause(unraisable):
    http = ScriptedHttp()
    http.error = RuntimeError("down")
    cache, _ = make_cache(http)
    with pytest.raises(InternalError) as first:
        cache.metadata()
    assert first.value.retryable is True
    with pytest.raises(InternalError) as ei:
        cache.metadata()
    assert ei.value.code == "discovery_backoff" and ei.value.retryable is True
    unraisable.expect(RuntimeError, "down", count=1, adapter=ScriptedHttp)


def test_backoff_retryable_follows_an_upstream_5xx_cause():
    http = ScriptedHttp()
    http.status = 503
    cache, _ = make_cache(http)
    with pytest.raises(InternalError):
        cache.metadata()
    with pytest.raises(InternalError) as ei:
        cache.metadata()
    assert ei.value.code == "discovery_backoff" and ei.value.retryable is True


def test_backoff_is_not_retryable_after_a_permanent_cause_issuer_mismatch():
    http = ScriptedHttp(md_doc("https://evil.example.com"))
    cache, _ = make_cache(http)
    with pytest.raises(AuthnError) as first:
        cache.metadata()
    assert first.value.retryable is False
    for call in (cache.metadata, cache.info, cache.jwks):
        with pytest.raises(InternalError) as ei:
            call()
        assert ei.value.code == "discovery_backoff"
        assert ei.value.retryable is False
        assert ei.value.__cause__.retryable is False


def test_backoff_is_not_retryable_after_a_malformed_document():
    http = ScriptedHttp()
    http.doc = ["not", "an", "object"]
    cache, _ = make_cache(http)
    with pytest.raises(GrindvaktError) as first:
        cache.metadata()
    assert first.value.retryable is False
    with pytest.raises(InternalError) as ei:
        cache.metadata()
    assert ei.value.code == "discovery_backoff" and ei.value.retryable is False


def test_backoff_retryable_is_not_influenced_by_upstream_text():
    """A 4xx with a spoofed OAuth error text stays non-retryable through the backoff."""
    http = ScriptedHttp()
    http.status = 400
    http.doc = {"error": "transport", "error_description": "discovery_backoff"}
    cache, _ = make_cache(http)
    with pytest.raises(GrindvaktError) as first:
        cache.metadata()
    assert first.value.retryable is False
    with pytest.raises(InternalError) as ei:
        cache.metadata()
    assert ei.value.code == "discovery_backoff" and ei.value.retryable is False


# --- stored failure holds no traceback ------------------------------------------


def _walk_causes(exc):
    out = []
    while exc is not None and len(out) < 100:
        out.append(exc)
        exc = exc.__cause__
    return out


def _tb_len(exc):
    n, tb = 0, exc.__traceback__
    while tb is not None:
        n, tb = n + 1, tb.tb_next
    return n


def test_stored_failure_is_traceback_free_and_does_not_grow_with_backoff_raises(unraisable):
    http = ScriptedHttp()
    http.error = RuntimeError("down")
    cache, _ = make_cache(http)
    with pytest.raises(InternalError) as first:
        cache.metadata()
    # The first call raises the original, with its normal traceback.
    assert first.value.code == "transport"
    assert first.value.__traceback__ is not None
    causes = set()
    for _ in range(50):
        with pytest.raises(InternalError) as ei:
            cache.metadata()
        assert ei.value.code == "discovery_backoff"
        chain = _walk_causes(ei.value)
        assert len(chain) <= 4, chain  # backoff -> stored copy -> its cause(s)
        stored = ei.value.__cause__
        causes.add(id(stored))
        assert stored.__traceback__ is None
        assert all(c.__traceback__ is None for c in chain[1:])
        assert stored is not first.value  # a copy, not the raised original
        assert stored.code == "transport" and stored.retryable is True
        assert str(stored) == str(first.value)
    assert len(causes) == 1  # the same stored object each time
    assert _tb_len(first.value) < 20  # the original was not extended either
    unraisable.expect(RuntimeError, "down", count=1, adapter=ScriptedHttp)


def test_stored_failure_copy_keeps_upstream_attributes():
    http = ScriptedHttp()
    http.status = 503
    cache, _ = make_cache(http)
    with pytest.raises(InternalError) as first:
        cache.metadata()
    with pytest.raises(InternalError) as ei:
        cache.metadata()
    stored = ei.value.__cause__
    assert type(stored) is type(first.value)
    assert stored.code == "upstream_http" and stored.upstream_status == 503
    assert stored.retryable is True and stored.auth_failure == first.value.auth_failure


# --- jwks() slot: an older entry never replaces a newer cache -------------------


class HookedHttp(ScriptedHttp):
    """Runs ``hook`` once, on the first ``post_form`` attribute lookup after arming.

    ``DiscoveryCache.jwks`` validates the client (``getattr(http, "post_form")``)
    while building its JwksCache, after it has read the metadata entry and
    before it installs the cache: the exact window of the race.
    """

    hook = None

    def __getattribute__(self, name):
        if name == "post_form":
            hook = object.__getattribute__(self, "hook")
            if hook is not None:
                self.hook = None  # disarm before running: the hook re-enters
                hook()
        return object.__getattribute__(self, name)


def test_older_entry_does_not_overwrite_a_newer_jwks_cache():
    http = HookedHttp()
    http.headers = [("Cache-Control", "max-age=60")]
    cache, clock = make_cache(http)
    cache.metadata()  # entry 1: JWKS_URI
    inner = {}

    def newer_thread_installs_u2():
        # Runs inside the outer jwks() call, which already holds entry 1.
        clock.advance(61)
        http.doc = md_doc(jwks_uri=JWKS_URI_2)
        inner["u2"] = cache.jwks()

    http.hook = newer_thread_installs_u2
    outer = cache.jwks()  # holds entry 1 (JWKS_URI), builds a cache for it
    assert inner["u2"].jwks_uri == JWKS_URI_2
    # The stale caller is served the NEWEST cache; it did not replace the slot.
    assert outer is inner["u2"]
    assert cache.jwks() is inner["u2"]
    assert cache.jwks().jwks_uri == JWKS_URI_2


def test_reuse_bumps_generation_so_older_entry_cannot_displace_it():
    """U1 (gen 1) -> U2 (gen 2, being installed by a slow thread) -> U1 again (gen 3)."""
    http = HookedHttp()
    http.headers = [("Cache-Control", "max-age=60")]
    cache, clock = make_cache(http)
    first_u1 = cache.jwks()  # slot: gen 1, U1
    clock.advance(61)
    http.doc = md_doc(jwks_uri=JWKS_URI_2)
    inner = {}

    def back_to_u1():
        # Meanwhile entry 3 (U1 again) is fetched and served by another thread.
        clock.advance(61)
        http.doc = md_doc()
        inner["u1"] = cache.jwks()

    cache.metadata()  # entry 2 (U2) is current; jwks() below must build U2
    http.hook = back_to_u1
    outer = cache.jwks()  # holds entry 2 (U2)
    assert inner["u1"] is first_u1  # reused, slot generation bumped to 3
    assert outer is first_u1  # entry 2 is stale: the newest cache is served
    assert cache.jwks() is first_u1


def test_concurrent_jwks_across_uri_changes_never_goes_back_to_an_old_cache():
    http = ScriptedHttp()
    http.headers = [("Cache-Control", "max-age=60")]
    cache, clock = make_cache(http)
    cache.metadata()
    stop = threading.Event()
    lock = threading.Lock()
    seen_u2 = []  # set once any call has returned the U2 cache
    violations = []

    def worker():
        while not stop.is_set():
            # Snapshot BEFORE the call: if U2 was already handed out, this call
            # started after that and must not get the U1 cache. (Checking the
            # append order instead is racy: a thread that got U1 before the swap
            # can be descheduled and append after a U2 entry.)
            with lock:
                u2_already_handed_out = bool(seen_u2)
            c = cache.jwks()
            uri = c.jwks_uri
            with lock:
                if uri == JWKS_URI_2:
                    seen_u2.append(True)
                elif u2_already_handed_out:
                    violations.append(uri)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    try:
        time.sleep(0.05)
        http.doc = md_doc(jwks_uri=JWKS_URI_2)
        clock.advance(61)
        time.sleep(0.3)
    finally:
        stop.set()
        for t in threads:
            t.join(timeout=10)
            assert not t.is_alive()
    assert cache.jwks().jwks_uri == JWKS_URI_2
    assert seen_u2, "U2 cache was never handed out"
    assert not violations, f"call started after U2 was handed out got {violations[:3]}"
