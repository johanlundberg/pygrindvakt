"""Error model: machine ``code``, ``upstream_*`` attributes, ``__cause__`` chaining."""

from __future__ import annotations

import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pygrindvakt
import pytest
from pygrindvakt import (
    AuthnError,
    GrindvaktError,
    InternalError,
    OAuthError,
    federation,
    rp,
)
from pygrindvakt.http import ReqwestClient

EXPECTED_CLASS_CODES = {
    "GrindvaktError": "internal",
    "BadRequestError": "bad_request",
    "AuthnError": "authn",
    "StateError": "state",
    "ConfigError": "config",
    "CryptoError": "crypto",
    "AttributeMappingError": "attribute",
    "JoseError": "jose",
    "UnknownKeyError": "unknown_kid",
    "JsonError": "json",
    "InternalError": "internal",
    "NoBoundEndpointError": "no_bound_endpoint",
    "UnknownModuleError": "unknown_module",
    "DpopError": "dpop",
    "DpopInvalidError": "invalid_dpop_proof",
    "DpopReplayError": "dpop_replay",
    "DpopNonceRequiredError": "use_dpop_nonce",
    "DpopServerError": "dpop_server",
}

UPSTREAM_ATTRS = (
    "upstream_status",
    "upstream_error",
    "upstream_error_description",
    "upstream_body",
)

PROV = rp.ProviderInfo("http://127.0.0.1:1", "http://127.0.0.1:1/a", "http://127.0.0.1:1/token")
RPC = rp.RpClient("demo", "https://rp.example.com/cb", client_secret="s")
VERIFIER = "v" * 48


@pytest.mark.parametrize("name,code", sorted(EXPECTED_CLASS_CODES.items()))
def test_class_level_code(name, code):
    cls = getattr(pygrindvakt, name)
    assert cls.code == code
    inst = cls("boom")
    assert inst.code == code
    assert str(inst) == "boom"
    for attr in UPSTREAM_ATTRS:
        assert getattr(inst, attr) is None


def test_oauth_error_code_is_instance_level():
    e = OAuthError("invalid_grant", "nope")
    assert e.code == "invalid_grant"
    assert e.upstream_status is None


def test_instance_code_override_does_not_leak_to_class():
    e = InternalError("x")
    e.code = "transport"
    assert InternalError("y").code == "internal"
    assert InternalError.code == "internal"


# --- upstream errors -------------------------------------------------------------


class FakeTokenClient:
    def __init__(self, status, body, ctype="application/json"):
        self.reply = (status, body, ctype)

    def get(self, url):
        return self.reply

    def post_form(self, url, form, headers):
        return self.reply


def test_exchange_code_400_exposes_upstream_details():
    body = b'{"error":"invalid_grant","error_description":"code expired for s3cret"}'
    with pytest.raises(AuthnError) as ei:
        rp.exchange_code(FakeTokenClient(400, body), PROV, RPC, "code", VERIFIER)
    e = ei.value
    assert str(e) == "authentication error: token endpoint returned 400"
    assert "s3cret" not in str(e)
    assert e.code == "invalid_grant"
    assert e.upstream_status == 400
    assert e.upstream_error == "invalid_grant"
    assert e.upstream_error_description == "code expired for s3cret"
    assert e.upstream_body is not None and "invalid_grant" in e.upstream_body


def test_upstream_body_is_escaped():
    body = b"bad \x1b[31mred\x1b[0m\nline2\rline3"
    with pytest.raises(AuthnError) as ei:
        rp.exchange_code(FakeTokenClient(400, body, "text/plain"), PROV, RPC, "code", VERIFIER)
    e = ei.value
    assert e.upstream_status == 400
    assert e.upstream_body is not None
    assert "\x1b" not in e.upstream_body
    assert "\n" not in e.upstream_body
    assert "\r" not in e.upstream_body
    assert "\x1b" not in str(e)
    # No OAuth error code in the body: the class default applies.
    assert e.upstream_error is None
    assert e.code == "authn"


def test_non_auth_upstream_error_code_is_always_upstream_http():
    body = b'{"error":"invalid_client","error_description":"d"}'
    with pytest.raises(InternalError) as ei:
        rp.fetch_jwks(FakeTokenClient(500, body), "http://127.0.0.1:1/jwks", "http://127.0.0.1:1")
    e = ei.value
    assert e.code == "upstream_http"
    assert e.upstream_error == "invalid_client"
    assert e.upstream_status == 500


def test_non_auth_upstream_failure_is_internal_with_attributes():
    with pytest.raises(InternalError) as ei:
        rp.fetch_jwks(
            FakeTokenClient(500, b"oops"),
            "http://127.0.0.1:1/jwks",
            "http://127.0.0.1:1",
        )
    e = ei.value
    assert e.upstream_status == 500
    assert e.code == "upstream_http"


# --- __cause__ chaining ----------------------------------------------------------


class RaisingClient:
    def __init__(self, exc):
        self.exc = exc

    def get(self, url):
        raise self.exc

    def post_form(self, url, form, headers):
        raise self.exc


@pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
def test_python_client_exception_is_chained():
    boom = ValueError("boom")
    with pytest.raises(InternalError) as ei:
        rp.exchange_code(RaisingClient(boom), PROV, RPC, "code", VERIFIER)
    assert ei.value.__cause__ is boom
    assert ei.value.code == "transport"
    assert ei.value.upstream_status is None


@pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
def test_python_client_get_exception_is_chained():
    boom = RuntimeError("get failed")
    with pytest.raises(InternalError) as ei:
        rp.discover(RaisingClient(boom), "http://127.0.0.1:1")
    assert ei.value.__cause__ is boom
    assert ei.value.code == "transport"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_reqwest_connect_failure_chains_connection_error():
    port = free_port()  # closed again: nothing listens
    client = ReqwestClient(connect_timeout=2, read_timeout=2, request_timeout=5)
    with pytest.raises(InternalError) as ei:
        client.get(f"http://127.0.0.1:{port}/")
    assert isinstance(ei.value.__cause__, ConnectionError)
    assert ei.value.code == "transport"
    with pytest.raises(InternalError) as ei:
        client.post_form(f"http://127.0.0.1:{port}/", [("a", "b")])
    assert isinstance(ei.value.__cause__, ConnectionError)


def test_reqwest_connect_failure_through_rp_function():
    port = free_port()
    client = ReqwestClient(connect_timeout=2, read_timeout=2, request_timeout=5)
    with pytest.raises(InternalError) as ei:
        rp.discover(client, f"http://127.0.0.1:{port}")
    assert isinstance(ei.value.__cause__, ConnectionError)
    assert ei.value.code == "transport"


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/slow":
            time.sleep(3)
        elif self.path == "/big":
            data = b"x" * 5000
            self.send_response(200)
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        self.send_response(200)
        self.send_header("content-length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


@pytest.fixture
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def test_reqwest_timeout_chains_timeout_error(server):
    client = ReqwestClient(connect_timeout=1, read_timeout=1, request_timeout=1)
    with pytest.raises(InternalError) as ei:
        client.get(f"{server}/slow")
    assert isinstance(ei.value.__cause__, TimeoutError)
    assert ei.value.code == "transport"


def test_reqwest_response_too_large(server):
    client = ReqwestClient(max_response_bytes=100)
    with pytest.raises(InternalError) as ei:
        client.get(f"{server}/big")
    assert ei.value.code == "response_too_large"
    assert ei.value.__cause__ is None


def test_success_after_failure_has_no_stale_cause(server):
    client = ReqwestClient(connect_timeout=1, read_timeout=1, request_timeout=1)
    with pytest.raises(InternalError):
        client.get(f"http://127.0.0.1:{free_port()}/")
    status, body, _ = client.get(f"{server}/")
    assert (status, body) == (200, b"ok")


def test_plain_internal_error_without_transport_failure_has_no_cause():
    # A bad return shape from the adapter is still a transport-level failure
    # raised by the adapter; but a plain Internal error elsewhere is not.
    with pytest.raises(GrindvaktError) as ei:
        rp.ProviderInfo("not a url", "x", "y")
    assert ei.value.__cause__ is None


def test_no_cross_call_leakage_between_threads(server):
    closed = free_port()
    results: dict[int, BaseException | None] = {}

    def fail(i):
        c = ReqwestClient(connect_timeout=2, read_timeout=2, request_timeout=5)
        try:
            c.get(f"http://127.0.0.1:{closed}/")
        except InternalError as e:
            results[i] = e

    def succeed(i):
        # Shares the process-wide default client; must never see another
        # thread's failure.
        try:
            for _ in range(5):
                rp.fetch_jwks(None, f"{server}/", server)
        except GrindvaktError as e:
            results[i] = e

    ths = [threading.Thread(target=fail, args=(i,)) for i in range(4)]
    ths += [threading.Thread(target=succeed, args=(10 + i,)) for i in range(4)]
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    for i in range(4):
        assert isinstance(results[i].__cause__, ConnectionError)
    for i in range(10, 14):
        # fetch_jwks of "ok" fails at JWKS parsing, never with a transport cause.
        assert results[i].__cause__ is None
        assert results[i].code != "transport"


@pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
def test_nested_calls_keep_their_own_causes():
    inner_boom = KeyError("inner")
    outer_boom = ValueError("outer")

    class Outer:
        def get(self, url):
            # A nested pygrindvakt call with its own failing client.
            with pytest.raises(InternalError) as ei:
                rp.discover(RaisingClient(inner_boom), "http://127.0.0.1:1")
            assert ei.value.__cause__ is inner_boom
            raise outer_boom

        def post_form(self, url, form, headers):
            raise outer_boom

    with pytest.raises(InternalError) as ei:
        rp.discover(Outer(), "http://127.0.0.1:1")
    assert ei.value.__cause__ is outer_boom


@pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
def test_tolerated_earlier_failure_is_not_blamed_for_a_later_error():
    """A failed fetch in a multi-fetch flow must only be attributed to the error
    that fetch produced. Trust-anchor resolution tolerates per-anchor failures
    and raises the last error; one anchor's client raises, the other answers
    500, so whichever error is raised must be self-consistent. (A stale-slot
    ``Internal`` error unrelated to a fetch is not producible through the
    public API; the attribution check compares the emitted message.)"""
    boom = ValueError("first anchor down")

    class Mixed:
        def get(self, url):
            if "ta1" in url:
                raise boom
            return (500, b"nope", "text/plain")

        def post_form(self, url, form, headers):
            return (500, b"", None)

    anchors = {"https://ta1.example": {"keys": []}, "https://ta2.example": {"keys": []}}
    with pytest.raises(GrindvaktError) as ei:
        federation.resolve_via_trust_anchors(Mixed(), "https://sub.example", anchors)
    e = ei.value
    if e.code == "transport":
        assert e.__cause__ is boom
    else:
        assert e.__cause__ is None
        assert e.upstream_status == 500
