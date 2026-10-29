"""Framework-agnostic request/response types and the built-in HTTP client."""

import os
import signal
import sys
import time

import pytest
from pygrindvakt import http


def test_request_data_normalization():
    """Path loses its leading slash, method is upper-cased, header names lower-cased."""
    r = http.HttpRequestData(
        path="/OIDC/token",
        method="post",
        uri="https://op/OIDC/token?x=1",
        query={"x": "1"},
        form={"grant_type": "code"},
        body=b"grant_type=code",
        headers={"Authorization": "Bearer t", "Content-Type": "x"},
        cookies={"s": "v"},
    )
    assert r.path == "OIDC/token" and r.method == "POST"
    assert r.headers == {"authorization": "Bearer t", "content-type": "x"}
    assert r.authorization() == "Bearer t" and r.bearer_token() == "t"
    assert r.param("x") == "1" and r.param("grant_type") == "code" and r.param("nope") is None
    assert r.body == b"grant_type=code" and r.cookies == {"s": "v"}
    r.headers = {"X-A": "b"}
    assert r.headers == {"x-a": "b"} and r.bearer_token() is None
    assert "HttpRequestData" in repr(r)


def test_request_data_defaults():
    r = http.HttpRequestData()
    assert r.method == "GET" and r.query == {} and r.body == b""


def test_request_data_preserves_duplicate_parameter_pairs():
    """Adapters retain multiplicity until an OAuth parser can reject it."""
    r = http.HttpRequestData(
        query=[("client_id", "first"), ("client_id", "second")],
        form=[("grant_type", "authorization_code"), ("grant_type", "refresh_token")],
    )
    assert r.query_pairs == [("client_id", "first"), ("client_id", "second")]
    assert r.form_pairs == [
        ("grant_type", "authorization_code"),
        ("grant_type", "refresh_token"),
    ]


def test_response_builders():
    r = http.Response.redirect("https://x")
    assert r.status == 302 and r.header("Location") == "https://x"
    r = http.Response.json({"a": [1, 2]}, status=201)
    assert r.status == 201 and r.body == b'{"a":[1,2]}' and r.header("content-type") == "application/json"
    r = http.Response.html("<p>hi</p>")
    assert r.text() == "<p>hi</p>" and "text/html" in r.header("content-type")
    r = http.Response.text_response(404, "nope").with_header("x-a", "1").with_header("x-a", "2")
    assert r.status == 404 and [v for k, v in r.headers if k == "x-a"] == ["1", "2"]
    r2 = http.Response(200, [("a", "b")], b"body")
    r2.status = 500
    r2.body = b"x"
    assert r2.status == 500 and r2.body == b"x" and r2.headers == [("a", "b")]


def test_fetch_response():
    f = http.HttpFetchResponse(200, b'{"k": 1}', "application/json")
    assert f.json() == {"k": 1} and f.text() == '{"k": 1}' and f.status == 200


def test_reqwest_client_validation():
    with pytest.raises(ValueError):
        http.ReqwestClient(connect_timeout=0)
    with pytest.raises(ValueError):
        http.ReqwestClient(max_response_bytes=0)
    c = http.ReqwestClient(request_timeout=5)
    assert "request_timeout=5" in repr(c)


def test_reqwest_client_against_local_server():
    """The built-in client talks to a real local HTTP server, never follows
    redirects, and enforces the response-size cap."""
    import http.server
    import threading

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path == "/redir":
                self.send_response(302)
                self.send_header("Location", "/ok")
                self.end_headers()
                return
            if self.path == "/big":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"x" * 5000)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok": true}')

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(n)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"echo:" + body + b"|" + self.headers.get("X-Test", "").encode())

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        c = __import__("pygrindvakt").http.ReqwestClient(max_response_bytes=1000)
        st, body, ct = c.get(f"{base}/ok")
        assert (st, body, ct) == (200, b'{"ok": true}', "application/json")
        st, body, ct = c.get(f"{base}/redir")
        assert st == 302  # not followed
        st, body, ct = c.post_form(f"{base}/p", [("a", "b c")], [("X-Test", "hdr")])
        assert body == b"echo:a=b+c|hdr"
        from pygrindvakt import InternalError

        with pytest.raises(InternalError, match="byte limit"):
            c.get(f"{base}/big")
    finally:
        srv.shutdown()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="fork test is Linux-only")
@pytest.mark.filterwarnings("ignore:.*fork.*:DeprecationWarning")
def test_reqwest_client_usable_after_fork():
    """A client used (and its pool warmed) before ``fork`` keeps working in the
    child: the PID-keyed pool is rebuilt lazily and the runtime is per process.

    The fork is quiescent (no other thread is inside a pygrindvakt call). Fork
    while another thread holds an internal lock is documented as unsupported,
    so it is deliberately not tested."""
    import http.server as hs
    import threading

    class H(hs.BaseHTTPRequestHandler):
        # HTTP/1.1 + Content-Length => keep-alive, so the parent really leaves a
        # live pooled connection behind at fork time.
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "4")
            self.end_headers()
            self.wfile.write(b"pong")

    srv = hs.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_port}/"
    try:
        c = http.ReqwestClient()
        assert c.get(url)[:2] == (200, b"pong")  # warm the pool in the parent
        pid = os.fork()
        if pid == 0:  # child
            code = 1
            try:
                ok = c.get(url)[:2] == (200, b"pong")
                ok = ok and c.post_form(url, [("a", "b")])[0] in (200, 501)
                code = 0 if ok else 2
            finally:
                os._exit(code)
        # A stale lock or runtime in the child hangs forever: poll with a
        # deadline, then kill and reap so the test fails instead of the job.
        deadline = time.monotonic() + 30
        while True:
            done, status = os.waitpid(pid, os.WNOHANG)
            if done:
                break
            if time.monotonic() > deadline:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
                pytest.fail("forked child hung (30 s)")
            time.sleep(0.05)
        assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, status
        assert c.get(url)[:2] == (200, b"pong")  # parent unaffected
    finally:
        srv.shutdown()


def _recording_servers():
    """Two local servers on different ports. A redirects (status taken from the
    path, e.g. /307) to B; B records every request it receives."""
    import http.server as hs
    import threading

    received = []

    class B(hs.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _record(self):
            n = int(self.headers.get("Content-Length", 0))
            received.append((self.command, self.headers.get("Authorization"), self.rfile.read(n)))
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"b")

        do_GET = do_POST = _record

    b = hs.ThreadingHTTPServer(("127.0.0.1", 0), B)

    class A(hs.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _redirect(self):
            n = int(self.headers.get("Content-Length", 0))
            self.rfile.read(n)
            self.send_response(int(self.path.strip("/")))
            self.send_header("Location", f"http://127.0.0.1:{b.server_port}/steal")
            self.end_headers()

        do_GET = do_POST = _redirect

    a = hs.ThreadingHTTPServer(("127.0.0.1", 0), A)
    for s in (a, b):
        threading.Thread(target=s.serve_forever, daemon=True).start()
    return a, b, received


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_credentials_never_forwarded_on_cross_origin_redirect(status):
    a, b, received = _recording_servers()
    try:
        c = http.ReqwestClient()
        base = f"http://127.0.0.1:{a.server_port}/{status}"
        st, _, _ = c.get(base, [("Authorization", "Bearer secret-token")])
        assert st == status
        st, _, _ = c.post_form(base, [("client_secret", "hunter2")], [("Authorization", "Basic abc")])
        assert st == status
        st, _, _ = c.get(base)
        assert st == status
        assert received == []  # B was never contacted
    finally:
        a.shutdown()
        b.shutdown()


def test_reqwest_get_sends_headers():
    import http.server as hs
    import threading

    seen = {}

    class H(hs.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            seen["auth"] = self.headers.get("Authorization")
            seen["x"] = self.headers.get_all("X-Multi")
            self.send_response(200)
            self.end_headers()

    srv = hs.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        c = http.ReqwestClient()
        url = f"http://127.0.0.1:{srv.server_port}/"
        assert (
            c.get(
                url,
                headers=[
                    ("Authorization", "Bearer t"),
                    ("X-Multi", "1"),
                    ("X-Multi", "2"),
                ],
            )[0]
            == 200
        )
        assert seen == {"auth": "Bearer t", "x": ["1", "2"]}
        assert c.get(url, None)[0] == 200 and seen["auth"] is None
    finally:
        srv.shutdown()


@pytest.mark.parametrize(
    "headers",
    [
        [("bad name", "v")],
        [("", "v")],
        [("X-Ok", "line\nbreak")],
        [("X-Ok", "café\x00")],
    ],
)
def test_reqwest_get_invalid_header_is_bad_request(headers):
    from pygrindvakt import BadRequestError

    with pytest.raises(BadRequestError):
        http.ReqwestClient().get("http://127.0.0.1:9/", headers)


# --- supports_get_with_headers -----------------------------------------------------------


class _GetPost:
    def get(self, url):
        raise AssertionError("no request may be made")

    def post_form(self, url, form, headers):
        raise AssertionError("no request may be made")


class _GetHeaders(_GetPost):
    def get(self, url, headers=None):
        raise AssertionError("no request may be made")


class _GetKwargs(_GetPost):
    def get(self, url, **kwargs):
        raise AssertionError("no request may be made")


class _GetWithHeaders(_GetPost):
    def get_with_headers(self, url, headers):
        raise AssertionError("no request may be made")


class _PositionalOnly(_GetPost):
    def get(self, url, headers=None, /):
        raise AssertionError("no request may be made")


class _NoPost:
    def get(self, url, headers=None):
        raise AssertionError("no request may be made")


class _Exploding:
    @property
    def get(self):
        raise RuntimeError("boom")

    post_form = None


@pytest.mark.parametrize(
    ("client", "expected"),
    [
        (None, True),
        (http.ReqwestClient(), True),
        (_GetPost(), False),
        (_GetHeaders(), True),
        (_GetKwargs(), True),
        (_GetWithHeaders(), True),
        (_PositionalOnly(), False),
        (_NoPost(), False),
        (_Exploding(), False),
        (object(), False),
        ("https://example.com", False),
        (42, False),
        (print, False),
    ],
)
def test_supports_get_with_headers(client, expected):
    assert http.supports_get_with_headers(client) is expected
