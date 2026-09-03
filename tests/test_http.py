"""Framework-agnostic request/response types and the built-in HTTP client."""

import pytest

from pygrindvakt import http


def test_request_data_normalization():
    """Path loses its leading slash, method is upper-cased, header names lower-cased."""
    r = http.HttpRequestData(
        path="/OIDC/token", method="post", uri="https://op/OIDC/token?x=1",
        query={"x": "1"}, form={"grant_type": "code"}, body=b"grant_type=code",
        headers={"Authorization": "Bearer t", "Content-Type": "x"}, cookies={"s": "v"},
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
