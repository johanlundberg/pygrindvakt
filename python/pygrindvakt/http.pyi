"""Type stubs for ``pygrindvakt.http`` - framework-agnostic request / response
types, the outbound ``HttpClient`` protocol, and the built-in reqwest client.

SECURITY: an injected ``HttpClientProtocol`` implementation is responsible for
timeouts, for *not* following redirects (a 307/308 would re-send token-endpoint
form bodies cross-origin), and for bounding response sizes. The built-in
``ReqwestClient`` does all three.

NAME SHADOWING: ``from pygrindvakt import http`` rebinds the name ``http`` in
the importing module and shadows the standard-library ``http`` package there
(``http.HTTPStatus``, ``http.client``, ``http.server`` ...). Prefer
``from pygrindvakt import http as gv_http`` or ``import pygrindvakt.http``.

THREADING: see ``ReqwestClient`` for the thread-safety and fork semantics of
the built-in client. A Python ``HttpClientProtocol`` implementation runs on the
calling thread while it holds the GIL, so one shared across threads must be
thread-safe itself.
"""

from typing import Any, Protocol

# Stub-only aliases (underscore-prefixed so they are not expected at runtime).
# What a client method may return: the ``(status, body, content_type)`` tuple or
# an ``HttpFetchResponse`` (see ``extract_fetch`` in ``src/http.rs``).
_FetchResult = tuple[int, bytes, str | None] | HttpFetchResponse
# What every networked function accepts as ``http``: any protocol client, the
# built-in ``ReqwestClient``, or ``None`` for the process-wide default client.
_HttpArg = HttpClientProtocol | ReqwestClient | None

class HttpClientProtocol(Protocol):
    """Outbound HTTP client protocol accepted wherever ``http=`` is taken.

    Either method may return an ``HttpFetchResponse`` or the
    ``(status, body, content_type)`` tuple. Exceptions are logged via
    ``sys.unraisablehook`` and reported as ``InternalError``.

    The implementation runs on the thread driving the pygrindvakt call, holding
    the GIL. An instance shared across threads must be thread-safe itself.
    Calling back into pygrindvakt from inside a method is supported; each such
    nested call runs on a helper thread.
    """

    def get(self, url: str) -> _FetchResult: ...
    def post_form(
        self,
        url: str,
        form: list[tuple[str, str]],
        headers: list[tuple[str, str]],
    ) -> _FetchResult: ...

class HttpRequestData:
    """A parsed inbound HTTP request, normalized for grindvakt.

    Build one from your framework's request object. ``headers`` keys are
    lower-cased; ``form`` is the parsed ``application/x-www-form-urlencoded``
    body.
    """

    def __init__(
        self,
        path: str = ...,
        method: str = ...,
        uri: str = ...,
        query: dict[str, str] | list[tuple[str, str]] | None = ...,
        form: dict[str, str] | list[tuple[str, str]] | None = ...,
        body: bytes | None = ...,
        headers: dict[str, str] | None = ...,
        cookies: dict[str, str] | None = ...,
    ) -> None: ...
    @property
    def path(self) -> str: ...
    @path.setter
    def path(self, value: str) -> None: ...
    @property
    def method(self) -> str: ...
    @method.setter
    def method(self, value: str) -> None: ...
    @property
    def uri(self) -> str: ...
    @uri.setter
    def uri(self, value: str) -> None: ...
    @property
    def query(self) -> dict[str, str]: ...
    @query.setter
    def query(self, value: dict[str, str]) -> None: ...
    @property
    def query_pairs(self) -> list[tuple[str, str]]: ...
    @property
    def form(self) -> dict[str, str]: ...
    @form.setter
    def form(self, value: dict[str, str]) -> None: ...
    @property
    def form_pairs(self) -> list[tuple[str, str]]: ...
    @property
    def body(self) -> bytes: ...
    @body.setter
    def body(self, value: bytes) -> None: ...
    @property
    def headers(self) -> dict[str, str]: ...
    @headers.setter
    def headers(self, value: dict[str, str]) -> None: ...
    @property
    def cookies(self) -> dict[str, str]: ...
    @cookies.setter
    def cookies(self, value: dict[str, str]) -> None: ...
    def param(self, key: str) -> str | None:
        """Look up a parameter from the query string first, then the form body."""
    def authorization(self) -> str | None:
        """The value of the ``Authorization`` header, if present."""
    def bearer_token(self) -> str | None:
        """Extract a Bearer token from the Authorization header."""

class Response:
    """A framework-agnostic HTTP response produced by grindvakt.

    ``headers`` is a list of ``(name, value)`` pairs (multi-valued headers such
    as ``set-cookie`` are supported); ``body`` is ``bytes``.
    """

    def __init__(
        self,
        status: int,
        headers: list[tuple[str, str]] | None = ...,
        body: bytes | None = ...,
    ) -> None: ...
    @property
    def status(self) -> int: ...
    @status.setter
    def status(self, value: int) -> None: ...
    @property
    def headers(self) -> list[tuple[str, str]]: ...
    @headers.setter
    def headers(self, value: list[tuple[str, str]]) -> None: ...
    @property
    def body(self) -> bytes: ...
    @body.setter
    def body(self, value: bytes) -> None: ...
    def text(self) -> str:
        """Body decoded as UTF-8 (lossy)."""
    def header(self, name: str) -> str | None:
        """First value of header ``name`` (case-insensitive), if any."""
    def with_header(self, name: str, value: str) -> Response:
        """Return a copy with an extra header appended."""
    def with_body(self, body: bytes) -> Response:
        """Return a copy with the body replaced."""
    @staticmethod
    def redirect(location: str) -> Response:
        """302 redirect to ``location``."""
    @staticmethod
    def html(body: str) -> Response:
        """A ``text/html`` response."""
    @staticmethod
    def json(value: Any, status: int = ...) -> Response:
        """An ``application/json`` response from any JSON-serializable value."""
    @staticmethod
    def text_response(status: int, body: str) -> Response:
        """A plain-text response."""

class HttpFetchResponse:
    """The result of an outbound fetch made through an ``HttpClient``."""

    def __init__(self, status: int, body: bytes, content_type: str | None = ...) -> None: ...
    @property
    def status(self) -> int: ...
    @property
    def body(self) -> bytes: ...
    @property
    def content_type(self) -> str | None: ...
    def text(self) -> str: ...
    def json(self) -> Any:
        """Parse the body as JSON into native Python objects."""

class ReqwestClient:
    """The built-in outbound HTTP client (reqwest + rustls).

    Never follows redirects, enforces connect/read/total timeouts and a
    streaming response-size cap. Also exposes ``get`` / ``post_form`` so it
    satisfies the Python ``HttpClientProtocol`` itself.

    Thread safety: instances are frozen and share their state behind an
    ``Arc``, so one instance may be used from many threads. The GIL is released
    during I/O, so concurrent calls run in parallel. ``http=None`` selects a
    process-wide default instance with the same properties.

    Fork safety: the connection pool is keyed by PID and rebuilt lazily in a
    child after ``fork``; inherited connections are never reused and the tokio
    runtime is rebuilt per process (ADR 0001). A request in flight in another
    thread at fork time does not exist in the child. A ``ReqwestClient`` may be
    created before ``fork``; a ``RedisStore`` must be created after.
    """

    def __init__(
        self,
        connect_timeout: int = ...,
        read_timeout: int = ...,
        request_timeout: int = ...,
        max_response_bytes: int = ...,
        user_agent: str | None = ...,
    ) -> None: ...
    def get(self, url: str) -> tuple[int, bytes, str | None]:
        """Issue a GET. Returns ``(status, body, content_type)``."""
    def post_form(
        self,
        url: str,
        form: list[tuple[str, str]],
        headers: list[tuple[str, str]] | None = ...,
    ) -> tuple[int, bytes, str | None]:
        """Issue a form-encoded POST. Returns ``(status, body, content_type)``."""
