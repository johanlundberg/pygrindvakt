pygrindvakt.http
================

.. py:module:: pygrindvakt.http

Framework-agnostic request and response types, the outbound ``HttpClient``
protocol, and the built-in reqwest client.

:class:`HttpRequestData` is what a web-framework adapter builds from the
incoming request (see :doc:`../guides/op_flask`); :class:`Response` is what
the application turns back into its framework's response type. Neither
depends on any framework.

Outbound HTTP (RP discovery, code exchange, federation fetches) goes through an
object satisfying the :class:`HttpClientProtocol`: either the built-in
:class:`ReqwestClient` or any Python object with ``get`` and ``post_form``
methods.

.. warning::

   An injected HTTP client is responsible for enforcing timeouts, for **not**
   following redirects (a 307 / 308 would re-send token-endpoint form bodies,
   including the ``client_secret`` and authorization code, cross-origin), and
   for bounding response sizes. The built-in client does all three.

Inbound request
---------------

.. py:class:: HttpRequestData(path: str = "", method: str = "GET", uri: str = "", query: dict[str, str] | None = None, form: dict[str, str] | None = None, body: bytes | None = None, headers: dict[str, str] | None = None, cookies: dict[str, str] | None = None)

   A parsed inbound HTTP request, normalized for grindvakt. Build one from
   your framework's request object.

   Normalization happens in the constructor and the setters: ``path`` loses
   its leading slash, ``method`` is upper-cased, and header names are
   lower-cased. ``form`` is the parsed ``application/x-www-form-urlencoded``
   body; ``body`` is the raw bytes. Every attribute is readable and writable.

   .. py:attribute:: path
      :type: str
   .. py:attribute:: method
      :type: str
   .. py:attribute:: uri
      :type: str
   .. py:attribute:: query
      :type: dict[str, str]
   .. py:attribute:: form
      :type: dict[str, str]
   .. py:attribute:: body
      :type: bytes
   .. py:attribute:: headers
      :type: dict[str, str]

      Header names are lower-cased on assignment.

   .. py:attribute:: cookies
      :type: dict[str, str]

   .. py:method:: param(key: str) -> str | None

      Look up a parameter from the query string first, then the form body.

   .. py:method:: authorization() -> str | None

      The value of the ``Authorization`` header, if present.

   .. py:method:: bearer_token() -> str | None

      Extract a Bearer token from the ``Authorization`` header, or ``None``
      when the header is absent or not a Bearer credential.

   Example, adapting a Flask request:

   .. code-block:: python

      import flask
      from pygrindvakt.http import HttpRequestData

      def request_data() -> HttpRequestData:
          r = flask.request
          return HttpRequestData(
              path=r.path.lstrip("/"),
              method=r.method,
              uri=r.url,
              query=list(r.args.items(multi=True)),
              form=list(r.form.items(multi=True)),
              body=r.get_data(),
              headers={k.lower(): v for k, v in r.headers.items()},
              cookies=r.cookies.to_dict(),
          )

Outbound response
-----------------

.. py:class:: Response(status: int, headers: list[tuple[str, str]] | None = None, body: bytes | None = None)

   A framework-agnostic HTTP response produced by grindvakt.

   ``headers`` is a list of ``(name, value)`` pairs, so multi-valued headers
   such as ``set-cookie`` are supported; ``body`` is ``bytes``. All three are
   readable and writable.

   .. py:attribute:: status
      :type: int
   .. py:attribute:: headers
      :type: list[tuple[str, str]]
   .. py:attribute:: body
      :type: bytes

   .. py:method:: text() -> str

      Body decoded as UTF-8 (lossy).

   .. py:method:: header(name: str) -> str | None

      First value of header ``name`` (case-insensitive), if any.

   .. py:method:: with_header(name: str, value: str) -> Response

      Return a copy with an extra header appended.

   .. py:method:: with_body(body: bytes) -> Response

      Return a copy with the body replaced.

   .. py:staticmethod:: redirect(location: str) -> Response

      A ``302`` redirect to ``location``.

   .. py:staticmethod:: html(body: str) -> Response

      A ``text/html`` response.

   .. py:staticmethod:: json(value: Any, status: int = 200) -> Response

      An ``application/json`` response from any JSON-serializable value.

   .. py:staticmethod:: text_response(status: int, body: str) -> Response

      A plain-text response.

   Example, converting to a framework response:

   .. code-block:: python

      from flask import Response as FlaskResponse
      from django.http import HttpResponse

      def to_flask(r):
          return FlaskResponse(r.body, status=r.status, headers=list(r.headers))

      def to_django(r):
          out = HttpResponse(r.body, status=r.status)
          del out["Content-Type"]          # keep only what pygrindvakt set
          for name, value in r.headers:
              out[name] = value
          return out

Outbound HTTP client protocol
-----------------------------

.. py:class:: HttpClientProtocol

   The duck-typed protocol accepted wherever an ``http`` argument is taken
   (every networked function in :mod:`pygrindvakt.rp`,
   :mod:`pygrindvakt.federation` and :mod:`pygrindvakt.discovery`). It is a
   :class:`typing.Protocol` in the stubs; at runtime any object with the two
   methods is accepted, and the methods are checked for existence when the
   object is first passed (``TypeError`` otherwise).

   Both methods may return either a ``(status, body, content_type)`` tuple or
   an :class:`HttpFetchResponse`. ``body`` must be ``bytes`` (not
   ``bytearray`` or ``memoryview``). An exception raised by either method is
   logged through ``sys.unraisablehook`` and reported to the caller as
   :class:`pygrindvakt.InternalError`.

   .. py:method:: get(url: str) -> tuple[int, bytes, str | None]

      Issue a GET and return ``(status, body, content_type)``.

   .. py:method:: post_form(url: str, form: list[tuple[str, str]], headers: list[tuple[str, str]]) -> tuple[int, bytes, str | None]

      Issue an ``application/x-www-form-urlencoded`` POST with the extra
      request ``headers`` (for example ``Authorization`` for
      ``client_secret_basic``) and return ``(status, body, content_type)``.
      ``form`` may be empty: :func:`pygrindvakt.rp.fetch_userinfo` sends the
      bearer token this way because the protocol has no per-request headers
      on ``get``.

   The implementation runs on the thread that is driving the pygrindvakt
   call, holding the GIL. It may call back into pygrindvakt, which is how a
   test's fake client drives an in-process
   :class:`pygrindvakt.provider.Provider`; the nested call runs on a helper
   thread and costs one thread spawn.

   Example, an ``httpx``-backed client with a private CA:

   .. code-block:: python

      import httpx

      class HttpxClient:
          def __init__(self, ca_file: str):
              self._c = httpx.Client(
                  verify=ca_file,
                  timeout=httpx.Timeout(10.0, connect=5.0),
                  follow_redirects=False,           # never follow redirects
              )

          def get(self, url):
              r = self._c.get(url)
              return r.status_code, r.content, r.headers.get("content-type")

          def post_form(self, url, form, headers):
              r = self._c.post(url, data=dict(form), headers=dict(headers))
              return r.status_code, r.content, r.headers.get("content-type")

      md = rp.discover(HttpxClient("/etc/ssl/private-ca.pem"), "https://op.example.com")

.. py:class:: HttpFetchResponse(status: int, body: bytes, content_type: str | None = None)

   The result of an outbound fetch made through an ``HttpClient``. A Python
   client may return one of these instead of the tuple.

   .. py:attribute:: status
      :type: int
   .. py:attribute:: body
      :type: bytes
   .. py:attribute:: content_type
      :type: str | None

   .. py:method:: text() -> str

      Body decoded as UTF-8 (lossy).

   .. py:method:: json() -> Any

      Parse the body as JSON into native Python objects.

Built-in client
---------------

.. py:class:: ReqwestClient(connect_timeout: int = 10, read_timeout: int = 15, request_timeout: int = 30, max_response_bytes: int = 8388608, user_agent: str | None = None)

   The built-in outbound HTTP client (reqwest + rustls; no OpenSSL).

   It never follows redirects, enforces connect / read / total timeouts (in
   seconds) and a streaming response-size cap (8 MiB by default; the cap is
   checked before every chunk is appended, so an untrusted ``Content-Length``
   cannot bypass it). Every limit must be greater than zero, otherwise the
   constructor raises ``ValueError``. The default ``user_agent`` is
   ``pygrindvakt/<version>``.

   The connection pool is keyed by process id and rebuilt after ``fork``, so a
   client created in a gunicorn master keeps working in the workers.

   It also exposes ``get`` / ``post_form`` so it satisfies the Python
   :class:`HttpClientProtocol` itself, which makes it usable from your own
   code for fetches that need the same hardening.

   .. py:method:: get(url: str) -> tuple[int, bytes, str | None]

      Issue a GET. Returns ``(status, body, content_type)``. A ``3xx`` comes
      back as-is (not followed). Raises :class:`pygrindvakt.InternalError` on
      connection failure or when the body exceeds ``max_response_bytes``.

   .. py:method:: post_form(url: str, form: list[tuple[str, str]], headers: list[tuple[str, str]] | None = None) -> tuple[int, bytes, str | None]

      Issue a form-encoded POST. Returns ``(status, body, content_type)``.

   Passing ``None`` as the ``http`` argument of any networked function
   selects a process-wide default ``ReqwestClient`` with the default limits.

   .. code-block:: python

      from pygrindvakt import http, rp

      client = http.ReqwestClient(request_timeout=5, max_response_bytes=256 * 1024)
      md = rp.discover(client, "https://op.example.com")
      status, body, content_type = client.get("https://op.example.com/jwks")
