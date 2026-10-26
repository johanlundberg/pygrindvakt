pygrindvakt.testing
===================

.. py:module:: pygrindvakt.testing

Helpers for testing code that uses pygrindvakt without a network: a static
HTTP client, a bridge from an RP's requests to an in-process
:class:`~pygrindvakt.provider.Provider`, and an ID Token minter.

.. warning::

   **Test-only.** Never make this module a runtime dependency of an
   application. Nothing in it is hardened for production: ``StaticHttpClient``
   answers from a dict, ``ProviderHttpClient`` runs the in-process provider
   with no network, TLS, timeouts or size limits, and ``mint_id_token`` signs
   whatever it is given with a key the caller supplies.

It is plain Python shipped in the wheel, has no third-party dependencies, and
is **not** imported by ``import pygrindvakt``: import it explicitly with
``from pygrindvakt import testing``.

.. versionadded:: 0.3.0

Example
-------

An RP test against an in-process OP (see ``tests/test_testing.py`` for the
whole flow including the authorization step):

.. code-block:: python

   from pygrindvakt import rp, testing

   http = testing.ProviderHttpClient(op, "https://op.example.com")
   info = rp.ProviderInfo.from_metadata(rp.discover(http, "https://op.example.com"))
   # ... drive op.authorization_redirect(...) to get a code ...
   tokens = rp.exchange_code(http, info, rp_client, code, code_verifier)
   claims = rp.JwksCache(http, info.jwks_uri, info.issuer).verify_id_token(
       tokens.id_token, "demo", expected_nonce, ["ES256"]
   )

Or serve fixed documents and assert on the requests made:

.. code-block:: python

   http = testing.StaticHttpClient.from_json(
       {
           "https://op.example.com/.well-known/openid-configuration": discovery_doc,
           "https://op.example.com/jwks": jwks_doc,
       }
   )
   cache = rp.DiscoveryCache(http, "https://op.example.com")
   assert http.calls[0].method == "GET"

Types
-----

.. py:data:: FetchResult
   :type: tuple[int, bytes, str | None, tuple[tuple[str, str], ...]]

   ``(status, body, content_type, headers)``: one canned response.
   ``headers`` are ``(name, value)`` pairs; names are lower-cased when
   returned to pygrindvakt. ``rp.JwksCache`` and ``rp.DiscoveryCache`` derive
   their TTL from ``Cache-Control`` and emit a one-time ``UserWarning``
   ("reports no response headers") when a response has no headers at all, so
   a response needs at least one header (normally ``Cache-Control``) to avoid
   it.

.. py:class:: RecordedRequest(method: str, url: str, form: tuple[tuple[str, str], ...] | None, headers: tuple[tuple[str, str], ...])

   A frozen dataclass: one request seen by a test client. ``form`` is
   ``None`` for a GET; ``headers`` is ``()`` when none were sent.

   .. warning::

      The recorder stores credentials verbatim in its attributes
      (``Authorization`` and other sensitive headers, form fields such as
      ``client_secret``, ``code``, ``code_verifier``, ``access_token``) so
      tests can assert on them. ``repr`` redacts the values of sensitive
      headers (``authorization``, ``proxy-authorization``, ``dpop``,
      ``cookie``, ``set-cookie``, ``x-api-key``) and form fields
      (``client_secret``, ``client_assertion``, ``code``, ``code_verifier``,
      ``access_token``, ``refresh_token``, ``id_token``, ``password``,
      ``assertion``, ``token``) as ``<redacted>``, case-insensitively, so
      pytest failure output does not leak them. Redact before dumping or
      serialising ``calls`` / ``forms`` yourself (JSON, JUnit, logs); use
      :meth:`redacted`.

   .. py:method:: redacted() -> RecordedRequest

      A copy with those header and form values replaced by ``"<redacted>"``.

   .. py:method:: header(name: str) -> str | None

      First request header ``name``, matched case-insensitively.

HTTP clients
------------

.. py:class:: StaticHttpClient(routes, *, default=(404, b"", "text/plain", ()))

   An ``HttpClientProtocol`` that answers from a map. ``routes`` maps a URL
   (any method) or a ``(METHOD, url)`` pair (that method only; the method is
   upper-cased at construction, so ``("post", url)`` matches a POST, and an
   empty method is a ``TypeError``) to
   a :data:`FetchResult` or to a callable taking a :class:`RecordedRequest`
   and returning one. A ``(METHOD, url)`` key wins over a plain URL key.
   Unmatched requests get ``default``.

   A response is the four-element :data:`FetchResult`, or the legacy
   three-element ``(status, body, content_type)`` form the HTTP client protocol
   also accepts (no headers; headerless by definition). Any other shape raises
   ``TypeError``:
   static values and ``default`` are checked in the constructor (the message
   names the route key), a callable's result when it is returned (the message
   names the request method and URL). A key that is neither a ``str`` nor a
   ``(str, str)`` pair is a ``TypeError`` too. ``routes`` is typed
   ``Mapping[Any, ...]`` (``Mapping`` is invariant in its key), so annotated
   ``dict[str, ...]``, ``dict[tuple[str, str], ...]`` and mixed dicts all
   type-check.

   **Headerless warning.** A route must be a four-element tuple with at
   least a ``Cache-Control`` header for ``rp.JwksCache`` /
   ``rp.DiscoveryCache`` to avoid the one-time "reports no response headers"
   warning (and to use the real TTL instead of ``default_ttl``). The
   three-element form, a four-element form with empty headers, and the
   default 404 are headerless. Test "no warning" claims with
   ``warnings.catch_warnings(record=True)`` and ``simplefilter("always")``,
   not ``simplefilter("error")``: pygrindvakt swallows an exception raised by
   ``warnings.warn``, so an ``error`` filter proves nothing.

   Every request is appended to :attr:`calls`. Redirects are never followed: a
   3xx response is returned verbatim and its ``Location`` is never requested.
   ``get`` accepts optional request headers and ``get_with_headers`` exists,
   so :func:`pygrindvakt.http.supports_get_with_headers` is ``True`` and
   ``rp.fetch_userinfo(method="GET")`` works. Not thread-safe.

   .. py:attribute:: calls
      :type: list[RecordedRequest]

      Every request, in order.

   .. py:classmethod:: from_json(routes: Mapping[str, object], *, default=..., cache_control: str | None = "max-age=300") -> StaticHttpClient

      Each value is a JSON-serialisable object answered as
      ``200 application/json`` with a ``Cache-Control: <cache_control>``
      header. ``cache_control=None`` sends no headers (so the caches warn
      once). ``default`` is not affected.

   .. py:method:: get(url: str, headers: list[tuple[str, str]] | None = None)

      Answer a GET.

   .. py:method:: get_with_headers(url: str, headers: list[tuple[str, str]])

      Answer a GET carrying request headers.

   .. py:method:: post_form(url: str, form: list[tuple[str, str]], headers: list[tuple[str, str]])

      Answer a form POST.

.. py:class:: ProviderHttpClient(op: Provider, issuer: str, *, token_path="/token", userinfo_path="/userinfo", jwks_path="/jwks", discovery_path="/.well-known/openid-configuration", cache_control: str | None = "max-age=300")

   An ``HttpClientProtocol`` that bridges an RP's requests to the in-process
   :class:`~pygrindvakt.provider.Provider` ``op``: discovery and JWKS (GET),
   the token endpoint (POST, using ``op.handle_token_request`` with the
   request's ``Authorization`` header) and UserInfo (POST, or GET with
   ``Authorization: Bearer``), each at ``issuer`` plus its path. An
   ``OAuthError`` from the provider becomes the response of
   ``OAuthError.to_response()``; any other URL is a 404. The provider's own
   metadata must advertise the same endpoint URLs. Calls back into
   pygrindvakt from inside the client are supported by the library, so no
   extra thread is needed. An ``OAuthError`` response carries its headers
   (``www-authenticate``, ``cache-control``, ...), lower-cased. UserInfo
   matches the ``Bearer`` scheme case-insensitively. The discovery and JWKS responses carry
   ``Cache-Control: <cache_control>`` (default ``max-age=300``), which
   ``rp.DiscoveryCache`` / ``rp.JwksCache`` use as the TTL without the
   headerless warning; ``cache_control=None`` returns them with no headers to
   exercise that path on purpose (the cache warns once and uses its
   ``default_ttl``). Token success responses carry ``cache-control: no-store``
   and ``pragma: no-cache`` (RFC 6749 section 5.1); other responses have no
   headers.

   UserInfo takes the token from ``Authorization: Bearer`` (GET or POST) or,
   on a POST with no ``Authorization`` header, from a form-encoded
   ``access_token`` (RFC 6750 section 2.2). An ``Authorization`` header together
   with a form ``access_token`` (or a repeated form ``access_token``) is a 400
   ``{"error": "invalid_request"}`` with
   ``www-authenticate: Bearer error="invalid_request"`` (RFC 6750 section 2).
   A missing credential, or an ``Authorization`` header that is present but
   not exactly ``Bearer <token>`` (blank, no token, extra or trailing
   whitespace, other scheme; the scheme is case-insensitive), is a 401 with
   ``www-authenticate: Bearer``. A present header never falls back to the
   form ``access_token``.

   .. warning::

      **DPoP is not supported.** The double passes no ``DpopProof`` to
      ``handle_token_request`` and no ``presented_jkt`` to ``userinfo``. A
      token or UserInfo request with a ``DPoP`` header (any case) or an
      ``Authorization: DPoP ...`` scheme raises ``NotImplementedError``, so a
      DPoP test fails loudly instead of passing or failing for the wrong
      reason. Test DPoP against the provider directly.

   To adjust one response in a subclass, override ``_answer(request)`` (it
   returns a response tuple; call ``super()._answer(request)`` for the rest)
   rather than ``get``, so recording and ``get_with_headers`` keep working.

   .. py:attribute:: calls
      :type: list[RecordedRequest]

      Every request, in order.

   .. py:property:: forms
      :type: list[list[tuple[str, str]]]

      The form body of each POST, in order (derived from :attr:`calls`).

   .. py:method:: get(url: str, headers: list[tuple[str, str]] | None = None)

      Answer a GET.

   .. py:method:: get_with_headers(url: str, headers: list[tuple[str, str]])

      Answer a GET carrying request headers.

   .. py:method:: post_form(url: str, form: list[tuple[str, str]], headers: list[tuple[str, str]])

      Answer a form POST.

Tokens
------

.. py:function:: mint_id_token(key: SigningKey, *, issuer: str, client_id: str, sub: str = "alice", nonce: str | None = None, access_token: str | None = None, code: str | None = None, lifetime: int = 300, iat: int | None = None, extra: Mapping[str, Any] | None = None) -> str

   Sign an ID Token with ``key`` (``alg`` and ``kid`` from the key). Claims:
   ``iss``, ``sub``, ``aud`` (``client_id``), ``iat`` (now unless given),
   ``exp`` (``iat + lifetime``); ``nonce`` when given; ``at_hash`` /
   ``c_hash`` from :func:`pygrindvakt.jwt.oidc_token_hash` when
   ``access_token`` / ``code`` is given. ``extra`` adds further claims
   (``azp``, ``auth_time``, ``jti``, ``acr``, ``amr``, ``email``, ...) but may
   not set ``iss``, ``sub``, ``aud``, ``exp``, ``iat``, ``nonce``,
   ``at_hash`` or ``c_hash``, even when this call does not set that claim:
   that raises ``ValueError``, before any hash is computed. ``lifetime`` must
   be an ``int`` (not ``bool``) greater than 0 and ``iat`` ``None`` or an
   ``int`` (not ``bool``) of at least 0, else ``ValueError``.

   An ``EdDSA`` key cannot carry ``at_hash`` / ``c_hash``: with
   ``access_token`` or ``code`` the ``CryptoError`` from ``oidc_token_hash``
   propagates.
