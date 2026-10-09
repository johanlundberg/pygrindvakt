Exceptions
==========

.. py:module:: pygrindvakt
   :no-index:

All errors raised by pygrindvakt derive from a single base class,
:class:`GrindvaktError`, so you can catch one base type or a specific subtype.
Every class carries a ``status_hint`` class attribute: the HTTP status that
conventionally accompanies the failure. It is a hint for your own error
handling, not something the binding sends anywhere.

The hierarchy mirrors grindvakt's ``Error`` and ``DpopError`` enums:

.. code-block:: text

   GrindvaktError(Exception)            status_hint
   ├── BadRequestError                  400
   ├── AuthnError                       401
   ├── StateError                       500
   ├── ConfigError                      500
   ├── CryptoError                      500
   ├── AttributeMappingError            500
   ├── JoseError                        500
   │   └── UnknownKeyError              401
   ├── JsonError                        500
   ├── InternalError                    500
   ├── NoBoundEndpointError             404
   ├── UnknownModuleError               404
   ├── OAuthError                       (per code: 400 / 401 / 500 / 503)
   └── DpopError                        400
       ├── DpopInvalidError             400
       ├── DpopReplayError              400
       ├── DpopNonceRequiredError       400
       └── DpopServerError              500

.. danger::

   Only :meth:`OAuthError.to_response` and :meth:`OAuthError.to_redirect`
   produce output that is safe to send to a client. The message of every
   other exception (``str(exc)``) is an operator-facing diagnostic: it may
   name internal hosts, quote upstream error bodies, or describe which
   cryptographic check failed. Log it; never put it in an HTTP response.

Base class
----------

.. py:exception:: GrindvaktError

   Base class for every pygrindvakt error.

   .. py:attribute:: code
      :type: str

      A short machine-readable identifier. Every class has a class-level
      default (see :ref:`error-codes`); an instance may override it with a
      more precise value. :attr:`OAuthError.code` has the same meaning.

   .. py:attribute:: upstream_status
      :type: int | None

      HTTP status of the upstream response that caused this error, else
      ``None``.

   .. py:attribute:: upstream_error
      :type: str | None

      The upstream's OAuth ``error`` code (capped at 64 characters), else
      ``None``.

   .. py:attribute:: upstream_error_description
      :type: str | None

      The upstream's ``error_description``, else ``None``.

   .. py:attribute:: upstream_body
      :type: str | None

      The upstream response body, else ``None``. Control and bidirectional
      characters are escaped and the length is capped.

   .. danger::

      ``upstream_error_description`` and ``upstream_body`` are free text from
      the upstream and may echo secrets (credentials, codes, tokens) or
      personal data. Escaping makes them safe to *print*, not safe to
      *disclose*: never log them verbatim and never return them to end users.
      ``upstream_status`` and ``upstream_error`` are not redacted.

   The ``upstream_*`` attributes are ``None`` unless the error was raised
   because an upstream endpoint (token, UserInfo, JWKS, discovery, federation)
   answered with a failure. ``str(exc)`` stays generic and does not contain
   the body, for example ``authentication error: token endpoint returned 400``.

.. _error-codes:

Error codes
-----------

``exc.code`` is the class default unless noted. These values are stable:

.. list-table::
   :header-rows: 1

   * - Class
     - Default ``code``
   * - ``GrindvaktError`` / ``InternalError``
     - ``internal``
   * - ``BadRequestError``
     - ``bad_request``
   * - ``AuthnError``
     - ``authn``
   * - ``StateError``
     - ``state``
   * - ``ConfigError``
     - ``config``
   * - ``CryptoError``
     - ``crypto``
   * - ``AttributeMappingError``
     - ``attribute``
   * - ``JoseError``
     - ``jose``
   * - ``UnknownKeyError``
     - ``unknown_kid``
   * - ``JsonError``
     - ``json``
   * - ``NoBoundEndpointError``
     - ``no_bound_endpoint``
   * - ``UnknownModuleError``
     - ``unknown_module``
   * - ``DpopError``
     - ``dpop``
   * - ``DpopInvalidError``
     - ``invalid_dpop_proof``
   * - ``DpopReplayError``
     - ``dpop_replay``
   * - ``DpopNonceRequiredError``
     - ``use_dpop_nonce``
   * - ``DpopServerError``
     - ``dpop_server``
   * - ``OAuthError``
     - the OAuth error string given at construction

Instance-level overrides:

* A failed token or UserInfo request (``AuthnError``) carries the upstream's
  OAuth ``error`` value when it sent one, for example ``invalid_client`` or
  ``invalid_grant`` (also available as ``upstream_error``). Without one the
  class default ``authn`` applies. Code values from the upstream are
  arbitrary strings; compare against known values, do not assume a closed set.
* ``userinfo_unverifiable`` (``AuthnError``): :func:`pygrindvakt.rp.fetch_userinfo`
  received a signed (``application/jwt``) UserInfo response but was not given
  everything needed to verify it (``jwks``, ``client_id``,
  ``allowed_algorithms``, ``trust``); it refuses rather than trusting it.
* ``userinfo_encrypted`` (``AuthnError``): the UserInfo response is an
  encrypted JWT (JWE), which is not supported.
* ``transport`` (``InternalError``): an outbound request failed before a
  response was obtained (connection refused, timeout, a Python ``HttpClient``
  that raised). The original failure is chained as ``__cause__``.
* ``response_too_large`` (``InternalError``): an outbound response exceeded the
  client's size cap.
* ``upstream_http`` (``InternalError``): a discovery, JWKS or federation
  fetch got a failing status. Always this value for such non-auth failures,
  even if the upstream sent an OAuth ``error`` (that stays in
  ``upstream_error``).

Transport causes
----------------

When an outbound fetch fails, the raised ``InternalError`` has ``code ==
"transport"`` and the underlying exception as ``__cause__``:

* the exception raised by your Python ``HttpClient`` (the very same object);
* for the built-in ``ReqwestClient``: ``TimeoutError`` for connect, read or
  total timeouts, ``ConnectionError`` for connection failures and ``OSError``
  for other transport or body-read failures. ``response_too_large`` has no
  cause.

The cause is captured per call, so concurrent and nested calls never see each
other's failures, and it is attached only to the error that the failed fetch
itself produced (a tolerated earlier failure is not blamed for an unrelated
error).

   .. py:attribute:: status_hint
      :type: int

      The HTTP status conventionally paired with this error class. ``500``
      on the base class; each subclass overrides it as listed above.

grindvakt errors
----------------

One subclass per ``grindvakt::Error`` variant.

.. py:exception:: BadRequestError

   The request was malformed (``status_hint`` 400). Raised, for example, by
   the federation and discovery parsers on an invalid entity identifier or a
   malformed policy, and by :meth:`pygrindvakt.federation.EntityStatement.jwks`
   when the statement carries no keys.

.. py:exception:: AuthnError

   Authentication failed somewhere in the flow (``status_hint`` 401). This is
   what the Relying Party functions raise when an upstream token endpoint or
   userinfo endpoint rejects the request, when an id_token fails
   verification, when :func:`pygrindvakt.rp.verify_id_token` is called
   without an expected nonce, and when a federation trust chain does not
   validate.

.. py:exception:: StateError

   Flow state could not be sealed or unsealed (``status_hint`` 500).

.. py:exception:: ConfigError

   Configuration is invalid (``status_hint`` 500). Raised, for instance, when
   :class:`pygrindvakt.provider.RedisStore` cannot parse its URL.

.. py:exception:: CryptoError

   Cryptographic or key-material failure (``status_hint`` 500): an unknown
   algorithm name, a PKCS#11 key that cannot be loaded, and similar.

.. py:exception:: AttributeMappingError

   Attribute mapping failure (``status_hint`` 500).

.. py:exception:: JoseError

   JOSE (JWS / JWE / JWK) error (``status_hint`` 500): a malformed JWK, a JWKS
   that does not deserialize, a JWK generation failure.

.. py:exception:: UnknownKeyError

   Subclass of :class:`JoseError` (``status_hint`` 401, ``code``
   ``unknown_kid``). Raised by :class:`pygrindvakt.rp.JwksCache` (and by
   :func:`pygrindvakt.rp.verify_id_token` / :func:`pygrindvakt.rp.fetch_userinfo`
   given a cache) when a token's ``kid`` names no key in the issuer's JWK Set
   even after the one rate-limited refresh. It is raised before the signature
   is checked and is the "reject, do not retry" signal for key-rotation
   handling. Because it derives from :class:`JoseError`, not
   :class:`AuthnError`, catch it explicitly if you treat both as a failed
   login.

.. py:exception:: JsonError

   JSON serialization or deserialization error (``status_hint`` 500).

.. py:exception:: InternalError

   Any other internal error (``status_hint`` 500). Outbound HTTP failures
   surface here: connection errors from the built-in client, a response that
   exceeds the size cap, a non-2xx status where one was required, and any
   exception raised by a Python ``HttpClient`` implementation.

.. py:exception:: NoBoundEndpointError

   No endpoint bound to the path (``status_hint`` 404).

.. py:exception:: UnknownModuleError

   Unknown module (``status_hint`` 404).

OAuthError
----------

.. py:exception:: OAuthError(code: str, description: str | None = None, state: str | None = None)

   An OAuth 2.0 / OpenID Connect protocol error (RFC 6749 section 5.2). This
   is the only exception that carries structured, client-facing data, and the
   only one with rendering methods.

   Raised by every :class:`pygrindvakt.provider.Provider` endpoint method and
   by :meth:`pygrindvakt.request.AuthorizationRequest.from_params`.
   Applications may also raise it themselves to translate their own
   authentication failures into a protocol response, for example
   ``OAuthError("access_denied", "wrong password", state)`` when a login form
   is submitted with bad credentials.

   ``code`` must be one of the recognised OAuth error strings:
   ``invalid_request``, ``invalid_client``, ``invalid_grant``,
   ``unauthorized_client``, ``unsupported_grant_type``,
   ``unsupported_response_type``, ``invalid_scope``, ``access_denied``,
   ``login_required``, ``server_error``, ``temporarily_unavailable`` or
   ``invalid_dpop_proof``. An unknown code raises ``ValueError`` at
   construction time, so a typo fails where it is written, not when the
   error is rendered.

   .. py:attribute:: code
      :type: str

      The OAuth error string, e.g. ``"invalid_request"``.

   .. py:attribute:: description
      :type: str | None

      Optional human-readable ``error_description``.

   .. py:attribute:: state
      :type: str | None

      The client's ``state`` value to echo back, if known.

   .. py:property:: http_status
      :type: int

      The HTTP status conventionally returned with this error code: ``400``
      for most codes, ``401`` for ``invalid_client``, ``500`` for
      ``server_error``, ``503`` for ``temporarily_unavailable``.

   .. py:property:: status_hint
      :type: int

      Alias of :attr:`http_status`, kept for parity with the other
      :class:`GrindvaktError` subclasses.

   .. py:method:: with_state(state: str | None) -> OAuthError

      Return a copy carrying ``state`` (the client's value to echo back).

   .. py:method:: to_response() -> pygrindvakt.http.Response

      Render as a direct JSON error response for the token and userinfo
      endpoints, and for authorization-endpoint failures that happen
      **before** the ``redirect_uri`` was validated.

      The result has the correct status, an ``application/json`` body of the
      form ``{"error": ..., "error_description": ...}``, a
      ``cache-control: no-store`` header and, for ``invalid_client``, a
      ``www-authenticate`` header. This output is safe to send to clients.

   .. py:method:: to_redirect(redirect_uri: str, response_mode: str) -> pygrindvakt.http.Response

      Render as a ``302`` redirect back to the client with ``error``,
      ``error_description`` and ``state`` in the query string, or in the URL
      fragment when ``response_mode="fragment"``. Pass the same mode selected
      for the successful authorization response. The mode is mandatory so an
      implicit or hybrid error cannot accidentally fall back to query mode.

      Only call this with a ``redirect_uri`` that has already been validated
      against the registered client, i.e. after
      :meth:`pygrindvakt.provider.Provider.validate_authorization_request`
      succeeded for that request. Redirecting to an unvalidated URI turns
      your OP into an open redirector.

DPoP errors
-----------

Raised by :func:`pygrindvakt.dpop.validate_proof` and
:func:`pygrindvakt.dpop.validate_resource_proof`. They mirror grindvakt's
``DpopError`` enum and are distinct from :class:`OAuthError` because RFC 9449
gives them their own response shapes; :doc:`guides/dpop` shows how to render
each one.

.. py:exception:: DpopError

   Base class for DPoP proof validation errors (``status_hint`` 400).

.. py:exception:: DpopInvalidError

   The DPoP proof is malformed or fails validation (``status_hint`` 400): a
   bad signature, wrong ``typ``, ``htm`` / ``htu`` mismatch, a stale ``iat``,
   or an ``ath`` that does not match the presented access token. Respond
   with ``invalid_dpop_proof``.

.. py:exception:: DpopReplayError

   The proof's ``jti`` was already seen within its lifetime (``status_hint``
   400). Respond with ``invalid_dpop_proof``.

.. py:exception:: DpopNonceRequiredError

   A server nonce is required but the proof carried none, or carried a stale
   or forged one (``status_hint`` 400). Challenge the client: respond with
   the ``use_dpop_nonce`` error and a fresh
   :func:`pygrindvakt.dpop.issue_nonce` value in a ``DPoP-Nonce`` header.

.. py:exception:: DpopServerError

   The replay store failed, so the proof could not be evaluated
   (``status_hint`` 500). Raised when a Python ``ReplayStore`` raises; the
   original exception has been logged through ``sys.unraisablehook``.

Example
-------

.. code-block:: python

   import logging

   import pygrindvakt
   from pygrindvakt import OAuthError

   log = logging.getLogger(__name__)

   try:
       tr = op.handle_token_request(form_pairs, TOKEN_URL, auth_header=auth)
       resp = tr.to_response()
   except OAuthError as e:
       resp = e.to_response()                 # client-safe: status, JSON body, no-store
   except pygrindvakt.GrindvaktError as e:
       log.exception("token endpoint failed")  # str(e) is for logs only
       resp = OAuthError("server_error").to_response()
