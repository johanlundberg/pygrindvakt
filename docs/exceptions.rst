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

   .. py:method:: to_redirect(redirect_uri: str) -> pygrindvakt.http.Response

      Render as a ``302`` redirect back to the client with ``error``,
      ``error_description`` and ``state`` in the query string (the
      authorization-endpoint error response).

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
       tr = op.handle_token_request(form, TOKEN_URL, auth_header=auth)
       resp = tr.to_response()
   except OAuthError as e:
       resp = e.to_response()                 # client-safe: status, JSON body, no-store
   except pygrindvakt.GrindvaktError as e:
       log.exception("token endpoint failed")  # str(e) is for logs only
       resp = OAuthError("server_error").to_response()
