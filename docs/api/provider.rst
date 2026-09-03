pygrindvakt.provider
====================

.. py:module:: pygrindvakt.provider

The OpenID Provider engine.

A :class:`Provider` is constructed once at startup and shared across requests
and threads. Its endpoint methods take already-extracted inputs (query / form
dicts, header strings) and return :class:`pygrindvakt.http.Response` objects
or raise :class:`pygrindvakt.OAuthError`, so any web framework can drive it.
The framework guides (:doc:`../guides/op_flask`, :doc:`../guides/op_django`,
:doc:`../guides/op_fastapi`) show the five endpoints wired up.

One-time use of authorization codes, refresh tokens and ``private_key_jwt``
assertion ``jti`` values is enforced through a token-use store:
:class:`InMemoryTokenUseStore` (single process), :class:`RedisStore`
(shared), or any Python object satisfying :class:`TokenUseStoreProtocol`.

Constants
---------

.. py:data:: CLIENT_ASSERTION_TYPE
   :type: str
   :value: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

   The ``client_assertion_type`` form value for ``private_key_jwt`` (RFC
   7523).

.. py:data:: DEFAULT_CLIENT_ASSERTION_MAX_AGE
   :type: int

   The default maximum age (seconds) accepted for a client assertion's
   ``iat``.

.. py:data:: RESERVED_ID_TOKEN_CLAIMS
   :type: list[str]
   :value: ["iss", "sub", "aud", "exp", "iat", "nbf", "jti", "nonce", "auth_time", "acr"]

   Claim names that :meth:`Provider.authorization_redirect` refuses in
   ``extra_claims``.

Provider
--------

.. py:class:: Provider(metadata: ProviderMetadata, signing_key: SigningKey, clients: InMemoryClientStore | ClientStoreProtocol, codec: TokenCodec, lifetimes: TokenLifetimes | None = None, token_use_store: InMemoryTokenUseStore | RedisStore | TokenUseStoreProtocol | None = None, client_assertion_max_age: int | None = None)

   The OpenID Provider engine. Build once, share across requests.

   * ``metadata``: the discovery document, mainly the issuer and endpoint
     URLs (:class:`pygrindvakt.metadata.ProviderMetadata`). It is copied.
   * ``signing_key``: signs id_tokens; its public half is published in the
     JWKS (:class:`pygrindvakt.keys.SigningKey`).
   * ``clients``: an :class:`pygrindvakt.client.InMemoryClientStore` or any
     object implementing :class:`pygrindvakt.client.ClientStoreProtocol`
     (checked at construction; ``TypeError`` if ``get`` / ``put`` are
     missing).
   * ``codec``: seals codes and tokens (:class:`pygrindvakt.tokens.TokenCodec`).
   * ``lifetimes``: token lifetimes; defaults to :class:`TokenLifetimes`
     defaults.
   * ``token_use_store``: defaults to a fresh :class:`InMemoryTokenUseStore`,
     which is **per process**. See :doc:`../guides/stores`.
   * ``client_assertion_max_age``: overrides
     :data:`DEFAULT_CLIENT_ASSERTION_MAX_AGE`.

   .. py:property:: clients
      :type: InMemoryClientStore | ClientStoreProtocol

      The client store object passed at construction (the same Python
      object, so a Python store can be inspected or mutated by the app).

   .. py:property:: token_use_store
      :type: InMemoryTokenUseStore | RedisStore | TokenUseStoreProtocol

      The token-use store in effect.

   .. py:property:: metadata
      :type: ProviderMetadata
   .. py:property:: signing_key
      :type: SigningKey
   .. py:property:: lifetimes
      :type: TokenLifetimes
   .. py:property:: issuer
      :type: str

   .. py:method:: discovery_document() -> dict[str, Any]

      The ``/.well-known/openid-configuration`` document as a dict. Serve it
      with ``Response.json(op.discovery_document())``.

   .. py:method:: jwks_document() -> dict[str, Any]

      The JWKS document (``{"keys": [...]}``) as a dict: the public half of
      the signing key only.

   .. py:method:: validate_authorization_request(request: AuthorizationRequest) -> Client

      Validate an authorization request against the registered client
      (known ``client_id``, exact ``redirect_uri`` match, allowed
      ``response_type``, ``nonce`` present for implicit / hybrid flows, and
      so on) and return that :class:`pygrindvakt.client.Client`.

      .. warning::

         On failure the ``redirect_uri`` is **not** trusted: render the raised
         :class:`pygrindvakt.OAuthError` with ``.to_response()``, never with
         ``.to_redirect()``. Redirecting an unvalidated URI makes the OP an
         open redirector.

   .. py:method:: authorization_redirect(request: AuthorizationRequest, sub: str, external_claims: dict[str, list[str]] | None = None, acr: str | None = None, extra_claims: dict[str, Any] | None = None) -> Response

      After the user has authenticated: mint the authorization code (or, for
      implicit / hybrid response types, the tokens) for ``sub`` and return
      the ``302`` redirect back to the client, with ``state`` echoed.

      ``external_claims`` maps claim name to a **list of string values**, the
      shape an attribute-based identity backend produces. Multi-valued claims
      become JSON arrays; single values are coerced for the standard claims
      (``"true"`` becomes ``True`` for ``email_verified``), exactly as
      :func:`flatten_claims` does. ``acr`` sets the authentication context
      class reference. ``extra_claims`` are typed id_token claims (any JSON
      value); the reserved names in :data:`RESERVED_ID_TOKEN_CLAIMS` raise
      ``ValueError``. grindvakt would silently drop them, which could hide
      an attempt to override ``sub`` or ``nonce``.

      On :class:`pygrindvakt.OAuthError`, the request's ``redirect_uri`` has
      already been validated (you called
      :meth:`validate_authorization_request` before showing the login page),
      so ``e.to_redirect(request.redirect_uri)`` is safe.

   .. py:method:: handle_token_request(form: dict[str, str], token_url: str, auth_header: str | None = None, dpop: DpopProof | None = None) -> TokenResponse

      Handle a token-endpoint request for the ``authorization_code``,
      ``refresh_token`` and ``client_credentials`` grants, authenticating the
      client by ``client_secret_basic`` (``auth_header``),
      ``client_secret_post`` (form fields), ``private_key_jwt``
      (``client_assertion``) or ``none``, as registered.

      * ``form`` is the parsed form body.
      * ``token_url`` is the absolute token endpoint URL **from
        configuration**. It is the audience a ``private_key_jwt`` assertion
        must name and the ``htu`` a DPoP proof must be bound to. Never derive
        it from the ``Host`` header.
      * ``auth_header`` is the raw ``Authorization`` header, if any.
      * ``dpop`` is an already-validated :class:`pygrindvakt.dpop.DpopProof`
        if the request carried a ``DPoP`` header (see :doc:`../guides/dpop`);
        the issued tokens are then bound to its key and ``token_type`` is
        ``DPoP``.

      Authorization codes and refresh tokens are single-use: a replay is
      ``invalid_grant``. Refresh tokens are rotated. Raises
      :class:`pygrindvakt.OAuthError`; render it with ``.to_response()``.

   .. py:method:: userinfo(access_token: str, presented_jkt: str | None = None) -> dict[str, Any]

      Handle a userinfo request: validate ``access_token`` and return the
      claims (``sub`` plus the claims resolved at authorization time,
      filtered by scope). For a DPoP-bound token, ``presented_jkt`` (the
      ``jkt`` of a proof validated with
      :func:`pygrindvakt.dpop.validate_resource_proof`) must match the
      token's ``cnf.jkt``; a bound token presented as plain Bearer is
      rejected. Raises :class:`pygrindvakt.OAuthError`.

   .. py:method:: authenticate_client(form: dict[str, str], token_url: str, auth_header: str | None = None) -> Client

      Authenticate a client from a token-endpoint style request (form +
      ``Authorization`` header) and return the
      :class:`pygrindvakt.client.Client`, without processing a grant. Useful
      for custom endpoints (introspection, revocation, registration
      management) that need client authentication. A ``private_key_jwt``
      assertion's ``jti`` is consumed here too, so an assertion cannot be
      replayed against another endpoint.

   .. code-block:: python

      from pygrindvakt import OAuthError, client, keys, metadata, provider, tokens
      from pygrindvakt.request import AuthorizationRequest

      ISSUER = "https://op.example.com"
      op = provider.Provider(
          metadata.ProviderMetadata(ISSUER),
          keys.signing_key_from_pem(open("op-key.pem", "rb").read(), kid="op-1"),
          client.InMemoryClientStore([client.Client("demo", client_secret="s3cret",
                                                    redirect_uris=["https://rp.example.com/cb"])]),
          tokens.TokenCodec(os.environ["OP_SECRET"]),
          token_use_store=provider.RedisStore(os.environ["REDIS_URL"]),   # after fork!
      )

      # Authorization endpoint, GET:
      req = AuthorizationRequest.from_params(query)
      op.validate_authorization_request(req)                # OAuthError -> e.to_response()
      # ... authenticate the user, then:
      resp = op.authorization_redirect(req, "alice", {"email": ["alice@example.com"]})

      # Token endpoint:
      try:
          resp = op.handle_token_request(form, f"{ISSUER}/token", auth_header=auth).to_response()
      except OAuthError as e:
          resp = e.to_response()

Token lifetimes and responses
-----------------------------

.. py:class:: TokenLifetimes(*, code_ttl: int = 600, access_token_ttl: int = 3600, id_token_ttl: int = 3600, refresh_token_ttl: int = 2592000)

   Lifetimes in seconds of issued artefacts. Immutable.

   .. py:property:: code_ttl
      :type: int
   .. py:property:: access_token_ttl
      :type: int
   .. py:property:: id_token_ttl
      :type: int
   .. py:property:: refresh_token_ttl
      :type: int

.. py:class:: TokenResponse

   A successful token-endpoint response.

   .. py:property:: access_token
      :type: str
   .. py:property:: token_type
      :type: str

      ``"Bearer"``, or ``"DPoP"`` for a sender-constrained token.

   .. py:property:: expires_in
      :type: int
   .. py:property:: id_token
      :type: str | None
   .. py:property:: scope
      :type: str | None
   .. py:property:: refresh_token
      :type: str | None

   .. py:method:: to_dict() -> dict[str, Any]

      Exactly the JSON body to send.

   .. py:method:: to_response() -> Response

      The complete HTTP response: ``200``, JSON body, ``cache-control:
      no-store``.

Token-use stores
----------------

.. py:class:: TokenUseStoreProtocol

   The duck-typed one-time-use store protocol accepted as ``token_use_store``.
   The object is checked for a callable ``consume`` when the ``Provider`` is
   built.

   .. py:method:: consume(token_hash: str, ttl_secs: int) -> bool

      Atomically record ``token_hash`` as used for ``ttl_secs`` seconds and
      return ``True`` iff it was **not** already recorded. ``token_hash`` is
      an opaque hash, never the token itself, so the store never sees
      credentials.

      **Fails closed:** an exception, or a non-``bool`` return value, is
      logged through ``sys.unraisablehook`` and reported to grindvakt as a
      store failure, which the client sees as ``server_error`` (HTTP 500).
      It is deliberately *not* treated as "already used": that would make a
      database outage look like an attack and would hide the outage from
      operators.

   The method runs on the thread driving the provider call, holding the GIL.
   It may call back into pygrindvakt; a nested call runs on a helper thread
   and costs one thread spawn.

   .. code-block:: python

      class RedisPyTokenUseStore:
          """The same SET NX EX pattern as RedisStore, over redis-py."""

          def __init__(self, r):
              self.r = r

          def consume(self, token_hash, ttl_secs):
              return bool(self.r.set(f"op:used:{token_hash}", 1, ex=ttl_secs, nx=True))

.. py:class:: InMemoryTokenUseStore()

   Process-local one-time-use store for codes, refresh tokens and assertion
   ``jti`` values, with TTL expiry and periodic purge. Fine for a single
   process, wrong across replicas: a code consumed in one worker is still
   fresh in another. Use :class:`RedisStore` or a Python-backed store there.

   .. py:method:: consume(token_hash: str, ttl_secs: int) -> bool

      Mark ``token_hash`` used; ``True`` iff it was not already used.

.. py:class:: RedisStore(redis_url: str, key_prefix: str | None = None)

   Redis-backed one-time-use store (``SET key 1 EX ttl NX``) for
   multi-process deployments. ``redis_url`` is a ``redis://`` or
   ``rediss://`` URL; ``key_prefix`` defaults to :attr:`DEFAULT_KEY_PREFIX`.
   Raises :class:`pygrindvakt.ConfigError` on a URL it cannot parse.

   .. warning::

      Construct it **after** ``fork``, for example in a gunicorn
      ``post_fork`` hook or lazily in the worker. The store's connection
      manager runs on the runtime of the process that created it; a store
      inherited across ``fork`` fails closed with a clear error
      (``server_error`` to the client) rather than hanging. See
      :doc:`../guides/stores`.

   .. py:attribute:: DEFAULT_KEY_PREFIX
      :type: str
      :value: "grindvakt:token-use:"

   .. py:method:: consume(token_hash: str, ttl_secs: int) -> bool

Helpers
-------

.. py:function:: flatten_claims(external: dict[str, list[str]]) -> dict[str, Any]

   Flatten ``{claim: [values]}`` into id_token / userinfo claim values the way
   the provider does: multi-valued claims stay lists, single values are
   unwrapped, and standard claims are coerced to their proper type
   (``email_verified`` to ``bool``).

   .. code-block:: python

      provider.flatten_claims({"email_verified": ["true"], "groups": ["a", "b"], "name": ["N"]})
      # {"email_verified": True, "groups": ["a", "b"], "name": "N"}
