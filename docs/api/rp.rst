pygrindvakt.rp
==============

.. py:module:: pygrindvakt.rp

The Relying Party (client) side of OIDC / OAuth 2.0: discovery, the
authorization URL, code exchange, id_token verification, userinfo, and
``private_key_jwt`` client assertions. :doc:`../guides/rp` shows the full
flow.

Outbound HTTP goes through the ``http`` argument of the networked functions:
``None`` for the built-in client, a :class:`pygrindvakt.http.ReqwestClient`,
or any object implementing :class:`pygrindvakt.http.HttpClientProtocol`.
Networked calls block the calling thread with the GIL released.

.. note:: Nonce policy

   :func:`verify_id_token` refuses to run without an expected nonce unless
   ``unsafe_skip_nonce_check=True`` is passed explicitly. This Python API
   guard makes an intentional nonce-free flow visible in code review.

Provider and client
-------------------

.. py:class:: ProviderInfo(issuer: str, authorization_endpoint: str, token_endpoint: str, userinfo_endpoint: str | None = None, jwks_uri: str | None = None, *, end_session_endpoint: str | None = None)

   The minimal upstream-provider information the RP needs. Immutable. Build
   one by hand for a statically configured provider, or with
   :meth:`from_metadata` from a discovered document.

   Construction validates the issuer and every endpoint as absolute HTTPS
   URLs. Plain HTTP is allowed only when the issuer itself is a loopback HTTP
   development origin, and then only for loopback endpoint hosts. URL
   credentials and fragments are rejected before any credentials can be sent.

   .. py:staticmethod:: from_metadata(metadata: ProviderMetadata) -> ProviderInfo

      Build from a :class:`pygrindvakt.metadata.ProviderMetadata` (as
      returned by :func:`discover`); the userinfo endpoint is ``None``
      if the provider does not advertise one. An advertised
      ``end_session_endpoint`` is carried over if it passes issuer validation;
      an unsafe one is dropped (``None``) so login never depends on logout
      (the direct constructor stays strict and raises).

   .. py:property:: issuer
      :type: str
   .. py:property:: authorization_endpoint
      :type: str
   .. py:property:: token_endpoint
      :type: str
   .. py:property:: userinfo_endpoint
      :type: str | None
   .. py:property:: jwks_uri
      :type: str | None
   .. py:property:: end_session_endpoint
      :type: str | None

      OIDC RP-Initiated Logout endpoint, or ``None``. Validated like the
      other endpoints at construction. Used by :func:`end_session_url`.

.. py:class:: RpClient(client_id: str, redirect_uri: str, *, scope: str = "openid profile email", client_secret: str | None = None, auth_method: str | None = None, signing_key: SigningKey | None = None, post_logout_redirect_uris: list[str] | None = None)

   RP client configuration: ``client_id``, the ``redirect_uri`` registered
   at the OP, the requested ``scope``, and how the client authenticates to
   the upstream token endpoint. Immutable.

   ``auth_method`` is one of ``"none"``, ``"client_secret_basic"``,
   ``"client_secret_post"`` or ``"private_key_jwt"``. When omitted it
   defaults to ``client_secret_basic`` if ``client_secret`` is given, else
   ``none``. Inconsistent combinations raise ``ValueError`` rather than
   being ignored: a secret method without ``client_secret``,
   ``private_key_jwt`` without ``signing_key``, an empty secret, or a secret
   or key that the chosen method would not use.

   ``post_logout_redirect_uris`` registers the post-logout redirect URIs this
   client may use with :func:`end_session_url`. Each is validated like a
   redirect URI (absolute, no fragment) at construction.

   .. warning::

      ``client_secret`` is a credential. Load it from a secret store or an
      environment variable rather than embedding it in source; it is held in
      memory as a Python ``str`` for the lifetime of the object and cannot
      be zeroized. It is never included in ``repr()``.

   .. py:property:: client_id
      :type: str
   .. py:property:: redirect_uri
      :type: str
   .. py:property:: scope
      :type: str
   .. py:property:: post_logout_redirect_uris
      :type: tuple[str, ...]

      The registered post-logout redirect URIs (empty if none).
   .. py:property:: auth_method
      :type: str

      The resolved token-endpoint authentication method as a string.

   .. code-block:: python

      from pygrindvakt import keys, rp

      confidential = rp.RpClient("demo", "https://rp.example.com/cb", client_secret=os.environ["OIDC_SECRET"])
      public = rp.RpClient("spa", "https://rp.example.com/cb", scope="openid")
      rp_key = keys.signing_key_from_pem(open("rp-key.pem", "rb").read(), kid="rp-1")
      jwt_auth = rp.RpClient("jwt-rp", "https://rp.example.com/cb",
                             auth_method="private_key_jwt", signing_key=rp_key)

.. py:class:: TokenSet

   The result of a successful code exchange. ``access_token``, ``id_token``
   and ``token_type`` are pulled out of the response; :attr:`raw` is the
   full JSON body (for ``refresh_token``, ``expires_in``, ``scope``, ...).
   ``repr()`` never shows the token values.

   .. py:property:: access_token
      :type: str
   .. py:property:: id_token
      :type: str
   .. py:property:: token_type
      :type: str
   .. py:property:: raw
      :type: dict[str, Any]

      The complete token-endpoint response as a dict.

Starting the flow
-----------------

.. py:function:: authorization_url(provider: ProviderInfo, client: RpClient, state: str, nonce: str, code_challenge: str | None = None, extra: dict[str, str] | list[tuple[str, str]] | None = None, *, redirect_uri: str | None = None) -> str

   Build the authorization request URL to redirect the user to, with
   ``response_type=code``, the client's id, redirect URI and scope,
   ``state``, ``nonce`` and, when ``code_challenge`` is given,
   ``code_challenge_method=S256``. An authorization endpoint that already
   has a query string is extended with ``&``.

   ``state`` and ``nonce`` must be fresh random values bound to the user's
   session (:func:`pygrindvakt.util.random_token`); ``code_challenge`` is the
   PKCE ``S256`` challenge (:func:`pygrindvakt.pkce.s256_challenge`).
   ``extra`` adds further query parameters, as a dict or as a list of
   ``(name, value)`` pairs when a name must repeat; anything else raises
   ``ValueError``. Library-controlled parameter names and ambiguous duplicate
   extension names are rejected; repeatable ``resource`` remains supported.

   ``redirect_uri`` overrides the client's configured value for this call
   only. It must be an absolute URL without a fragment, else
   :class:`pygrindvakt.BadRequestError` is raised, and the same value must
   be passed to :func:`exchange_code`; keep it in the session.

.. py:function:: begin(provider: ProviderInfo, client: RpClient, *, extra: dict[str, str] | list[tuple[str, str]] | None = None, redirect_uri: str | None = None, pkce: bool = True, request_object_key: SigningKey | None = None) -> tuple[str, str, str, str | None]

   Start an authorization-code flow: generate a fresh ``state`` and
   ``nonce`` (32 random bytes each, base64url) and a PKCE verifier (48
   random bytes, 64 characters), and return ``(url, state, nonce,
   verifier)``. The challenge is ``S256``. Store ``state``, ``nonce`` and
   ``verifier`` (and ``redirect_uri`` if overridden) in the user's session.

   ``pkce=False`` omits PKCE and returns ``None`` as the verifier; it is
   refused with :class:`pygrindvakt.BadRequestError` for public clients
   (``auth_method="none"``). With ``request_object_key`` a signed request
   object (see :func:`signed_request_object`) is added as the ``request``
   parameter. ``extra`` and ``redirect_uri`` behave as in
   :func:`authorization_url`.

.. py:function:: signed_request_object(provider: ProviderInfo, client: RpClient, key: SigningKey, state: str, nonce: str, code_challenge: str | None = None, *, redirect_uri: str | None = None) -> str

   Build a signed request object (RFC 9101, "JAR") carrying the
   authorization-request parameters as JWT claims, signed with ``key``, with
   ``iss`` = the client id, ``aud`` = the issuer, a 300-second lifetime and
   a ``jti``.

   OpenID Federation automatic registration needs this: pass the result as
   the ``request`` parameter via ``authorization_url(..., extra={"request":
   jar})`` alongside the plain parameters. ``key`` must be one of the RP's
   published client keys. ``redirect_uri`` overrides the client's value, as
   in :func:`authorization_url`.

Discovery and keys
------------------

.. py:function:: discover(http: HttpClientProtocol | None, issuer: str) -> ProviderMetadata

   Discover provider metadata from ``issuer``
   (``<issuer>/.well-known/openid-configuration``).

   The issuer must be an ``https`` URL (plain ``http`` only for loopback
   hosts), and the ``issuer`` in the returned document must match the
   requested one exactly (OIDC Discovery section 4.3). Raises
   :class:`pygrindvakt.InternalError` on a transport failure or non-200,
   :class:`pygrindvakt.AuthnError` / :class:`pygrindvakt.BadRequestError`
   on an issuer mismatch or unusable document.

   The result's :attr:`~pygrindvakt.metadata.ProviderMetadata.raw` is the
   response body as fetched (parsed to a dict), obtained by recording the body
   handed to the upstream discovery routine; no validation is reimplemented.

.. py:function:: end_session_url(provider: ProviderInfo, *, id_token_hint: str | None = None, client: RpClient | None = None, post_logout_redirect_uri: str | None = None, state: str | None = None, logout_hint: str | None = None, ui_locales: str | None = None, extra: dict[str, str] | list[tuple[str, str]] | None = None) -> str

   Build the OIDC RP-Initiated Logout 1.0 URL to redirect the user to.
   Parameters are appended to ``provider.end_session_endpoint`` (an existing
   query is preserved) with proper percent-encoding. ``client`` adds
   ``client_id``. ``post_logout_redirect_uri`` is accepted **only** when
   ``client`` is given and the value exactly equals (string equality, as
   RP-Initiated Logout requires) one of ``client.post_logout_redirect_uris``;
   anything else, including an ``id_token_hint``-only call, raises
   :class:`pygrindvakt.BadRequestError`. Registration is structural so that a
   value taken from a request parameter cannot turn logout into an open
   redirect carrying ``id_token_hint``. It must also be registered at the OP. ``extra`` may not
   contain ``id_token_hint``, ``client_id``, ``post_logout_redirect_uri``,
   ``state``, ``logout_hint`` or ``ui_locales``, and neither may the endpoint's
   own query. Raises :class:`pygrindvakt.ConfigError` when the provider has no
   ``end_session_endpoint`` and :class:`pygrindvakt.BadRequestError` for unsafe
   or invalid input. ``state`` is echoed back to ``post_logout_redirect_uri``
   by the OP; generate it like the login ``state`` and verify it.

.. py:function:: fetch_jwks(http: HttpClientProtocol | None, jwks_uri: str, issuer: str) -> dict[str, Any]

   Fetch a JWKS document from ``jwks_uri`` for its associated ``issuer``
   and return it as a dict (``{"keys": [...]}``), ready for
   :func:`verify_id_token`. The issuer is mandatory so remote metadata cannot
   inherit the loopback HTTP development exception. This is a single
   uncached fetch; use :class:`JwksCache` to cache the key set and handle key
   rotation.

.. py:class:: JwksCache(http: HttpClientProtocol | None, jwks_uri: str, issuer: str, *, default_ttl: int = 3600, min_ttl: int = 60, max_ttl: int = 86400, min_refresh_interval: int = 30)

   A thread-safe cache of one issuer's JWK Set (frozen; read-only
   ``jwks_uri`` and ``issuer`` properties). ``jwks_uri`` and ``issuer`` are
   validated at construction exactly as :func:`fetch_jwks` does, and so is
   ``http``; no request is made until first use. Pass the cache wherever a
   ``jwks`` dict is accepted: :func:`verify_id_token` and, for signed
   responses, :func:`fetch_userinfo`.

   **Lifetime.** The set lives for the response's ``Cache-Control: max-age``
   minus its ``Age`` header when present, otherwise ``default_ttl`` seconds,
   clamped to ``[min_ttl, max_ttl]``. ``no-store``, ``no-cache`` and
   ``max-age=0`` (and an ``Age`` that exhausts ``max-age``) give a lifetime of
   0, which ``min_ttl`` then raises: with the default ``min_ttl=60`` such a
   response is still reused for 60 seconds, protecting the OP from a refetch
   on every request. Pass ``min_ttl=0`` to honour those directives literally
   (every use refetches). ``min_ttl`` must not exceed ``max_ttl``; negative
   values raise ``ValueError``.

   .. note::

      ``Cache-Control`` and ``Age`` are honoured only when the HTTP client
      reports response headers. The built-in
      :class:`~pygrindvakt.http.ReqwestClient` (or ``None``) always does; a
      Python :class:`~pygrindvakt.http.HttpClientProtocol` must return them
      (a 4-tuple, or :class:`~pygrindvakt.http.HttpFetchResponse` with
      ``headers``). Otherwise the lifetime is ``default_ttl`` (clamped) and a
      ``UserWarning`` is emitted on the cache's first fetch, so a revoked key
      can stay trusted for up to ``default_ttl``: return headers, or lower
      ``default_ttl`` / ``max_ttl``. ``no-store``, ``no-cache`` and
      ``max-age=0`` are floored to ``min_ttl``; ``min_ttl=0`` makes them
      uncached.

   **Never stale.** An expired set is not served. If the refetch fails,
   :meth:`jwks` and the verification methods raise the fetch error (transport
   failures as :class:`pygrindvakt.InternalError` with ``code == "transport"``
   and the original exception as ``__cause__``; non-200 answers with
   ``upstream_status`` and ``code == "upstream_http"``). Failed fetches are
   not cached, so the next call tries again; a failure while refreshing for an
   unknown ``kid`` keeps the still-valid cached set.

   **Concurrency.** Callers share one in-flight fetch: sixteen threads that
   find the cache empty or expired cause a single request, and the others wait
   (with the GIL released) and reuse its result. The GIL is released during
   the fetch. Do not call a cache from inside its own HTTP client.

   **Fork.** The cache is plain in-process memory, so a forked child keeps
   the cached set and its expiry (the clock is monotonic). As with the rest of
   the library, fork only while no other thread is inside a call.

   .. py:method:: jwks() -> dict[str, Any]

      The key set as a new dict, fetched first if none is cached or it has
      expired.

   .. py:method:: refresh() -> None

      Force a refetch. The very first fetch always goes through; after that a
      call within ``min_refresh_interval`` seconds of the previous fetch
      attempt (successful or not) returns without fetching. A failing fetch
      raises and leaves the cached set in place.

   .. py:method:: verify_id_token(id_token: str, client_id: str, expected_nonce: str | None, allowed_algorithms: list[str], *, trusted_additional_audiences: list[str] | None = None, unsafe_skip_nonce_check: bool = False, leeway: int | None = None, max_age: int | None = None, acr_values: list[str] | None = None, access_token: str | None = None, require_at_hash: bool = False, authorization_code: str | None = None, require_c_hash: bool = False, strict_hashes: bool = False) -> dict[str, Any]

      :func:`verify_id_token` against this cache's key set, with the cache's
      ``issuer`` as the expected issuer; the options are those of the
      function. Argument errors (missing nonce, bad algorithm name, ``leeway``
      above 300, ``require_at_hash`` without ``access_token``, an empty
      ``acr_values``) are raised before anything is fetched.

      The token's header is read without verification to find its ``kid``.
      If the cached set has keys with a ``kid`` and none equals the token's,
      the set is refetched once and the check repeated; if it still names no
      key, :class:`pygrindvakt.UnknownKeyError` (``code == "unknown_kid"``) is
      raised without verifying anything. That refetch happens at most once per
      ``min_refresh_interval`` seconds across all callers, counted from the
      previous fetch attempt, so a stream of tokens with random ``kid`` values
      cannot make the RP hammer the OP (they get ``UnknownKeyError`` without a
      fetch). A set whose keys have no ``kid``, and a token without one,
      behave as in :func:`verify_id_token`: no refresh, and the usual
      :class:`pygrindvakt.AuthnError`.

Finishing the flow
------------------

.. py:function:: exchange_code(http: HttpClientProtocol | None, provider: ProviderInfo, client: RpClient, code: str, code_verifier: str | None = None, *, redirect_uri: str | None = None) -> TokenSet

   Exchange an authorization ``code`` for tokens at the provider's token
   endpoint, authenticating as configured on ``client``
   (``client_secret_basic`` via the ``Authorization`` header,
   ``client_secret_post`` in the form, ``private_key_jwt`` with a fresh
   assertion, or nothing). ``code_verifier`` is the PKCE verifier matching
   the challenge sent in :func:`authorization_url`. If the authorization
   request overrode ``redirect_uri``, pass the same ``redirect_uri`` here.

   A non-200 response raises :class:`pygrindvakt.AuthnError` with a generic
   message; ``exc.code`` / ``exc.upstream_error`` hold the upstream OAuth error
   (for example ``invalid_client`` or ``invalid_grant``) and ``exc.upstream_status``,
   ``exc.upstream_error_description`` and ``exc.upstream_body`` the sanitized
   details. The description and body may echo secrets: never log them
   verbatim or show them to users.

.. py:function:: verify_id_token(jwks: dict[str, Any] | JwksCache, id_token: str, issuer: str, client_id: str, expected_nonce: str | None, allowed_algorithms: list[str], trusted_additional_audiences: list[str] | None = None, unsafe_skip_nonce_check: bool = False, *, leeway: int | None = None, max_age: int | None = None, acr_values: list[str] | None = None, access_token: str | None = None, require_at_hash: bool = False, authorization_code: str | None = None, require_c_hash: bool = False, strict_hashes: bool = False) -> dict[str, Any]

   Verify an ``id_token`` against the provider JWKS (a dict
   ``{"keys": [...]}`` or a :class:`JwksCache`), the expected ``issuer``,
   audience ``client_id`` and
   ``expected_nonce``; ``sub``, ``exp`` and ``iat`` are required. The protected
   algorithm must be in ``allowed_algorithms``. Additional audiences are
   rejected unless explicitly listed in ``trusted_additional_audiences``;
   multi-audience tokens also require ``azp`` equal to ``client_id``. Returns the
   validated claims as a dict. Raises :class:`pygrindvakt.AuthnError` (or
   another :class:`pygrindvakt.GrindvaktError` subclass) on any failure:
   bad signature, unknown key, wrong issuer or audience, expired, nonce
   mismatch. When the key set has several keys the token must carry a ``kid``
   (OIDC Core 10.1).

   With none of the keyword options the behaviour is unchanged (a ``at_hash``
   or ``c_hash`` claim is ignored, as there is nothing to check it against).
   The options:

   ``leeway``
      Clock-skew tolerance in seconds for ``exp`` / ``nbf`` / ``iat`` and for
      the future-``auth_time`` check; default 60. Above 300 raises
      :class:`pygrindvakt.BadRequestError` (it is for clock drift, not for
      reviving expired tokens); negative raises ``ValueError``. It is not
      added to ``max_age``.

   ``max_age``
      The OIDC ``max_age`` policy, in seconds. It is checked against the
      ``auth_time`` claim (never ``iat``): the token must carry a numeric
      ``auth_time`` (a fractional value is floored) with ``now <= auth_time +
      max_age``. A missing or non-numeric ``auth_time`` is an
      :class:`pygrindvakt.AuthnError`, as is an ``auth_time`` older than
      ``max_age`` or more than ``leeway`` in the future. Send ``max_age`` in
      the authorization request as well; this is the RP-side enforcement.

   ``acr_values``
      Allow-list: the ``acr`` claim must be a string in the list, else
      :class:`pygrindvakt.AuthnError`. An empty list is a
      :class:`pygrindvakt.BadRequestError`.

   ``access_token``, ``require_at_hash``
      ``at_hash`` is compared with the hash of ``access_token`` (constant
      time) when the id_token carries one. Without ``require_at_hash`` a token
      lacking ``at_hash`` is accepted, so it is **not** bound to the access
      token; set ``require_at_hash=True`` when the binding must hold (implicit
      and hybrid flows, or an OP known to emit it). ``require_at_hash`` without
      ``access_token`` raises :class:`pygrindvakt.BadRequestError`.

   ``authorization_code``, ``require_c_hash``
      The same for ``c_hash`` (hybrid flows need ``require_c_hash=True``).

   ``strict_hashes``
      By default an ``at_hash`` / ``c_hash`` claim is **ignored** when the
      matching ``access_token`` / ``authorization_code`` is not passed, so a
      missing binding goes unnoticed. With ``strict_hashes=True`` such a token
      raises :class:`pygrindvakt.AuthnError` instead. Implicit and hybrid
      flows must pass the values (with ``require_*_hash``) or set this.

   The hash is computed with the SHA-2 variant matching the token's ``alg``.
   ``EdDSA`` defines none: an ``EdDSA`` token that carries ``at_hash`` /
   ``c_hash`` while the matching value is supplied raises
   :class:`pygrindvakt.CryptoError`, and ``require_*_hash`` cannot be met by
   it in practice. An ``EdDSA`` token without the claim passes unless
   required. Supplying ``access_token`` or ``authorization_code`` to an OP
   that signs with ``EdDSA`` and emits hashes therefore fails; omit them there.

   ``expected_nonce`` is the nonce this RP sent in the authorization
   request. Passing ``None`` is refused with :class:`pygrindvakt.AuthnError`
   unless ``unsafe_skip_nonce_check=True`` is given as well, which disables
   the nonce check entirely and emits a ``UserWarning``. A nonce that is
   given is always enforced, flag or not.

   .. danger::

      Only skip the nonce check for flows that genuinely carry no nonce
      (e.g. a pure OAuth 2.0 flow that still returns an id_token). Skipping
      it for the standard code flow allows id_token replay.

.. py:function:: fetch_userinfo(http: HttpClientProtocol | None, userinfo_endpoint: str | None, access_token: str, expected_sub: str, issuer: str, *, method: Literal["POST", "GET"] = "POST", jwks: dict[str, Any] | JwksCache | None = None, client_id: str | None = None, allowed_algorithms: list[str] | None = None, trust: str | None = None, typ: str | None = None, max_age: int | None = 300, require_exp: bool = False) -> dict[str, Any]

   Fetch the UserInfo response with a Bearer ``access_token`` and return its
   claims as a dict. The ``sub`` must exactly equal ``expected_sub`` from the
   validated ID token. The associated ``issuer`` is mandatory to scope the
   loopback HTTP development exception. Raises :class:`pygrindvakt.AuthnError`
   on a non-200 or subject mismatch.

   ``userinfo_endpoint`` is ``None`` when the OP does not advertise one (see
   :attr:`ProviderInfo.userinfo_endpoint`); that raises
   :class:`pygrindvakt.ConfigError` (``provider does not advertise a
   userinfo_endpoint``).

   **Method.** ``method="POST"`` (the default) sends an empty form body with
   the token in the ``Authorization`` header and works with every HTTP client.
   ``method="GET"`` (OIDC Core 5.3.1 allows both) sends the token in the
   ``Authorization`` header of a GET and needs a client that supports request
   headers on GET: the built-in :class:`~pygrindvakt.http.ReqwestClient`, or a
   Python client with ``get(url, headers=...)`` or ``get_with_headers(url,
   headers)`` (see :doc:`http`). Otherwise :class:`pygrindvakt.ConfigError`.
   The built-in client never follows redirects, so the token is never sent to
   a redirect target; an injected client must do the same, or strip
   ``Authorization`` on a cross-origin redirect.

   **JSON responses** (any content type except ``application/jwt``) are parsed
   directly; none of the keyword arguments below is used.

   **Signed responses** (``application/jwt``) are verified, never trusted
   as-is, and fail closed: unless ``jwks``, ``client_id``,
   ``allowed_algorithms`` (non-empty) **and** ``trust`` are all given, an
   :class:`pygrindvakt.AuthnError` with ``code == "userinfo_unverifiable"`` is
   raised. ``jwks`` is a JWK Set dict or a :class:`JwksCache`, as for
   :func:`verify_id_token` (with a cache, an unknown ``kid`` in the response
   triggers the same single rate-limited refresh, else
   :class:`pygrindvakt.UnknownKeyError`). The JWS must be signed by a key in ``jwks`` with an
   allowed algorithm and carry a ``kid`` naming it, ``iss`` must equal
   ``issuer``, ``aud`` must be exactly ``client_id`` (multi-audience tokens are
   refused), and ``sub`` must equal ``expected_sub``. A token carrying
   ``nonce``, ``at_hash`` or ``c_hash``, or a ``typ`` of ``id_token+jwt`` /
   ``at+jwt``, is refused as an id_token or access token presented as
   UserInfo. ``exp`` is checked when present; ``require_exp=True`` demands it.

   ``trust`` states how the JWT is proven to be UserInfo rather than an
   id_token the OP signed with the same key and replayed here (the ``iss``,
   ``aud`` and ``sub`` of both are identical):

   * ``"typed"`` (safe): requires the exact JOSE ``typ`` header given as
     ``typ``. For OPs that type their UserInfo JWTs. ``typ`` must identify
     UserInfo specifically; ``JWT``, ``id_token+jwt`` and ``at+jwt`` are
     refused.
   * ``"dedicated_keys"`` (safe, as far as your attestation holds): you assert
     that ``jwks`` contains only keys the OP uses to sign UserInfo, never
     id_tokens, so a token that verifies cannot be an id_token. It does not
     prove the token is UserInfo rather than some other JWT signed by those
     keys.
   * ``"untyped_shared_key_compat"`` (**weakest**; compatibility only): for OPs
     that sign UserInfo and id_tokens with the same keys and set no ``typ``. A
     fresh id_token that omits ``nonce``, ``at_hash`` and ``c_hash`` is
     indistinguishable from UserInfo and **will be accepted** for up to
     ``max_age`` seconds. Prefer ``"typed"`` or ``"dedicated_keys"``.

   ``typ`` is only valid with ``trust="typed"``, and ``trust="typed"``
   requires it (``ValueError`` otherwise, as for an unknown ``trust`` or
   ``method``).

   ``max_age`` (default 300 seconds) requires an ``iat`` claim and rejects a
   token older than that (plus the library's 60 second clock-skew leeway), so
   a captured token cannot be replayed indefinitely even without ``exp``.

   .. warning::

      ``max_age=None`` removes both the ``iat`` requirement and the age bound.
      A token without ``exp`` can then be **replayed without limit**. Use it
      only for an OP that emits neither ``iat`` nor ``exp``.

   Encrypted (JWE) responses are not supported and raise
   :class:`pygrindvakt.AuthnError` with ``code == "userinfo_encrypted"``.

   .. code-block:: python

      profile = rp.fetch_userinfo(
          http_client, info.userinfo_endpoint, ts.access_token, claims["sub"],
          info.issuer,
          method="GET",
          jwks=jwks, client_id="demo", allowed_algorithms=["ES256"],
          trust="typed", typ="userinfo+jwt",   # only used if the OP signs it
      )

Client assertions and attribute mapping
---------------------------------------

.. py:function:: build_client_assertion(key: SigningKey, client_id: str, audience: str) -> str

   Build a ``private_key_jwt`` client assertion (RFC 7523) signed with
   ``key``: ``iss`` = ``sub`` = ``client_id``, ``aud`` = ``audience`` (the
   token endpoint URL), valid for 300 seconds, with a random ``jti``.
   :func:`exchange_code` calls this itself for a ``private_key_jwt`` client;
   use it directly for other endpoints that require client authentication.

.. py:function:: claims_to_attributes(claims: dict[str, Any]) -> dict[str, list[str]]

   Convert a userinfo or id_token claims dict into the attribute-map shape
   ``{name: [values]}`` used by identity proxies: strings become
   one-element lists, lists keep their string members, numbers and booleans
   are stringified, and anything else (nested objects, ``null``, empty
   lists) is dropped.

Example
-------

.. code-block:: python

   from pygrindvakt import AuthnError, http, rp

   http_client = http.ReqwestClient()
   info = rp.ProviderInfo.from_metadata(rp.discover(http_client, "https://op.example.com"))
   jwks_cache = rp.JwksCache(http_client, info.jwks_uri, info.issuer)   # once per process
   me = rp.RpClient("demo", "https://rp.example.com/cb", client_secret=os.environ["OIDC_SECRET"])

   # Login: keep state, nonce and verifier in the session.
   redirect_to, state, nonce, verifier = rp.begin(info, me)

   # Callback: check state, then exchange and verify.
   try:
       ts = rp.exchange_code(http_client, info, me, code, code_verifier=verifier)
       claims = rp.verify_id_token(jwks_cache, ts.id_token,
                                   info.issuer, me.client_id, nonce, ["ES256"])
       profile = rp.fetch_userinfo(http_client, info.userinfo_endpoint, ts.access_token,
                                   claims["sub"], info.issuer)
   except AuthnError:
       log.exception("login failed")            # never show str(e) to the user
       raise
   attributes = rp.claims_to_attributes(profile)   # {"email": ["alice@example.com"], ...}
