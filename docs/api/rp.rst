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

.. py:class:: ProviderInfo(issuer: str, authorization_endpoint: str, token_endpoint: str, userinfo_endpoint: str | None = None, jwks_uri: str | None = None)

   The minimal upstream-provider information the RP needs. Immutable. Build
   one by hand for a statically configured provider, or with
   :meth:`from_metadata` from a discovered document.

   Construction validates the issuer and every endpoint as absolute HTTPS
   URLs. Plain HTTP is allowed only when the issuer itself is a loopback HTTP
   development origin, and then only for loopback endpoint hosts. URL
   credentials and fragments are rejected before any credentials can be sent.

   .. py:staticmethod:: from_metadata(metadata: ProviderMetadata) -> ProviderInfo

      Build from a :class:`pygrindvakt.metadata.ProviderMetadata` (as
      returned by :func:`discover`); the userinfo endpoint and JWKS URI are
      always set in that case.

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

.. py:class:: RpClient(client_id: str, redirect_uri: str, *, scope: str = "openid profile email", client_secret: str | None = None, auth_method: str | None = None, signing_key: SigningKey | None = None)

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

.. py:function:: fetch_jwks(http: HttpClientProtocol | None, jwks_uri: str, issuer: str) -> dict[str, Any]

   Fetch a JWKS document from ``jwks_uri`` for its associated ``issuer``
   and return it as a dict (``{"keys": [...]}``), ready for
   :func:`verify_id_token`. The issuer is mandatory so remote metadata cannot
   inherit the loopback HTTP development exception. Cache the result and
   refetch when an id_token arrives with an unknown ``kid``.

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

   A non-200 response raises :class:`pygrindvakt.AuthnError` carrying a
   sanitized, truncated copy of the upstream error body (for example
   ``invalid_client`` or ``invalid_grant``). That message is for logs.

.. py:function:: verify_id_token(jwks: dict[str, Any], id_token: str, issuer: str, client_id: str, expected_nonce: str | None, allowed_algorithms: list[str], trusted_additional_audiences: list[str] | None = None, unsafe_skip_nonce_check: bool = False) -> dict[str, Any]

   Verify an ``id_token`` against the provider JWKS (a dict
   ``{"keys": [...]}``), the expected ``issuer``, audience ``client_id`` and
   ``expected_nonce``; ``sub``, ``exp`` and ``iat`` are required. The protected
   algorithm must be in ``allowed_algorithms``. Additional audiences are
   rejected unless explicitly listed in ``trusted_additional_audiences``;
   multi-audience tokens also require ``azp`` equal to ``client_id``. Returns the
   validated claims as a dict. Raises :class:`pygrindvakt.AuthnError` (or
   another :class:`pygrindvakt.GrindvaktError` subclass) on any failure:
   bad signature, unknown key, wrong issuer or audience, expired, nonce
   mismatch.

   ``expected_nonce`` is the nonce this RP sent in the authorization
   request. Passing ``None`` is refused with :class:`pygrindvakt.AuthnError`
   unless ``unsafe_skip_nonce_check=True`` is given as well, which disables
   the nonce check entirely and emits a ``UserWarning``. A nonce that is
   given is always enforced, flag or not.

   .. danger::

      Only skip the nonce check for flows that genuinely carry no nonce
      (e.g. a pure OAuth 2.0 flow that still returns an id_token). Skipping
      it for the standard code flow allows id_token replay.

.. py:function:: fetch_userinfo(http: HttpClientProtocol | None, userinfo_endpoint: str, access_token: str, expected_sub: str, issuer: str) -> dict[str, Any]

   Fetch the userinfo document with a Bearer ``access_token`` and return it
   as a dict. The response must contain a string ``sub`` exactly equal to
   ``expected_sub`` from the validated ID token. The associated ``issuer``
   is mandatory to scope the loopback HTTP development exception. Raises
   :class:`pygrindvakt.AuthnError` on a non-200 or subject mismatch.

   The request is a **POST** with an empty form body and the token in the
   ``Authorization`` header (the ``HttpClient`` protocol has no per-request
   headers on GET). OIDC Core section 5.3 allows either method; an OP built
   with pygrindvakt should accept both at its userinfo endpoint.

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
   me = rp.RpClient("demo", "https://rp.example.com/cb", client_secret=os.environ["OIDC_SECRET"])

   # Login: keep state, nonce and verifier in the session.
   redirect_to, state, nonce, verifier = rp.begin(info, me)

   # Callback: check state, then exchange and verify.
   try:
       ts = rp.exchange_code(http_client, info, me, code, code_verifier=verifier)
       claims = rp.verify_id_token(rp.fetch_jwks(http_client, info.jwks_uri, info.issuer), ts.id_token,
                                   info.issuer, me.client_id, nonce, ["ES256"])
       profile = rp.fetch_userinfo(http_client, info.userinfo_endpoint, ts.access_token,
                                   claims["sub"], info.issuer)
   except AuthnError:
       log.exception("login failed")            # never show str(e) to the user
       raise
   attributes = rp.claims_to_attributes(profile)   # {"email": ["alice@example.com"], ...}
