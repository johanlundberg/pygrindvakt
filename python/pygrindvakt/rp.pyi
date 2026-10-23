"""Type stubs for ``pygrindvakt.rp`` - the relying-party (client) side of OIDC."""

from typing import Any, Literal, overload

from .http import _HttpArg, _HttpHeadersArg
from .keys import SigningKey
from .metadata import ProviderMetadata

MAX_ID_TOKEN_LEEWAY: int
"""Largest ``leeway`` (seconds) ``verify_id_token`` accepts (300).

A cap on skew tolerance, not a recommended value. A larger ``leeway`` raises
``ConfigError``.

.. versionadded:: 0.3.0
"""

class ProviderInfo:
    """Minimal upstream-provider information the RP needs.

    ``end_session_endpoint`` receives ``id_token_hint`` (the full ID token) in
    the query string, so it must have the same origin as ``issuer`` (scheme,
    host, effective port) unless ``allow_cross_origin_end_session=True``. The
    constructor raises ``ConfigError`` for a cross-origin endpoint without
    the opt-in; ``from_metadata`` drops it to ``None`` instead (so
    ``end_session_url`` raises ``ConfigError``). The opt-in still requires the
    scheme/userinfo/fragment checks to pass. Other metadata endpoints are not
    origin-checked.
    """

    def __init__(
        self,
        issuer: str,
        authorization_endpoint: str,
        token_endpoint: str,
        userinfo_endpoint: str | None = ...,
        jwks_uri: str | None = ...,
        *,
        end_session_endpoint: str | None = ...,
        allow_cross_origin_end_session: bool = ...,
    ) -> None: ...
    @staticmethod
    def from_metadata(metadata: ProviderMetadata, *, allow_cross_origin_end_session: bool = ...) -> ProviderInfo: ...
    @property
    def issuer(self) -> str: ...
    @property
    def authorization_endpoint(self) -> str: ...
    @property
    def token_endpoint(self) -> str: ...
    @property
    def userinfo_endpoint(self) -> str | None: ...
    @property
    def jwks_uri(self) -> str | None: ...
    @property
    def end_session_endpoint(self) -> str | None: ...
    def __repr__(self) -> str: ...

class RpClient:
    """RP client configuration, including the token-endpoint auth method.

    ``auth_method`` is one of ``"none"``, ``"client_secret_basic"``,
    ``"client_secret_post"`` or ``"private_key_jwt"``; it defaults to
    ``client_secret_basic`` when ``client_secret`` is given, else ``none``.
    Inconsistent combinations raise :class:`ConfigError` (also a
    ``ValueError``).

    ``post_logout_redirect_uris`` registers the only values
    :func:`end_session_url` will accept as ``post_logout_redirect_uri`` (exact
    string match); each is syntax-validated here.

    ``redirect_uris`` registers the alternative login redirect URIs accepted
    as the per-call ``redirect_uri=`` override (exact string match; the
    configured ``redirect_uri`` is always accepted). Entries are
    syntax-validated here and must not be plain ``http`` to a non-loopback
    host (``https``, loopback ``http`` and custom/private-use schemes for
    native apps are allowed). ``allow_unregistered_redirect_uri=True`` accepts
    any valid override instead (RFC 7591 dynamic registrations only; never
    feed it request-supplied values).
    """

    def __init__(
        self,
        client_id: str,
        redirect_uri: str,
        *,
        scope: str = ...,
        client_secret: str | None = ...,
        auth_method: str | None = ...,
        signing_key: SigningKey | None = ...,
        post_logout_redirect_uris: list[str] | None = ...,
        redirect_uris: list[str] | None = ...,
        allow_unregistered_redirect_uri: bool = ...,
    ) -> None: ...
    @property
    def client_id(self) -> str: ...
    @property
    def redirect_uri(self) -> str: ...
    @property
    def scope(self) -> str: ...
    @property
    def auth_method(self) -> str: ...
    @property
    def post_logout_redirect_uris(self) -> tuple[str, ...]: ...
    @property
    def redirect_uris(self) -> tuple[str, ...]: ...
    @property
    def allow_unregistered_redirect_uri(self) -> bool: ...
    def __repr__(self) -> str: ...

class TokenSet:
    """The result of a successful code exchange."""

    @property
    def access_token(self) -> str: ...
    @property
    def id_token(self) -> str: ...
    @property
    def token_type(self) -> str: ...
    @property
    def raw(self) -> dict[str, Any]: ...
    def __repr__(self) -> str: ...

def authorization_url(
    provider: ProviderInfo,
    client: RpClient,
    state: str,
    nonce: str,
    code_challenge: str | None = ...,
    extra: dict[str, str] | list[tuple[str, str]] | None = ...,
    *,
    redirect_uri: str | None = ...,
) -> str: ...
def signed_request_object(
    provider: ProviderInfo,
    client: RpClient,
    key: SigningKey,
    state: str,
    nonce: str,
    code_challenge: str | None = ...,
    *,
    redirect_uri: str | None = ...,
) -> str: ...
def begin(
    provider: ProviderInfo,
    client: RpClient,
    *,
    extra: dict[str, str] | list[tuple[str, str]] | None = ...,
    redirect_uri: str | None = ...,
    pkce: bool = ...,
    request_object_key: SigningKey | None = ...,
) -> tuple[str, str, str, str | None]: ...
def discover(http: _HttpArg, issuer: str) -> ProviderMetadata: ...
def end_session_url(
    provider: ProviderInfo,
    *,
    id_token_hint: str | None = ...,
    client: RpClient | None = ...,
    post_logout_redirect_uri: str | None = ...,
    state: str | None = ...,
    logout_hint: str | None = ...,
    ui_locales: str | None = ...,
    extra: dict[str, str] | list[tuple[str, str]] | None = ...,
) -> str:
    """OIDC RP-Initiated Logout 1.0 request URL.

    ``post_logout_redirect_uri`` is accepted only with ``client`` and when it
    exactly equals one of ``client.post_logout_redirect_uris``; otherwise
    ``BadRequestError``. This prevents an open redirect carrying
    ``id_token_hint`` when the value comes from a request parameter.
    """

def fetch_jwks(http: _HttpArg, jwks_uri: str, issuer: str) -> dict[str, Any]:
    """Fetch the JWK Set at ``jwks_uri`` and return it as a dict.

    A published JWK Set must not carry symmetric keys (OIDC Core section
    10.1). Every ``oct`` key is dropped from the result and a ``UserWarning``
    is emitted ("published JWKS contains a symmetric (oct) key, ignored"), so
    the returned set can never verify an ``HS256`` / ``HS384`` / ``HS512``
    token. Build the key set for MAC-signed ID tokens from the ``client_secret``
    instead; see :func:`verify_id_token`.

    The warning is emitted once per call (there is no global dedup). Python's
    warnings registry collapses identical messages per location by default,
    but under ``simplefilter("always")`` or ``"error"`` it fires on every
    call. The returned dict may therefore not equal the OP's published
    document; callers that cache or diff it should use a warnings filter or
    :class:`JwksCache`, which caches the filtered set.

    .. versionchanged:: 0.3.0
       ``oct`` keys are dropped with a ``UserWarning`` (once per call).
    """

def exchange_code(
    http: _HttpArg,
    provider: ProviderInfo,
    client: RpClient,
    code: str,
    code_verifier: str | None = ...,
    *,
    redirect_uri: str | None = ...,
) -> TokenSet: ...
def verify_id_token(
    jwks: dict[str, Any] | JwksCache,
    id_token: str,
    issuer: str,
    client_id: str,
    expected_nonce: str | None,
    allowed_algorithms: list[str],
    trusted_additional_audiences: list[str] | None = ...,
    unsafe_skip_nonce_check: bool = ...,
    *,
    leeway: int | None = ...,
    max_age: int | None = ...,
    acr_values: list[str] | None = ...,
    access_token: str | None = ...,
    require_at_hash: bool = ...,
    authorization_code: str | None = ...,
    require_c_hash: bool = ...,
    strict_hashes: bool = ...,
) -> dict[str, Any]:
    """Verify an id_token and return its claims.

    ``jwks`` is a key-set dict or a :class:`JwksCache`.

    ``HS256`` / ``HS384`` / ``HS512`` ID tokens are MAC'd with a key derived
    from the ``client_secret``, never from the OP's published JWK Set (OIDC
    Core section 10.1). Verify them with a key set you build yourself, for
    example ``{"keys": [{"kty": "oct", "k": <base64url(client_secret)>}]}``
    with ``allowed_algorithms=["HS256"]``. The secret must be at least as long
    as the hash output (32 / 48 / 64 bytes for ``HS256`` / ``HS384`` /
    ``HS512``, RFC 7518 section 3.2); a shorter ``oct`` key the token selects (by ``kid``) raises
    ``ConfigError`` with ``code == "weak_shared_secret"`` (the message never
    contains the key). A :class:`JwksCache` with an ``HS*`` algorithm raises
    ``ConfigError`` with ``code == "shared_secret_algorithm"``. ``none`` is
    never accepted (``ConfigError``, invalid algorithm).

    .. versionchanged:: 0.3.0
       A :class:`JwksCache` with ``HS*`` algorithms is refused, and a caller-built
       ``oct`` key shorter than the hash output is refused (``weak_shared_secret``;
       before, ``HS384`` / ``HS512`` keys of 33 bytes or more were accepted, and
       a 32-byte ``HS256`` secret failed with a confusing ``JoseError``).

    Optional checks, all off by default:

    * ``leeway``: clock-skew tolerance in seconds (default 60; above 300 raises
      ``ConfigError``).
    * ``max_age``: needs a numeric ``auth_time`` no older than ``max_age``
      seconds (``iat`` is not used; a missing or non-numeric ``auth_time`` is
      an ``AuthnError``; leeway is not added).
    * ``acr_values``: ``acr`` must be present and listed.
    * ``access_token`` / ``authorization_code``: check ``at_hash`` / ``c_hash``
      when present; ``require_at_hash`` / ``require_c_hash`` also reject
      tokens lacking the claim (and need the matching value, else
      ``ConfigError``). ``EdDSA`` tokens carrying a hash claim cannot be
      checked (``CryptoError``).
    * ``strict_hashes``: rejects (``AuthnError``) an id_token carrying
      ``at_hash`` / ``c_hash`` that cannot be checked (no matching
      ``access_token`` / ``authorization_code``), and requires ``at_hash`` /
      ``c_hash`` whenever ``access_token`` / ``authorization_code`` is passed,
      as if ``require_*`` were set. Code-flow callers who pass ``access_token``
      but whose OP omits ``at_hash`` must leave it off. ``EdDSA`` tokens cannot
      satisfy the requirement.
    """

class JwksCache:
    """Caching JWK Set fetcher for one issuer, with kid-rotation refresh.

    The set is refetched on expiry: ``Cache-Control: max-age`` minus ``Age``
    when present, else ``default_ttl``, clamped to ``[min_ttl, max_ttl]``
    (``no-store`` / ``no-cache`` / ``max-age=0`` are floored to ``min_ttl``;
    ``min_ttl=0`` leaves them uncached). ``Cache-Control`` is honoured only when
    the ``HttpClient`` reports response headers: the built-in client (``None`` /
    ``ReqwestClient``) always does, a Python adapter must return them (4-tuple
    or ``HttpFetchResponse(headers=...)``); otherwise ``default_ttl`` applies
    and a ``UserWarning`` is emitted on the first fetch. An expired set is never
    served: a failed refetch raises. Concurrent callers share one fetch.
    The cache is in-process memory; it stays valid after ``fork``.

    ``fetch_timeout`` (seconds, finite, at least 1e-9, default 45: the built-in client's 30s timeout plus margin) bounds how long a
    thread WAITS for another thread's in-flight fetch; on expiry the waiter
    raises ``InternalError`` with ``code == "jwks_fetch_timeout"``. It does not
    interrupt the thread running the fetch: a Python ``HttpClient`` adapter
    must set its own network timeouts, and a stalled adapter still stalls its
    own caller. The fetch carries on and its result is cached when it ends.

    Symmetric (``oct``) keys in the fetched document are dropped with a
    ``UserWarning`` (once per fetch): an OP must not publish them (OIDC Core
    section 10.1). ``HS256`` / ``HS384`` / ``HS512`` in ``allowed_algorithms``
    of :meth:`verify_id_token` raise ``ConfigError`` with
    ``code == "shared_secret_algorithm"``, with no override: MAC-signed ID
    tokens are verified with :func:`verify_id_token` and a key set built from
    the ``client_secret``.

    .. versionchanged:: 0.3.0
       ``oct`` keys are dropped with a warning and ``HS*`` algorithms are refused.
    """

    def __init__(
        self,
        http: _HttpArg,
        jwks_uri: str,
        issuer: str,
        *,
        default_ttl: int = 3600,
        min_ttl: int = 60,
        max_ttl: int = 86400,
        min_refresh_interval: int = 30,
        fetch_timeout: float = 45.0,
    ) -> None: ...
    @property
    def jwks_uri(self) -> str: ...
    @property
    def issuer(self) -> str: ...
    @property
    def fetch_timeout(self) -> float: ...
    def jwks(self) -> dict[str, Any]:
        """The cached key set, fetched first if absent or expired."""
    def refresh(self) -> None:
        """Force a refetch; a no-op within ``min_refresh_interval`` seconds of
        the previous attempt, except for the very first fetch."""
    def verify_id_token(
        self,
        id_token: str,
        client_id: str,
        expected_nonce: str | None,
        allowed_algorithms: list[str],
        *,
        trusted_additional_audiences: list[str] | None = ...,
        unsafe_skip_nonce_check: bool = ...,
        leeway: int | None = ...,
        max_age: int | None = ...,
        acr_values: list[str] | None = ...,
        access_token: str | None = ...,
        require_at_hash: bool = ...,
        authorization_code: str | None = ...,
        require_c_hash: bool = ...,
        strict_hashes: bool = ...,
    ) -> dict[str, Any]:
        """:func:`verify_id_token` against this cache's keys and issuer.

        If the token's ``kid`` is missing from a set whose keys have ``kid``s,
        the set is refreshed once (rate-limited by ``min_refresh_interval``)
        and a still-unknown ``kid`` raises ``UnknownKeyError``.

        ``HS256`` / ``HS384`` / ``HS512`` in ``allowed_algorithms`` raise
        ``ConfigError`` (``code == "shared_secret_algorithm"``) before any fetch.
        """
    def __repr__(self) -> str: ...

@overload
def fetch_userinfo(
    http: _HttpArg,
    userinfo_endpoint: str | None,
    access_token: str,
    expected_sub: str,
    issuer: str,
    *,
    method: Literal["POST"] = ...,
    jwks: dict[str, Any] | JwksCache | None = ...,
    client_id: str | None = ...,
    allowed_algorithms: list[str] | None = ...,
    trust: Literal["typed", "dedicated_keys", "untyped_shared_key_compat"] | None = ...,
    typ: str | None = ...,
    max_age: int | None = ...,
    require_exp: bool = ...,
) -> dict[str, Any]:
    """Fetch UserInfo with a Bearer ``access_token`` and return its claims.

    ``method="GET"`` needs an ``http`` client that supports request headers on
    GET (see ``pygrindvakt.http``); otherwise ``ConfigError``. ``userinfo_endpoint=None``
    (the OP advertises none) raises ``ConfigError``.

    A signed ``application/jwt`` response is verified only when ``jwks``,
    ``client_id``, ``allowed_algorithms`` and ``trust`` are all given;
    otherwise ``AuthnError`` with ``code == "userinfo_unverifiable"``.
    ``trust`` is how the JWT is proven to be UserInfo: ``"typed"`` (needs
    ``typ``; safe), ``"dedicated_keys"`` (safe if ``jwks`` holds only UserInfo
    signing keys) or ``"untyped_shared_key_compat"`` (weakest: a fresh
    id_token without nonce/at_hash/c_hash is accepted). ``max_age`` bounds the
    token age from ``iat`` (default 300 s); ``None`` removes the bound and
    replay becomes unbounded. Encrypted (JWE) responses are rejected
    (``code == "userinfo_encrypted"``).

    ``HS*`` in ``allowed_algorithms`` works with a caller-built ``jwks`` dict
    (an ``oct`` key from the ``client_secret``; shorter than 32 / 48 / 64 bytes
    raises ``ConfigError``, ``code == "weak_shared_secret"``). With a
    :class:`JwksCache` it raises ``ConfigError``
    (``code == "shared_secret_algorithm"``).
    """

@overload
def fetch_userinfo(
    http: _HttpHeadersArg,
    userinfo_endpoint: str | None,
    access_token: str,
    expected_sub: str,
    issuer: str,
    *,
    method: Literal["GET"],
    jwks: dict[str, Any] | JwksCache | None = ...,
    client_id: str | None = ...,
    allowed_algorithms: list[str] | None = ...,
    trust: Literal["typed", "dedicated_keys", "untyped_shared_key_compat"] | None = ...,
    typ: str | None = ...,
    max_age: int | None = ...,
    require_exp: bool = ...,
) -> dict[str, Any]: ...
def build_client_assertion(key: SigningKey, client_id: str, audience: str) -> str: ...
def claims_to_attributes(claims: dict[str, Any]) -> dict[str, list[str]]: ...
def validate_issuer(issuer: str) -> None:
    """Check the syntax of an issuer identifier.

    Requires an absolute ``https`` URL (``http`` only for loopback hosts) with
    no userinfo, query, fragment, whitespace, control or invisible characters;
    raises ``ConfigError`` otherwise (the issuer is integrator configuration
    or provider metadata, not request input). Syntax only: it does NOT
    establish that the issuer is trusted, nor that it matches any discovery
    metadata. Backslashes are rejected (the URL parser would reinterpret them
    as ``/``, making the parsed authority differ from the raw string). Compare
    issuers byte-for-byte (exact string match); never suffix/substring checks.

    .. versionadded:: 0.3.0
    """

def validate_redirect_uri_syntax(redirect_uri: str) -> None:
    """Check the syntax of a redirect URI.

    Requires an absolute URL without a fragment (upstream's rule). This
    binding also rejects whitespace, control, bidi and invisible formatting
    characters and userinfo (binding-side hardening, stricter than core 0.9).
    Raises ``BadRequestError`` otherwise (not ``ConfigError``: a redirect URI
    can come from a request). This checks syntax only. The scheme is NOT
    checked, so ``com.example.app:/cb``, ``javascript:`` and
    ``http://attacker.example/cb`` all pass. It is the syntax step of
    ``RpClient``'s redirect URI handling, which also requires registration,
    exact-string comparison and a transport check (ADR 0004); it is NOT a
    registration policy. Do not use it to vet client registrations on an OP:
    this library provides no OP-side registration policy, so apply an https or
    scheme allow-list and compare by EXACT match yourself. Backslashes are rejected (the URL
    parser would reinterpret them as ``/``, making the parsed authority differ
    from the raw string).

    .. versionadded:: 0.3.0
    """

def validate_service_endpoint(
    name: str, endpoint: str, issuer: str | None = ..., *, allow_loopback_http: bool = ...
) -> None:
    """The loopback ``http`` exception is opt-in (``allow_loopback_http=True``) and ``issuer`` must then be the authenticated, locally configured issuer, never taken from the document being validated.

    Checks that a metadata endpoint is an absolute ``https`` URL. ``name``
    appears in the error message. By default only ``https`` passes; if
    ``issuer`` is given it is still validated first (as
    :func:`validate_issuer`; an invalid issuer raises ``ConfigError``) but
    never enables loopback ``http``. With ``allow_loopback_http=True``,
    ``issuer`` is required (else ``ConfigError``) and loopback ``http`` is also
    allowed on ANY port when the issuer is itself a loopback ``http`` origin; a
    ``UserWarning`` is emitted whenever a plain ``http`` endpoint is accepted.
    Raises ``ConfigError`` otherwise (endpoints are integrator configuration or
    provider metadata, not request input). It does NOT check same-origin with
    the issuer or establish trust. Backslashes in ``endpoint`` or ``issuer``
    are rejected (the URL parser would reinterpret them as ``/``, making the
    parsed authority differ from the raw string). Compare issuers
    byte-for-byte (exact string match); never suffix/substring checks.

    .. versionadded:: 0.3.0
    """

def asymmetric_algorithms() -> list[str]:
    """A fixed list of the classical asymmetric JWS algorithms the library parses.

    ``RS256/384/512``, ``PS256/384/512``, ``ES256/384/512``, ``ES256K`` and
    ``EdDSA``; never ``HS*`` or ``none``. Post-quantum names (ML-DSA,
    feature-gated in jose-rs) are NOT included even if the build parses them.
    This is a parser probe, not a recommended allowlist; it is not a list an
    OP advertises and not what suits your deployment. Pass an explicit
    allowlist to :func:`verify_id_token`. It includes ``EdDSA``, for which
    :func:`pygrindvakt.jwt.supports_oidc_token_hash` is ``False``, so
    ``allowed_algorithms=rp.asymmetric_algorithms()`` with
    ``strict_hashes=True`` on a flow that needs ``at_hash`` / ``c_hash`` is
    unsatisfiable for EdDSA tokens: filter with
    ``jwt.supports_oidc_token_hash`` or pass an explicit allowlist.

    .. versionadded:: 0.3.0
    """
