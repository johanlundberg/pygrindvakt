"""Type stubs for ``pygrindvakt.rp`` - the relying-party (client) side of OIDC."""

from typing import Any, Literal, overload

from .http import _HttpArg, _HttpHeadersArg
from .keys import SigningKey
from .metadata import ProviderMetadata

class ProviderInfo:
    """Minimal upstream-provider information the RP needs."""

    def __init__(
        self,
        issuer: str,
        authorization_endpoint: str,
        token_endpoint: str,
        userinfo_endpoint: str | None = ...,
        jwks_uri: str | None = ...,
        *,
        end_session_endpoint: str | None = ...,
    ) -> None: ...
    @staticmethod
    def from_metadata(metadata: ProviderMetadata) -> ProviderInfo: ...
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
    Inconsistent combinations raise ``ValueError``.
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
    ) -> None: ...
    @property
    def client_id(self) -> str: ...
    @property
    def redirect_uri(self) -> str: ...
    @property
    def scope(self) -> str: ...
    @property
    def auth_method(self) -> str: ...
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
    """OIDC RP-Initiated Logout 1.0 request URL."""
def fetch_jwks(http: _HttpArg, jwks_uri: str, issuer: str) -> dict[str, Any]: ...
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
) -> dict[str, Any]:
    """Verify an id_token and return its claims.

    ``jwks`` is a key-set dict or a :class:`JwksCache`. Optional checks, all
    off by default:

    * ``leeway``: clock-skew tolerance in seconds (default 60; above 300 raises
      ``BadRequestError``).
    * ``max_age``: needs a numeric ``auth_time`` no older than ``max_age``
      seconds (``iat`` is not used; a missing or non-numeric ``auth_time`` is
      an ``AuthnError``; leeway is not added).
    * ``acr_values``: ``acr`` must be present and listed.
    * ``access_token`` / ``authorization_code``: check ``at_hash`` / ``c_hash``
      when present; ``require_at_hash`` / ``require_c_hash`` also reject
      tokens lacking the claim (and need the matching value, else
      ``BadRequestError``). ``EdDSA`` tokens carrying a hash claim cannot be
      checked (``CryptoError``).
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
    ) -> None: ...
    @property
    def jwks_uri(self) -> str: ...
    @property
    def issuer(self) -> str: ...
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
    ) -> dict[str, Any]:
        """:func:`verify_id_token` against this cache's keys and issuer.

        If the token's ``kid`` is missing from a set whose keys have ``kid``s,
        the set is refreshed once (rate-limited by ``min_refresh_interval``)
        and a still-unknown ``kid`` raises ``UnknownKeyError``.
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
