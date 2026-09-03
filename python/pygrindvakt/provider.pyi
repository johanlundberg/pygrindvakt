"""Type stubs for ``pygrindvakt.provider`` - the OpenID Provider engine.

A ``Provider`` is constructed once at startup and shared across requests. Its
endpoint methods take already-extracted inputs (query / form dicts, header
strings) and return ``Response`` objects or raise ``OAuthError``, so any web
framework can drive it.

One-time use of authorization codes / refresh tokens / ``private_key_jwt``
``jti``s is enforced through a token-use store: ``InMemoryTokenUseStore``
(single process), ``RedisStore`` (shared), or any Python object satisfying
``TokenUseStoreProtocol``.
"""

from typing import Any, Protocol

from .client import Client, ClientStoreProtocol, InMemoryClientStore
from .dpop import DpopProof
from .http import Response
from .keys import SigningKey
from .metadata import ProviderMetadata
from .request import AuthorizationRequest
from .tokens import TokenCodec

CLIENT_ASSERTION_TYPE: str
DEFAULT_CLIENT_ASSERTION_MAX_AGE: int
RESERVED_ID_TOKEN_CLAIMS: list[str]

class TokenUseStoreProtocol(Protocol):
    """One-time-use store protocol: ``consume`` returns True iff
    ``token_hash`` was not already used. An exception is reported as a store
    failure, which grindvakt renders as ``server_error``."""

    def consume(self, token_hash: str, ttl_secs: int) -> bool: ...

class TokenLifetimes:
    """Lifetimes (seconds) of issued artefacts."""

    def __init__(
        self,
        *,
        code_ttl: int = ...,
        access_token_ttl: int = ...,
        id_token_ttl: int = ...,
        refresh_token_ttl: int = ...,
    ) -> None: ...
    @property
    def code_ttl(self) -> int: ...
    @property
    def access_token_ttl(self) -> int: ...
    @property
    def id_token_ttl(self) -> int: ...
    @property
    def refresh_token_ttl(self) -> int: ...

class TokenResponse:
    """A successful token-endpoint response. ``to_dict()`` is exactly the JSON
    body to send (with ``cache-control: no-store``)."""

    @property
    def access_token(self) -> str: ...
    @property
    def token_type(self) -> str: ...
    @property
    def expires_in(self) -> int: ...
    @property
    def id_token(self) -> str | None: ...
    @property
    def scope(self) -> str | None: ...
    @property
    def refresh_token(self) -> str | None: ...
    def to_dict(self) -> dict[str, Any]: ...
    def to_response(self) -> Response:
        """The complete HTTP response: 200, JSON body, ``cache-control: no-store``."""

class InMemoryTokenUseStore:
    """Process-local one-time-use store for codes, refresh tokens and
    assertion ``jti``s. Fine for a single process; use ``RedisStore`` or a
    Python-backed store across replicas."""

    def __init__(self) -> None: ...
    def consume(self, token_hash: str, ttl_secs: int) -> bool:
        """Mark ``token_hash`` used; True iff it was not already used."""

class RedisStore:
    """Redis-backed one-time-use store (``SET key 1 EX ttl NX``) for
    multi-process deployments. Construct it *after* fork (e.g. in a gunicorn
    ``post_fork`` hook or lazily in the worker)."""

    DEFAULT_KEY_PREFIX: str
    def __init__(self, redis_url: str, key_prefix: str | None = ...) -> None: ...
    def consume(self, token_hash: str, ttl_secs: int) -> bool: ...

class Provider:
    """The OpenID Provider engine. Build once, share across requests.

    ``clients`` is an ``InMemoryClientStore`` or any object implementing
    ``ClientStoreProtocol``; ``token_use_store`` defaults to a fresh
    ``InMemoryTokenUseStore``.
    """

    def __init__(
        self,
        metadata: ProviderMetadata,
        signing_key: SigningKey,
        clients: InMemoryClientStore | ClientStoreProtocol,
        codec: TokenCodec,
        lifetimes: TokenLifetimes | None = ...,
        token_use_store: InMemoryTokenUseStore | RedisStore | TokenUseStoreProtocol | None = ...,
        client_assertion_max_age: int | None = ...,
    ) -> None: ...
    @property
    def clients(self) -> InMemoryClientStore | ClientStoreProtocol:
        """The client store passed at construction."""
    @property
    def token_use_store(self) -> InMemoryTokenUseStore | RedisStore | TokenUseStoreProtocol:
        """The token-use store in effect."""
    @property
    def metadata(self) -> ProviderMetadata: ...
    @property
    def signing_key(self) -> SigningKey: ...
    @property
    def lifetimes(self) -> TokenLifetimes: ...
    @property
    def issuer(self) -> str: ...
    def discovery_document(self) -> dict[str, Any]:
        """The ``/.well-known/openid-configuration`` document as a dict."""
    def jwks_document(self) -> dict[str, Any]:
        """The JWKS document (``{"keys": [...]}``) as a dict."""
    def validate_authorization_request(self, request: AuthorizationRequest) -> Client:
        """Validate an authorization request against the registered client and
        return that ``Client``.

        On failure the ``redirect_uri`` is NOT trusted: render the raised
        ``OAuthError`` with ``.to_response()``, never ``.to_redirect()``.
        """
    def authorization_redirect(
        self,
        request: AuthorizationRequest,
        sub: str,
        external_claims: dict[str, list[str]] | None = ...,
        acr: str | None = ...,
        extra_claims: dict[str, Any] | None = ...,
    ) -> Response:
        """After the user authenticated: mint the code / tokens for ``sub`` and
        return the redirect ``Response`` back to the client.

        ``external_claims`` maps claim name -> list of string values.
        ``extra_claims`` are typed id_token claims; the reserved names in
        ``RESERVED_ID_TOKEN_CLAIMS`` raise ``ValueError``.

        On ``OAuthError``, the request's ``redirect_uri`` has already been
        validated so ``.to_redirect(request.redirect_uri)`` is safe.
        """
    def handle_token_request(
        self,
        form: dict[str, str],
        token_url: str,
        auth_header: str | None = ...,
        dpop: DpopProof | None = ...,
    ) -> TokenResponse:
        """Handle a token-endpoint request.

        ``form`` is the parsed form body, ``auth_header`` the raw
        ``Authorization`` header, ``token_url`` the absolute token endpoint
        URL *from configuration* (it is the ``private_key_jwt`` audience and
        the DPoP ``htu``), and ``dpop`` an already-validated ``DpopProof`` if
        the request carried one. Raises ``OAuthError``; render it with
        ``.to_response()``.
        """
    def userinfo(self, access_token: str, presented_jkt: str | None = ...) -> dict[str, Any]:
        """Handle a userinfo request: validate ``access_token`` (and, for a
        DPoP-bound token, that ``presented_jkt`` matches) and return the claims."""
    def authenticate_client(
        self,
        form: dict[str, str],
        token_url: str,
        auth_header: str | None = ...,
    ) -> Client:
        """Authenticate a client from a token-endpoint style request (form +
        ``Authorization`` header) and return the ``Client``."""

def flatten_claims(external: dict[str, list[str]]) -> dict[str, Any]:
    """Flatten ``{claim: [values]}`` into id_token / userinfo claim values the
    way the provider does (single values coerced for standard claims)."""
