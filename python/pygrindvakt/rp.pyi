"""Type stubs for ``pygrindvakt.rp`` - the relying-party (client) side of OIDC."""

from typing import Any

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
) -> str: ...
def signed_request_object(
    provider: ProviderInfo,
    client: RpClient,
    key: SigningKey,
    state: str,
    nonce: str,
    code_challenge: str | None = ...,
) -> str: ...
def discover(http: Any | None, issuer: str) -> ProviderMetadata: ...
def fetch_jwks(http: Any | None, jwks_uri: str, issuer: str) -> dict[str, Any]: ...
def exchange_code(
    http: Any | None,
    provider: ProviderInfo,
    client: RpClient,
    code: str,
    code_verifier: str | None = ...,
) -> TokenSet: ...
def verify_id_token(
    jwks: dict[str, Any],
    id_token: str,
    issuer: str,
    client_id: str,
    expected_nonce: str | None,
    allowed_algorithms: list[str],
    trusted_additional_audiences: list[str] | None = ...,
    unsafe_skip_nonce_check: bool = ...,
) -> dict[str, Any]: ...
def fetch_userinfo(
    http: Any | None,
    userinfo_endpoint: str,
    access_token: str,
    expected_sub: str,
    issuer: str,
) -> dict[str, Any]: ...
def build_client_assertion(key: SigningKey, client_id: str, audience: str) -> str: ...
def claims_to_attributes(claims: dict[str, Any]) -> dict[str, list[str]]: ...
