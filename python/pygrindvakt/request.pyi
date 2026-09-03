"""Type stubs for ``pygrindvakt.request`` - parsed OIDC authorization requests."""

from typing import Any

class AuthorizationRequest:
    """A parsed OIDC authorization request.

    Build with ``AuthorizationRequest.from_params(query_dict)``. It is JSON
    round-trippable (``to_dict`` / ``from_dict``) so applications can stash it
    in a session between the authorization request and the redirect back.
    """

    @staticmethod
    def from_params(params: dict[str, str]) -> AuthorizationRequest:
        """Parse from a flat parameter dict (the query string, or the merged
        request object). Raises ``OAuthError(invalid_request)`` on missing
        ``client_id`` / ``response_type`` / ``redirect_uri`` or a bad
        ``claims`` value."""
    @staticmethod
    def from_dict(d: dict[str, Any]) -> AuthorizationRequest: ...
    def to_dict(self) -> dict[str, Any]: ...
    @property
    def client_id(self) -> str: ...
    @property
    def redirect_uri(self) -> str: ...
    @property
    def response_type(self) -> str: ...
    @property
    def scope(self) -> str: ...
    @property
    def state(self) -> str | None: ...
    @property
    def nonce(self) -> str | None: ...
    @property
    def code_challenge(self) -> str | None: ...
    @property
    def code_challenge_method(self) -> str | None: ...
    @property
    def response_mode(self) -> str | None: ...
    @property
    def prompt(self) -> str | None: ...
    @property
    def acr_values(self) -> str | None: ...
    @property
    def claims(self) -> dict[str, Any] | None:
        """The parsed ``claims`` request parameter, if present."""
    @property
    def request_object(self) -> str | None:
        """The raw ``request`` parameter (RFC 9101 request object JWT), if present."""
    @property
    def extra(self) -> dict[str, str]:
        """Other parameters preserved verbatim."""
    def scopes(self) -> list[str]:
        """The scopes as a list."""
    def is_oidc(self) -> bool:
        """True if ``scope`` contains ``openid``."""
    def has_prompt(self, expected: str) -> bool:
        """Whether ``prompt`` contains ``expected`` (exact, case-sensitive)."""
    def validate_prompt(self) -> None:
        """Validate the ``prompt`` combinations OIDC Core constrains. Raises ``OAuthError``."""
    def wants_code(self) -> bool: ...
    def wants_id_token(self) -> bool: ...
    def use_fragment(self) -> bool:
        """True when the response must be returned in the URL fragment."""
    def validate_response_type(self) -> None:
        """Validate that ``response_type`` is one the OP supports. Raises ``OAuthError``."""
