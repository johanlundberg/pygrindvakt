"""Type stubs for ``pygrindvakt.errors`` - the Python-defined ``OAuthError``."""

from . import GrindvaktError
from .http import Response

class OAuthError(GrindvaktError):
    """An OAuth 2.0 / OpenID Connect protocol error (RFC 6749 section 5.2).

    Raised by ``Provider`` endpoint methods and by ``AuthorizationRequest``
    parsing. Applications may also raise it themselves to translate their own
    authentication failures into a protocol response. An unknown ``code``
    raises ``ValueError`` at construction time.
    """

    code: str
    description: str | None
    state: str | None
    def __init__(self, code: str, description: str | None = ..., state: str | None = ...) -> None: ...
    @property
    def http_status(self) -> int:
        """HTTP status conventionally returned with this error (400/401/500/503)."""
    @property
    def status_hint(self) -> int: ...  # type: ignore[override]
    def with_state(self, state: str | None) -> OAuthError:
        """Return a copy carrying ``state`` (the client's value to echo back)."""
    def to_response(self) -> Response:
        """Render as a direct JSON error response (token / userinfo endpoints)."""
    def to_redirect(self, redirect_uri: str) -> Response:
        """Render as a redirect back to the client (authorization endpoint).

        Only call this with a ``redirect_uri`` that has already been validated
        against the registered client.
        """
