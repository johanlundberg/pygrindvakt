"""Exception types that need Python-level behaviour.

Most pygrindvakt exceptions are created natively (see ``pygrindvakt._native``).
``OAuthError`` carries structured data *and* rendering methods, which the
abi3 build cannot express in Rust for Python < 3.12, so it lives here and
delegates rendering to two native helpers.
"""

from __future__ import annotations

from pygrindvakt import _native


class OAuthError(_native.GrindvaktError):
    """An OAuth 2.0 / OpenID Connect protocol error (RFC 6749 section 5.2).

    Raised by ``Provider`` endpoint methods and by ``AuthorizationRequest``
    parsing. Applications may also raise it themselves to translate their own
    authentication failures into a protocol response.

    Attributes:
        code: the OAuth error string, e.g. ``"invalid_request"``.
        description: optional human-readable ``error_description``.
        state: the client's ``state`` value to echo back, if known.
    """

    def __init__(
        self,
        code: str,
        description: str | None = None,
        state: str | None = None,
    ) -> None:
        # Validate the code eagerly so a typo fails at raise time, not render time.
        _native.oauth_error_http_status(code)
        super().__init__(code, description, state)
        self.code = code
        self.description = description
        self.state = state

    def __str__(self) -> str:
        if self.description:
            return f"{self.code}: {self.description}"
        return self.code

    def __repr__(self) -> str:
        return (
            f"OAuthError(code={self.code!r}, description={self.description!r}, "
            f"state={self.state!r})"
        )

    @property
    def http_status(self) -> int:
        """HTTP status conventionally returned with this error (400/401/500/503)."""
        return _native.oauth_error_http_status(self.code)

    @property
    def status_hint(self) -> int:  # keep parity with GrindvaktError subclasses
        return self.http_status

    def with_state(self, state: str | None) -> OAuthError:
        """Return a copy carrying ``state`` (the client's value to echo back)."""
        return OAuthError(self.code, self.description, state)

    def to_response(self):
        """Render as a direct JSON error response (token / userinfo endpoints).

        The result is a :class:`pygrindvakt.http.Response` with the correct
        status, ``application/json`` body, ``cache-control: no-store`` and, for
        ``invalid_client``, a ``www-authenticate`` header. This output is safe
        to send to clients.
        """
        return _native.oauth_error_response(self.code, self.description, self.state)

    def to_redirect(self, redirect_uri: str):
        """Render as a redirect back to the client (authorization endpoint).

        Only call this with a ``redirect_uri`` that has already been validated
        against the registered client (i.e. after
        ``Provider.validate_authorization_request`` succeeded).
        """
        return _native.oauth_error_redirect(
            self.code, redirect_uri, self.description, self.state
        )
