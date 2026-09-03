"""Type stubs for ``pygrindvakt.jwt`` - thin JWS sign/verify helpers.

Claims and headers cross the boundary as dicts. ``Validation`` is a small
builder mirroring ``jose_rs::jwt::Validation``.
"""

from typing import Any

from .keys import SigningKey

class Validation:
    """JWT validation rules.

    Every ``with_*`` / ``require_*`` method returns a new ``Validation``, so
    calls can be chained.
    """

    def __init__(self) -> None: ...
    def with_issuer(self, issuer: str) -> Validation:
        """Require ``iss`` to equal ``issuer``."""
    def with_audience(self, audience: str) -> Validation:
        """Require ``aud`` to contain ``audience``."""
    def with_subject(self, subject: str) -> Validation:
        """Require ``sub`` to equal ``subject``."""
    def with_leeway(self, seconds: int) -> Validation:
        """Clock-skew leeway in seconds for ``exp`` / ``nbf`` / ``iat``."""
    def with_typ(self, typ: str) -> Validation:
        """Require the protected header ``typ`` to equal ``typ`` (RFC 8725 section 3.11)."""
    def with_max_age(self, seconds: int) -> Validation:
        """Reject tokens whose ``iat`` is older than ``seconds`` (also requires ``iat``)."""
    def with_allowed_algorithms(self, algs: list[str]) -> Validation:
        """Restrict the accepted header ``alg`` values, e.g. ``["ES256", "RS256"]``."""
    def require_exp(self) -> Validation: ...
    def require_nbf(self) -> Validation: ...
    def require_iat(self) -> Validation: ...
    def require_kid(self) -> Validation: ...

def sign(key: SigningKey, claims: dict[str, Any], typ: str | None = ...) -> str:
    """Sign a claims dict into a compact JWS with ``key``, setting ``alg``,
    ``kid`` and (optionally) a custom ``typ`` header."""

def verify_with_jwks(jwks: dict[str, Any], token: str, validation: Validation) -> dict[str, Any]:
    """Verify a compact JWS against a JWKS dict (``{"keys": [...]}``) and
    return the validated claims as a dict."""

def verify_with_jwk(jwk: dict[str, Any], token: str, validation: Validation) -> dict[str, Any]:
    """Verify a compact JWS against a single JWK dict."""

def peek_header(token: str) -> dict[str, Any]:
    """The protected header of a compact JWS as a dict, WITHOUT verification."""

def peek_claims_unverified(token: str) -> dict[str, Any]:
    """The claims of a compact JWS as a dict, WITHOUT verifying the signature.

    SECURITY: only for inspection (e.g. reading ``iss`` to choose a key).
    Never trust these values.
    """
