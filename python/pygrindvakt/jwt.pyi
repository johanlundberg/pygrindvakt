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
    def __repr__(self) -> str: ...

def sign(key: SigningKey, claims: dict[str, Any], typ: str | None = ...) -> str:
    """Sign a claims dict into a compact JWS with ``key``, setting ``alg``,
    ``kid`` and (optionally) a custom ``typ`` header."""

def verify_with_jwks(jwks: dict[str, Any], token: str, validation: Validation) -> dict[str, Any]:
    """Verify a compact JWS against a JWKS dict (``{"keys": [...]}``) and
    return the validated claims as a dict.

    .. versionchanged:: 0.3.0
       BEHAVIOUR CHANGE: for an ``HS256`` / ``HS384`` / ``HS512`` token, an
       ``oct`` key the token selects (by ``kid``; without one, every key jose-rs
       would try) shorter than 32 / 48 / 64 bytes (RFC 7518 section 3.2) or
       with ``k`` that is not strict unpadded base64url raises
       ``ConfigError`` (``code == "weak_shared_secret"``), and a selected ``oct``
       key without ``alg`` is pinned to the token's ``alg``. Previously such
       keys (e.g. 40 bytes for ``HS512``) verified. No opt-out.
    """

def verify_with_jwk(jwk: dict[str, Any], token: str, validation: Validation) -> dict[str, Any]:
    """Verify a compact JWS against a single JWK dict.

    .. versionchanged:: 0.3.0
       BEHAVIOUR CHANGE: the same RFC 7518 section 3.2 minimum-key-length
       gate as :func:`verify_with_jwks` applies to an ``oct`` ``jwk`` and an
       ``HS*`` token (``ConfigError``, ``code == "weak_shared_secret"``); the
       token's ``kid`` is ignored, as this is the only key used.
       No opt-out.
    """

def peek_header(token: str) -> dict[str, Any]:
    """The protected header of a compact JWS as a dict, WITHOUT verification."""

def peek_claims_unverified(token: str) -> dict[str, Any]:
    """The claims of a compact JWS as a dict, WITHOUT verifying the signature.

    SECURITY: only for inspection (e.g. reading ``iss`` to choose a key).
    Never trust these values.
    """

def oidc_token_hash(alg: str, value: str) -> str:
    """Compute the OIDC Core ``at_hash`` / ``c_hash`` value for ``value``.

    The left half of the SHA-2 digest matching the JWS ``alg`` (SHA-256,
    SHA-384 or SHA-512), base64url-encoded without padding. ``HS256`` /
    ``HS384`` / ``HS512`` work too (same SHA family). It only computes the
    value; it is NOT verification. Compare the result in constant time with
    the claim yourself (:func:`pygrindvakt.mac.constant_time_eq` on the
    encoded bytes), or use the ``at_hash`` / ``c_hash`` checks of
    ``rp.verify_id_token``. An unknown or unparseable ``alg``, and an
    algorithm with no defined hash (such as ``EdDSA``), both raise
    ``CryptoError``.

    .. versionadded:: 0.3.0
    """

def supports_oidc_token_hash(alg: str) -> bool:
    """Whether OIDC Core defines a token-hash function for the JWS ``alg``.

    ``False`` for ``EdDSA`` and for an unrecognised ``alg`` name; it is a
    predicate and never raises.

    .. versionadded:: 0.3.0
    """
