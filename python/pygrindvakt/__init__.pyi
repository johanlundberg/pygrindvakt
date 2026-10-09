"""Type stubs for pygrindvakt - Python bindings for the grindvakt OAuth 2.0 /
OpenID Connect / OpenID Federation library.

This is a PEP 561 stub describing the compiled extension and its submodules
(client, discovery, dpop, federation, http, jwt, keys, mac, metadata, pkce,
provider, request, rp, tokens, util).
"""

from . import (
    client as client,
    discovery as discovery,
    dpop as dpop,
    federation as federation,
    http as http,
    jwt as jwt,
    keys as keys,
    mac as mac,
    metadata as metadata,
    pkce as pkce,
    provider as provider,
    request as request,
    rp as rp,
    tokens as tokens,
    util as util,
)
from .errors import OAuthError as OAuthError

__version__: str

class GrindvaktError(Exception):
    """Base class for all pygrindvakt errors.

    ``code`` is a short machine-readable identifier: a class-level default
    that an instance may override with a more precise value (for example the
    upstream OAuth ``error`` code). The ``upstream_*`` attributes are set only
    for errors that came from an upstream HTTP response and are otherwise
    ``None``; ``upstream_error_description`` and ``upstream_body`` may echo
    secrets and must not be logged or shown to end users.
    """

    status_hint: int
    code: str
    upstream_status: int | None
    upstream_error: str | None
    upstream_error_description: str | None
    upstream_body: str | None

class BadRequestError(GrindvaktError):
    """The request was malformed (400)."""

class AuthnError(GrindvaktError):
    """Authentication failed somewhere in the flow (401)."""

class StateError(GrindvaktError):
    """Flow state could not be sealed/unsealed (500)."""

class ConfigError(GrindvaktError):
    """Configuration is invalid (500)."""

class CryptoError(GrindvaktError):
    """Cryptographic / key-material failure (500)."""

class AttributeMappingError(GrindvaktError):
    """Attribute mapping failure (500)."""

class JoseError(GrindvaktError):
    """JOSE (JWS/JWE/JWK) error (500)."""

class UnknownKeyError(JoseError):
    """The token's ``kid`` names no key in the issuer's JWK Set, even after a refresh (401)."""

class JsonError(GrindvaktError):
    """JSON (de)serialization error (500)."""

class InternalError(GrindvaktError):
    """Any other internal error (500)."""

class NoBoundEndpointError(GrindvaktError):
    """No endpoint bound to path (404)."""

class UnknownModuleError(GrindvaktError):
    """Unknown module (404)."""

class DpopError(GrindvaktError):
    """Base class for DPoP proof validation errors (400)."""

class DpopInvalidError(DpopError):
    """The DPoP proof is malformed or fails validation (400)."""

class DpopReplayError(DpopError):
    """The DPoP proof's jti was already seen (400)."""

class DpopNonceRequiredError(DpopError):
    """A server nonce is required; challenge the client with ``use_dpop_nonce`` (400)."""

class DpopServerError(DpopError):
    """The replay store failed; the proof could not be evaluated (500)."""

__all__ = [
    "__version__",
    "GrindvaktError",
    "BadRequestError",
    "AuthnError",
    "StateError",
    "ConfigError",
    "CryptoError",
    "AttributeMappingError",
    "JoseError",
    "UnknownKeyError",
    "JsonError",
    "InternalError",
    "NoBoundEndpointError",
    "UnknownModuleError",
    "OAuthError",
    "DpopError",
    "DpopInvalidError",
    "DpopReplayError",
    "DpopNonceRequiredError",
    "DpopServerError",
    "client",
    "discovery",
    "dpop",
    "federation",
    "http",
    "jwt",
    "keys",
    "mac",
    "metadata",
    "pkce",
    "provider",
    "request",
    "rp",
    "tokens",
    "util",
]
