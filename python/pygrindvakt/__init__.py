"""pygrindvakt - Python bindings for the grindvakt OAuth 2.0 / OpenID Connect /
OpenID Federation library.

The compiled extension is ``pygrindvakt._native``. Importing it registers each
grindvakt area as a submodule in ``sys.modules`` (``pygrindvakt.provider``,
``pygrindvakt.rp``, ...). This package re-exports the native names and
submodules so the public API is the same whether you ``import pygrindvakt`` or
``from pygrindvakt import provider``.
"""

from ._native import (
    AttributeMappingError,
    AuthnError,
    BadRequestError,
    ConfigError,
    CryptoError,
    DpopError,
    DpopInvalidError,
    DpopNonceRequiredError,
    DpopReplayError,
    DpopServerError,
    GrindvaktError,
    InternalError,
    JoseError,
    JsonError,
    NoBoundEndpointError,
    StateError,
    UnknownKeyError,
    UnknownModuleError,
    __version__,
    client,
    discovery,
    dpop,
    federation,
    http,
    jwt,
    keys,
    mac,
    metadata,
    pkce,
    provider,
    request,
    rp,
    tokens,
    util,
)

# OAuthError is defined in Python (it needs methods; see errors.py). It must be
# imported after _native so the native side can resolve it lazily.
from .errors import OAuthError

__all__ = [
    "AttributeMappingError",
    "AuthnError",
    "BadRequestError",
    "ConfigError",
    "CryptoError",
    "DpopError",
    "DpopInvalidError",
    "DpopNonceRequiredError",
    "DpopReplayError",
    "DpopServerError",
    "GrindvaktError",
    "InternalError",
    "JoseError",
    "JsonError",
    "NoBoundEndpointError",
    "OAuthError",
    "StateError",
    "UnknownKeyError",
    "UnknownModuleError",
    "__version__",
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
