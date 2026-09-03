"""pygrindvakt - Python bindings for the grindvakt OAuth 2.0 / OpenID Connect /
OpenID Federation library.

The compiled extension is ``pygrindvakt._native``. Importing it registers each
grindvakt area as a submodule in ``sys.modules`` (``pygrindvakt.provider``,
``pygrindvakt.rp``, ...). This package re-exports the native names and
submodules so the public API is the same whether you ``import pygrindvakt`` or
``from pygrindvakt import provider``.
"""

from ._native import (  # noqa: F401
    __version__,
    GrindvaktError,
    BadRequestError,
    AuthnError,
    StateError,
    ConfigError,
    CryptoError,
    AttributeMappingError,
    JoseError,
    JsonError,
    InternalError,
    NoBoundEndpointError,
    UnknownModuleError,
    DpopError,
    DpopInvalidError,
    DpopReplayError,
    DpopNonceRequiredError,
    DpopServerError,
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
from .errors import OAuthError  # noqa: E402,F401

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
