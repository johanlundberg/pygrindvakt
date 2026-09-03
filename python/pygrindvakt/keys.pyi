"""Type stubs for ``pygrindvakt.keys`` - signing-key loading (PEM/DER, JWK,
PKCS#11).

A ``SigningKey`` is opaque: the private material never crosses into Python.
Only the algorithm, key id, and the public JWK / JWKS are exposed.
"""

from typing import Any

class SigningKey:
    """A loaded signing key (software or HSM-backed).

    Immutable and cheap to clone; the private material is never exposed to
    Python. Construct via the ``signing_key_from_*`` functions.
    """

    @property
    def alg(self) -> str:
        """The JWS algorithm this key signs with, e.g. ``"ES256"``."""
    @property
    def kid(self) -> str | None:
        """The key id published in JWKS / JWT headers, if any."""
    def public_jwk(self) -> dict[str, Any]:
        """The public JWK (no private components) as a dict."""
    def to_public_jwks(self) -> dict[str, Any]:
        """A one-key JWKS document (``{"keys": [...]}``) as a dict."""

def signing_key_from_pem(data: bytes, alg: str | None = ..., kid: str | None = ...) -> SigningKey:
    """Load a signing key from PEM (or DER) bytes: PKCS#8, PKCS#1 or SEC1.

    ``alg`` overrides the algorithm inferred from the key type; ``kid`` sets
    the published key id.
    """

def signing_key_from_jwk_json(json: str, alg: str | None = ..., kid: str | None = ...) -> SigningKey:
    """Load a signing key from a private JWK given as a JSON string."""

def signing_key_from_jwk(jwk: dict[str, Any], alg: str | None = ..., kid: str | None = ...) -> SigningKey:
    """Load a signing key from a private JWK given as a dict."""

def signing_key_from_pkcs11(
    module_path: str,
    pin: str,
    key_label: str,
    alg: str,
    kid: str | None = ...,
) -> SigningKey:
    """Load a signing key whose private material lives on a PKCS#11 token
    (SoftHSM2, Kryoptic, a hardware HSM).

    ``module_path`` is the PKCS#11 shared library; ``key_label`` is the
    ``CKA_LABEL`` of the key pair; ``alg`` is the JWS algorithm to sign with
    (e.g. ``"ES256"``).

    SECURITY: ``pin`` is a Python ``str`` and cannot be zeroized after use.
    """

def generate_ec_jwk(curve: str = ...) -> dict[str, Any]:
    """Generate a fresh EC private JWK (``"P-256"`` or ``"P-384"``) as a dict.

    Intended for tests and bootstrapping; persist the result yourself.
    """

def generate_rsa_jwk(bits: int = ...) -> dict[str, Any]:
    """Generate a fresh RSA private JWK as a dict (default 2048 bits)."""

def generate_ed25519_jwk() -> dict[str, Any]:
    """Generate a fresh Ed25519 private JWK as a dict."""

def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    """RFC 7638 SHA-256 JWK thumbprint (base64url) of a JWK dict."""
