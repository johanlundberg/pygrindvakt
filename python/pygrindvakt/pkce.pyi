"""Type stubs for ``pygrindvakt.pkce`` - RFC 7636 PKCE helpers."""

def s256_challenge(verifier: str) -> str:
    """The ``S256`` code challenge for a PKCE verifier (RFC 7636)."""

def verify(verifier: str, challenge: str, method: str | None = ...) -> bool:
    """Verify a PKCE verifier against a challenge.

    ``method`` defaults to ``S256``; ``"plain"`` is accepted only when named
    explicitly.
    """
