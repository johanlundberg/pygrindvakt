"""Type stubs for ``pygrindvakt.util`` - time and randomness helpers."""

def now_secs() -> int:
    """Current Unix time in seconds."""

def now_rfc3339() -> str:
    """RFC 3339 timestamp for "now" (UTC)."""

def random_token(n: int = ...) -> str:
    """A URL-safe random token from ``n`` bytes of OS entropy (base64url, no padding)."""
