"""Type stubs for ``pygrindvakt.mac`` - HMAC / digest helpers."""

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA256 of ``data`` under ``key``."""

def sha256(data: bytes) -> bytes:
    """SHA-256 digest of ``data``."""

def constant_time_eq(a: bytes, b: bytes) -> bool:
    """Constant-time byte-string equality."""
