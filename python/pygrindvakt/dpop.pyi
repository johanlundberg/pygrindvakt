"""Type stubs for ``pygrindvakt.dpop`` - RFC 9449 sender-constrained tokens.

Proof validation is stateless except for ``jti`` replay protection, which is
delegated to an atomic replay store: the built-in ``InMemoryReplayStore`` for
one process, or a shared Python object satisfying ``ReplayStoreProtocol``.
"""

from typing import Protocol

class ReplayStoreProtocol(Protocol):
    """Replay store protocol: ``record`` returns True iff ``jti`` was not
    already live. An exception is reported as ``DpopServerError``."""

    def record(self, jti: str, ttl_secs: int) -> bool: ...

class DpopConfig:
    """DPoP validation settings.

    ``nonce_secret`` keys the stateless server nonces and MUST be set (to a
    high-entropy value derived from your master secret) when
    ``require_nonce=True``.
    """

    def __init__(
        self,
        *,
        proof_max_age_secs: int = ...,
        require_nonce: bool = ...,
        nonce_lifetime_secs: int = ...,
        nonce_secret: str | None = ...,
    ) -> None: ...
    @property
    def proof_max_age_secs(self) -> int: ...
    @property
    def require_nonce(self) -> bool: ...
    @property
    def nonce_lifetime_secs(self) -> int: ...

class DpopProof:
    """A validated DPoP proof: the SHA-256 JWK thumbprint of the proof key."""

    @property
    def jkt(self) -> str: ...

class InMemoryReplayStore:
    """Process-local TTL replay cache for DPoP ``jti``s. Use a shared
    (Python / Redis-backed) store when running several replicas."""

    def __init__(self) -> None: ...
    def record(self, jti: str, ttl_secs: int) -> bool:
        """Record ``jti``; returns True iff it was not already live."""

class NoReplayStore:
    """Removed compatibility marker whose constructor always raises ValueError."""

    def __init__(self) -> None: ...

def validate_proof(
    store: InMemoryReplayStore | ReplayStoreProtocol,
    config: DpopConfig,
    proof: str,
    htm: str,
    htu: str,
) -> DpopProof:
    """Validate a ``DPoP`` header value for a **token-endpoint** request.

    ``htm`` is the HTTP method and ``htu`` the absolute token URL the proof
    must be bound to. Derive ``htu`` from configuration, never from the
    ``Host`` header. On success the proof's ``jti`` has been recorded in
    ``store``.

    Raises ``DpopInvalidError``, ``DpopReplayError``,
    ``DpopNonceRequiredError`` (respond with ``use_dpop_nonce`` and a fresh
    ``issue_nonce``) or ``DpopServerError``.
    """

def validate_resource_proof(
    store: InMemoryReplayStore | ReplayStoreProtocol,
    config: DpopConfig,
    proof: str,
    htm: str,
    htu: str,
    access_token: str,
) -> DpopProof:
    """Validate a ``DPoP`` header value for a **resource** request (e.g.
    userinfo), additionally binding it to ``access_token`` through the
    ``ath`` claim."""

def issue_nonce(config: DpopConfig) -> str:
    """Mint a fresh server nonce (stateless HMAC over the current time window)
    to send in a ``DPoP-Nonce`` header."""
