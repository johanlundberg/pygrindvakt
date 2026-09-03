pygrindvakt.dpop
================

.. py:module:: pygrindvakt.dpop

RFC 9449 DPoP: sender-constrained access tokens.

A DPoP proof is a short-lived JWT signed by a key the client holds, bound to
the HTTP method and URL of the request (``htm`` / ``htu``) and, at a resource
server, to the access token (``ath``). Validating one is stateless except for
``jti`` replay protection, which is delegated to a replay store: the built-in
:class:`InMemoryReplayStore`, :class:`NoReplayStore` (only safe with
``require_nonce=True``), or any Python object satisfying
:class:`ReplayStoreProtocol`. :doc:`../guides/dpop` walks through the token
endpoint and userinfo integration.

Configuration
-------------

.. py:class:: DpopConfig(*, proof_max_age_secs: int = 300, require_nonce: bool = False, nonce_lifetime_secs: int = 300, nonce_secret: str | None = None)

   DPoP validation settings. Immutable.

   * ``proof_max_age_secs``: how far in the past a proof's ``iat`` may lie.
   * ``require_nonce``: demand a server-issued nonce in every proof
     (RFC 9449 section 8). Clients that omit it, or present a stale or forged
     one, get :class:`pygrindvakt.DpopNonceRequiredError` and must retry
     with the nonce from the ``DPoP-Nonce`` response header.
   * ``nonce_lifetime_secs``: how long an issued nonce stays valid.
   * ``nonce_secret``: keys the stateless server nonces (an HMAC over the
     current time window, so no nonce storage is needed and every replica
     accepts every other replica's nonces). It **must** be set, to a
     high-entropy value derived from your master secret, when
     ``require_nonce=True``; the constructor raises ``ValueError``
     otherwise.

   .. py:property:: proof_max_age_secs
      :type: int
   .. py:property:: require_nonce
      :type: bool
   .. py:property:: nonce_lifetime_secs
      :type: int

   The secret is not readable back and not shown in ``repr()``.

   .. code-block:: python

      from pygrindvakt import dpop

      cfg = dpop.DpopConfig(require_nonce=True, nonce_secret=os.environ["DPOP_NONCE_SECRET"])

.. py:class:: DpopProof(jkt: str)

   A validated DPoP proof: the SHA-256 JWK thumbprint (RFC 7638) of the key
   that signed it. Pass it to
   :meth:`pygrindvakt.provider.Provider.handle_token_request` to issue tokens
   bound to that key, or compare its ``jkt`` with a token's ``cnf.jkt``.

   .. py:property:: jkt
      :type: str

Replay stores
-------------

.. py:class:: ReplayStoreProtocol

   The duck-typed replay store protocol accepted as the ``store`` argument of
   :func:`validate_proof` and :func:`validate_resource_proof`. The object is
   checked for a callable ``record`` on each call (``TypeError`` otherwise).

   .. py:method:: record(jti: str, ttl_secs: int) -> bool

      Atomically record ``jti`` for ``ttl_secs`` seconds and return ``True``
      iff it was **not** already live.

      **Fails closed:** an exception, or a non-``bool`` return, is logged
      through ``sys.unraisablehook`` and raised to the caller as
      :class:`pygrindvakt.DpopServerError` (HTTP 500), not reported as a
      replay.

   The method runs on the thread driving the validation call, holding the
   GIL. It may call back into pygrindvakt; a nested call runs on a helper
   thread and costs one thread spawn.

   .. code-block:: python

      class RedisPyReplayStore:
          def __init__(self, r):
              self.r = r

          def record(self, jti, ttl_secs):
              return bool(self.r.set(f"dpop:jti:{jti}", 1, ex=ttl_secs, nx=True))

.. py:class:: InMemoryReplayStore()

   Process-local TTL replay cache for DPoP ``jti`` values. grindvakt itself
   ships no such store; the binding provides one over its in-memory
   token-use store, plus a guard that rejects ``jti`` values longer than
   256 bytes so a client cannot bloat the cache. Use a shared (Python or
   Redis-backed) store when running several replicas.

   .. py:method:: record(jti: str, ttl_secs: int) -> bool

      Record ``jti``; returns ``True`` iff it was not already live.

.. py:class:: NoReplayStore()

   A replay store that records nothing.

   Only safe together with ``DpopConfig(require_nonce=True)``, where the
   short-lived server nonce bounds the replay window to
   ``nonce_lifetime_secs``. Used with ``require_nonce=False`` it leaves
   proofs replayable for ``proof_max_age_secs``, so the binding emits a
   ``UserWarning`` at validation time in that combination.

Functions
---------

.. py:function:: validate_proof(store: InMemoryReplayStore | NoReplayStore | ReplayStoreProtocol, config: DpopConfig, proof: str, htm: str, htu: str) -> DpopProof

   Validate a ``DPoP`` header value for a **token-endpoint** request.

   ``proof`` is the raw header value; ``htm`` is the HTTP method (``"POST"``)
   and ``htu`` the absolute token URL the proof must be bound to. **Derive
   ``htu`` from configuration, never from the** ``Host`` **header.** On
   success the proof's ``jti`` has been recorded in ``store``.

   Checks performed: ``typ`` is ``dpop+jwt``; the header carries a public
   ``jwk`` and the signature verifies under it with an asymmetric algorithm;
   ``htm`` / ``htu`` match exactly (a trailing slash is a mismatch); ``iat``
   is within ``proof_max_age_secs``; the nonce, when required; the ``jti``
   is fresh.

   Raises :class:`pygrindvakt.DpopInvalidError`,
   :class:`pygrindvakt.DpopReplayError`,
   :class:`pygrindvakt.DpopNonceRequiredError` (respond with
   ``use_dpop_nonce`` and a fresh :func:`issue_nonce`) or
   :class:`pygrindvakt.DpopServerError`.

.. py:function:: validate_resource_proof(store: InMemoryReplayStore | NoReplayStore | ReplayStoreProtocol, config: DpopConfig, proof: str, htm: str, htu: str, access_token: str) -> DpopProof

   Validate a ``DPoP`` header value for a **resource** request (for example
   userinfo), additionally binding it to ``access_token`` through the ``ath``
   claim (the base64url SHA-256 of the token). Pass the returned ``jkt`` as
   ``presented_jkt`` to :meth:`pygrindvakt.provider.Provider.userinfo`.

.. py:function:: issue_nonce(config: DpopConfig) -> str

   Mint a fresh server nonce (a stateless HMAC over the current time window
   under ``nonce_secret``) to send in a ``DPoP-Nonce`` header. Send one with
   every ``use_dpop_nonce`` challenge and, optionally, with every successful
   response so well-behaved clients stay current.

.. code-block:: python

   from pygrindvakt import DpopError, DpopNonceRequiredError, OAuthError, dpop
   from pygrindvakt.http import Response

   store = dpop.InMemoryReplayStore()          # or a shared store
   cfg = dpop.DpopConfig()

   def token_endpoint(form, headers):
       proof = None
       if (hdr := headers.get("dpop")) is not None:
           try:
               proof = dpop.validate_proof(store, cfg, hdr, "POST", TOKEN_URL)
           except DpopNonceRequiredError:
               return (Response.json({"error": "use_dpop_nonce"}, status=400)
                       .with_header("DPoP-Nonce", dpop.issue_nonce(cfg)))
           except DpopError:
               return OAuthError("invalid_dpop_proof").to_response()
       try:
           return op.handle_token_request(form, TOKEN_URL, auth_header=headers.get("authorization"),
                                          dpop=proof).to_response()
       except OAuthError as e:
           return e.to_response()
