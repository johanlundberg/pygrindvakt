DPoP: sender-constrained tokens
===============================

DPoP (RFC 9449) binds an access token to a key the client holds. The client
sends a **proof**, a short-lived JWT signed with that key, in a ``DPoP``
header on the token request; the OP issues a token whose ``cnf.jkt`` is the
key's thumbprint; every later resource request carries a fresh proof that
also hashes the access token (``ath``). A stolen token is useless without
the key.

:mod:`pygrindvakt.dpop` validates proofs; the provider and resource endpoints
consume the result. Nothing is stateful except ``jti`` replay tracking, and
even that can be traded for server nonces.

.. contents::
   :local:
   :depth: 1

Configuration
-------------

.. code-block:: python

   from pygrindvakt import dpop

   DPOP_STORE = dpop.InMemoryReplayStore()                 # per process; see below
   DPOP_CFG = dpop.DpopConfig(proof_max_age_secs=300)

   # Or, with server nonces (recommended for multi-replica deployments):
   DPOP_CFG = dpop.DpopConfig(
       require_nonce=True,
       nonce_lifetime_secs=300,
       nonce_secret=os.environ["DPOP_NONCE_SECRET"],       # high entropy, derived from the master secret
   )

Advertise support in discovery by setting
``dpop_signing_alg_values_supported`` on the
:class:`~pygrindvakt.metadata.ProviderMetadata` (for example
``["ES256", "RS256"]``).

The token endpoint
------------------

Validate the proof **before** calling ``handle_token_request`` and pass the
result through. ``htm`` is the method, ``htu`` the token endpoint URL from
configuration:

.. code-block:: python

   from pygrindvakt import DpopError, DpopNonceRequiredError, OAuthError, dpop
   from pygrindvakt.http import Response

   @app.post("/token")
   def token():
       data = request_data()
       proof = None
       hdr = data.headers.get("dpop")
       if hdr is not None:
           try:
               proof = dpop.validate_proof(DPOP_STORE, DPOP_CFG, hdr, "POST", TOKEN_URL)
           except DpopNonceRequiredError:
               return to_flask(use_dpop_nonce())
           except DpopError:
               return to_flask(OAuthError("invalid_dpop_proof").to_response())
       try:
           tr = op.handle_token_request(data.form, TOKEN_URL, auth_header=data.authorization(), dpop=proof)
       except OAuthError as e:
           return to_flask(e.to_response())
       resp = tr.to_response()                      # token_type is "DPoP" when proof was given
       if DPOP_CFG.require_nonce:
           resp = resp.with_header("DPoP-Nonce", dpop.issue_nonce(DPOP_CFG))
       return to_flask(resp)

The ``use_dpop_nonce`` challenge
--------------------------------

When ``require_nonce`` is on and the proof carries no nonce, or a stale or
forged one, :func:`~pygrindvakt.dpop.validate_proof` raises
:class:`pygrindvakt.DpopNonceRequiredError`. RFC 9449 section 8 says the
server answers with the ``use_dpop_nonce`` error and a fresh nonce in a
``DPoP-Nonce`` header; the client retries with that nonce in its proof.

.. code-block:: python

   def use_dpop_nonce() -> Response:
       body = {"error": "use_dpop_nonce", "error_description": "a DPoP nonce is required"}
       return (Response.json(body, status=400)
               .with_header("DPoP-Nonce", dpop.issue_nonce(DPOP_CFG))
               .with_header("cache-control", "no-store"))

Nonces are stateless: :func:`~pygrindvakt.dpop.issue_nonce` is an HMAC over
the current time window under ``nonce_secret``, so every replica accepts the
nonces every other replica issued, and nothing is stored. Rotate the window
by ``nonce_lifetime_secs``.

Resource requests: userinfo
---------------------------

A DPoP-bound access token must be presented with a proof for the resource
request, carrying ``ath`` (the base64url SHA-256 of the token). Validate it
with :func:`~pygrindvakt.dpop.validate_resource_proof` and hand the
thumbprint to :meth:`~pygrindvakt.provider.Provider.userinfo` as
``presented_jkt``; the provider compares it with the token's ``cnf.jkt`` and
refuses a bound token presented as a plain Bearer.

.. code-block:: python

   @app.get("/userinfo")
   def userinfo():
       data = request_data()
       auth = data.authorization() or ""
       scheme, _, token = auth.partition(" ")
       if scheme.lower() == "dpop":
           try:
               proof = dpop.validate_resource_proof(DPOP_STORE, DPOP_CFG, data.headers.get("dpop", ""),
                                                    "GET", USERINFO_URL, token)
           except DpopNonceRequiredError:
               return to_flask(use_dpop_nonce())
           except DpopError:
               return to_flask(OAuthError("invalid_dpop_proof").to_response())
           jkt = proof.jkt
       elif scheme.lower() == "bearer":
           jkt = None                      # a DPoP-bound token will be rejected by userinfo()
       else:
           return to_flask(OAuthError("access_denied", "missing token").to_response())
       try:
           return to_flask(Response.json(op.userinfo(token, presented_jkt=jkt)))
       except OAuthError as e:
           return to_flask(e.to_response())

A resource server that is not the OP validates the token with
:meth:`pygrindvakt.tokens.TokenCodec.open_access_token` (sharing the codec
secret) and compares ``payload.cnf_jkt`` with the proof's ``jkt`` itself.

Replay stores
-------------

Each proof carries a unique ``jti``. Without replay tracking a captured
proof could be reused for ``proof_max_age_secs``. Three options:

:class:`~pygrindvakt.dpop.InMemoryReplayStore`
   A process-local TTL cache. Correct for a single process; across replicas
   a proof replayed against a *different* worker is not detected.

A Python store (:class:`~pygrindvakt.dpop.ReplayStoreProtocol`)
   Anything with ``record(jti, ttl_secs) -> bool`` that returns ``True``
   only the first time. Redis ``SET NX EX`` is the natural fit:

   .. code-block:: python

      class RedisReplayStore:
          def __init__(self, r):
              self.r = r

          def record(self, jti, ttl_secs):
              return bool(self.r.set(f"dpop:jti:{jti}", 1, ex=ttl_secs, nx=True))

   If ``record`` raises, validation fails closed with
   :class:`pygrindvakt.DpopServerError` (HTTP 500) and the exception is
   logged via ``sys.unraisablehook``.

:class:`~pygrindvakt.dpop.NoReplayStore` with ``require_nonce=True``
   Records nothing; the server nonce bounds the replay window to
   ``nonce_lifetime_secs`` instead. This is stateless and replica-safe.
   Using ``NoReplayStore`` **without** ``require_nonce`` leaves proofs
   replayable, so the binding emits a ``UserWarning`` in that combination.

Errors at a glance
------------------

.. list-table::
   :header-rows: 1
   :widths: 34 66

   * - Exception
     - Response
   * - :class:`pygrindvakt.DpopNonceRequiredError`
     - ``400`` ``{"error": "use_dpop_nonce"}`` plus a ``DPoP-Nonce`` header.
   * - :class:`pygrindvakt.DpopInvalidError`, :class:`pygrindvakt.DpopReplayError`
     - ``OAuthError("invalid_dpop_proof").to_response()`` (``400``).
   * - :class:`pygrindvakt.DpopServerError`
     - ``OAuthError("server_error").to_response()`` (``500``); the store is
       down.

Testing
-------

``tests/test_dpop.py`` builds client-side proofs in Python with the
``cryptography`` package and drives the full flow: proof at the token
endpoint, a ``DPoP`` token type, rejection as Bearer at userinfo, acceptance
with a matching resource proof, and the nonce challenge. It is a good
template for testing your own endpoints.
