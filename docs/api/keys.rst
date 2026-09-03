pygrindvakt.keys
================

.. py:module:: pygrindvakt.keys

Signing-key loading from PEM / DER, JWK, or a PKCS#11 token, plus JWK
generation and thumbprints.

A :class:`SigningKey` is **opaque**: the private material never crosses into
Python. Only the algorithm, the key id and the public JWK / JWKS are exposed,
and ``repr()`` shows nothing else.

.. py:class:: SigningKey

   A loaded signing key, software or HSM-backed. Immutable and cheap to
   clone; construct via the ``signing_key_from_*`` functions.

   .. py:property:: alg
      :type: str

      The JWS algorithm this key signs with, e.g. ``"ES256"``.

   .. py:property:: kid
      :type: str | None

      The key id published in JWKS and JWT headers, if any.

   .. py:method:: public_jwk() -> dict[str, Any]

      The public JWK (no private components) as a dict.

   .. py:method:: to_public_jwks() -> dict[str, Any]

      A one-key JWKS document (``{"keys": [...]}``) as a dict. This is what
      an RP registers with an OP for ``private_key_jwt``, and what a
      federation entity publishes in its entity configuration.

   .. code-block:: python

      from pygrindvakt import keys

      key = keys.signing_key_from_pem(open("op-key.pem", "rb").read(), kid="op-1")
      key.alg                 # "ES256" for a P-256 key, "RS256" for RSA, "EdDSA" for Ed25519
      key.to_public_jwks()    # {"keys": [{"kty": "EC", "crv": "P-256", "kid": "op-1", ...}]}

Loading keys
------------

.. py:function:: signing_key_from_pem(data: bytes, alg: str | None = None, kid: str | None = None) -> SigningKey

   Load a signing key from PEM (or DER) bytes in PKCS#8, PKCS#1 or SEC1
   encoding. ``alg`` overrides the algorithm inferred from the key type (for
   example ``"PS256"`` instead of ``"RS256"`` for an RSA key); ``kid`` sets
   the published key id. Raises :class:`pygrindvakt.CryptoError` or
   :class:`pygrindvakt.JoseError` on unparsable input.

.. py:function:: signing_key_from_jwk_json(json: str, alg: str | None = None, kid: str | None = None) -> SigningKey

   Load a signing key from a private JWK given as a JSON string.

.. py:function:: signing_key_from_jwk(jwk: dict[str, Any], alg: str | None = None, kid: str | None = None) -> SigningKey

   Load a signing key from a private JWK given as a dict.

   .. code-block:: python

      jwk = keys.generate_ec_jwk("P-256")
      key = keys.signing_key_from_jwk(jwk, alg="ES256", kid="op-1")

.. py:function:: signing_key_from_pkcs11(module_path: str, pin: str, key_label: str, alg: str, kid: str | None = None) -> SigningKey

   Load a signing key whose private material lives on a PKCS#11 token
   (SoftHSM2, Kryoptic, a hardware HSM). Signing happens on the token; the
   private key is never read out.

   ``module_path`` is the PKCS#11 shared library; ``key_label`` is the
   ``CKA_LABEL`` of the key pair; ``alg`` is the JWS algorithm to sign with
   (e.g. ``"ES256"``, ``"RS256"``). An unknown ``alg`` raises
   :class:`pygrindvakt.CryptoError`.

   .. warning::

      ``pin`` is a Python ``str`` and cannot be zeroized after use. Read it
      from a secret store or the environment at startup and do not keep
      other references to it.

   .. code-block:: python

      key = keys.signing_key_from_pkcs11(
          "/usr/lib/softhsm/libsofthsm2.so", os.environ["HSM_PIN"], "op-signing-key", "ES256", kid="hsm-1"
      )

   Prefer building the wheel on (or against) the target host when deploying
   with an HSM: the PKCS#11 module is loaded with ``dlopen`` at runtime from
   that host. See :doc:`../installation`.

Generating keys
---------------

These are intended for tests and bootstrapping. Persist the result yourself;
the examples write it to a mode ``0600`` file on first run.

.. py:function:: generate_ec_jwk(curve: str = "P-256") -> dict[str, Any]

   Generate a fresh EC private JWK (``"P-256"`` or ``"P-384"``) as a dict.

.. py:function:: generate_rsa_jwk(bits: int = 2048) -> dict[str, Any]

   Generate a fresh RSA private JWK as a dict.

.. py:function:: generate_ed25519_jwk() -> dict[str, Any]

   Generate a fresh Ed25519 private JWK as a dict.

Thumbprints
-----------

.. py:function:: jwk_thumbprint(jwk: dict[str, Any]) -> str

   The RFC 7638 SHA-256 JWK thumbprint (base64url) of a JWK dict. This is the
   ``jkt`` value a DPoP-bound access token is confirmed against, so an OP or
   resource server can compare ``jwk_thumbprint(proof_jwk)`` with
   :attr:`pygrindvakt.dpop.DpopProof.jkt`.
