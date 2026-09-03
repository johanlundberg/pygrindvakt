pygrindvakt.jwt
===============

.. py:module:: pygrindvakt.jwt

Thin JWS sign / verify helpers over jose-rs. Claims and headers cross the
boundary as dicts; :class:`Validation` is a small builder mirroring
``jose_rs::jwt::Validation``.

These are the primitives the higher-level modules are built on. Use them for
custom tokens (an internal service token, a signed logout token) and for
tests; for id_tokens, entity statements and client assertions prefer the
dedicated functions in :mod:`pygrindvakt.rp` and
:mod:`pygrindvakt.federation`, which apply the right validation rules.

Validation rules
----------------

.. py:class:: Validation()

   JWT validation rules. Immutable: every ``with_*`` / ``require_*`` method
   returns a new ``Validation``, so calls can be chained. A fresh
   ``Validation()`` checks ``exp`` and ``nbf`` when present, rejects an
   ``iat`` in the future, and allows 60 seconds of clock skew; it requires
   no claim and pins no issuer, audience, ``typ`` or algorithm. Add the
   constraints you need.

   .. py:method:: with_issuer(issuer: str) -> Validation

      Require ``iss`` to equal ``issuer``.

   .. py:method:: with_audience(audience: str) -> Validation

      Require ``aud`` to contain ``audience`` (string or array form).

   .. py:method:: with_subject(subject: str) -> Validation

      Require ``sub`` to equal ``subject``.

   .. py:method:: with_leeway(seconds: int) -> Validation

      Clock-skew leeway in seconds for ``exp`` / ``nbf`` / ``iat``.

   .. py:method:: with_typ(typ: str) -> Validation

      Require the protected header ``typ`` to equal ``typ`` (RFC 8725
      section 3.11: explicit typing prevents a token issued for one purpose
      being accepted for another).

   .. py:method:: with_max_age(seconds: int) -> Validation

      Reject tokens whose ``iat`` is older than ``seconds`` (also requires
      ``iat``).

   .. py:method:: with_allowed_algorithms(algs: list[str]) -> Validation

      Restrict the accepted header ``alg`` values, e.g. ``["ES256", "RS256"]``.
      An unknown name raises :class:`pygrindvakt.CryptoError`. Without this,
      any asymmetric algorithm the key supports is accepted; ``none`` and
      symmetric algorithms are never accepted against a public key.

   .. py:method:: require_exp() -> Validation
   .. py:method:: require_nbf() -> Validation
   .. py:method:: require_iat() -> Validation
   .. py:method:: require_kid() -> Validation

      Require the corresponding claim (or the ``kid`` header) to be present.

Signing and verifying
---------------------

.. py:function:: sign(key: SigningKey, claims: dict[str, Any], typ: str | None = None) -> str

   Sign a claims dict into a compact JWS with ``key``, setting the ``alg``
   and ``kid`` headers from the key and, optionally, a custom ``typ`` header.
   ``claims`` may contain any JSON values; nothing is added or checked, so
   set ``iat`` / ``exp`` yourself.

.. py:function:: verify_with_jwks(jwks: dict[str, Any], token: str, validation: Validation) -> dict[str, Any]

   Verify a compact JWS against a JWKS dict (``{"keys": [...]}``), selecting
   the key by ``kid`` when the header has one, and return the validated
   claims as a dict. Raises :class:`pygrindvakt.JoseError` /
   :class:`pygrindvakt.AuthnError` on a bad signature or a failed rule.

.. py:function:: verify_with_jwk(jwk: dict[str, Any], token: str, validation: Validation) -> dict[str, Any]

   Verify a compact JWS against a single JWK dict.

Inspection without verification
-------------------------------

.. py:function:: peek_header(token: str) -> dict[str, Any]

   The protected header of a compact JWS as a dict, **without**
   verification. Use it to read ``kid`` or ``typ`` before choosing a key set.

.. py:function:: peek_claims_unverified(token: str) -> dict[str, Any]

   The claims of a compact JWS as a dict, **without** verifying the
   signature.

   .. warning::

      Inspection only, for example reading ``iss`` to decide which JWKS to
      fetch. Never make a decision on these values; verify first.

Example
-------

.. code-block:: python

   from pygrindvakt import jwt, keys, util

   key = keys.signing_key_from_jwk(keys.generate_ec_jwk(), alg="ES256", kid="svc-1")
   now = util.now_secs()
   token = jwt.sign(
       key,
       {"iss": "https://svc.example", "aud": "https://api.example", "sub": "job-42",
        "iat": now, "exp": now + 300},
       typ="svc+jwt",
   )

   rules = (jwt.Validation()
            .with_issuer("https://svc.example")
            .with_audience("https://api.example")
            .with_typ("svc+jwt")
            .with_allowed_algorithms(["ES256"])
            .require_exp()
            .require_iat()
            .with_max_age(600))
   claims = jwt.verify_with_jwks(key.to_public_jwks(), token, rules)
   assert claims["sub"] == "job-42"

   jwt.peek_header(token)["kid"]     # "svc-1", unverified
