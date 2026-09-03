pygrindvakt.mac
===============

.. py:module:: pygrindvakt.mac

HMAC and digest helpers, exposed for applications that want to derive
per-purpose secrets or compare credentials the same way grindvakt does.
Inputs and outputs are ``bytes``.

.. py:function:: hmac_sha256(key: bytes, data: bytes) -> bytes

   HMAC-SHA256 of ``data`` under ``key`` (32 bytes).

.. py:function:: sha256(data: bytes) -> bytes

   SHA-256 digest of ``data`` (32 bytes).

.. py:function:: constant_time_eq(a: bytes, b: bytes) -> bool

   Constant-time byte-string equality. Use it, or :func:`hmac.compare_digest`,
   whenever you compare a secret or a MAC with an attacker-supplied value.

.. code-block:: python

   import base64
   from pygrindvakt import mac

   master = os.environ["OP_SECRET"].encode()
   # Derive an independent secret for DPoP nonces from the master secret.
   nonce_secret = base64.urlsafe_b64encode(mac.hmac_sha256(master, b"dpop-nonce")).decode()

   # Access-token hash for DPoP's ``ath`` claim (base64url, no padding).
   ath = base64.urlsafe_b64encode(mac.sha256(access_token.encode())).rstrip(b"=").decode()

   assert mac.constant_time_eq(b"abc", b"abc")
