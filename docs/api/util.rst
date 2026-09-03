pygrindvakt.util
================

.. py:module:: pygrindvakt.util

Time and randomness helpers.

.. py:function:: now_secs() -> int

   Current Unix time in seconds, the clock grindvakt uses for ``iat`` /
   ``exp`` checks.

.. py:function:: now_rfc3339() -> str

   An RFC 3339 timestamp for "now" (UTC).

.. py:function:: random_token(n: int = 32) -> str

   A URL-safe random token from ``n`` bytes of OS entropy (base64url, no
   padding). Use it for ``state``, ``nonce``, PKCE verifiers and session
   identifiers. 24 bytes gives 192 bits of entropy; 32 bytes is the
   43-character verifier RFC 7636 recommends.

.. code-block:: python

   from pygrindvakt import util

   state = util.random_token(24)
   nonce = util.random_token(24)
   verifier = util.random_token(32)
   exp = util.now_secs() + 300
