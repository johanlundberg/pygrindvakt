pygrindvakt.pkce
================

.. py:module:: pygrindvakt.pkce

RFC 7636 Proof Key for Code Exchange helpers.

On the RP side, generate a random verifier, send its ``S256`` challenge in the
authorization request, and send the verifier with the code exchange. The OP
side (:class:`pygrindvakt.provider.Provider`) checks the pair itself; the
:func:`verify` function is exposed for custom grant handling and tests.

.. py:function:: s256_challenge(verifier: str) -> str

   The ``S256`` code challenge for a PKCE verifier: base64url, no padding, of
   the SHA-256 of the verifier's ASCII bytes.

.. py:function:: verify(verifier: str, challenge: str, method: str | None = None) -> bool

   Verify a PKCE verifier against a challenge. ``method`` is ``"S256"`` or
   ``"plain"``; per RFC 7636 section 4.3 a missing method means ``plain``,
   so **always pass** ``"S256"`` **explicitly** when you know the method, and
   advertise only ``S256`` in ``code_challenge_methods_supported`` (the
   default).

.. code-block:: python

   from pygrindvakt import pkce, util

   verifier = util.random_token(32)                 # 43 URL-safe characters
   challenge = pkce.s256_challenge(verifier)
   # ... authorization request carries code_challenge=challenge&code_challenge_method=S256 ...
   assert pkce.verify(verifier, challenge, "S256")
   assert not pkce.verify("wrong", challenge, "S256")
