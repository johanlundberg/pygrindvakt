API reference
=============

One page per submodule. Every page is hand-written from the type stubs and the
Rust doc comments, so the reference is exact for the released binding without
requiring the compiled extension to build.

Conventions that hold across the whole API:

* **JSON-shaped values are native Python.** Claims, JWKs, JWK Sets
  (``{"keys": [...]}``), metadata documents and policies are plain dicts and
  lists in both directions.
* **Enums are lower-case strings**, for example ``"client_secret_basic"``.
* **Wrapped objects are immutable** unless the page says otherwise, and are
  safe to share across threads.
* **Networked functions take ``http`` first.** Pass ``None`` for the built-in
  :class:`pygrindvakt.http.ReqwestClient`, an explicit ``ReqwestClient``, or
  any object implementing the ``HttpClient`` protocol. The call blocks the
  calling thread with the GIL released.
* **Secrets are** ``str``. A Python string cannot be zeroized, so a
  ``client_secret``, codec secret or PKCS#11 PIN stays in memory until the
  garbage collector reclaims it. Load them from a secret store, not from
  source.
* **Errors** are the typed :doc:`exception hierarchy <../exceptions>`;
  protocol errors are :class:`pygrindvakt.OAuthError`.

.. toctree::
   :maxdepth: 1

   http
   keys
   client
   metadata
   request
   tokens
   provider
   dpop
   rp
   federation
   discovery
   jwt
   pkce
   mac
   util
