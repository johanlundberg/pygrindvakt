Quickstart
==========

This page builds a complete OpenID Provider (OP) in a few dozen lines and then
drives it from the Relying Party (RP) side, all in one process and without a
network. Everything here is framework-agnostic: inputs are plain dicts and
strings, outputs are :class:`pygrindvakt.http.Response` objects. The framework
guides show how to wire the same calls into Flask, Django and FastAPI.

Build a Provider
----------------

A :class:`~pygrindvakt.provider.Provider` needs four things: its metadata
(mainly the issuer URL), a signing key, a client store, and a token codec
secret. Build it once at startup and share it across requests and threads.

.. code-block:: python

   from pygrindvakt import client, keys, metadata, provider, tokens

   ISSUER = "https://op.example.com"

   op = provider.Provider(
       metadata.ProviderMetadata(ISSUER),                       # endpoints derived from ISSUER
       keys.signing_key_from_pem(open("op-key.pem", "rb").read(), kid="op-1"),
       client.InMemoryClientStore([
           client.Client(
               "demo",
               client_secret="s3cret",
               redirect_uris=["https://rp.example.com/cb"],
               grant_types=["authorization_code", "refresh_token"],
           ),
       ]),
       tokens.TokenCodec("a-long-random-secret"),               # seals codes / tokens
       token_use_store=provider.InMemoryTokenUseStore(),        # one-time-use tracking
   )

For a quick experiment without a PEM file, generate a key in memory:

.. code-block:: python

   op_key = keys.signing_key_from_jwk(keys.generate_ec_jwk("P-256"), alg="ES256", kid="op-1")

.. note::

   ``InMemoryTokenUseStore`` and ``InMemoryClientStore`` are per-process.
   Behind gunicorn or any multi-worker server, use
   :class:`~pygrindvakt.provider.RedisStore` or a Python-backed store instead;
   see :doc:`guides/stores`.

The five endpoints
------------------

Every OP exposes the same five endpoints. Each maps to one or two calls on the
provider; the only framework-specific work is extracting the query / form dict
and the ``Authorization`` header, and converting the returned ``Response``.

**Discovery and JWKS** are static dicts:

.. code-block:: python

   from pygrindvakt.http import Response

   discovery = Response.json(op.discovery_document())   # /.well-known/openid-configuration
   jwks = Response.json(op.jwks_document())             # /jwks (public keys only)

**Authorization**, first half: parse and validate the incoming request. On
failure the ``redirect_uri`` is *not* trusted yet, so render the error
directly.

.. code-block:: python

   from pygrindvakt import OAuthError
   from pygrindvakt.request import AuthorizationRequest

   try:
       req = AuthorizationRequest.from_params(query_pairs)  # preserve duplicates for rejection
       op.validate_authorization_request(req)            # returns the registered Client
   except OAuthError as e:
       return e.to_response()                            # 400 JSON, never a redirect
   session["authz"] = req.to_dict()                      # stash it while the user logs in

**Authorization**, second half: after your application has authenticated the
user, mint the code and redirect back. Now the ``redirect_uri`` has been
validated, so protocol errors may be redirected.

.. code-block:: python

   req = AuthorizationRequest.from_dict(session.pop("authz"))
   try:
       resp = op.authorization_redirect(
           req, "alice",                                     # the subject identifier
           {"email": ["alice@example.com"], "email_verified": ["true"]},
       )
   except OAuthError as e:
       mode = "fragment" if req.use_fragment() else "query"
       resp = e.to_redirect(req.redirect_uri, mode)
   # resp.status == 302, resp.header("location") carries ?code=...&state=...

**Token**: hand over the form body, the *configured* token URL and the raw
``Authorization`` header.

.. code-block:: python

   try:
       tr = op.handle_token_request(
           form_pairs,                            # preserve duplicates for rejection
           f"{ISSUER}/token",                     # from configuration, never from Host
           auth_header=headers.get("authorization"),
       )
       resp = tr.to_response()                    # 200, JSON, cache-control: no-store
   except OAuthError as e:
       resp = e.to_response()                     # 400 / 401 / 500 with the right body

**Userinfo**: validate the bearer token and return the claims.

.. code-block:: python

   try:
       resp = Response.json(op.userinfo(access_token))
   except OAuthError as e:
       resp = e.to_response()

Converting a ``Response`` into your framework's type is one line; for Flask:

.. code-block:: python

   from flask import Response as FlaskResponse

   def to_flask(r):
       return FlaskResponse(r.body, status=r.status, headers=list(r.headers))

.. important::

   Only ``OAuthError.to_response()`` and ``OAuthError.to_redirect()`` produce
   output that is safe to send to a client. Never put ``str(exc)`` of any
   other :class:`pygrindvakt.GrindvaktError` into a response body: those
   messages are for logs and can leak internal detail. See
   :doc:`guides/security`.

The Relying Party side
----------------------

The :mod:`pygrindvakt.rp` module is the client half. Discover the provider,
build the authorization URL with fresh ``state``, ``nonce`` and PKCE values,
then exchange the returned code and verify the id_token.

.. code-block:: python

   from pygrindvakt import http, pkce, rp, util

   http_client = http.ReqwestClient()             # never follows redirects, bounded body
   md = rp.discover(http_client, "https://op.example.com")
   info = rp.ProviderInfo.from_metadata(md)
   me = rp.RpClient("demo", "https://rp.example.com/cb", client_secret="s3cret")

   # 1. Start the flow: store these three in the user's session.
   state, nonce, verifier = util.random_token(24), util.random_token(24), util.random_token(32)
   url = rp.authorization_url(info, me, state, nonce, code_challenge=pkce.s256_challenge(verifier))
   # ... redirect the browser to `url` ...

   # 2. On the callback: check `state`, then exchange the code.
   tokens_ = rp.exchange_code(http_client, info, me, code, code_verifier=verifier)
   jwks = rp.fetch_jwks(http_client, info.jwks_uri, info.issuer)
   claims = rp.verify_id_token(jwks, tokens_.id_token, info.issuer, "demo", nonce, ["ES256"])
   userinfo = rp.fetch_userinfo(http_client, info.userinfo_endpoint, tokens_.access_token,
                                claims["sub"], info.issuer)

``verify_id_token`` **requires** the expected nonce and an explicit signing
algorithm allowlist. Passing ``None`` for the nonce raises
:class:`pygrindvakt.AuthnError` unless you also pass
``unsafe_skip_nonce_check=True``, which emits a ``UserWarning``; that is
reserved for flows that genuinely carry no nonce.

A full round trip in one process
--------------------------------

The test suite drives the RP against an in-process OP by implementing the
``HttpClient`` protocol in Python. The same trick is useful for integration
tests of your own application:

.. code-block:: python

   import json

   class FakeHttpClient:
       """Routes the RP's outbound requests into an in-process Provider."""

       def __init__(self, op):
           self.op = op

       def get(self, url):
           if url.endswith("/.well-known/openid-configuration"):
               return 200, json.dumps(self.op.discovery_document()).encode(), "application/json"
           if url.endswith("/jwks"):
               return 200, json.dumps(self.op.jwks_document()).encode(), "application/json"
           return 404, b"", None

       def post_form(self, url, form, headers):
           hdrs = {k.lower(): v for k, v in headers}
           try:
               tr = self.op.handle_token_request(form, url, auth_header=hdrs.get("authorization"))
               return 200, json.dumps(tr.to_dict()).encode(), "application/json"
           except OAuthError as e:
               r = e.to_response()
               return r.status, r.body, "application/json"

   md = rp.discover(FakeHttpClient(op), ISSUER)
   assert md.issuer == ISSUER

.. note::

   The fake client calls back into pygrindvakt (``handle_token_request``,
   ``userinfo``) from inside the RP's ``discover`` / ``exchange_code`` call.
   That nested call is supported: the runtime notices it is already inside a
   call and runs the nested one on a helper thread, at the cost of one thread
   spawn per nested call. See :doc:`guides/stores`.

Where to go next
----------------

* :doc:`guides/security` is the most important next read: the guards the
  binding adds, what is client-safe to render, and the ``unsafe_*`` footguns.
* :doc:`guides/op_flask`, :doc:`guides/op_django` and :doc:`guides/op_fastapi`
  show the request / response adapters for each framework.
* :doc:`guides/rp` covers the Relying Party in depth, including
  ``private_key_jwt`` and custom HTTP clients.
* :doc:`guides/dpop` adds sender-constrained tokens.
* :doc:`guides/federation` covers OpenID Federation trust chains and
  automatic client registration.
* :doc:`guides/stores` explains multi-process deployment and the runtime model.
