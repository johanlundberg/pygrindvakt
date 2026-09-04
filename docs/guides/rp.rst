Relying Party integration
=========================

A Relying Party (RP) sends the user to an OpenID Provider (OP), receives an
authorization code on its callback, exchanges it for tokens, verifies the
id_token, and optionally fetches userinfo. :mod:`pygrindvakt.rp` implements
each step; this guide strings them together. The runnable version is
``examples/flask-rp`` in the repository.

.. contents::
   :local:
   :depth: 1

Discovery
---------

Resolve the OP's metadata from its issuer URL. The issuer must be ``https``
(plain ``http`` only for loopback hosts), and the ``issuer`` in the returned
document must equal the requested one exactly, so a document served from the
wrong place cannot redirect you to someone else's endpoints.

.. code-block:: python

   from pygrindvakt import http, rp

   http_client = http.ReqwestClient()                     # never follows redirects, bounded body
   md = rp.discover(http_client, "https://op.example.com")
   info = rp.ProviderInfo.from_metadata(md)

Discovery is one HTTP round trip; cache ``info`` (and the JWKS, below) for
the process lifetime and refresh on a timer or when verification fails with
an unknown ``kid``. For a statically configured OP, build the
:class:`~pygrindvakt.rp.ProviderInfo` by hand instead:

.. code-block:: python

   info = rp.ProviderInfo(
       "https://op.example.com",
       "https://op.example.com/authorization",
       "https://op.example.com/token",
       userinfo_endpoint="https://op.example.com/userinfo",
       jwks_uri="https://op.example.com/jwks",
   )

The client
----------

An :class:`~pygrindvakt.rp.RpClient` carries the ``client_id``, the
``redirect_uri`` registered at the OP, the requested ``scope`` and how the
client authenticates at the token endpoint. The method defaults to
``client_secret_basic`` when a secret is given and ``none`` otherwise;
inconsistent combinations raise ``ValueError`` rather than being ignored.

.. code-block:: python

   me = rp.RpClient("demo", "https://rp.example.com/cb", client_secret=os.environ["OIDC_CLIENT_SECRET"])
   # or, for a public client (native app, SPA): rp.RpClient("spa", "https://rp.example.com/cb")

Starting the flow: PKCE, state and nonce in the session
-------------------------------------------------------

Generate three fresh random values per login and store them in the user's
session before redirecting:

* ``state`` binds the callback to this browser session (CSRF protection on
  the callback).
* ``nonce`` binds the id_token to this authorization request (replay
  protection); it comes back inside the signed id_token.
* the PKCE ``verifier`` binds the code exchange to the party that started
  the flow; only its ``S256`` challenge leaves the RP.

.. code-block:: python

   from pygrindvakt import pkce, util

   @app.get("/login")
   def login():
       state, nonce, verifier = util.random_token(24), util.random_token(24), util.random_token(32)
       session["oidc"] = {"state": state, "nonce": nonce, "verifier": verifier}
       url = rp.authorization_url(info, me, state, nonce, code_challenge=pkce.s256_challenge(verifier))
       return redirect(url)

``authorization_url`` also accepts ``extra`` parameters (a dict or a list of
pairs, so names can repeat) for ``prompt``, ``acr_values``, ``login_hint`` or
a signed request object:

.. code-block:: python

   url = rp.authorization_url(info, me, state, nonce, code_challenge=challenge,
                              extra={"prompt": "login", "acr_values": "urn:mfa"})

The callback: exchange and verify
---------------------------------

On the callback, check ``state`` first and pop the session entry so it can be
used only once. Then exchange the code with the stored verifier, fetch the
JWKS and verify the id_token against the issuer, your ``client_id`` and the
stored nonce.

.. code-block:: python

   from pygrindvakt import AuthnError, GrindvaktError

   @app.get("/callback")
   def callback():
       pending = session.pop("oidc", None)
       if pending is None or request.args.get("state") != pending["state"]:
           abort(400)                                        # not our flow
       if "error" in request.args:
           log.warning("OP returned %s", request.args["error"])
           return render_template("login_failed.html")
       try:
           ts = rp.exchange_code(http_client, info, me, request.args["code"], code_verifier=pending["verifier"])
           jwks = rp.fetch_jwks(http_client, info.jwks_uri, info.issuer)
           claims = rp.verify_id_token(
               jwks, ts.id_token, info.issuer, me.client_id,
               pending["nonce"], ["ES256"],
           )
       except GrindvaktError:
           log.exception("login failed")                     # str(e) is for logs only
           return render_template("login_failed.html")
       session["user"] = {"sub": claims["sub"], "email": claims.get("email")}
       return redirect("/")

:func:`~pygrindvakt.rp.verify_id_token` checks the signature against the
JWKS, the explicit signing-algorithm allowlist, ``iss``, ``sub``, every
``aud`` value, ``azp`` when applicable, ``exp``, ``iat`` and the nonce, and
returns the claims as a dict. A non-200 from the token endpoint raises
:class:`pygrindvakt.AuthnError` with a sanitized, truncated copy of the
upstream error body; treat it as log material, never show it to the user.

.. important:: The nonce is required.

   ``verify_id_token`` refuses ``expected_nonce=None`` with
   :class:`pygrindvakt.AuthnError`. Omitting the nonce in the code flow lets a
   captured id_token be replayed into a different session. The only way past
   the guard is
   ``unsafe_skip_nonce_check=True``, which emits a ``UserWarning`` and exists
   for flows that genuinely carry no nonce (a pure OAuth 2.0 flow whose
   token response happens to include an id_token). A nonce that *is* given
   is always enforced, flag or not.

Userinfo
--------

.. code-block:: python

   profile = rp.fetch_userinfo(
       http_client, info.userinfo_endpoint, ts.access_token, claims["sub"], info.issuer
   )

The request is a POST with the token in the ``Authorization`` header, which
OIDC Core permits and every OP built with pygrindvakt accepts. A non-200
raises :class:`pygrindvakt.AuthnError`. The response must contain a string
``sub`` exactly equal to the validated ID-token subject. The result is a dict;
:func:`~pygrindvakt.rp.claims_to_attributes` flattens it (or the id_token
claims) into the ``{name: [values]}`` shape an attribute-based backend or a
SAML proxy expects.

The rest of the token response (``refresh_token``, ``expires_in``,
``scope``) is available as ``ts.raw``.

Authenticating with ``private_key_jwt``
---------------------------------------

With ``private_key_jwt`` the RP proves possession of a private key instead
of sending a shared secret; the OP holds only the public JWKS. Register the
public key set at the OP and give the :class:`~pygrindvakt.rp.RpClient` the
signing key:

.. code-block:: python

   from pygrindvakt import keys

   rp_key = keys.signing_key_from_pem(open("rp-key.pem", "rb").read(), kid="rp-1")
   # The OP registers: client.Client("jwt-rp", redirect_uris=[...],
   #                    token_endpoint_auth_method="private_key_jwt", jwks=rp_key.to_public_jwks())
   me = rp.RpClient("jwt-rp", "https://rp.example.com/cb", auth_method="private_key_jwt", signing_key=rp_key)

:func:`~pygrindvakt.rp.exchange_code` then builds and sends the assertion
itself. For other endpoints that require client authentication (introspection,
revocation, a federation OP's token endpoint from custom code), build one
explicitly with :func:`~pygrindvakt.rp.build_client_assertion`. The audience
is the token endpoint URL:

.. code-block:: python

   assertion = rp.build_client_assertion(rp_key, "jwt-rp", info.token_endpoint)
   form = [
       ("grant_type", "authorization_code"), ("code", code), ("redirect_uri", me.redirect_uri),
       ("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
       ("client_assertion", assertion),
   ]
   status, body, _ = http_client.post_form(info.token_endpoint, form, [])

The assertion has ``iss`` = ``sub`` = ``client_id``, ``aud`` = the audience,
a 300-second lifetime and a random ``jti``; the OP consumes the ``jti`` so an
assertion cannot be replayed.

Signed request objects (JAR)
----------------------------

OpenID Federation automatic registration, and some OPs by policy, require the
authorization parameters to arrive as a signed JWT (RFC 9101).
:func:`~pygrindvakt.rp.signed_request_object` builds one from the same
inputs as ``authorization_url``; pass it as the ``request`` parameter
alongside the plain parameters:

.. code-block:: python

   jar = rp.signed_request_object(info, me, rp_key, state, nonce, code_challenge=challenge)
   url = rp.authorization_url(info, me, state, nonce, code_challenge=challenge, extra={"request": jar})

Using a custom HTTP client
--------------------------

Every networked function takes ``http`` first: ``None`` for the shared
built-in client, an explicit :class:`~pygrindvakt.http.ReqwestClient` with
your own limits, or any object implementing
:class:`~pygrindvakt.http.HttpClientProtocol`. Reasons to inject your own:
a private CA, an outbound proxy, per-host allowlists, or tests.

.. code-block:: python

   import httpx

   class HttpxClient:
       def __init__(self, **kw):
           self._c = httpx.Client(follow_redirects=False, timeout=httpx.Timeout(10.0), **kw)

       def get(self, url):
           r = self._c.get(url)
           return r.status_code, r.content, r.headers.get("content-type")

       def post_form(self, url, form, headers):
           r = self._c.post(url, data=dict(form), headers=dict(headers))
           return r.status_code, r.content, r.headers.get("content-type")

   http_client = HttpxClient(verify="/etc/ssl/private-ca.pem", proxy="http://proxy.internal:3128")
   md = rp.discover(http_client, "https://op.internal.example")

The contract: return ``(status, body: bytes, content_type)`` or an
:class:`~pygrindvakt.http.HttpFetchResponse`; **never follow redirects**;
enforce timeouts; bound the body size. An exception is logged through
``sys.unraisablehook`` and surfaces as :class:`pygrindvakt.InternalError`.
The methods run on the thread that called ``rp.discover`` (holding the GIL);
they may call back into pygrindvakt, at the cost of a helper thread per
nested call.

Testing without a network
-------------------------

Because the HTTP client is injectable, an RP can be tested end to end against
an in-process :class:`~pygrindvakt.provider.Provider`, as
``tests/test_rp.py`` does: a fake client answers discovery and JWKS from
``op.discovery_document()`` / ``op.jwks_document()`` and forwards token and
userinfo requests to ``op.handle_token_request`` / ``op.userinfo``. Those
nested calls into pygrindvakt from inside the fake are supported; each runs
on a helper thread (see :doc:`stores`).

Security notes
--------------

* Check ``state`` before touching anything else on the callback, and pop the
  session entry so it cannot be reused.
* Always pass the stored nonce; never ``unsafe_skip_nonce_check`` in a code
  flow.
* Prefer ``private_key_jwt``; load the key from a file or HSM, not source.
* Treat every :class:`pygrindvakt.AuthnError` as log material.
* Keep the built-in HTTP client unless you need a private CA or proxy, and
  then keep its three properties.

See :doc:`security` for the full list.
