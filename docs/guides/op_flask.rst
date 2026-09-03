OpenID Provider on Flask
========================

This guide builds the five OP endpoints as Flask views. The full, runnable
version is ``examples/flask-op/app.py`` in the repository (with the shared
demo configuration in ``examples/common/op_config.py``); run it with
``python examples/flask-op/app.py`` and it listens on ``127.0.0.1:5000``.

The recipe is the same for every framework: two small adapters translate
between the framework's request / response objects and pygrindvakt's
:class:`~pygrindvakt.http.HttpRequestData` / :class:`~pygrindvakt.http.Response`,
and the views call the :class:`~pygrindvakt.provider.Provider`.

The adapters
------------

.. code-block:: python

   import flask
   from pygrindvakt.http import HttpRequestData, Response

   def request_data() -> HttpRequestData:
       """Normalize the current ``flask.request`` into an ``HttpRequestData``."""
       r = flask.request
       return HttpRequestData(
           path=r.path.lstrip("/"),
           method=r.method,
           uri=r.url,
           query=r.args.to_dict(),
           form=r.form.to_dict(),
           body=r.get_data(),
           headers={k.lower(): v for k, v in r.headers.items()},
           cookies=r.cookies.to_dict(),
       )

   def to_flask(resp: Response) -> flask.Response:
       """Turn a pygrindvakt ``Response`` into a Flask response."""
       return flask.Response(resp.body, status=resp.status, headers=list(resp.headers))

``HttpRequestData`` is a convenience: the provider methods themselves only
need the query dict, the form dict and the ``Authorization`` header, so you
may equally pass ``r.args.to_dict()`` and ``r.headers.get("Authorization")``
directly. The adapter keeps the views identical across frameworks and gives
you ``bearer_token()`` for free.

Building the provider
---------------------

Build the ``Provider`` once, at application creation, from configuration.
Every endpoint URL derives from the issuer setting, never from the request.

.. code-block:: python

   import os
   from flask import Flask, session
   from pygrindvakt import OAuthError, client, keys, metadata, provider, tokens
   from pygrindvakt.request import AuthorizationRequest

   ISSUER = os.environ.get("OP_ISSUER", "http://127.0.0.1:5000")

   def build_provider(issuer: str) -> provider.Provider:
       demo_rp = client.Client(
           "demo",
           client_secret="demo-secret",
           redirect_uris=["http://127.0.0.1:5001/callback"],
           grant_types=["authorization_code", "refresh_token"],
           client_name="Demo RP",
       )
       return provider.Provider(
           metadata.ProviderMetadata(issuer),
           keys.signing_key_from_jwk(json.load(open("op-key.json")), alg="ES256", kid="op-1"),
           client.InMemoryClientStore([demo_rp]),
           tokens.TokenCodec(os.environ["OP_SECRET"]),
           token_use_store=provider.InMemoryTokenUseStore(),   # RedisStore under gunicorn
       )

   def create_app(issuer: str = ISSUER) -> Flask:
       app = Flask(__name__)
       app.secret_key = os.environ["OP_SECRET_KEY"]
       op = build_provider(issuer)
       token_url = f"{issuer}/token"      # from configuration, never from the Host header
       ...
       return app

The five endpoints
------------------

**Discovery and JWKS** serve static dicts:

.. code-block:: python

   @app.get("/.well-known/openid-configuration")
   def discovery():
       return to_flask(Response.json(op.discovery_document()))

   @app.get("/jwks")
   def jwks():
       return to_flask(Response.json(op.jwks_document()))

**Authorization, GET**: parse and validate, stash the request in the session,
show the login form. Until validation succeeds the ``redirect_uri`` is
untrusted, so errors are rendered directly.

.. code-block:: python

   @app.get("/authorization")
   def authorization():
       data = request_data()
       try:
           req = AuthorizationRequest.from_params(data.query)
           op.validate_authorization_request(req)
       except OAuthError as e:
           # The redirect_uri is not trusted until validation succeeds: never redirect here.
           return to_flask(e.to_response())
       session["authz"] = req.to_dict()
       return render_login_form(req.client_id)

**Authorization, POST**: check the credentials, then either redirect back
with a code or redirect back with ``access_denied``. Both redirects are safe
because the URI was validated on the GET.

.. code-block:: python

   @app.post("/authorization")
   def login():
       stored = session.pop("authz", None)
       if stored is None:
           return to_flask(OAuthError("invalid_request", "no pending authorization request").to_response())
       req = AuthorizationRequest.from_dict(stored)
       form = request_data().form
       claims = authenticate(form.get("username", ""), form.get("password", ""))
       if claims is None:
           err = OAuthError("access_denied", "wrong username or password", req.state)
           return to_flask(err.to_redirect(req.redirect_uri))       # validated on the GET
       try:
           return to_flask(op.authorization_redirect(req, form["username"], claims))
       except OAuthError as e:
           return to_flask(e.to_redirect(req.redirect_uri))

``authenticate`` is your application's business: it returns the user's claims
in ``external_claims`` shape (claim name to list of strings), for example
``{"email": ["alice@example.com"], "email_verified": ["true"]}``, or ``None``.
Pass the ``acr`` argument when you know how the user authenticated.

**Token**: form body, configured token URL, raw ``Authorization`` header.

.. code-block:: python

   @app.post("/token")
   def token():
       data = request_data()
       try:
           tr = op.handle_token_request(data.form, token_url, auth_header=data.authorization())
       except OAuthError as e:
           return to_flask(e.to_response())
       return to_flask(tr.to_response())

**Userinfo**: the bearer token from the header. Accept both GET and POST:
OIDC Core allows either, and :func:`pygrindvakt.rp.fetch_userinfo` sends a
POST.

.. code-block:: python

   @app.route("/userinfo", methods=["GET", "POST"])     # OIDC Core 5.3 allows both
   def userinfo():
       access_token = request_data().bearer_token()
       if access_token is None:
           return to_flask(OAuthError("access_denied", "missing bearer token").to_response())
       try:
           return to_flask(Response.json(op.userinfo(access_token)))
       except OAuthError as e:
           return to_flask(e.to_response())

Sessions and CSRF
-----------------

The pending :class:`~pygrindvakt.request.AuthorizationRequest` round-trips
through ``to_dict()`` / ``from_dict()``, so Flask's signed-cookie session is
enough; no server-side storage is needed. Pop it on the POST so a second
submission cannot reuse it. The example sets a distinct session cookie name
because the demo RP runs on the same host.

The token endpoint is called by OAuth clients, not browsers, and must be
reachable without a CSRF token or a session cookie. If you use Flask-WTF's
global CSRF protection, exempt ``/token``.

Running under gunicorn
----------------------

Build the ``Provider`` in ``create_app()`` (as above) so each worker builds
its own, or build it in a ``post_fork`` hook. Replace
``InMemoryTokenUseStore`` with :class:`~pygrindvakt.provider.RedisStore`
constructed **in the worker**, otherwise a code consumed by one worker is
still valid in the others. :doc:`stores` has the details and a ``post_fork``
example.

Adding DPoP
-----------

Validate the ``DPoP`` header before ``handle_token_request`` and pass the
proof through; at userinfo, validate the resource proof and pass
``presented_jkt``. :doc:`dpop` shows both endpoints.
