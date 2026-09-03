OpenID Provider on Django
=========================

This guide builds the five OP endpoints as Django views. The runnable version
is ``examples/django-op`` in the repository: ``op/adapters.py`` holds the two
adapters, ``op/provider.py`` the process-wide ``Provider``, ``op/views.py``
the views, and ``opsite/urls.py`` the routing. Run it with
``cd examples/django-op && python manage.py runserver 5000``.

The adapters
------------

Django's ``request.headers`` already presents ``META``'s ``HTTP_*`` entries
by their natural names; pygrindvakt wants them lower-cased. Read ``body``
before ``POST`` so the raw bytes remain available.

.. code-block:: python

   from django.http import HttpRequest, HttpResponse
   from pygrindvakt.http import HttpRequestData, Response

   def request_data(request: HttpRequest) -> HttpRequestData:
       body = request.body
       return HttpRequestData(
           path=request.path.lstrip("/"),
           method=request.method or "GET",
           uri=request.build_absolute_uri(),
           query=request.GET.dict(),
           form=request.POST.dict(),
           body=body,
           headers={k.lower(): v for k, v in request.headers.items()},
           cookies=dict(request.COOKIES),
       )

   def to_django(resp: Response) -> HttpResponse:
       out = HttpResponse(resp.body, status=resp.status)
       del out["Content-Type"]              # keep only what pygrindvakt set
       for name, value in resp.headers:
           out[name] = value
       return out

Deleting Django's default ``Content-Type`` matters: a ``302`` from
``authorization_redirect`` carries no content type, and the JSON responses
carry their own.

.. note::

   ``uri`` is populated from ``build_absolute_uri()`` for completeness, but
   nothing security-relevant reads it. The token URL passed to the provider
   comes from settings, below.

The provider
------------

Build it once per process from settings. The issuer is a setting, and the
token URL derives from it:

.. code-block:: python

   # opsite/settings.py
   OP_ISSUER = os.environ.get("OP_ISSUER", "http://127.0.0.1:5000")

   # op/provider.py
   from django.conf import settings
   from common.op_config import build_provider

   OP = build_provider(settings.OP_ISSUER)
   TOKEN_URL = f"{settings.OP_ISSUER}/token"

Building at import time is the simplest arrangement and works with
``runserver`` and with gunicorn's default (non-preloading) mode, where each
worker imports the app after fork. With ``gunicorn --preload``, or any server
that imports the application before forking, build it lazily in the worker
or in a ``post_fork`` hook instead: see :doc:`stores`.

The example uses signed-cookie sessions
(``SESSION_ENGINE = "django.contrib.sessions.backends.signed_cookies"``) so
the pending authorization request lives in the cookie and no database table
is needed. Any session backend works.

The views
---------

.. code-block:: python

   from django.http import HttpRequest, HttpResponse
   from django.middleware.csrf import get_token
   from django.views.decorators.csrf import csrf_exempt
   from django.views.decorators.http import require_GET, require_http_methods, require_POST

   from pygrindvakt import OAuthError
   from pygrindvakt.http import Response
   from pygrindvakt.request import AuthorizationRequest

   @require_GET
   def discovery(request: HttpRequest) -> HttpResponse:
       return to_django(Response.json(OP.discovery_document()))

   @require_GET
   def jwks(request: HttpRequest) -> HttpResponse:
       return to_django(Response.json(OP.jwks_document()))

The authorization view handles both methods. On GET it validates, stores the
request in the session and renders the login form with Django's CSRF token;
on POST it authenticates and redirects back.

.. code-block:: python

   @require_http_methods(["GET", "POST"])
   def authorization(request: HttpRequest) -> HttpResponse:
       if request.method == "GET":
           data = request_data(request)
           try:
               req = AuthorizationRequest.from_params(data.query)
               OP.validate_authorization_request(req)
           except OAuthError as e:
               # The redirect_uri is not trusted until validation succeeds: never redirect here.
               return to_django(e.to_response())
           request.session["authz"] = req.to_dict()
           csrf = f'<input type="hidden" name="csrfmiddlewaretoken" value="{get_token(request)}">'
           return HttpResponse(render_login_form(req.client_id, hidden=csrf))

       stored = request.session.pop("authz", None)
       if stored is None:
           return to_django(OAuthError("invalid_request", "no pending authorization request").to_response())
       req = AuthorizationRequest.from_dict(stored)
       form = request_data(request).form
       claims = authenticate(form.get("username", ""), form.get("password", ""))
       if claims is None:
           err = OAuthError("access_denied", "wrong username or password", req.state)
           return to_django(err.to_redirect(req.redirect_uri))      # validated on the GET
       try:
           return to_django(OP.authorization_redirect(req, form["username"], claims))
       except OAuthError as e:
           return to_django(e.to_redirect(req.redirect_uri))

In a real deployment ``authenticate`` is ``django.contrib.auth.authenticate``
plus a mapping from the ``User`` to claims, and you would pass
``user.last_login`` semantics through ``acr`` or ``external_claims`` as your
policy requires.

The token and userinfo endpoints are called by OAuth clients with no session
and no CSRF token, so both are exempt from Django's CSRF middleware. Userinfo
accepts GET and POST, since :func:`pygrindvakt.rp.fetch_userinfo` sends a
POST:

.. code-block:: python

   @csrf_exempt
   @require_POST
   def token(request: HttpRequest) -> HttpResponse:
       data = request_data(request)
       try:
           tr = OP.handle_token_request(data.form, TOKEN_URL, auth_header=data.authorization())
       except OAuthError as e:
           return to_django(e.to_response())
       return to_django(tr.to_response())

   @csrf_exempt                                    # called by RPs, not browsers
   @require_http_methods(["GET", "POST"])          # OIDC Core 5.3 allows both
   def userinfo(request: HttpRequest) -> HttpResponse:
       access_token = request_data(request).bearer_token()
       if access_token is None:
           return to_django(OAuthError("access_denied", "missing bearer token").to_response())
       try:
           return to_django(Response.json(OP.userinfo(access_token)))
       except OAuthError as e:
           return to_django(e.to_response())

Routing:

.. code-block:: python

   from django.urls import path
   from op import views

   urlpatterns = [
       path(".well-known/openid-configuration", views.discovery),
       path("jwks", views.jwks),
       path("authorization", views.authorization),
       path("token", views.token),
       path("userinfo", views.userinfo),
   ]

Backing the client store with the ORM
-------------------------------------

The demo uses a static :class:`~pygrindvakt.client.InMemoryClientStore`. A
model-backed registry needs only ``get`` and ``put``
(:class:`pygrindvakt.client.ClientStoreProtocol`); return a
:meth:`~pygrindvakt.client.Client.to_dict`-shaped dict from ``get``:

.. code-block:: python

   class OrmClientStore:
       def get(self, client_id):
           row = RegisteredClient.objects.filter(pk=client_id).first()
           return row.as_client_dict() if row else None

       def put(self, client):
           RegisteredClient.objects.update_or_create(pk=client.client_id, defaults={"data": client.to_dict()})

   OP = provider.Provider(md, key, OrmClientStore(), codec, token_use_store=...)

The store's methods run on the request thread holding the GIL, so ORM access
is fine. If ``get`` raises (database
down), the exception is logged via ``sys.unraisablehook`` and the client is
treated as unknown.

Multi-process deployment
------------------------

Django is almost always run with several workers. Use
:class:`~pygrindvakt.provider.RedisStore` (built in the worker) or a
``TokenUseStore`` over Django's cache framework for the token-use store; the
in-memory store is per process. :doc:`stores` explains the fork semantics and
gives a gunicorn ``post_fork`` example.
