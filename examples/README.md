# pygrindvakt framework examples

Three OpenID Providers (Flask, Django, FastAPI) that expose the same five
endpoints on port 5000, and one Flask Relying Party on port 5001 that logs in
against whichever of them is running. `common/op_config.py` holds the shared
provider configuration: a generated ES256 signing key (`op-key.json`, written
on first run in the current directory, or `OP_SIGNING_JWK`), two static clients
(`demo` for the code flow, `svc` for `client_credentials`) and the single user
`alice` / `alice`.

**These are demos.** In-memory stores, development secrets, plain http on
loopback, and a hard-coded user. They show where each piece of pygrindvakt
plugs into a web framework, nothing more.

## Running

Every command runs from the repository root with the project's virtualenv.

Flask OP:

```sh
.venv/bin/python examples/flask-op/app.py
```

Django OP:

```sh
cd examples/django-op && ../../.venv/bin/python manage.py runserver 5000
```

FastAPI OP (needs `uvicorn`):

```sh
cd examples/fastapi-op && ../../.venv/bin/uvicorn app:app --port 5000
```

Then, with one OP up, start the RP and visit <http://127.0.0.1:5001/login>:

```sh
.venv/bin/python examples/flask-rp/app.py
```

Sign in as `alice` / `alice`; the RP shows the verified id_token claims and
the userinfo response. A wrong password sends the browser back to the RP with
`error=access_denied`.

Environment variables: `OP_ISSUER` (default `http://127.0.0.1:5000`, also
read by the RP), `OP_SIGNING_JWK` / `OP_KEY_FILE`, `OP_SECRET` (token codec),
`OP_SECRET_KEY` (framework session secret), `RP_CLIENT_SECRET`, `RP_SECRET_KEY`.

## What each OP example shows

* An adapter pair per framework: `request_data(...)` builds a
  `pygrindvakt.http.HttpRequestData` (lower-cased headers, parsed query and
  form) from the framework request, and `to_<framework>(resp)` turns a
  `pygrindvakt.http.Response` back into a framework response. Views only use
  the framework-agnostic types.
* `/authorization` GET: `AuthorizationRequest.from_params` +
  `Provider.validate_authorization_request`. Errors are rendered with
  `to_response()`, never redirected, because the `redirect_uri` has not been
  validated yet. The parsed request is stashed in the session (`to_dict()`).
* `/authorization` POST: after checking the credentials, `from_dict` restores
  the request and `Provider.authorization_redirect(req, sub, claims)` mints the
  code and returns the redirect. A failed login becomes
  `OAuthError("access_denied", ...).to_redirect(req.redirect_uri, mode)`.
* `/token`: `Provider.handle_token_request(form, TOKEN_URL, auth_header=...)`.
  `TOKEN_URL` comes from the configured issuer, never from the `Host` header,
  because it is the `private_key_jwt` audience and the DPoP `htu`.
* `/userinfo` (GET or POST, as OIDC Core allows; `pygrindvakt.rp.fetch_userinfo`
  uses POST): `HttpRequestData.bearer_token()` then `Provider.userinfo(token)`.

Framework notes:

* **Flask** builds the provider inside `create_app()`.
* **Django** builds it once at import in `op/provider.py`; with a pre-forking
  server (`gunicorn --preload`) build it post-fork instead. Sessions use the
  signed-cookie backend so no database is needed; the token endpoint is
  `csrf_exempt`.
* **FastAPI** runs the blocking provider calls through
  `starlette.concurrency.run_in_threadpool`, parses the form body itself (so
  `python-multipart` is not required) and keeps the pending authorization
  request in an `itsdangerous`-signed cookie.

The RP uses `pygrindvakt.http.ReqwestClient` for outbound requests, PKCE,
`rp.discover` / `rp.exchange_code` / `rp.verify_id_token` / `rp.fetch_userinfo`.

## Tests

`tests/test_frameworks.py` drives the full code flow through each OP's test
client and the RP end to end (with the RP's HTTP client routed into the Flask
OP's test client):

```sh
.venv/bin/python -m pytest tests/test_frameworks.py -q
```
