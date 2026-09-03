"""The five OP endpoints as Django views."""

from django.http import HttpRequest, HttpResponse
from django.middleware.csrf import get_token
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from common.op_config import authenticate, render_login_form
from op.adapters import request_data, to_django
from op.provider import OP, TOKEN_URL
from pygrindvakt import OAuthError
from pygrindvakt.http import Response
from pygrindvakt.request import AuthorizationRequest


@require_GET
def discovery(request: HttpRequest) -> HttpResponse:
    return to_django(Response.json(OP.discovery_document()))


@require_GET
def jwks(request: HttpRequest) -> HttpResponse:
    return to_django(Response.json(OP.jwks_document()))


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
        return to_django(err.to_redirect(req.redirect_uri))  # validated on the GET
    try:
        return to_django(OP.authorization_redirect(req, form["username"], claims))
    except OAuthError as e:
        return to_django(e.to_redirect(req.redirect_uri))


@csrf_exempt  # called by OAuth clients, not browsers
@require_POST
def token(request: HttpRequest) -> HttpResponse:
    data = request_data(request)
    try:
        tr = OP.handle_token_request(data.form, TOKEN_URL, auth_header=data.authorization())
    except OAuthError as e:
        return to_django(e.to_response())
    return to_django(tr.to_response())


@csrf_exempt  # called by RPs, not browsers
@require_http_methods(["GET", "POST"])  # OIDC Core 5.3 allows both
def userinfo(request: HttpRequest) -> HttpResponse:
    access_token = request_data(request).bearer_token()
    if access_token is None:
        return to_django(OAuthError("access_denied", "missing bearer token").to_response())
    try:
        return to_django(Response.json(OP.userinfo(access_token)))
    except OAuthError as e:
        return to_django(e.to_response())
