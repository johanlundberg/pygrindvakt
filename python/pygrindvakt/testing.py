"""Test helpers for code that uses pygrindvakt.

.. warning::

   TEST-ONLY. Never make this module a runtime dependency of an application.
   Nothing here is hardened for production: :class:`StaticHttpClient` answers
   from a dict, :class:`ProviderHttpClient` bridges requests to an in-process
   ``Provider`` with no network, TLS, timeouts or size limits, and
   :func:`mint_id_token` signs whatever you ask with a key you supply.

The module is not imported by ``import pygrindvakt``; import it explicitly
(``from pygrindvakt import testing``). It has no third-party dependencies.

.. versionadded:: 0.3.0
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, TypeAlias

from . import OAuthError, jwt, keys, provider

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

__all__ = [
    "FetchResult",
    "ProviderHttpClient",
    "RecordedRequest",
    "StaticHttpClient",
    "mint_id_token",
]

FetchResult: TypeAlias = tuple[int, bytes, str | None, tuple[tuple[str, str], ...]]
"""``(status, body, content_type, headers)``: the response form of the
``HttpClientProtocol`` that carries response headers (so ``rp.JwksCache`` /
``rp.DiscoveryCache`` see ``Cache-Control``; with no headers they warn once)."""

_Pairs: TypeAlias = tuple[tuple[str, str], ...]
_Response: TypeAlias = tuple[int, bytes, str | None, list[tuple[str, str]]]
"""The normalised response handed to pygrindvakt: header names lower-cased."""

_Static: TypeAlias = "FetchResult | tuple[int, bytes, str | None]"
_Route: TypeAlias = "_Static | Callable[[RecordedRequest], _Static]"

_NOT_FOUND: FetchResult = (404, b"", "text/plain", ())

# Claims mint_id_token owns; refused in ``extra`` whether or not this call
# sets them (nonce / at_hash / c_hash only when requested). azp, auth_time,
# jti, acr and amr are deliberately NOT here: tests may set them.
_PROTOCOL_CLAIMS = frozenset({"iss", "sub", "aud", "exp", "iat", "nonce", "at_hash", "c_hash"})


_REDACTED = "<redacted>"
_SENSITIVE_HEADERS = frozenset({"authorization", "proxy-authorization", "dpop", "cookie", "set-cookie", "x-api-key"})
_SENSITIVE_FIELDS = frozenset(
    {
        "client_secret",
        "client_assertion",
        "code",
        "code_verifier",
        "access_token",
        "refresh_token",
        "id_token",
        "password",
        "assertion",
        "token",
    }
)


def _redact(pairs: _Pairs, sensitive: frozenset[str]) -> _Pairs:
    return tuple((k, _REDACTED if k.lower() in sensitive else v) for k, v in pairs)


@dataclass(frozen=True, repr=False)
class RecordedRequest:
    """One outbound request seen by a test client.

    ``form`` is ``None`` for a GET. ``headers`` are the request headers as
    given (``()`` when none were sent).

    The recorder stores credentials verbatim in its attributes (``Authorization``
    and other sensitive headers, form fields such as ``client_secret``,
    ``code``, ``code_verifier``, ``access_token``), so tests can assert on
    them. ``repr`` redacts the values of sensitive headers and form fields
    (names stay visible), so pytest failure output and logs do not leak them.
    Redact yourself (:meth:`redacted`) before dumping or serialising ``calls``
    or ``forms`` (JSON, JUnit, logs).
    """

    method: str
    url: str
    form: _Pairs | None
    headers: _Pairs

    def header(self, name: str) -> str | None:
        """First request header ``name`` (case-insensitive), or ``None``."""
        return _lookup(self.headers, name)

    def redacted(self) -> RecordedRequest:
        """A copy with the values of sensitive headers and form fields
        replaced by ``"<redacted>"`` (names matched case-insensitively)."""
        form = None if self.form is None else _redact(self.form, _SENSITIVE_FIELDS)
        return RecordedRequest(self.method, self.url, form, _redact(self.headers, _SENSITIVE_HEADERS))

    def __repr__(self) -> str:
        r = self.redacted()
        return f"RecordedRequest(method={r.method!r}, url={r.url!r}, form={r.form!r}, headers={r.headers!r})"


def _lookup(headers: _Pairs, name: str) -> str | None:
    wanted = name.lower()
    for key, value in headers:
        if key.lower() == wanted:
            return value
    return None


def _pairs(pairs: Any, what: str, where: str) -> _Pairs:
    """Validate request header / form ``pairs`` as ``(str, str)`` and return a tuple.

    Anything else is a ``TypeError`` naming ``where`` (``METHOD url``)."""
    if pairs is None:
        return ()
    try:
        items = list(pairs)
    except TypeError:
        raise TypeError(f"{where}: {what} must be a sequence of (str, str) pairs, got {pairs!r:.100}") from None
    for item in items:
        if not (isinstance(item, (tuple, list)) and len(item) == 2 and all(isinstance(x, str) for x in item)):
            raise TypeError(f"{where}: {what} must be a sequence of (str, str) pairs, got entry {item!r:.100}")
    return tuple((k, v) for k, v in items)


def _check_shape(result: object, where: str) -> FetchResult:
    """Validate one response and return it as a 4-tuple ``FetchResult``.

    Accepts ``(status, body, content_type)`` (the legacy three-element form,
    normalised to no headers) and the four-element form. Anything else is a
    ``TypeError`` naming ``where``.
    """
    expected = "(status: int, body: bytes, content_type: str | None[, headers: ((name, value), ...)])"
    if not isinstance(result, tuple) or len(result) not in (3, 4):
        raise TypeError(f"{where}: expected {expected}, got {result!r:.100}")
    status, body, content_type = result[:3]
    headers = result[3] if len(result) == 4 else ()
    if isinstance(status, bool) or not isinstance(status, int):
        raise TypeError(f"{where}: status must be int, got {status!r:.60}; expected {expected}")
    if not isinstance(body, bytes):
        raise TypeError(f"{where}: body must be bytes, got {type(body).__name__}; expected {expected}")
    if content_type is not None and not isinstance(content_type, str):
        raise TypeError(f"{where}: content_type must be str or None, got {content_type!r:.60}; expected {expected}")
    if not isinstance(headers, (tuple, list)) or not all(
        isinstance(h, (tuple, list)) and len(h) == 2 and all(isinstance(x, str) for x in h) for h in headers
    ):
        raise TypeError(f"{where}: headers must be a sequence of (name, value) str pairs, got {headers!r:.100}")
    return status, body, content_type, tuple((k, v) for k, v in headers)


def _normalise(result: object, where: str) -> _Response:
    # Response header names are lower-cased, as the protocol documents; the
    # native side takes a list of pairs.
    status, body, content_type, headers = _check_shape(result, where)
    return status, body, content_type, [(k.lower(), v) for k, v in headers]


_DEFAULT_CACHE_CONTROL = "max-age=300"


def _json_result(
    value: object,
    status: int = 200,
    cache_control: str | None = None,
    extra_headers: _Pairs = (),
) -> FetchResult:
    headers: _Pairs = (() if cache_control is None else (("cache-control", cache_control),)) + extra_headers
    return status, json.dumps(value).encode(), "application/json", headers


_DPOP_UNSUPPORTED = (
    "ProviderHttpClient does not support DPoP; the double does not pass a DpopProof to "
    "handle_token_request or presented_jkt to userinfo, so a DPoP test would pass or fail for the wrong "
    "reason. Test DPoP against the provider directly, or subclass and override _answer"
)


class _RecordingClient:
    """Shared plumbing: request dispatch, ``.calls`` recording and response
    normalisation. Subclasses implement :meth:`_answer` only."""

    def __init__(self) -> None:
        self.calls: list[RecordedRequest] = []

    def _answer(self, request: RecordedRequest) -> object:
        raise NotImplementedError

    def _dispatch(self, request: RecordedRequest) -> _Response:
        self.calls.append(request)
        return _normalise(self._answer(request), f"{request.method} {request.url}")

    def get(self, url: str, headers: list[tuple[str, str]] | None = None) -> _Response:
        """Answer a GET (``headers`` are the optional request headers)."""
        return self._dispatch(RecordedRequest("GET", url, None, _pairs(headers, "headers", f"GET {url}")))

    def get_with_headers(self, url: str, headers: list[tuple[str, str]]) -> _Response:
        """Answer a GET carrying request ``headers``."""
        return self.get(url, headers)

    def post_form(
        self,
        url: str,
        form: list[tuple[str, str]],
        headers: list[tuple[str, str]],
    ) -> _Response:
        """Answer a form POST."""
        return self._dispatch(
            RecordedRequest("POST", url, _pairs(form, "form", f"POST {url}"), _pairs(headers, "headers", f"POST {url}"))
        )


class StaticHttpClient(_RecordingClient):
    """An ``HttpClientProtocol`` that answers from a URL to response map.

    ``routes`` maps a URL (any method) or a ``(METHOD, url)`` pair (that
    method only; the method is upper-cased at construction, so ``("post", url)``
    matches a POST; an empty method is a ``TypeError``) to either a :data:`FetchResult` or
    a callable taking the :class:`RecordedRequest` and returning one. A
    ``(METHOD, url)`` key wins over a plain URL key. Anything unmatched gets
    ``default`` (404 by default). Every request is appended to :attr:`calls`.

    A response is ``(status, body, content_type, headers)`` or the legacy
    three-element ``(status, body, content_type)`` (no headers); anything else
    raises ``TypeError``. Static values and ``default`` are checked when the
    client is built (the message names the route key); a callable's result is
    checked when it is returned (the message names the request method and
    URL). Keys must be a ``str`` or a ``(str, str)`` pair, else ``TypeError``.

    Redirects are never followed: a 3xx response is returned verbatim and the
    ``Location`` target is never requested. Response header names are
    lower-cased and the four-element form is always returned to pygrindvakt.

    Headerless responses: ``rp.JwksCache`` and ``rp.DiscoveryCache`` derive
    their TTL from ``Cache-Control`` and emit a one-time ``UserWarning``
    ("reports no response headers") when a response carries no headers at
    all. A route must therefore be a four-element tuple with at least a
    ``Cache-Control`` header to avoid that warning. The legacy three-element
    form, a four-element form with empty headers, and the default 404 are
    headerless by definition. :meth:`from_json` adds ``Cache-Control`` for
    you. ``get``
    takes optional request headers and ``get_with_headers`` is provided, so
    ``http.supports_get_with_headers`` is ``True`` and
    ``rp.fetch_userinfo(method="GET")`` works.

    Not thread-safe and not fork-aware: it is a test double.
    """

    def __init__(
        self,
        routes: Mapping[Any, _Route],
        *,
        default: _Static = _NOT_FOUND,
    ) -> None:
        super().__init__()
        self._routes: dict[str | tuple[str, str], _Route] = {}
        for key, value in routes.items():
            is_pair = isinstance(key, tuple) and len(key) == 2 and all(isinstance(x, str) for x in key)
            if not (isinstance(key, str) or is_pair):
                raise TypeError(f"route key must be a URL str or a (METHOD, url) pair of str, got {key!r:.100}")
            route_key: str | tuple[str, str] = key
            if isinstance(key, tuple):
                if not key[0]:
                    raise TypeError(f"route key method must not be empty, got {key!r:.100}")
                route_key = (key[0].upper(), key[1])
            if route_key in self._routes:
                raise TypeError(f"duplicate route key after upper-casing the method: {route_key!r:.100}")
            self._routes[route_key] = value if callable(value) else _check_shape(value, f"route {key!r}")
        self._default = _check_shape(default, "default")

    @classmethod
    def from_json(
        cls,
        routes: Mapping[str, object],
        *,
        default: _Static = _NOT_FOUND,
        cache_control: str | None = _DEFAULT_CACHE_CONTROL,
    ) -> StaticHttpClient:
        """A client whose ``routes`` map URL to a JSON-serialisable object,
        answered as ``200 application/json`` with a ``Cache-Control:
        <cache_control>`` header (default ``max-age=300``). ``cache_control=None``
        sends no headers, which makes ``rp.JwksCache`` / ``rp.DiscoveryCache``
        emit the one-time "reports no response headers" warning. ``default``
        is not affected."""
        return cls(
            {url: _json_result(obj, cache_control=cache_control) for url, obj in routes.items()},
            default=default,
        )

    def _answer(self, request: RecordedRequest) -> object:
        route = self._routes.get((request.method, request.url))
        if route is None:
            route = self._routes.get(request.url)
        if route is None:
            return self._default
        if callable(route):
            return route(request)
        return route


class ProviderHttpClient(_RecordingClient):
    """An ``HttpClientProtocol`` that bridges an RP's requests to an
    in-process ``provider.Provider``.

    Serves discovery, JWKS (GET), the token endpoint (POST) and UserInfo (POST
    or GET with ``Authorization: Bearer``, scheme matched case-insensitively)
    at ``issuer`` plus the given paths. A ``provider.Provider`` error
    (``OAuthError``) becomes the response of ``OAuthError.to_response()``,
    status, body and headers (``www-authenticate``, ``cache-control``, ...)
    included; unknown URLs are 404. Redirects do not occur. Re-entrant calls
    into pygrindvakt are supported by the library, so no extra thread is
    needed. The provider's metadata must advertise the same endpoint URLs
    (``jwks_uri`` etc.) as the paths used here.

    Every request is recorded in :attr:`calls`; :attr:`forms` is the form body
    of each POST in order. To tweak one response in a subclass, override
    ``_answer(request)`` and delegate to ``super()._answer(request)`` (it
    returns a response tuple); do not override ``get``.

    The discovery and JWKS responses carry ``Cache-Control: <cache_control>``
    (default ``max-age=300``), which ``rp.DiscoveryCache`` / ``rp.JwksCache``
    use to derive the TTL without the "reports no response headers" warning.
    ``cache_control=None`` returns them without any headers, to test that
    path on purpose (the cache then warns once and uses its ``default_ttl``).
    Token and UserInfo responses are unaffected by it. Token success
    responses carry ``cache-control: no-store`` and ``pragma: no-cache``
    (RFC 6749 section 5.1).

    UserInfo takes the token from ``Authorization: Bearer`` (GET or POST) or,
    on a POST with no ``Authorization`` header, from a form-encoded
    ``access_token`` (RFC 6750 section 2.2). Both together, or a repeated form
    ``access_token``, is a 400 ``invalid_request`` (RFC 6750 section 2). A
    missing credential, or an ``Authorization`` header that is present but not
    exactly ``Bearer <token>`` (blank, no token, extra or trailing
    whitespace, other scheme), is a 401 with ``www-authenticate: Bearer``; a
    present header never falls back to the form ``access_token``.

    **DPoP is not supported.** This double does not pass a ``DpopProof`` to
    ``handle_token_request`` nor ``presented_jkt`` to ``userinfo``. A request
    with a ``DPoP`` header, or an ``Authorization: DPoP ...`` scheme, on the
    token or UserInfo endpoint raises ``NotImplementedError`` instead of
    silently passing or failing for the wrong reason.
    """

    def __init__(
        self,
        op: provider.Provider,
        issuer: str,
        *,
        token_path: str = "/token",
        userinfo_path: str = "/userinfo",
        jwks_path: str = "/jwks",
        discovery_path: str = "/.well-known/openid-configuration",
        cache_control: str | None = _DEFAULT_CACHE_CONTROL,
    ) -> None:
        super().__init__()
        base = issuer.rstrip("/")
        self.op = op
        self.issuer = issuer
        self._token_url = base + token_path
        self._userinfo_url = base + userinfo_path
        self._jwks_url = base + jwks_path
        self._discovery_url = base + discovery_path
        self._cache_control = cache_control

    @property
    def forms(self) -> list[list[tuple[str, str]]]:
        """The form body of each POST, in order."""
        return [list(r.form) for r in self.calls if r.method == "POST" and r.form is not None]

    @staticmethod
    def _oauth_error(e: OAuthError) -> FetchResult:
        resp = e.to_response()
        return resp.status, resp.body, resp.header("content-type"), tuple((k.lower(), v) for k, v in resp.headers)

    @staticmethod
    def _reject_dpop(request: RecordedRequest) -> None:
        auth = request.header("authorization") or ""
        if request.header("dpop") is not None or auth.partition(" ")[0].lower() == "dpop":
            raise NotImplementedError(_DPOP_UNSUPPORTED)

    def _userinfo(self, request: RecordedRequest) -> FetchResult:
        auth = request.header("authorization")
        has_auth = auth is not None
        form_tokens = [v for k, v in request.form or () if k == "access_token"]
        if (has_auth and form_tokens) or len(form_tokens) > 1:
            return (
                400,
                json.dumps({"error": "invalid_request"}).encode(),
                "application/json",
                (("www-authenticate", 'Bearer error="invalid_request"'),),
            )
        if has_auth:
            assert auth is not None
            scheme, sep, token = auth.partition(" ")
            if scheme.lower() != "bearer" or not sep or token != token.strip() or " " in token:
                token = ""
        else:
            token = form_tokens[0] if form_tokens else ""
        if not token:
            return 401, b"", None, (("www-authenticate", "Bearer"),)
        try:
            return _json_result(self.op.userinfo(token))
        except OAuthError as e:
            return self._oauth_error(e)

    def _answer(self, request: RecordedRequest) -> FetchResult:
        url = request.url
        if request.method == "GET":
            if url == self._discovery_url:
                return _json_result(self.op.discovery_document(), cache_control=self._cache_control)
            if url == self._jwks_url:
                return _json_result(self.op.jwks_document(), cache_control=self._cache_control)
            if url == self._userinfo_url:
                self._reject_dpop(request)
                return self._userinfo(request)
        elif request.form is not None:
            if url == self._token_url:
                self._reject_dpop(request)
                try:
                    tr = self.op.handle_token_request(
                        list(request.form), self._token_url, auth_header=request.header("authorization")
                    )
                except OAuthError as e:
                    return self._oauth_error(e)
                return _json_result(tr.to_dict(), extra_headers=(("cache-control", "no-store"), ("pragma", "no-cache")))
            if url == self._userinfo_url:
                self._reject_dpop(request)
                return self._userinfo(request)
        return 404, b"not found", "text/plain", ()


def mint_id_token(
    key: keys.SigningKey,
    *,
    issuer: str,
    client_id: str,
    sub: str = "alice",
    nonce: str | None = None,
    access_token: str | None = None,
    code: str | None = None,
    lifetime: int = 300,
    iat: int | None = None,
    extra: Mapping[str, Any] | None = None,
) -> str:
    """Sign an ID Token with ``key`` (the caller supplies the key; test-only).

    Claims: ``iss``, ``sub``, ``aud`` (``client_id``), ``iat`` (now unless
    given), ``exp`` (``iat + lifetime``), plus ``nonce`` when given and
    ``at_hash`` / ``c_hash`` computed with ``jwt.oidc_token_hash(key.alg, ...)``
    when ``access_token`` / ``code`` is given. ``extra`` adds other claims
    (``azp``, ``auth_time``, ``jti``, ``acr``, ``amr``, ``email`` ...); it may
    not contain a protocol claim (``iss``, ``sub``, ``aud``, ``exp``,
    ``iat``, ``nonce``, ``at_hash``, ``c_hash``; refused even when this call
    does not set ``nonce`` / ``at_hash`` / ``c_hash``): ``ValueError``. The ``alg`` and ``kid`` come
    from the key.

    ``lifetime`` must be an ``int`` (not ``bool``) greater than 0 and ``iat``
    ``None`` or an ``int`` (not ``bool``) of at least 0, else ``ValueError``.
    The ``extra`` collision check runs before any hash is computed, so it is
    reported first.

    An ``EdDSA`` key has no defined token hash: with ``access_token`` or
    ``code`` the ``CryptoError`` of ``jwt.oidc_token_hash`` propagates.
    """
    if isinstance(lifetime, bool) or not isinstance(lifetime, int) or lifetime <= 0:
        raise ValueError(f"lifetime must be an int > 0, got {lifetime!r:.60}")
    if iat is not None and (isinstance(iat, bool) or not isinstance(iat, int) or iat < 0):
        raise ValueError(f"iat must be None or an int >= 0, got {iat!r:.60}")
    clash = _PROTOCOL_CLAIMS.intersection(extra or ())
    if clash:
        raise ValueError(f"extra may not set protocol claims: {sorted(clash)}")
    issued = int(time.time()) if iat is None else iat
    claims: dict[str, Any] = {
        "iss": issuer,
        "sub": sub,
        "aud": client_id,
        "iat": issued,
        "exp": issued + lifetime,
    }
    if nonce is not None:
        claims["nonce"] = nonce
    if access_token is not None:
        claims["at_hash"] = jwt.oidc_token_hash(key.alg, access_token)
    if code is not None:
        claims["c_hash"] = jwt.oidc_token_hash(key.alg, code)
    claims.update(extra or {})
    return jwt.sign(key, claims)
