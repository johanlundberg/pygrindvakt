"""Static typing smoke test, checked in CI with ``mypy --strict`` (not run by pytest).

Exercises the ``http`` argument of ``rp`` / ``federation`` / ``discovery`` with
the built-in ``ReqwestClient``, ``None`` and a custom protocol client.
"""

from __future__ import annotations

import pygrindvakt.http
from pygrindvakt import (
    AuthnError,
    GrindvaktError,
    InternalError,
    OAuthError,
    discovery,
    federation,
    rp,
)


class TupleClient:
    """Custom client returning the plain tuple form."""

    def get(self, url: str) -> tuple[int, bytes, str | None]:
        return 200, b"{}", "application/json"

    def post_form(
        self,
        url: str,
        form: list[tuple[str, str]],
        headers: list[tuple[str, str]],
    ) -> tuple[int, bytes, str | None]:
        return 200, b"{}", None


class FetchResponseClient:
    """Custom client returning ``HttpFetchResponse``."""

    def get(self, url: str) -> pygrindvakt.http.HttpFetchResponse:
        return pygrindvakt.http.HttpFetchResponse(200, b"{}", "application/json")

    def post_form(
        self,
        url: str,
        form: list[tuple[str, str]],
        headers: list[tuple[str, str]],
    ) -> pygrindvakt.http.HttpFetchResponse:
        return pygrindvakt.http.HttpFetchResponse(200, b"{}")


class HeadersClient(TupleClient):
    """``get`` accepts request headers (``HttpClientWithHeadersProtocol``)."""

    def get(self, url: str, headers: list[tuple[str, str]] | None = None) -> tuple[int, bytes, str | None]:
        return 200, b"{}", "application/json"


class GetWithHeadersClient(TupleClient):
    """Provides ``get_with_headers`` (``HttpClientGetWithHeadersProtocol``)."""

    def get_with_headers(self, url: str, headers: list[tuple[str, str]]) -> tuple[int, bytes, str | None]:
        return 200, b"{}", "application/json"


def use_all() -> None:
    reqwest = pygrindvakt.http.ReqwestClient(request_timeout=5)
    custom = TupleClient()
    fetch = FetchResponseClient()

    md = rp.discover(reqwest, "https://op.example.com")
    rp.discover(None, "https://op.example.com")
    rp.discover(custom, "https://op.example.com")
    rp.discover(fetch, "https://op.example.com")
    info = rp.ProviderInfo.from_metadata(md)
    me = rp.RpClient("demo", "https://rp.example.com/cb", client_secret="s")
    rp.exchange_code(reqwest, info, me, "code")
    rp.exchange_code(custom, info, me, "code", code_verifier="v")
    rp.exchange_code(reqwest, info, me, "code", "v", redirect_uri="https://rp.example.com/alt")
    url, state, nonce, verifier = rp.begin(info, me)
    check: tuple[str, str, str, str | None] = (url, state, nonce, verifier)
    del check
    rp.begin(
        info,
        me,
        extra={"prompt": "login"},
        redirect_uri="https://rp.example.com/alt",
        pkce=False,
    )
    rp.authorization_url(info, me, state, nonce, redirect_uri=None)
    logout: str = rp.end_session_url(info, id_token_hint="t", client=me, state="s", extra={"k": "v"})
    rpc_logout = rp.RpClient(
        "demo",
        "https://rp.example.com/cb",
        post_logout_redirect_uris=["https://rp.example.com/bye"],
    )
    registered: tuple[str, ...] = rpc_logout.post_logout_redirect_uris
    rp.end_session_url(info, client=rpc_logout, post_logout_redirect_uri="https://rp.example.com/bye")
    del registered
    rpc_login = rp.RpClient(
        "demo",
        "https://rp.example.com/cb",
        redirect_uris=["https://rp.example.com/alt"],
        allow_unregistered_redirect_uri=False,
    )
    login_uris: tuple[str, ...] = rpc_login.redirect_uris
    allow_any: bool = rpc_login.allow_unregistered_redirect_uri
    del login_uris, allow_any
    es: str | None = info.end_session_endpoint
    rp.ProviderInfo(
        "https://op.example.com",
        "https://op.example.com/a",
        "https://op.example.com/t",
        end_session_endpoint="https://op.example.com/logout",
    )
    rp.ProviderInfo(
        "https://op.example.com",
        "https://op.example.com/a",
        "https://op.example.com/t",
        end_session_endpoint="https://logout.other.example/logout",
        allow_cross_origin_end_session=True,
    )
    xo: rp.ProviderInfo = rp.ProviderInfo.from_metadata(md, allow_cross_origin_end_session=True)
    del xo
    acr: list[str] | None = md.acr_values_supported
    flag: bool | None = md.backchannel_logout_supported
    rev: str | None = md.revocation_endpoint
    md.acr_values_supported = None
    md.end_session_endpoint = "https://op.example.com/logout"
    raw: dict[str, object] | None = md.raw
    dumped: dict[str, object] = md.to_dict(exclude_defaults=True)
    del logout, es, acr, flag, rev, raw, dumped
    rp.fetch_jwks(fetch, "https://op.example.com/jwks", "https://op.example.com")
    cache = rp.JwksCache(
        reqwest,
        "https://op.example.com/jwks",
        "https://op.example.com",
        default_ttl=600,
        min_ttl=30,
        max_ttl=3600,
        min_refresh_interval=10,
        fetch_timeout=5.0,
    )
    rp.JwksCache(None, "https://op.example.com/jwks", "https://op.example.com")
    keyset: dict[str, object] = cache.jwks()
    cache.refresh()
    cached_claims: dict[str, object] = cache.verify_id_token(
        "tok",
        "demo",
        "n",
        ["ES256"],
        leeway=30,
        max_age=300,
        acr_values=["mfa"],
        access_token="at",
        require_at_hash=True,
        authorization_code="c",
        require_c_hash=False,
        strict_hashes=True,
        trusted_additional_audiences=["https://api.example"],
    )
    direct: dict[str, object] = rp.verify_id_token(
        cache, "tok", "https://op.example.com", "demo", "n", ["ES256"], max_age=60
    )
    rp.verify_id_token(keyset, "tok", "https://op.example.com", "demo", "n", ["ES256"], leeway=5)
    del keyset, cached_claims, direct
    rp.fetch_userinfo(reqwest, "https://op.example.com/ui", "tok", "sub", "https://op.example.com")

    rp.fetch_userinfo(
        reqwest,
        None,
        "tok",
        "sub",
        "https://op.example.com",
        method="GET",
        jwks={"keys": []},
        client_id="demo",
        allowed_algorithms=["ES256"],
        trust="typed",
        typ="userinfo+jwt",
        max_age=None,
        require_exp=True,
    )
    rp.fetch_userinfo(custom, "https://op.example.com/ui", "tok", "sub", "https://op.example.com")
    rp.fetch_userinfo(
        HeadersClient(),
        "https://op.example.com/ui",
        "tok",
        "sub",
        "https://op.example.com",
        method="GET",
        trust="dedicated_keys",
    )
    rp.fetch_userinfo(
        GetWithHeadersClient(),
        "https://op.example.com/ui",
        "tok",
        "sub",
        "https://op.example.com",
        method="GET",
    )
    reqwest.get("https://op.example.com", [("Authorization", "Bearer t")])

    federation.fetch_entity_configuration(reqwest, "https://ta.example.com")
    federation.fetch_entity_configuration(custom, "https://ta.example.com")
    federation.fetch_collection(None, "https://ta.example.com/collection", "openid_provider")

    discovery.self_published_rp(reqwest, "https://rp.example.com")
    discovery.self_published_rp(custom, "https://rp.example.com")
    discovery.self_published_initiate_login_uri(None, "https://rp.example.com")

    status, body, content_type = reqwest.get("https://op.example.com")
    reveal: tuple[int, bytes, str | None] = (status, body, content_type)
    del reveal


def use_errors() -> None:
    try:
        rp.JwksCache(None, "https://x/jwks", "https://x").verify_id_token("t", "c", "n", ["ES256"])
    except pygrindvakt.UnknownKeyError as ke:
        jose: pygrindvakt.JoseError = ke
        print(jose.code, ke.status_hint)

    try:
        rp.exchange_code(
            None,
            rp.ProviderInfo("i", "a", "t"),
            rp.RpClient("c", "https://x/cb"),
            "code",
        )
    except GrindvaktError as e:
        code: str = e.code
        status: int | None = e.upstream_status
        upstream_error: str | None = e.upstream_error
        description: str | None = e.upstream_error_description
        body: str | None = e.upstream_body
        cause: BaseException | None = e.__cause__
        del code, status, upstream_error, description, body, cause
    except (AuthnError, InternalError, OAuthError) as e:
        print(e.code)
