"""Static typing smoke test, checked in CI with ``mypy --strict`` (not run by pytest).

Exercises the ``http`` argument of ``rp`` / ``federation`` / ``discovery`` with
the built-in ``ReqwestClient``, ``None`` and a custom protocol client.
"""

from __future__ import annotations

import pygrindvakt.http
from pygrindvakt import discovery, federation, rp


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
    rp.fetch_jwks(fetch, "https://op.example.com/jwks", "https://op.example.com")
    rp.fetch_userinfo(
        reqwest, "https://op.example.com/ui", "tok", "sub", "https://op.example.com"
    )

    federation.fetch_entity_configuration(reqwest, "https://ta.example.com")
    federation.fetch_entity_configuration(custom, "https://ta.example.com")
    federation.fetch_collection(
        None, "https://ta.example.com/collection", "openid_provider"
    )

    discovery.self_published_rp(reqwest, "https://rp.example.com")
    discovery.self_published_rp(custom, "https://rp.example.com")
    discovery.self_published_initiate_login_uri(None, "https://rp.example.com")

    status, body, content_type = reqwest.get("https://op.example.com")
    reveal: tuple[int, bytes, str | None] = (status, body, content_type)
    del reveal
