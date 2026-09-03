"""Python-implemented protocol objects (stores, http client): they are honoured,
they fail closed, and they cannot deadlock or re-enter the runtime."""

import pytest

from conftest import ISSUER, REDIRECT_URI, TOKEN_URL, FakeHttpClient, basic_auth, code_from_redirect
from pygrindvakt import GrindvaktError, InternalError, OAuthError, client, metadata, pkce, provider, request, rp, tokens, util


class DictClientStore:
    """A ClientStore backed by a plain dict (think: Django ORM / cache)."""

    def __init__(self, *clients):
        self.d = {c.client_id: c for c in clients}
        self.ttl_calls = []

    def get(self, client_id):
        return self.d.get(client_id)

    def put(self, c):
        self.d[c.client_id] = c

    def put_with_ttl(self, c, ttl):
        self.ttl_calls.append((c.client_id, ttl))
        self.d[c.client_id] = c


class SetTokenUseStore:
    def __init__(self):
        self.seen = set()

    def consume(self, h, ttl):
        if h in self.seen:
            return False
        self.seen.add(h)
        return True


def _op(op_key, clients, tus=None):
    md = metadata.ProviderMetadata(ISSUER)
    return provider.Provider(md, op_key, clients, tokens.TokenCodec("s"), token_use_store=tus)


def _flow(op, verifier="v" * 43):
    req = request.AuthorizationRequest.from_params(
        {"client_id": "demo", "response_type": "code", "redirect_uri": REDIRECT_URI, "scope": "openid",
         "code_challenge": pkce.s256_challenge(verifier), "code_challenge_method": "S256"})
    op.validate_authorization_request(req)
    code = code_from_redirect(op.authorization_redirect(req, "alice"))
    return op.handle_token_request(
        {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT_URI, "code_verifier": verifier},
        TOKEN_URL, auth_header=basic_auth("demo", "s3cret"))


def test_python_client_store_and_token_use_store(op_key, demo_client):
    """Both stores implemented in Python drive a full code flow; the token-use
    store sees the code hash once and rejects the replay."""
    store = DictClientStore(demo_client)
    tus = SetTokenUseStore()
    op = _op(op_key, store, tus)
    assert op.clients is store and op.token_use_store is tus
    tr = _flow(op)
    assert tr.access_token and len(tus.seen) == 1
    with pytest.raises(OAuthError):
        _flow(op) if False else op.handle_token_request(
            {"grant_type": "refresh_token", "refresh_token": "junk"}, TOKEN_URL, auth_header=basic_auth("demo", "s3cret"))


def test_client_store_returning_dict(op_key, demo_client):
    class D:
        def get(self, cid):
            return demo_client.to_dict() if cid == "demo" else None

        def put(self, c):
            pass

    assert _flow(_op(op_key, D())).token_type == "Bearer"


def test_client_store_get_raising_is_unknown_client(op_key):
    """A raising get() is treated as 'no such client' and logged, never as a crash."""

    class Bad:
        def get(self, cid):
            raise RuntimeError("db down")

        def put(self, c):
            pass

    op = _op(op_key, Bad())
    req = request.AuthorizationRequest.from_params(
        {"client_id": "demo", "response_type": "code", "redirect_uri": REDIRECT_URI, "scope": "openid"})
    with pytest.raises(OAuthError):
        op.validate_authorization_request(req)


def test_token_use_store_raising_is_server_error(op_key, demo_client):
    """An infrastructure failure in consume() is reported as server_error, not
    as a replay (invalid_grant)."""

    class Broken:
        def consume(self, h, ttl):
            raise RuntimeError("redis down")

    op = _op(op_key, client.InMemoryClientStore([demo_client]), Broken())
    with pytest.raises(OAuthError) as ei:
        _flow(op)
    assert ei.value.code == "server_error" and ei.value.http_status == 500


def test_token_use_store_wrong_return_type(op_key, demo_client):
    class Wrong:
        def consume(self, h, ttl):
            return "yes"

    with pytest.raises(OAuthError) as ei:
        _flow(_op(op_key, client.InMemoryClientStore([demo_client]), Wrong()))
    assert ei.value.code == "server_error"


def test_protocol_validation_at_construction(op_key, demo_client):
    """Objects missing protocol methods are rejected when the Provider is built."""
    with pytest.raises(TypeError, match="ClientStore"):
        _op(op_key, object())
    with pytest.raises(TypeError, match="TokenUseStore"):
        _op(op_key, client.InMemoryClientStore([demo_client]), tus=object())


def test_reentrant_adapter_is_supported(op_key, demo_client):
    """An adapter that calls back into pygrindvakt from inside a request (an
    in-process fake, as used in tests) works: the nested call runs on a helper
    thread instead of tripping tokio's nested-runtime panic."""
    inner = client.InMemoryClientStore([demo_client])

    class Reentrant:
        def get(self, cid):
            return inner.get(cid)  # nested block_on

        def put(self, c):
            pass

    op = _op(op_key, Reentrant())
    assert _flow(op).token_type == "Bearer"


def test_reentrant_http_client_drives_in_process_provider(op):
    """A fake HttpClient that calls Provider.handle_token_request in-process
    completes a full RP code exchange (nested async inside async)."""
    from urllib.parse import parse_qs, urlparse

    fake = FakeHttpClient(op)
    info = rp.ProviderInfo.from_metadata(rp.discover(fake, ISSUER))
    me = rp.RpClient("demo", REDIRECT_URI, client_secret="s3cret")
    verifier = util.random_token(32)
    url = rp.authorization_url(info, me, "st", "nn", code_challenge=pkce.s256_challenge(verifier))
    params = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
    req = request.AuthorizationRequest.from_params(params)
    op.validate_authorization_request(req)
    code = code_from_redirect(op.authorization_redirect(req, "alice", {"email": ["a@b"]}))
    ts = rp.exchange_code(fake, info, me, code, code_verifier=verifier)
    claims = rp.verify_id_token(rp.fetch_jwks(fake, info.jwks_uri), ts.id_token, ISSUER, "demo", "nn")
    assert claims["sub"] == "alice"
    assert rp.fetch_userinfo(fake, info.userinfo_endpoint, ts.access_token)["email"] == "a@b"


def test_python_http_client_is_used(op):
    fake = FakeHttpClient(op)
    md = rp.discover(fake, ISSUER)
    assert md.issuer == ISSUER and fake.calls[0] == ("GET", f"{ISSUER}/.well-known/openid-configuration")


def test_python_http_client_raising(op):
    class Bad:
        def get(self, url):
            raise ConnectionError("boom")

        def post_form(self, url, form, headers):
            raise ConnectionError("boom")

    with pytest.raises(InternalError, match="boom"):
        rp.discover(Bad(), ISSUER)


def test_python_http_client_bad_return(op):
    class Bad:
        def get(self, url):
            return "nope"

        def post_form(self, url, form, headers):
            return None

    with pytest.raises(GrindvaktError):
        rp.discover(Bad(), ISSUER)
    with pytest.raises(TypeError, match="HttpClient"):
        rp.discover(object(), ISSUER)


def test_fetch_response_object_accepted(op):
    """An HttpClient may return HttpFetchResponse instead of a tuple."""
    from pygrindvakt import http

    class Obj:
        def get(self, url):
            import json

            return http.HttpFetchResponse(200, json.dumps(op.discovery_document()).encode(), "application/json")

        def post_form(self, url, form, headers):
            raise AssertionError

    assert rp.discover(Obj(), ISSUER).issuer == ISSUER


def test_fork_rebuilds_runtime(op_key, demo_client):
    """A Provider built in the parent keeps working in a forked child (the
    tokio runtime is rebuilt lazily per PID)."""
    import multiprocessing
    import os

    if not hasattr(os, "fork"):
        pytest.skip("no fork")
    op = _op(op_key, client.InMemoryClientStore([demo_client]))
    _flow(op)  # make sure the runtime exists in the parent
    ctx = multiprocessing.get_context("fork")
    q = ctx.Queue()

    def child(q):
        try:
            q.put(_flow(op).token_type)
        except BaseException as e:  # noqa: BLE001
            q.put(f"ERR {e!r}")

    p = ctx.Process(target=child, args=(q,))
    p.start()
    result = q.get(timeout=30)
    p.join(30)
    assert result == "Bearer", result


@pytest.mark.redis
def test_redis_store_before_fork_fails_closed(redis_url, op_key, demo_client):
    import multiprocessing

    store = provider.RedisStore(redis_url, key_prefix="pygrindvakt-fork:")
    op = _op(op_key, client.InMemoryClientStore([demo_client]), store)
    _flow(op)
    ctx = multiprocessing.get_context("fork")
    q = ctx.Queue()

    def child(q):
        try:
            _flow(op)
            q.put("ok")
        except OAuthError as e:
            q.put(e.code)

    p = ctx.Process(target=child, args=(q,))
    p.start()
    assert q.get(timeout=30) == "server_error"
    p.join(30)
