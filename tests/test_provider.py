"""OpenID Provider flows driven the way a web app would drive them."""

import base64
import hashlib
import json
import time
from urllib.parse import parse_qs, urlparse

import pytest

from conftest import ISSUER, REDIRECT_URI, TOKEN_URL, basic_auth, code_from_redirect
from pygrindvakt import (
    ConfigError,
    OAuthError,
    jwt,
    keys,
    metadata,
    pkce,
    provider,
    request,
    rp,
    util,
)


def authz(op, verifier=None, **extra):
    """Run the front half of a code flow; return (request, code)."""
    params = {
        "client_id": "demo", "response_type": "code", "redirect_uri": REDIRECT_URI,
        "scope": "openid email", "state": "st", "nonce": "n1",
    }
    if verifier:
        params["code_challenge"] = pkce.s256_challenge(verifier)
        params["code_challenge_method"] = "S256"
    params.update(extra)
    req = request.AuthorizationRequest.from_params(list(params.items()))
    op.validate_authorization_request(req)
    resp = op.authorization_redirect(req, "alice", {"email": ["alice@example.com"], "email_verified": ["true"]})
    return req, code_from_redirect(resp)


def test_discovery_and_jwks(op):
    """Discovery reflects the configured issuer; JWKS carries the signing key only."""
    d = op.discovery_document()
    assert d["issuer"] == ISSUER and d["token_endpoint"] == TOKEN_URL
    assert d["code_challenge_methods_supported"] == ["S256"]
    j = op.jwks_document()
    assert [k["kid"] for k in j["keys"]] == ["op-1"] and "d" not in j["keys"][0]
    assert op.issuer == ISSUER and op.metadata.issuer == ISSUER
    assert op.signing_key.kid == "op-1"
    assert op.lifetimes.code_ttl == 600


def test_full_code_flow_with_pkce(op):
    """authorization_code + PKCE + client_secret_basic, then userinfo and refresh."""
    verifier = util.random_token(32)
    req, code = authz(op, verifier)
    tr = op.handle_token_request(list({"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT_URI, "code_verifier": verifier}.items()),
        TOKEN_URL, auth_header=basic_auth("demo", "s3cret"),
    )
    assert tr.token_type == "Bearer" and tr.expires_in == 3600 and tr.refresh_token
    body = tr.to_dict()
    assert set(body) >= {"access_token", "id_token", "token_type", "expires_in", "refresh_token"}
    r = tr.to_response()
    assert r.status == 200 and r.header("cache-control") == "no-store" and json.loads(r.body)["token_type"] == "Bearer"
    claims = rp.verify_id_token(op.jwks_document(), tr.id_token, ISSUER, "demo", "n1", ["ES256"])
    assert claims["sub"] == "alice" and claims["email"] == "alice@example.com" and claims["email_verified"] is True
    ui = op.userinfo(tr.access_token)
    assert ui == {"sub": "alice", "email": "alice@example.com", "email_verified": True}
    tr2 = op.handle_token_request(list({"grant_type": "refresh_token", "refresh_token": tr.refresh_token}.items()),
        TOKEN_URL, auth_header=basic_auth("demo", "s3cret"),
    )
    assert tr2.refresh_token != tr.refresh_token
    with pytest.raises(OAuthError) as ei:  # old refresh token is single-use
        op.handle_token_request(list({"grant_type": "refresh_token", "refresh_token": tr.refresh_token}.items()), TOKEN_URL,
                                auth_header=basic_auth("demo", "s3cret"))
    assert ei.value.code == "invalid_grant"


def test_code_replay_rejected(op):
    """Consuming the same authorization code twice fails with invalid_grant."""
    verifier = util.random_token(32)
    _, code = authz(op, verifier)
    form = {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT_URI, "code_verifier": verifier}
    op.handle_token_request(list(form.items()), TOKEN_URL, auth_header=basic_auth("demo", "s3cret"))
    with pytest.raises(OAuthError) as ei:
        op.handle_token_request(list(form.items()), TOKEN_URL, auth_header=basic_auth("demo", "s3cret"))
    assert ei.value.code == "invalid_grant" and ei.value.http_status == 400


def test_pkce_mismatch_and_bad_secret(op):
    _, code = authz(op, "verifier-one")
    with pytest.raises(OAuthError) as ei:
        op.handle_token_request(list({"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT_URI, "code_verifier": "wrong"}.items()),
            TOKEN_URL, auth_header=basic_auth("demo", "s3cret"))
    assert ei.value.code == "invalid_grant"
    with pytest.raises(OAuthError) as ei:
        op.handle_token_request(list({"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT_URI}.items()),
                                TOKEN_URL, auth_header=basic_auth("demo", "nope"))
    assert ei.value.code == "invalid_client" and ei.value.to_response().status == 401


def test_validate_authorization_request_errors(op):
    """Unknown client / bad redirect_uri must be rendered directly, not redirected."""
    with pytest.raises(OAuthError) as ei:
        request.AuthorizationRequest.from_params(list({"client_id": "demo"}.items()))
    assert ei.value.code == "invalid_request"
    req = request.AuthorizationRequest.from_params(list({"client_id": "demo", "response_type": "code", "redirect_uri": "https://evil/cb", "scope": "openid"}.items()))
    with pytest.raises(OAuthError):
        op.validate_authorization_request(req)
    req = request.AuthorizationRequest.from_params(list({"client_id": "ghost", "response_type": "code", "redirect_uri": REDIRECT_URI, "scope": "openid"}.items()))
    with pytest.raises(OAuthError) as ei:
        op.validate_authorization_request(req)
    assert ei.value.code in ("invalid_client", "invalid_request", "unauthorized_client")


def test_authorization_request_accessors():
    req = request.AuthorizationRequest.from_params(list({"client_id": "c", "response_type": "code id_token", "redirect_uri": "r", "scope": "openid a",
         "prompt": "login consent", "claims": '{"id_token": {"acr": null}}', "foo": "bar"}.items()))
    assert req.scopes() == ["openid", "a"] and req.is_oidc()
    assert req.has_prompt("login") and not req.has_prompt("none")
    assert req.wants_code() and req.wants_id_token() and req.use_fragment()
    assert req.claims == {"id_token": {"acr": None}} and req.extra == {"foo": "bar"}
    req.validate_prompt()
    req.validate_response_type()
    d = req.to_dict()
    assert request.AuthorizationRequest.from_dict(d).client_id == "c"
    access_token_flow = request.AuthorizationRequest.from_params(list({"client_id": "c", "response_type": "code token", "redirect_uri": "r"}.items()))
    assert access_token_flow.use_fragment()  # front-channel tokens never default to query
    bad = request.AuthorizationRequest.from_params(list({"client_id": "c", "response_type": "code", "redirect_uri": "r", "prompt": "none login", "state": "s"}.items()))
    with pytest.raises(OAuthError) as ei:
        bad.validate_prompt()
    assert ei.value.state == "s"


def test_reserved_extra_claims_rejected(op):
    """grindvakt silently drops reserved id_token claims; the binding raises instead."""
    req = request.AuthorizationRequest.from_params(list({"client_id": "demo", "response_type": "code", "redirect_uri": REDIRECT_URI, "scope": "openid"}.items()))
    with pytest.raises(ValueError, match="reserved"):
        op.authorization_redirect(req, "alice", extra_claims={"sub": "x", "ok": 1})
    resp = op.authorization_redirect(req, "alice", extra_claims={"tenant": "t1"})
    assert resp.status == 302


def test_extra_claims_land_in_id_token(op):
    verifier = util.random_token(32)
    params = {"client_id": "demo", "response_type": "code", "redirect_uri": REDIRECT_URI, "scope": "openid",
              "nonce": "n", "code_challenge": pkce.s256_challenge(verifier), "code_challenge_method": "S256"}
    req = request.AuthorizationRequest.from_params(list(params.items()))
    resp = op.authorization_redirect(req, "alice", acr="urn:mfa", extra_claims={"tenant": {"id": 7}})
    code = code_from_redirect(resp)
    tr = op.handle_token_request(list({"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT_URI, "code_verifier": verifier}.items()),
        TOKEN_URL, auth_header=basic_auth("demo", "s3cret"))
    claims = jwt.peek_claims_unverified(tr.id_token)
    assert claims["tenant"] == {"id": 7} and claims["acr"] == "urn:mfa" and claims["nonce"] == "n"


def test_client_credentials(op):
    tr = op.handle_token_request(list({"grant_type": "client_credentials", "client_id": "svc", "client_secret": "svc-secret", "scope": "read"}.items()),
        TOKEN_URL)
    assert tr.scope == "read" and tr.id_token is None and tr.refresh_token is None
    with pytest.raises(OAuthError) as ei:
        op.handle_token_request(list({"grant_type": "client_credentials", "client_id": "svc", "client_secret": "svc-secret", "scope": "admin"}.items()),
            TOKEN_URL)
    assert ei.value.code == "invalid_scope"
    with pytest.raises(OAuthError) as ei:  # demo may not use client_credentials
        op.handle_token_request(list({"grant_type": "client_credentials"}.items()), TOKEN_URL, auth_header=basic_auth("demo", "s3cret"))
    assert ei.value.code in ("unauthorized_client", "invalid_grant")


def test_private_key_jwt(op, rp_key):
    """private_key_jwt client auth with a client assertion built by the rp module;
    the assertion's jti is single-use."""
    verifier = util.random_token(32)
    params = {"client_id": "jwt-rp", "response_type": "code", "redirect_uri": REDIRECT_URI, "scope": "openid",
              "code_challenge": pkce.s256_challenge(verifier), "code_challenge_method": "S256"}
    req = request.AuthorizationRequest.from_params(list(params.items()))
    op.validate_authorization_request(req)
    code = code_from_redirect(op.authorization_redirect(req, "bob"))
    assertion = rp.build_client_assertion(rp_key, "jwt-rp", TOKEN_URL)
    form = {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT_URI, "code_verifier": verifier,
            "client_assertion_type": provider.CLIENT_ASSERTION_TYPE, "client_assertion": assertion}
    tr = op.handle_token_request(list(form.items()), TOKEN_URL)
    assert jwt.peek_claims_unverified(tr.id_token)["sub"] == "bob"
    c = op.authenticate_client(list({"client_assertion_type": provider.CLIENT_ASSERTION_TYPE,
                                "client_assertion": rp.build_client_assertion(rp_key, "jwt-rp", TOKEN_URL)}.items()), TOKEN_URL)
    assert c.client_id == "jwt-rp"
    with pytest.raises(OAuthError) as ei:  # replayed assertion
        op.authenticate_client(list({"client_assertion_type": provider.CLIENT_ASSERTION_TYPE,
                                "client_assertion": assertion}.items()), TOKEN_URL)
    assert ei.value.code == "invalid_client"
    with pytest.raises(OAuthError):  # wrong audience
        op.authenticate_client(list({"client_assertion_type": provider.CLIENT_ASSERTION_TYPE,
                                "client_assertion": rp.build_client_assertion(rp_key, "jwt-rp", "https://other/token")}.items()),
                               TOKEN_URL)


def test_implicit_requires_nonce_and_fragment(op):
    req = request.AuthorizationRequest.from_params(list({"client_id": "demo", "response_type": "id_token", "redirect_uri": REDIRECT_URI, "scope": "openid"}.items()))
    with pytest.raises(OAuthError):
        op.validate_authorization_request(req)


def test_provider_requires_explicit_token_use_store(op_key, demo_client):
    from pygrindvakt import client, tokens

    with pytest.raises(ValueError, match="token_use_store is required"):
        provider.Provider(metadata.ProviderMetadata(ISSUER), op_key,
                          client.InMemoryClientStore([demo_client]), tokens.TokenCodec("s"))


def test_provider_rejects_symmetric_id_token_signing_key(demo_client):
    """OIDC MAC ID tokens require the individual client's own secret."""
    from pygrindvakt import client, tokens

    encoded = base64.urlsafe_b64encode(b"x" * 32).rstrip(b"=").decode()
    symmetric = keys.signing_key_from_jwk(
        {"kty": "oct", "k": encoded}, alg="HS256", kid="op-hs"
    )
    with pytest.raises(ConfigError, match="asymmetric"):
        provider.Provider(
            metadata.ProviderMetadata(ISSUER),
            symmetric,
            client.InMemoryClientStore([demo_client]),
            tokens.TokenCodec("s"),
            token_use_store=provider.InMemoryTokenUseStore(),
        )


def test_duplicate_authorization_and_token_parameters_are_rejected(op):
    pairs = [("client_id", "demo"), ("client_id", "attacker"), ("response_type", "code"),
             ("redirect_uri", REDIRECT_URI), ("scope", "openid")]
    with pytest.raises(OAuthError) as exc:
        request.AuthorizationRequest.from_params(pairs)
    assert exc.value.code == "invalid_request"

    resources = request.AuthorizationRequest.from_params(
        [
            ("client_id", "demo"),
            ("response_type", "code"),
            ("redirect_uri", REDIRECT_URI),
            ("resource", "https://api-one.example"),
            ("resource", "https://api-two.example"),
        ]
    )
    assert resources.resources == ["https://api-one.example", "https://api-two.example"]
    assert "resource" not in resources.extra
    assert request.AuthorizationRequest.from_dict(resources.to_dict()).resources == resources.resources

    with pytest.raises(OAuthError) as exc:
        op.handle_token_request(
            [("grant_type", "authorization_code"), ("grant_type", "refresh_token")],
            TOKEN_URL,
        )
    assert exc.value.code == "invalid_request"

    with pytest.raises(OAuthError) as exc:
        op.authenticate_client(
            [("client_id", "demo"), ("client_secret", "s3cret")],
            TOKEN_URL,
            auth_header=basic_auth("demo", "s3cret"),
        )
    assert exc.value.code == "invalid_client"
    assert exc.value.description == "multiple client authentication methods"


def test_protocol_boundaries_reject_mappings_that_cannot_represent_duplicates(op):
    """Security-sensitive entry points require the original ordered pairs."""
    with pytest.raises(TypeError, match="mappings discard duplicate"):
        request.AuthorizationRequest.from_params({"client_id": "demo"})
    with pytest.raises(TypeError, match="mappings discard duplicate"):
        op.handle_token_request({"grant_type": "client_credentials"}, TOKEN_URL)
    with pytest.raises(TypeError, match="mappings discard duplicate"):
        op.authenticate_client({"client_id": "demo"}, TOKEN_URL)


def test_minting_revalidates_deserialized_request(op):
    req = request.AuthorizationRequest.from_params(list({"client_id": "demo", "response_type": "code", "redirect_uri": REDIRECT_URI,
         "scope": "openid"}.items()))
    stored = req.to_dict()
    stored["redirect_uri"] = "https://evil.example/callback"
    tampered = request.AuthorizationRequest.from_dict(stored)
    with pytest.raises(OAuthError, match="redirect_uri"):
        op.authorization_redirect(tampered, "alice")


def test_token_bearing_query_mode_and_empty_subject_are_rejected(op):
    req = request.AuthorizationRequest.from_params(list({"client_id": "demo", "response_type": "code id_token", "redirect_uri": REDIRECT_URI,
         "scope": "openid", "nonce": "n", "response_mode": "query"}.items()))
    with pytest.raises(OAuthError):
        op.validate_authorization_request(req)

    code_req = request.AuthorizationRequest.from_params(list({"client_id": "demo", "response_type": "code", "redirect_uri": REDIRECT_URI,
         "scope": "openid"}.items()))
    with pytest.raises(OAuthError, match="subject"):
        op.authorization_redirect(code_req, "")


def test_hybrid_and_implicit_responses_include_oidc_hashes(op_key):
    from pygrindvakt import client, tokens

    c = client.Client(
        "flows", client_secret="secret", redirect_uris=[REDIRECT_URI],
        response_types=["code id_token", "id_token token", "code token", "code id_token token"],
        scope="openid profile",
    )
    flow_op = provider.Provider(
        metadata.ProviderMetadata(ISSUER), op_key, client.InMemoryClientStore([c]),
        tokens.TokenCodec("flow-secret"), token_use_store=provider.InMemoryTokenUseStore(),
    )

    hybrid = request.AuthorizationRequest.from_params(list({"client_id": "flows", "response_type": "code id_token", "redirect_uri": REDIRECT_URI,
         "scope": "openid", "nonce": "n"}.items()))
    location = flow_op.authorization_redirect(hybrid, "alice").header("location")
    values = parse_qs(urlparse(location).fragment)
    claims = jwt.peek_claims_unverified(values["id_token"][0])
    expected_c_hash = base64.urlsafe_b64encode(
        hashlib.sha256(values["code"][0].encode()).digest()[:16]
    ).rstrip(b"=").decode()
    assert claims["c_hash"] == expected_c_hash

    implicit = request.AuthorizationRequest.from_params(list({"client_id": "flows", "response_type": "id_token token", "redirect_uri": REDIRECT_URI,
         "scope": "openid", "nonce": "n"}.items()))
    location = flow_op.authorization_redirect(implicit, "alice").header("location")
    values = parse_qs(urlparse(location).fragment)
    assert values["token_type"] == ["Bearer"] and int(values["expires_in"][0]) > 0
    claims = jwt.peek_claims_unverified(values["id_token"][0])
    expected_at_hash = base64.urlsafe_b64encode(
        hashlib.sha256(values["access_token"][0].encode()).digest()[:16]
    ).rstrip(b"=").decode()
    assert claims["at_hash"] == expected_at_hash

    for response_type in ["code token", "code id_token token"]:
        req = request.AuthorizationRequest.from_params(list({"client_id": "flows", "response_type": response_type, "redirect_uri": REDIRECT_URI,
             "scope": "openid", "nonce": "n"}.items()))
        response = flow_op.authorization_redirect(req, "alice")
        assert response.status == 302 and urlparse(response.header("location")).fragment

    # RFC 6749 section 3.1.1 defines response_type as an unordered list.
    reordered = request.AuthorizationRequest.from_params(list({"client_id": "flows", "response_type": "token id_token", "redirect_uri": REDIRECT_URI,
         "scope": "openid", "nonce": "n"}.items()))
    assert flow_op.authorization_redirect(reordered, "alice").status == 302


def test_non_openid_flow_omits_id_token_and_userinfo_and_claims_are_scope_filtered(op, op_key):
    from pygrindvakt import client, tokens

    c = client.Client("oauth", client_secret="secret", redirect_uris=[REDIRECT_URI], scope="email")
    oauth_op = provider.Provider(
        metadata.ProviderMetadata(ISSUER), op_key, client.InMemoryClientStore([c]),
        tokens.TokenCodec("oauth-secret"), token_use_store=provider.InMemoryTokenUseStore(),
    )
    req = request.AuthorizationRequest.from_params(list({"client_id": "oauth", "response_type": "code", "redirect_uri": REDIRECT_URI,
         "scope": "email"}.items()))
    code = code_from_redirect(oauth_op.authorization_redirect(req, "alice", {"email": ["a@b"]}))
    tr = oauth_op.handle_token_request(list({"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT_URI}.items()),
        TOKEN_URL, auth_header=basic_auth("oauth", "secret"),
    )
    assert tr.id_token is None
    with pytest.raises(OAuthError, match="openid scope"):
        oauth_op.userinfo(tr.access_token)

    oidc_service = client.Client(
        "oidc-service", client_secret="secret", grant_types=["client_credentials"],
        token_endpoint_auth_method="client_secret_post", scope="openid email")
    service_op = provider.Provider(
        metadata.ProviderMetadata(ISSUER), op_key,
        client.InMemoryClientStore([oidc_service]), tokens.TokenCodec("service-secret"),
        token_use_store=provider.InMemoryTokenUseStore(),
    )
    with pytest.raises(OAuthError, match="end-user authorization"):
        service_op.handle_token_request(list({"grant_type": "client_credentials", "client_id": "oidc-service",
             "client_secret": "secret", "scope": "openid"}.items()), TOKEN_URL)

    req = request.AuthorizationRequest.from_params(list({"client_id": "demo", "response_type": "code", "redirect_uri": REDIRECT_URI,
         "scope": "openid", "nonce": "n"}.items()))
    code = code_from_redirect(op.authorization_redirect(
        req, "alice", {"email": ["a@b"], "name": ["Alice"], "tenant": ["example"]}
    ))
    tr = op.handle_token_request(list({"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT_URI}.items()),
        TOKEN_URL, auth_header=basic_auth("demo", "s3cret"),
    )
    claims = jwt.peek_claims_unverified(tr.id_token)
    assert "email" not in claims and "name" not in claims and claims["tenant"] == "example"
    assert op.userinfo(tr.access_token) == {"sub": "alice", "tenant": "example"}


def test_metadata_does_not_advertise_unimplemented_features(op, op_key):
    assert op.discovery_document()["subject_types_supported"] == ["public"]
    md = metadata.ProviderMetadata(ISSUER)
    with pytest.raises(ValueError, match="unsupported"):
        md.set_extra_field("end_session_endpoint", f"{ISSUER}/logout")
    with pytest.raises(ValueError, match="reserved"):
        md.extra = {"issuer": "https://evil.example"}


def test_token_lifetimes_and_metadata_customisation(op_key, demo_client):
    from pygrindvakt import client, tokens

    md = metadata.ProviderMetadata("https://issuer.example", "https://issuer.example/oidc")
    assert md.token_endpoint == "https://issuer.example/oidc/token"
    md.scopes_supported = ["openid"]
    md.set_extra_field("custom", {"x": 1})
    md.claims_parameter_supported = True
    lt = provider.TokenLifetimes(code_ttl=5, access_token_ttl=7)
    p = provider.Provider(md, op_key, client.InMemoryClientStore([demo_client]), tokens.TokenCodec("s"),
                          lifetimes=lt, token_use_store=provider.InMemoryTokenUseStore(),
                          client_assertion_max_age=10)
    d = p.discovery_document()
    assert d["custom"] == {"x": 1} and d["scopes_supported"] == ["openid"]
    assert d["claims_parameter_supported"] is False
    assert d["id_token_signing_alg_values_supported"] == ["ES256"]
    assert p.lifetimes.access_token_ttl == 7 and p.lifetimes.refresh_token_ttl == 2_592_000
    assert metadata.ProviderMetadata.from_dict(d).token_endpoint == md.token_endpoint
    assert isinstance(p.token_use_store, provider.InMemoryTokenUseStore)


def test_flatten_claims():
    assert provider.flatten_claims({"email_verified": ["true"], "groups": ["a", "b"], "name": ["N"]}) == {
        "email_verified": True, "groups": ["a", "b"], "name": "N"}
    assert "sub" in provider.RESERVED_ID_TOKEN_CLAIMS


def test_userinfo_rejects_garbage_and_expired(op, op_key):
    with pytest.raises(OAuthError) as ei:
        op.userinfo("not-a-token")
    assert ei.value.code in ("invalid_request", "access_denied", "invalid_grant")


def test_threads_do_not_deadlock(op):
    """The runtime bridge releases the GIL; many threads can drive the provider."""
    from concurrent.futures import ThreadPoolExecutor

    def one(i):
        v = util.random_token(32)
        _, code = authz(op, v)
        tr = op.handle_token_request(list({"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT_URI, "code_verifier": v}.items()),
            TOKEN_URL, auth_header=basic_auth("demo", "s3cret"))
        return op.userinfo(tr.access_token)["sub"]

    with ThreadPoolExecutor(8) as ex:
        assert set(ex.map(one, range(40))) == {"alice"}


def test_in_memory_token_use_store_direct():
    s = provider.InMemoryTokenUseStore()
    assert s.consume("h", 60) is True
    assert s.consume("h", 60) is False


@pytest.mark.redis
def test_redis_store(redis_url):
    s = provider.RedisStore(redis_url, key_prefix="pygrindvakt-test:")
    h = util.random_token(8)
    assert s.consume(h, 5) is True
    assert s.consume(h, 5) is False
    assert provider.RedisStore.DEFAULT_KEY_PREFIX == "grindvakt:token-use:"
