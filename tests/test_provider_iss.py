"""RFC 9207: opt-in ``iss`` on authorization responses from the in-process Provider."""

from __future__ import annotations

import warnings
from urllib.parse import parse_qsl, urlsplit

import pytest
from conftest import ISSUER, REDIRECT_URI
from pygrindvakt import OAuthError, client, metadata, provider, rp, tokens
from pygrindvakt.request import AuthorizationRequest

ISS_MEMBER = "authorization_response_iss_parameter_supported"


def _provider(op_key, *redirect_uris, iss=True):
    c = client.Client(
        "demo",
        client_secret="s3cret",
        redirect_uris=list(redirect_uris) or [REDIRECT_URI],
        response_types=["code", "id_token"],
    )
    return provider.Provider(
        metadata.ProviderMetadata(ISSUER),
        op_key,
        client.InMemoryClientStore([c]),
        tokens.TokenCodec("op-secret"),
        token_use_store=provider.InMemoryTokenUseStore(),
        authorization_response_iss=iss,
    )


def _request(redirect_uri=REDIRECT_URI, **extra):
    params = {
        "response_type": "code",
        "client_id": "demo",
        "redirect_uri": redirect_uri,
        "scope": "openid",
        "state": "st-1",
        **extra,
    }
    return AuthorizationRequest.from_params(list(params.items()))


def _pairs(resp, fragment=False):
    parts = urlsplit(resp.header("location"))
    return parse_qsl(parts.fragment if fragment else parts.query)


def _iss(pairs):
    return [v for k, v in pairs if k == "iss"]


def test_discovery_member_follows_flag(op_key):
    assert _provider(op_key).discovery_document()[ISS_MEMBER] is True
    assert ISS_MEMBER not in _provider(op_key, iss=False).discovery_document()


def test_success_redirect_query_carries_iss_once(op_key):
    op = _provider(op_key)
    resp = op.authorization_redirect(_request(), "alice")
    pairs = _pairs(resp)
    assert _iss(pairs) == [ISSUER]
    assert "state" in dict(pairs)


def test_success_redirect_fragment_carries_iss_once(op_key):
    op = _provider(op_key)
    req = _request(response_type="id_token", response_mode="fragment", nonce="n")
    resp = op.authorization_redirect(req, "alice")
    assert _iss(_pairs(resp, fragment=True)) == [ISSUER]


def test_success_redirect_without_flag_has_no_iss(op_key):
    op = _provider(op_key, iss=False)
    assert _iss(_pairs(op.authorization_redirect(_request(), "alice"))) == []


@pytest.mark.parametrize("query", ["iss=x", "%69ss=x"])
def test_registered_redirect_uri_with_iss_refused_in_query_mode(op_key, query):
    uri = f"{REDIRECT_URI}?{query}"
    op = _provider(op_key, uri)
    req = _request(uri)
    with pytest.raises(OAuthError) as ei:
        op.authorization_redirect(req, "alice")
    assert ei.value.code == "server_error"
    assert "=x" not in (ei.value.description or "")  # the colliding value is not echoed
    with pytest.raises(OAuthError) as ei:
        op.authorization_error_redirect(req, OAuthError("access_denied", state="st-1"))
    assert ei.value.code == "server_error"


def test_registered_redirect_uri_with_iss_fine_in_fragment_mode(op_key):
    uri = f"{REDIRECT_URI}?iss=x"
    op = _provider(op_key, uri)
    req = _request(uri, response_type="id_token", response_mode="fragment", nonce="n")
    resp = op.authorization_redirect(req, "alice")
    assert _iss(_pairs(resp, fragment=True)) == [ISSUER]


def test_registered_redirect_uri_with_iss_fine_without_flag(op_key):
    uri = f"{REDIRECT_URI}?iss=x"
    op = _provider(op_key, uri, iss=False)
    assert op.authorization_redirect(_request(uri), "alice").status == 302


def test_error_redirect_carries_iss_and_state(op_key):
    op = _provider(op_key)
    resp = op.authorization_error_redirect(_request(), OAuthError("access_denied", "no", "st-1"))
    pairs = dict(_pairs(resp))
    assert resp.status == 302
    assert pairs["error"] == "access_denied" and pairs["state"] == "st-1"
    assert pairs["iss"] == ISSUER


def test_error_redirect_fragment_mode(op_key):
    op = _provider(op_key)
    req = _request(response_type="id_token", response_mode="fragment", nonce="n")
    resp = op.authorization_error_redirect(req, OAuthError("access_denied", state="st-1"))
    assert _iss(_pairs(resp, fragment=True)) == [ISSUER]
    assert urlsplit(resp.header("location")).query == ""


def test_error_redirect_without_flag_has_no_iss(op_key):
    op = _provider(op_key, iss=False)
    resp = op.authorization_error_redirect(_request(), OAuthError("access_denied", state="st-1"))
    pairs = dict(_pairs(resp))
    assert pairs["error"] == "access_denied" and pairs["state"] == "st-1"
    assert "iss" not in pairs


@pytest.mark.parametrize("flag", [True, False])
@pytest.mark.parametrize("bad", ["https://evil.example/cb", "https://rp.example.com/cb\r\nX-Evil: 1"])
def test_error_redirect_refuses_forged_unvalidated_request(op_key, flag, bad):
    op = _provider(op_key, iss=flag)
    forged = AuthorizationRequest.from_dict({**_request().to_dict(), "redirect_uri": bad})
    with pytest.raises(OAuthError) as ei:
        op.authorization_error_redirect(forged, OAuthError("access_denied", state="st-1"))
    assert ei.value.code == "invalid_request"
    assert "evil" not in str(ei.value).lower()


def test_error_redirect_refuses_unknown_client(op_key):
    op = _provider(op_key)
    forged = AuthorizationRequest.from_dict({**_request().to_dict(), "client_id": "nobody"})
    with pytest.raises(OAuthError):
        op.authorization_error_redirect(forged, OAuthError("access_denied"))


def test_advertising_member_without_flag_warns(op_key):
    md = metadata.ProviderMetadata(ISSUER)
    md.set_extra_field(ISS_MEMBER, True)
    args = (md, op_key, client.InMemoryClientStore([]), tokens.TokenCodec("s"))
    with pytest.warns(UserWarning, match=ISS_MEMBER):
        provider.Provider(*args, token_use_store=provider.InMemoryTokenUseStore())
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        provider.Provider(*args, token_use_store=provider.InMemoryTokenUseStore(), authorization_response_iss=True)


def test_end_to_end_rp_matches_iss(op_key):
    op = _provider(op_key)
    ok = rp.parse_authorization_response(_pairs(op.authorization_redirect(_request(), "alice")))
    assert ok.matches_iss(ISSUER)
    assert not ok.matches_iss("https://mixup.example.com")
    err = rp.parse_authorization_response(
        _pairs(op.authorization_error_redirect(_request(), OAuthError("access_denied", state="st-1")))
    )
    assert err.is_error and err.state == "st-1" and err.matches_iss(ISSUER)
    plain = _provider(op_key, iss=False)
    bare = rp.parse_authorization_response(_pairs(plain.authorization_redirect(_request(), "alice")))
    assert not bare.matches_iss(ISSUER)
