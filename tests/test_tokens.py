"""TokenCodec: sealed authorization codes / access / refresh tokens."""

import time

import pytest

from pygrindvakt import GrindvaktError, tokens


def _code(exp=None):
    return tokens.AuthCodePayload(
        client_id="demo",
        redirect_uri="https://rp/cb",
        scope="openid",
        sub="alice",
        auth_time=int(time.time()),
        exp=exp or int(time.time()) + 60,
        nonce="n",
        claims={"email": "a@b", "groups": ["x", "y"]},
    )


def test_code_round_trip():
    """A sealed code opens to an equal payload, including nested JSON claims."""
    codec = tokens.TokenCodec("secret")
    sealed = codec.seal_code(_code())
    assert sealed.count(".") == 4  # compact JWE
    opened = codec.open_code(sealed)
    assert opened.sub == "alice" and opened.nonce == "n"
    assert opened.claims == {"email": "a@b", "groups": ["x", "y"]}
    assert opened.to_dict()["client_id"] == "demo"
    assert "AuthCodePayload" in repr(opened)


def test_expired_code_rejected():
    codec = tokens.TokenCodec("secret")
    sealed = codec.seal_code(_code(exp=int(time.time()) - 1))
    with pytest.raises(GrindvaktError):
        codec.open_code(sealed)


def test_wrong_secret_rejected():
    sealed = tokens.TokenCodec("a").seal_code(_code())
    with pytest.raises(GrindvaktError):
        tokens.TokenCodec("b").open_code(sealed)


def test_type_confusion_rejected():
    """A code cannot be presented as an access token or refresh token."""
    codec = tokens.TokenCodec("secret")
    sealed = codec.seal_code(_code())
    with pytest.raises(GrindvaktError):
        codec.open_access_token(sealed)
    with pytest.raises(GrindvaktError):
        codec.open_refresh_token(sealed)


def test_key_rotation_with_previous_secrets():
    """Tokens sealed under an old secret still open after rotation."""
    old = tokens.TokenCodec("old")
    at = tokens.AccessTokenPayload(client_id="demo", sub="alice", scope="openid", exp=int(time.time()) + 60)
    sealed = old.seal_access_token(at)
    new = tokens.TokenCodec("new", previous_secrets=["old"])
    assert new.open_access_token(sealed).sub == "alice"
    with pytest.raises(GrindvaktError):
        tokens.TokenCodec("new").open_access_token(sealed)


def test_refresh_payload_round_trip_and_dpop_binding():
    codec = tokens.TokenCodec("s")
    rt = tokens.RefreshTokenPayload(
        client_id="demo", sub="a", scope="openid", auth_time=1, exp=int(time.time()) + 5, cnf_jkt="thumb"
    )
    opened = codec.open_refresh_token(codec.seal_refresh_token(rt))
    assert opened.cnf_jkt == "thumb" and opened.acr is None


def test_payload_from_dict():
    p = tokens.AccessTokenPayload.from_dict({"client_id": "c", "sub": "s", "scope": "x", "exp": 5})
    assert p.claims == {} and p.exp == 5
    with pytest.raises(ValueError):
        tokens.AccessTokenPayload.from_dict({"sub": "s"})
