"""jwt / pkce / mac / util helpers."""

import hashlib
import hmac
import time

import pytest

from pygrindvakt import GrindvaktError, jwt, keys, mac, pkce, util

# ---- jwt --------------------------------------------------------------------


def test_sign_and_verify_with_jwks(op_key):
    tok = jwt.sign(op_key, {"iss": "i", "aud": "a", "sub": "s", "exp": int(time.time()) + 60, "x": [1, 2]}, typ="custom+jwt")
    hdr = jwt.peek_header(tok)
    assert hdr["alg"] == "ES256" and hdr["kid"] == "op-1" and hdr["typ"] == "custom+jwt"
    v = jwt.Validation().with_issuer("i").with_audience("a").with_typ("custom+jwt").require_exp()
    claims = jwt.verify_with_jwks(op_key.to_public_jwks(), tok, v)
    assert claims["sub"] == "s" and claims["x"] == [1, 2]


def test_validation_failures(op_key):
    tok = jwt.sign(op_key, {"iss": "i", "exp": int(time.time()) + 60})
    with pytest.raises(GrindvaktError):
        jwt.verify_with_jwks(op_key.to_public_jwks(), tok, jwt.Validation().with_issuer("other"))
    with pytest.raises(GrindvaktError):
        jwt.verify_with_jwks(op_key.to_public_jwks(), tok, jwt.Validation().with_allowed_algorithms(["RS256"]))
    with pytest.raises(GrindvaktError):
        jwt.Validation().with_allowed_algorithms(["nope"])


def test_wrong_key_rejected(op_key, rp_key):
    tok = jwt.sign(op_key, {"a": 1})
    with pytest.raises(GrindvaktError):
        jwt.verify_with_jwks(rp_key.to_public_jwks(), tok, jwt.Validation())


def test_peek_claims_unverified(op_key):
    tok = jwt.sign(op_key, {"iss": "peek"})
    assert jwt.peek_claims_unverified(tok)["iss"] == "peek"
    with pytest.raises(GrindvaktError):
        jwt.peek_claims_unverified("not.a.jwt.at.all")


def test_expired_token_rejected(op_key):
    tok = jwt.sign(op_key, {"exp": int(time.time()) - 100})
    with pytest.raises(GrindvaktError):
        jwt.verify_with_jwk(op_key.public_jwk(), tok, jwt.Validation())
    # leeway rescues it
    assert jwt.verify_with_jwk(op_key.public_jwk(), tok, jwt.Validation().with_leeway(1000))


# ---- pkce -------------------------------------------------------------------


def test_pkce_rfc7636_vector():
    """RFC 7636 appendix B test vector."""
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert pkce.s256_challenge(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    assert pkce.verify(verifier, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "S256")
    assert not pkce.verify(verifier, "wrong", "S256")
    valid_plain = "a" * 43
    assert pkce.verify(valid_plain, valid_plain, "plain")
    assert not pkce.verify("abc", "abc", "plain")
    assert pkce.verify(valid_plain, valid_plain)  # RFC 7636 section 4.3: no method means plain
    assert not pkce.verify(verifier, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")  # plain compare fails
    assert not pkce.verify("abc", "abc", "S512")


# ---- mac --------------------------------------------------------------------


def test_mac_matches_hashlib():
    assert mac.sha256(b"abc") == hashlib.sha256(b"abc").digest()
    assert mac.hmac_sha256(b"k", b"d") == hmac.new(b"k", b"d", "sha256").digest()
    assert mac.constant_time_eq(b"x", b"x") and not mac.constant_time_eq(b"x", b"y")


# ---- util -------------------------------------------------------------------


def test_util():
    assert abs(util.now_secs() - time.time()) < 5
    assert util.now_rfc3339().endswith("Z")
    t = util.random_token(32)
    assert len(t) == 43 and t != util.random_token(32)
    assert len(util.random_token()) == 43
