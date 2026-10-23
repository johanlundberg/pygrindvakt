"""jwt / pkce / mac / util helpers."""

import base64
import hashlib
import hmac
import time

import pytest
from pygrindvakt import CryptoError, GrindvaktError, jwt, mac, pkce, rp, util

# ---- jwt --------------------------------------------------------------------


def test_sign_and_verify_with_jwks(op_key):
    tok = jwt.sign(
        op_key,
        {"iss": "i", "aud": "a", "sub": "s", "exp": int(time.time()) + 60, "x": [1, 2]},
        typ="custom+jwt",
    )
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
        jwt.verify_with_jwks(
            op_key.to_public_jwks(),
            tok,
            jwt.Validation().with_allowed_algorithms(["RS256"]),
        )
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


# ---- jwt: OIDC token hash -----------------------------------------------------


def test_oidc_token_hash_core_appendix_a3_vector():
    assert jwt.oidc_token_hash("RS256", "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y") == "77QmUPtjPfzWtF2AnpK9RQ"


@pytest.mark.parametrize(
    ("alg", "digest", "encoded_len"),
    [
        ("ES256", hashlib.sha256, 22),
        ("PS256", hashlib.sha256, 22),
        ("ES384", hashlib.sha384, 32),
        ("RS512", hashlib.sha512, 43),
        ("ES256K", hashlib.sha256, 22),
        ("HS256", hashlib.sha256, 22),
        ("HS384", hashlib.sha384, 32),
        ("HS512", hashlib.sha512, 43),
    ],
)
def test_oidc_token_hash_is_left_half_of_matching_digest(alg, digest, encoded_len):
    out = jwt.oidc_token_hash(alg, "access-token")
    raw = digest(b"access-token").digest()
    assert len(out) == encoded_len
    assert out == base64.urlsafe_b64encode(raw[: len(raw) // 2]).rstrip(b"=").decode()


def test_oidc_token_hash_errors():
    with pytest.raises(CryptoError):
        jwt.oidc_token_hash("bogus", "x")
    with pytest.raises(CryptoError):
        jwt.oidc_token_hash("EdDSA", "x")


@pytest.mark.parametrize("alg", [*rp.asymmetric_algorithms(), "HS256", "HS384", "HS512", "bogus"])
def test_supports_oidc_token_hash_iff_oidc_token_hash_succeeds(alg):
    supported = jwt.supports_oidc_token_hash(alg)
    try:
        jwt.oidc_token_hash(alg, "x")
        succeeded = True
    except CryptoError:
        succeeded = False
    assert supported is succeeded
    assert supported is (alg not in ("EdDSA", "bogus"))


def test_supports_oidc_token_hash():
    assert jwt.supports_oidc_token_hash("ES384") is True
    assert jwt.supports_oidc_token_hash("EdDSA") is False
    assert jwt.supports_oidc_token_hash("bogus") is False
    assert jwt.supports_oidc_token_hash("vendor-alg-1") is False
