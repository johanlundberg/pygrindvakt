"""jwt / pkce / mac / util helpers."""

import base64
import hashlib
import hmac
import json
import time
import warnings

import pytest
from pygrindvakt import ConfigError, CryptoError, GrindvaktError, JoseError, jwt, mac, pkce, rp, util

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


# ---- jwt.verify_with_* shared-secret gate (RFC 7518 section 3.2, ADR 0006) ---

_HS = {"HS256": (hashlib.sha256, 32), "HS384": (hashlib.sha384, 48), "HS512": (hashlib.sha512, 64)}


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _hs_token(secret: bytes, alg: str, kid: str | None = None) -> str:
    """Sign by hand so secrets of any length can be used."""
    header = {"alg": alg}
    if kid is not None:
        header["kid"] = kid
    h = _b64u(json.dumps(header).encode())
    p = _b64u(json.dumps({"exp": int(time.time()) + 60, "sub": "s"}).encode())
    sig = hmac.new(secret, f"{h}.{p}".encode(), _HS[alg][0]).digest()
    return f"{h}.{p}.{_b64u(sig)}"


def _verify(fn: str, jwk: dict, token: str, alg: str):
    v = jwt.Validation().with_allowed_algorithms([alg])
    if fn == "jwks":
        return jwt.verify_with_jwks({"keys": [jwk]}, token, v)
    return jwt.verify_with_jwk(jwk, token, v)


FUNCS = pytest.mark.parametrize("fn", ["jwks", "jwk"])


@FUNCS
@pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
@pytest.mark.parametrize("kid", [None, "c"])
@pytest.mark.parametrize("pinned", [False, True])
def test_verify_mac_min_length_ok(fn, alg, kid, pinned):
    secret = b"k" * _HS[alg][1]
    jwk = {"kty": "oct", "k": _b64u(secret)}
    if kid:
        jwk["kid"] = kid
    if pinned:
        jwk["alg"] = alg
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert _verify(fn, jwk, _hs_token(secret, alg, kid), alg)["sub"] == "s"


@FUNCS
@pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
@pytest.mark.parametrize("pinned", [False, True])
def test_verify_mac_below_min_refused(fn, alg, pinned):
    secret = b"k" * (_HS[alg][1] - 1)
    jwk = {"kty": "oct", "k": _b64u(secret)}
    if pinned:
        jwk["alg"] = alg
    with pytest.raises(ConfigError) as ei:
        _verify(fn, jwk, _hs_token(secret, alg), alg)
    assert ei.value.code == "weak_shared_secret"
    assert _b64u(secret) not in str(ei.value)


@FUNCS
def test_verify_mac_hs512_40_bytes_refused(fn):
    """PoC for F2: an unpinned 40-byte key used to verify HS512."""
    secret = b"p" * 40
    with pytest.raises(ConfigError) as ei:
        _verify(fn, {"kty": "oct", "k": _b64u(secret)}, _hs_token(secret, "HS512"), "HS512")
    assert ei.value.code == "weak_shared_secret"


@FUNCS
def test_verify_mac_hs256_33_bytes_unpinned_verifies(fn):
    # Previously accepted only by jose-rs' length heuristic; now by the pin.
    secret = b"q" * 33
    assert _verify(fn, {"kty": "oct", "k": _b64u(secret)}, _hs_token(secret, "HS256"), "HS256")


def test_verify_mac_no_allow_list_still_gated():
    secret = b"p" * 40
    jwk = {"kty": "oct", "k": _b64u(secret)}
    tok = _hs_token(secret, "HS512")
    with pytest.raises(ConfigError):
        jwt.verify_with_jwks({"keys": [jwk]}, tok, jwt.Validation())
    with pytest.raises(ConfigError):
        jwt.verify_with_jwk(jwk, tok, jwt.Validation())


def test_verify_mac_kid_selects_candidate():
    good, short = b"g" * 32, b"s" * 5
    keys = {
        "keys": [
            {"kty": "oct", "k": _b64u(short), "kid": "other"},
            {"kty": "oct", "k": _b64u(good), "kid": "c"},
        ]
    }
    v = jwt.Validation().with_allowed_algorithms(["HS256"])
    assert jwt.verify_with_jwks(keys, _hs_token(good, "HS256", "c"), v)["sub"] == "s"
    # No kid on the token: jose-rs tries every key, so every compatible oct key
    # is checked ...
    with pytest.raises(ConfigError):
        jwt.verify_with_jwks(keys, _hs_token(good, "HS256"), v)
    # ... unless require_kid makes jose-rs refuse the token before any key.
    with pytest.raises(JoseError) as ei:
        jwt.verify_with_jwks(keys, _hs_token(good, "HS256"), v.require_kid())
    assert getattr(ei.value, "code", None) != "weak_shared_secret"
    # F3: a kid that names an incompatible key does not look at the weak one.
    keys["keys"].append({"kty": "oct", "k": _b64u(good), "kid": "enc", "use": "enc"})
    with pytest.raises(JoseError) as ei:
        jwt.verify_with_jwks(keys, _hs_token(good, "HS256", "enc"), v)
    assert not isinstance(ei.value, ConfigError)
    # A kid that names no key is jose-rs' own error.
    with pytest.raises(JoseError) as ei:
        jwt.verify_with_jwks(keys, _hs_token(good, "HS256", "zzz"), v)
    assert not isinstance(ei.value, ConfigError)


def test_verify_mac_ec_plus_weak_oct_token_naming_ec_key(op_key):
    """F3 PoC: the weak oct key is not the one the token selects."""
    weak = {"kty": "oct", "k": _b64u(b"short"), "kid": "legacy"}
    keys = {"keys": [*op_key.to_public_jwks()["keys"], weak]}
    v = jwt.Validation().with_allowed_algorithms(["HS256"])
    with pytest.raises(JoseError) as ei:
        jwt.verify_with_jwks(keys, _hs_token(b"x" * 40, "HS256", "op-1"), v)
    assert not isinstance(ei.value, ConfigError)
    assert ei.value.code == "jose"
    # Selecting the weak key by its kid is the documented residual.
    with pytest.raises(ConfigError) as ei:
        jwt.verify_with_jwks(keys, _hs_token(b"short", "HS256", "legacy"), v)
    assert ei.value.code == "weak_shared_secret"


def test_verify_with_jwk_ignores_token_kid_for_the_gate():
    """A single JWK is used whatever the token's kid says, so it is always checked."""
    secret = b"short"
    jwk = {"kty": "oct", "k": _b64u(secret), "kid": "a"}
    v = jwt.Validation().with_allowed_algorithms(["HS256"])
    with pytest.raises(ConfigError) as ei:
        jwt.verify_with_jwk(jwk, _hs_token(secret, "HS256", "zzz"), v)
    assert ei.value.code == "weak_shared_secret"


@FUNCS
@pytest.mark.parametrize("extra", [{"alg": "A128KW"}, {"use": "enc"}, {"key_ops": ["encrypt"]}])
def test_verify_mac_incompatible_oct_keys_not_checked(fn, extra):
    secret = b"x" * 8
    jwk = {"kty": "oct", "k": _b64u(secret), **extra}
    with pytest.raises(GrindvaktError) as ei:
        _verify(fn, jwk, _hs_token(secret, "HS256"), "HS256")
    assert getattr(ei.value, "code", None) != "weak_shared_secret"
    # Not mutated: a good key beside it still verifies.
    good = b"g" * 32
    if fn == "jwks":
        keys = {"keys": [jwk, {"kty": "oct", "k": _b64u(good), "kid": "c"}]}
        v = jwt.Validation().with_allowed_algorithms(["HS256"])
        assert jwt.verify_with_jwks(keys, _hs_token(good, "HS256", "c"), v)


@FUNCS
@pytest.mark.parametrize("bad_k", ["QUJD\n", "QUJD=", "QUJD+/", "A" * 5])
def test_verify_mac_invalid_k_material(fn, bad_k):
    tok = _hs_token(b"k" * 32, "HS256")
    with pytest.raises(ConfigError) as ei:
        _verify(fn, {"kty": "oct", "k": bad_k}, tok, "HS256")
    assert ei.value.code == "weak_shared_secret"
    assert bad_k.strip() not in str(ei.value)


@FUNCS
def test_verify_asymmetric_unaffected(fn, op_key):
    tok = jwt.sign(op_key, {"exp": int(time.time()) + 60, "sub": "s"})
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        if fn == "jwks":
            assert jwt.verify_with_jwks(op_key.to_public_jwks(), tok, jwt.Validation())["sub"] == "s"
        else:
            assert jwt.verify_with_jwk(op_key.public_jwk(), tok, jwt.Validation())["sub"] == "s"
