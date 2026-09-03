"""Signing-key loading: JWK, PEM (openssl-generated), PKCS#11 (SoftHSM2)."""

import pytest

from pygrindvakt import CryptoError, GrindvaktError, jwt, keys


def test_generate_and_load_ec_jwk():
    """A generated P-256 JWK loads as ES256 and publishes only public components."""
    jwk = keys.generate_ec_jwk("P-256")
    assert jwk["kty"] == "EC" and "d" in jwk
    key = keys.signing_key_from_jwk(jwk, alg="ES256", kid="k1")
    assert key.alg == "ES256" and key.kid == "k1"
    pub = key.public_jwk()
    assert pub["kty"] == "EC" and "d" not in pub and pub["kid"] == "k1" and pub["alg"] == "ES256"
    jwks = key.to_public_jwks()
    assert [k["kid"] for k in jwks["keys"]] == ["k1"]
    assert "SigningKey" in repr(key)


def test_default_alg_inferred_from_key_type():
    """Without an alg override the algorithm follows the key type."""
    assert keys.signing_key_from_jwk(keys.generate_ec_jwk("P-256")).alg == "ES256"
    assert keys.signing_key_from_jwk(keys.generate_ec_jwk("P-384")).alg == "ES384"
    assert keys.signing_key_from_jwk(keys.generate_ed25519_jwk()).alg == "EdDSA"


def test_jwk_json_string_loader():
    import json

    jwk = keys.generate_ec_jwk()
    key = keys.signing_key_from_jwk_json(json.dumps(jwk), kid="j")
    assert key.kid == "j"


def test_bad_alg_override_raises():
    with pytest.raises(GrindvaktError):
        keys.signing_key_from_jwk(keys.generate_ec_jwk(), alg="HS256x")


def test_bad_jwk_raises():
    with pytest.raises(GrindvaktError):
        keys.signing_key_from_jwk({"kty": "EC"})


def test_rsa_jwk_generation_and_signing():
    """RSA keys default to RS256 and can sign/verify a JWT round trip."""
    key = keys.signing_key_from_jwk(keys.generate_rsa_jwk(2048), kid="r")
    assert key.alg == "RS256"
    tok = jwt.sign(key, {"iss": "me", "sub": "you"})
    claims = jwt.verify_with_jwks(key.to_public_jwks(), tok, jwt.Validation().with_issuer("me"))
    assert claims["sub"] == "you"


def test_pem_ec_loader(ec_pem):
    """A PKCS#8 EC PEM from openssl loads and signs."""
    key = keys.signing_key_from_pem(ec_pem, kid="pem-ec")
    assert key.alg == "ES256"
    tok = jwt.sign(key, {"a": 1})
    assert jwt.verify_with_jwk(key.public_jwk(), tok, jwt.Validation())["a"] == 1


def test_pem_rsa_loader(rsa_pem):
    key = keys.signing_key_from_pem(rsa_pem, alg="RS256")
    assert key.alg == "RS256"
    assert key.public_jwk()["kty"] == "RSA"


def test_pem_garbage_raises():
    with pytest.raises(GrindvaktError):
        keys.signing_key_from_pem(b"-----BEGIN NOTHING-----\nAAAA\n-----END NOTHING-----\n")


def test_jwk_thumbprint_is_stable():
    """RFC 7638 thumbprints depend only on the public required members."""
    jwk = keys.generate_ec_jwk()
    pub = keys.signing_key_from_jwk(jwk).public_jwk()
    assert keys.jwk_thumbprint(jwk) == keys.jwk_thumbprint(pub)
    assert len(keys.jwk_thumbprint(pub)) == 43


@pytest.mark.pkcs11
def test_pkcs11_signing_key(softhsm):
    """A key held in SoftHSM2 signs JWTs verifiable with its public JWK."""
    module, pin, label = softhsm
    key = keys.signing_key_from_pkcs11(module, pin, label, "ES256", kid="hsm")
    assert key.alg == "ES256" and key.kid == "hsm"
    tok = jwt.sign(key, {"iss": "hsm"})
    assert jwt.verify_with_jwks(key.to_public_jwks(), tok, jwt.Validation())["iss"] == "hsm"


@pytest.mark.pkcs11
def test_pkcs11_wrong_pin(softhsm):
    module, pin, label = softhsm
    with pytest.raises(CryptoError):
        keys.signing_key_from_pkcs11(module, "9999", label, "ES256")
