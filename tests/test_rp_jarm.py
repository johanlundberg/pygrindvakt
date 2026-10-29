"""rp.AuthorizationResponse.verify_jarm (JARM, JWT Secured Authorization Response Mode)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import pytest
from pygrindvakt import AuthnError, BadRequestError, ConfigError, InternalError, UnknownKeyError, jwt, keys, rp

ISS = "https://op.example.com"
CLIENT = "demo"
ES = ["ES256"]
JWKS_URI = "https://op.example.com/jwks"


def _b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def make_key(kid="k1"):
    return keys.signing_key_from_jwk(keys.generate_ec_jwk("P-256"), alg="ES256", kid=kid)


def claims(**over):
    c = {"iss": ISS, "aud": CLIENT, "exp": int(time.time()) + 300, "code": "the-code", "state": "st"}
    c.update(over)
    return {k: v for k, v in c.items() if v is not None}


def stub(token):
    return rp.parse_authorization_response([("response", token)], accept_jarm=True)


def jwks_of(*ks):
    return {"keys": [k.public_jwk() for k in ks]}


def verify(token, ks, **kw):
    kw.setdefault("issuer", ISS)
    kw.setdefault("client_id", CLIENT)
    kw.setdefault("allowed_algorithms", ES)
    return stub(token).verify_jarm(jwks_of(ks) if not isinstance(ks, (dict, rp.JwksCache)) else ks, **kw)


@pytest.fixture
def key():
    return make_key()


def typed(key, **over):
    return jwt.sign(key, claims(**over), rp.JARM_TYP)


def test_constants():
    algs = rp.JARM_ASYMMETRIC_ALGORITHMS
    assert isinstance(algs, tuple)
    assert set(algs) == {
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "ES384",
        "ES512",
        "EdDSA",
    }
    assert not any(a.startswith("HS") for a in algs) and "ES256K" not in algs
    assert rp.JARM_TYP == "oauth-authz-resp+jwt"


def test_happy_path_typed(key):
    token = typed(key)
    s = stub(token)
    assert s.jarm_verified is False
    r = s.verify_jarm(jwks_of(key), issuer=ISS, client_id=CLIENT, allowed_algorithms=rp.JARM_ASYMMETRIC_ALGORITHMS)
    assert r.jarm_verified is True
    assert (r.code, r.state, r.iss, r.error) == ("the-code", "st", ISS, None)
    assert r.response == token and r.response_mode == "query"
    assert r.matches_state("st") and not r.matches_state("other")
    assert r.matches_iss(ISS) and not r.matches_iss("https://evil.example")
    assert not s.matches_state("st") and not s.matches_iss(ISS)
    assert s.jarm_verified is False


def test_transport_label_preserved(key):
    s = rp.parse_authorization_response([("response", typed(key))], accept_jarm=True, response_mode="fragment")
    r = s.verify_jarm(jwks_of(key), issuer=ISS, client_id=CLIENT, allowed_algorithms=ES)
    assert r.response_mode == "fragment"


def test_non_jarm_response_has_flag_false():
    r = rp.parse_authorization_response([("code", "c")])
    assert r.jarm_verified is False


def test_explicit_typ_and_case_and_application_prefix(key):
    t = jwt.sign(key, claims(), "Application/OAuth-Authz-Resp+JWT")
    assert verify(t, key).jarm_verified
    t = jwt.sign(key, claims(), "custom+jwt")
    assert verify(t, key, typ="custom+jwt").code == "the-code"
    with pytest.raises(AuthnError):
        verify(typed(key), key, typ="custom+jwt")


@pytest.mark.parametrize("typ", ["JWT", "at+jwt", "id_token+jwt", "logout+jwt", "other"])
def test_wrong_typ_rejected_typed(key, typ):
    with pytest.raises(AuthnError):
        verify(jwt.sign(key, claims(), typ), key)


def test_missing_typ_rejected_typed(key):
    with pytest.raises(AuthnError, match="typ"):
        verify(jwt.sign(key, claims()), key)


def test_id_token_not_accepted_as_jarm(key):
    now = int(time.time())
    idt = {
        "iss": ISS,
        "aud": CLIENT,
        "sub": "alice",
        "exp": now + 300,
        "iat": now,
        "nonce": "n",
        "code": "c",
        "state": "s",
    }
    for typ in (None, "JWT"):
        with pytest.raises(AuthnError):
            verify(jwt.sign(key, idt, typ), key)
    with pytest.raises(AuthnError):
        verify(jwt.sign(key, idt, "at+jwt"), key, trust="dedicated_keys")


@pytest.mark.parametrize("trust", ["dedicated_keys", "untyped_shared_key_compat"])
def test_untyped_trust_modes(key, trust):
    assert verify(jwt.sign(key, claims()), key, trust=trust).code == "the-code"
    assert verify(jwt.sign(key, claims(), "JWT"), key, trust=trust).code == "the-code"
    assert verify(typed(key), key, trust=trust).code == "the-code"
    with pytest.raises(AuthnError):
        verify(jwt.sign(key, claims(), "id_token+jwt"), key, trust=trust)


def test_bad_signature(key):
    other = make_key("k1")
    with pytest.raises(AuthnError):
        verify(typed(other), key)


@pytest.mark.parametrize(
    "over",
    [
        {"iss": "https://evil.example"},
        {"iss": None},
        {"aud": "other"},
        {"aud": None},
        {"aud": [CLIENT, "other"]},
        {"exp": int(time.time()) - 3600},
        {"exp": None},
    ],
)
def test_bad_claims(key, over):
    with pytest.raises(AuthnError):
        verify(typed(key, **over), key)


def test_single_element_aud_array_ok(key):
    assert verify(typed(key, aud=[CLIENT]), key).code == "the-code"


def test_leeway(key):
    t = typed(key, exp=int(time.time()) - 200)
    with pytest.raises(AuthnError):
        verify(t, key)
    assert verify(t, key, leeway=300).code == "the-code"


def test_leeway_over_cap(key):
    with pytest.raises(ConfigError, match="leeway"):
        verify(typed(key), key, leeway=rp.MAX_ID_TOKEN_LEEWAY + 1)
    assert verify(typed(key), key, leeway=rp.MAX_ID_TOKEN_LEEWAY).jarm_verified


def test_alg_not_allowed(key):
    with pytest.raises(AuthnError):
        verify(typed(key), key, allowed_algorithms=["ES384"])
    with pytest.raises(AuthnError):
        verify(typed(key), key, allowed_algorithms=["RS256"])


def test_alg_none_rejected(key):
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    token = f"{b64({'alg': 'none', 'typ': rp.JARM_TYP})}.{b64(claims())}."
    with pytest.raises((AuthnError, BadRequestError)):
        verify(token, key)
    with pytest.raises(ConfigError):
        verify(typed(key), key, allowed_algorithms=["none"])


def test_jwe_rejected(key):
    with pytest.raises(BadRequestError, match="encrypted"):
        stub("a.b.c.d.e").verify_jarm(jwks_of(key), issuer=ISS, client_id=CLIENT, allowed_algorithms=ES)


def test_jwe_does_not_fetch_from_cache():
    class NoNet:
        def get(self, url):
            raise AssertionError("fetched")

        def post_form(self, url, form, headers):
            raise AssertionError("posted")

    cache = rp.JwksCache(NoNet(), JWKS_URI, ISS)
    with pytest.raises(BadRequestError):
        stub("a.b.c.d.e").verify_jarm(cache, issuer=ISS, client_id=CLIENT, allowed_algorithms=ES)


def test_malformed_jwt(key):
    with pytest.raises(BadRequestError):
        stub("not-a-jwt").verify_jarm(jwks_of(key), issuer=ISS, client_id=CLIENT, allowed_algorithms=ES)


def test_non_jarm_and_already_verified(key):
    plain = rp.parse_authorization_response([("code", "c")])
    with pytest.raises(BadRequestError):
        plain.verify_jarm(jwks_of(key), issuer=ISS, client_id=CLIENT, allowed_algorithms=ES)
    done = verify(typed(key), key)
    with pytest.raises(BadRequestError):
        done.verify_jarm(jwks_of(key), issuer=ISS, client_id=CLIENT, allowed_algorithms=ES)


def test_bad_inner_shape(key):
    with pytest.raises(BadRequestError):
        verify(typed(key, code=5), key)
    with pytest.raises(BadRequestError):
        verify(typed(key, code=None, state="x"), key)  # neither code nor error
    with pytest.raises(BadRequestError):
        verify(typed(key, error="access_denied"), key)  # both code and error


def test_config_errors(key):
    t = typed(key)
    for bad in (
        {"allowed_algorithms": []},
        {"trust": "bogus"},
        {"trust": "dedicated_keys", "typ": "x"},
        {"trust": "untyped_shared_key_compat", "typ": "x"},
        {"allowed_algorithms": ["NOPE"]},
    ):
        with pytest.raises(ConfigError):
            verify(t, key, **bad)


def test_allowed_algorithms_required(key):
    with pytest.raises(TypeError):
        stub(typed(key)).verify_jarm(jwks_of(key), issuer=ISS, client_id=CLIENT)  # type: ignore[call-arg]


def _oct_jwk(secret, kid="c"):
    k = base64.urlsafe_b64encode(secret).rstrip(b"=").decode()
    return {"kty": "oct", "k": k, "kid": kid, "alg": "HS256"}


def test_hs_with_literal_set_strong_secret_verifies():
    jwk = _oct_jwk(b"s" * 32)
    sk = keys.signing_key_from_jwk(jwk, alg="HS256", kid="c")
    t = jwt.sign(sk, claims(), rp.JARM_TYP)
    r = stub(t).verify_jarm({"keys": [jwk]}, issuer=ISS, client_id=CLIENT, allowed_algorithms=["HS256"])
    assert r.code == "the-code"


def test_hs_with_literal_set_weak_secret_refused():
    secret = b"s" * 16
    jwk = _oct_jwk(secret)
    h = _b64u(json.dumps({"alg": "HS256", "typ": rp.JARM_TYP, "kid": "c"}).encode())
    p = _b64u(json.dumps(claims()).encode())
    sig = hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest()
    t = f"{h}.{p}.{_b64u(sig)}"
    with pytest.raises(ConfigError) as exc:
        stub(t).verify_jarm({"keys": [jwk]}, issuer=ISS, client_id=CLIENT, allowed_algorithms=["HS256"])
    assert exc.value.code == "weak_shared_secret"


def test_unmatched_kid_in_literal_multi_key_set_fails_closed():
    k1, k2, other = make_key("k1"), make_key("k2"), make_key("other")
    with pytest.raises(AuthnError):
        verify(typed(other), jwks_of(k1, k2))


def test_negative_leeway_is_config_error(key):
    with pytest.raises(ConfigError, match="leeway must not be negative"):
        verify(typed(key), key, leeway=-1)


def test_excessive_leeway_is_config_error(key):
    with pytest.raises(ConfigError):
        verify(typed(key), key, leeway=rp.MAX_ID_TOKEN_LEEWAY + 1)
    assert verify(typed(key), key, leeway=rp.MAX_ID_TOKEN_LEEWAY).jarm_verified


@pytest.mark.parametrize("field", ["issuer", "client_id"])
def test_empty_issuer_or_client_id_is_config_error(key, field):
    with pytest.raises(ConfigError, match=f"{field} must not be empty"):
        verify(typed(key), key, **{field: ""})


@pytest.mark.parametrize("typ", ["", "  "])
def test_empty_or_blank_typ_is_config_error(key, typ):
    with pytest.raises(ConfigError, match="typ must not be empty"):
        verify(typed(key), key, typ=typ)


def test_empty_typ_with_untyped_trust_keeps_trust_error(key):
    with pytest.raises(ConfigError, match='typ is only used with trust="typed"'):
        verify(typed(key), key, typ="", trust="dedicated_keys")


class Http:
    def __init__(self, doc):
        self.doc = doc
        self.calls = 0

    def get(self, url):
        self.calls += 1
        return 200, json.dumps(self.doc).encode(), "application/json", []

    def post_form(self, url, form, headers):
        return 404, b"", "text/plain"


def test_cache_hs_refused():
    cache = rp.JwksCache(Http({"keys": []}), JWKS_URI, ISS)
    with pytest.raises(ConfigError) as ei:
        stub("a.b.c").verify_jarm(cache, issuer=ISS, client_id=CLIENT, allowed_algorithms=["HS256"])
    assert ei.value.code == "shared_secret_algorithm"


def test_cache_issuer_mismatch(key):
    http = Http(jwks_of(key))
    cache = rp.JwksCache(http, JWKS_URI, "https://other.example.com")
    with pytest.raises(ConfigError, match="issuer"):
        verify(typed(key), cache)
    assert http.calls == 0


def test_cache_happy_and_kid_refresh():
    k1, k2 = make_key("k1"), make_key("k2")
    http = Http(jwks_of(k1))
    now = [1000.0]
    cache = rp.JwksCache(http, JWKS_URI, ISS, _now=lambda: now[0])
    assert verify(typed(k1), cache).jarm_verified
    assert http.calls == 1
    http.doc = jwks_of(k1, k2)
    now[0] += 31
    assert verify(typed(k2), cache).jarm_verified
    assert http.calls == 2


def test_cache_unknown_kid_after_refresh_is_authn_error():
    k1, k2 = make_key("k1"), make_key("k2")
    http = Http(jwks_of(k1))
    now = [1000.0]
    cache = rp.JwksCache(http, JWKS_URI, ISS, _now=lambda: now[0])
    assert verify(typed(k1), cache).jarm_verified
    now[0] += 31  # refresh allowed, but the OP still lacks k2
    with pytest.raises(AuthnError, match="kid") as ei:
        verify(typed(k2), cache)
    assert not isinstance(ei.value, UnknownKeyError)
    assert ei.value.code == "unknown_kid"
    assert isinstance(ei.value.__cause__, UnknownKeyError)
    assert http.calls == 2


def test_cache_unknown_kid_refresh_skipped_is_authn_error():
    k1, k2 = make_key("k1"), make_key("k2")
    http = Http(jwks_of(k1))
    now = [1000.0]
    cache = rp.JwksCache(http, JWKS_URI, ISS, _now=lambda: now[0])
    assert verify(typed(k1), cache).jarm_verified
    http.doc = jwks_of(k1, k2)  # would resolve, but the refresh is rate limited
    with pytest.raises(AuthnError, match="kid") as ei:
        verify(typed(k2), cache)  # clock not advanced past the minimum refresh interval
    assert not isinstance(ei.value, UnknownKeyError)
    assert ei.value.code == "unknown_kid"
    assert isinstance(ei.value.__cause__, UnknownKeyError)
    assert http.calls == 1


def test_cache_other_errors_not_converted(key):
    http = Http(jwks_of(key))
    cache = rp.JwksCache(http, JWKS_URI, "https://other.example.com")
    with pytest.raises(ConfigError) as ei:
        verify(typed(key), cache)
    assert not isinstance(ei.value, AuthnError)


def test_cache_fetch_failure_not_converted(key):
    class FailingHttp(Http):
        def get(self, url):
            self.calls += 1
            return 503, b"", "text/plain", []

    http = FailingHttp(jwks_of(key))
    cache = rp.JwksCache(http, JWKS_URI, ISS)
    with pytest.raises(InternalError) as ei:
        verify(typed(key), cache)
    assert not isinstance(ei.value, AuthnError)
    assert ei.value.__cause__ is None or not isinstance(ei.value.__cause__, UnknownKeyError)
    assert http.calls == 1


def error_token(key, **over):
    return typed(key, code=None, state="st", error="access_denied", **over)


def test_error_response(key):
    r = verify(error_token(key, error_description="user said no", error_uri="https://op.example.com/e"), key)
    assert r.is_error and r.error == "access_denied" and r.code is None
    assert r.error_description_safe == "user said no"
    assert r.error_uri == "https://op.example.com/e"
    assert r.jarm_verified


def test_error_uri_fragment_filtered(key):
    r = verify(error_token(key, error_uri="https://op.example.com/e#frag"), key)
    assert r.error_uri is None


def test_error_description_uses_our_escaper(key):
    r = verify(error_token(key, error_description="a\x1b[31mred\x1b[0m b\\n \u202eevil"), key)
    d = r.error_description_safe
    assert d is not None
    assert "\x1b" not in d and "\u202e" not in d
    assert "\\x1b" in d or "\\u" in d  # escaped, not dropped
    # Our escaper's output for the same text, via a plain (non-JARM) callback.
    plain = rp.parse_authorization_response(
        [("error", "access_denied"), ("error_description", "a\x1b[31mred\x1b[0m b\\n \u202eevil")]
    )
    assert d == plain.error_description_safe


def test_error_description_capped_and_absent(key):
    r = verify(error_token(key, error_description="x" * 1000), key)
    assert r.error_description_safe is not None and len(r.error_description_safe) <= 256 + 3
    assert verify(error_token(key), key).error_description_safe is None
    assert verify(typed(key), key).error_description_safe is None


def test_repr_hides_secrets(key):
    r = verify(typed(key), key)
    text = repr(r)
    assert "the-code" not in text and "st'" not in text
