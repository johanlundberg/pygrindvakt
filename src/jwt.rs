//! Bindings for `grindvakt::jwt` - thin JWS sign/verify helpers over jose-rs.
//!
//! Claims and headers cross the boundary as dicts. `Validation` is a small
//! builder mirroring `jose_rs::jwt::Validation`.

use pyo3::prelude::*;
use pyo3::types::{PyModule, PyString};

use grindvakt::jose_rs::algorithm::JwsAlgorithm;
use grindvakt::jose_rs::jwk::{Jwk, JwkSet};
use grindvakt::jose_rs::jwt::{Claims, Validation as RsValidation};
use grindvakt::jwt as gj;

use crate::convert::{from_py, new_submodule, to_py, warn};
use crate::errors::{config_err, crypto_err, err, with_code};
use crate::keys::SigningKey;

/// JWT validation rules. Every `with_*` / `require_*` method returns a new
/// `Validation`, so calls can be chained.
#[pyclass(
    module = "pygrindvakt.jwt",
    name = "Validation",
    frozen,
    from_py_object
)]
#[derive(Clone)]
pub struct Validation {
    pub inner: RsValidation,
}

#[pymethods]
impl Validation {
    #[new]
    fn new() -> Self {
        Self {
            inner: RsValidation::new(),
        }
    }
    /// Require `iss` to equal `issuer`.
    fn with_issuer(&self, issuer: String) -> Self {
        Self {
            inner: self.inner.clone().with_issuer(issuer),
        }
    }
    /// Require `aud` to contain `audience`.
    fn with_audience(&self, audience: String) -> Self {
        Self {
            inner: self.inner.clone().with_audience(audience),
        }
    }
    /// Require `sub` to equal `subject`.
    fn with_subject(&self, subject: String) -> Self {
        Self {
            inner: self.inner.clone().with_subject(subject),
        }
    }
    /// Clock-skew leeway in seconds for `exp` / `nbf` / `iat`.
    fn with_leeway(&self, seconds: u64) -> Self {
        Self {
            inner: self.inner.clone().with_leeway(seconds),
        }
    }
    /// Require the protected header `typ` to equal `typ` (RFC 8725 section 3.11).
    fn with_typ(&self, typ: String) -> Self {
        Self {
            inner: self.inner.clone().with_typ(typ),
        }
    }
    /// Reject tokens whose `iat` is older than `seconds` (also requires `iat`).
    fn with_max_age(&self, seconds: u64) -> Self {
        Self {
            inner: self.inner.clone().with_max_age(seconds),
        }
    }
    /// Restrict the accepted header `alg` values, e.g. `["ES256", "RS256"]`.
    fn with_allowed_algorithms(&self, algs: Vec<String>) -> PyResult<Self> {
        let parsed = algs
            .iter()
            .map(|a| {
                JwsAlgorithm::from_str(a).map_err(|e| crypto_err(format!("bad algorithm {a}: {e}")))
            })
            .collect::<PyResult<Vec<_>>>()?;
        Ok(Self {
            inner: self.inner.clone().with_allowed_algorithms(parsed),
        })
    }
    fn require_exp(&self) -> Self {
        Self {
            inner: self.inner.clone().require_exp(),
        }
    }
    fn require_nbf(&self) -> Self {
        Self {
            inner: self.inner.clone().require_nbf(),
        }
    }
    fn require_iat(&self) -> Self {
        Self {
            inner: self.inner.clone().require_iat(),
        }
    }
    fn require_kid(&self) -> Self {
        Self {
            inner: self.inner.clone().require_kid(),
        }
    }
    fn __repr__(&self) -> String {
        format!("Validation({:?})", self.inner)
    }
}

pub fn claims_from_py(obj: &Bound<'_, PyAny>) -> PyResult<Claims> {
    from_py(obj)
}

pub fn jwks_from_py(obj: &Bound<'_, PyAny>) -> PyResult<JwkSet> {
    from_py(obj)
}

/// The algorithms a `Validation` accepts for the shared-secret gate: its
/// allow-list, or every HMAC algorithm when it has none (no restriction).
fn validation_algorithms(validation: &Validation) -> Vec<JwsAlgorithm> {
    if validation.inner.allowed_algorithms.is_empty() {
        vec![
            JwsAlgorithm::HS256,
            JwsAlgorithm::HS384,
            JwsAlgorithm::HS512,
        ]
    } else {
        validation.inner.allowed_algorithms.clone()
    }
}

/// RFC 7518 section 3.2: the minimum key length in bytes for an HMAC `alg`,
/// `None` for any other algorithm. Single source for "is a MAC algorithm".
pub(crate) fn mac_min_key_bytes(alg: JwsAlgorithm) -> Option<usize> {
    match alg {
        JwsAlgorithm::HS256 => Some(32),
        JwsAlgorithm::HS384 => Some(48),
        JwsAlgorithm::HS512 => Some(64),
        _ => None,
    }
}

/// `HS256` / `HS384` / `HS512`.
pub(crate) fn is_mac(alg: JwsAlgorithm) -> bool {
    mac_min_key_bytes(alg).is_some()
}

/// A JWK of type `oct` (symmetric); `kty` is matched case-insensitively.
pub(crate) fn is_oct_key(k: &grindvakt::jose_rs::jwk::Jwk) -> bool {
    k.kty.eq_ignore_ascii_case("oct")
}

/// Consumer-side oct policy: drop every symmetric (`oct`) key from a key set
/// that was fetched from, or supplied as, a published JWK Set, and warn once
/// per call if any was dropped. `subject` names the set in the warning
/// ("<subject> contains a symmetric (oct) key, ignored: <reason>").
pub(crate) fn drop_oct_keys(
    py: Python<'_>,
    mut jwks: JwkSet,
    subject: &str,
    reason: &str,
) -> JwkSet {
    let before = jwks.keys.len();
    jwks.keys.retain(|k| !is_oct_key(k));
    if jwks.keys.len() != before {
        warn(
            py,
            &format!("{subject} contains a symmetric (oct) key, ignored: {reason}"),
        );
    }
    jwks
}

/// Publisher-side oct policy: warn (never drop or refuse) when a key set about
/// to be published contains a symmetric (`oct`) key. `what` names the
/// publishing call, e.g. "Provider.jwks_document()".
pub(crate) fn warn_if_publishing_oct(py: Python<'_>, jwks: &JwkSet, what: &str, tail: &str) {
    if jwks.keys.iter().any(is_oct_key) {
        warn(
            py,
            &format!("{what} is publishing a symmetric (oct) key: {tail}"),
        );
    }
}

/// Byte length of an `oct` key's `k` (unpadded base64url), or `None` if `k`
/// is not strictly that: any character outside `[A-Za-z0-9_-]` (padding,
/// whitespace, `+`, `/`) or a length of 1 mod 4 makes it invalid.
pub(crate) fn oct_key_len(k: &str) -> Option<usize> {
    let n = k.len();
    if n % 4 == 1
        || !k
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    Some(n * 6 / 8)
}

/// How the verifier that follows the shared-secret gate picks its key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeySelection {
    /// `decode_with_jwk`: the one key is used whatever the token's `kid` says.
    Single,
    /// `decode_with_jwkset` (jose-rs): the first key with the token's `kid`;
    /// an unmatched `kid` is an error unless no key has a `kid` at all; no
    /// `kid` tries every key, unless `require_kid` refuses such tokens.
    Jose { require_kid: bool },
    /// The rp checks (`verify_id_token`, signed userinfo): the token's `kid`
    /// must name a key, and a token without one needs a one-key set.
    Named,
}

/// For a caller-built key set verifying an HS* token (`token`'s header `alg`
/// is an allowed HMAC algorithm): refuse an `oct` key shorter than the hash
/// output (RFC 7518 section 3.2) with `ConfigError(code="weak_shared_secret")`,
/// and pin `alg` on unpinned `oct` keys to the token's algorithm. Without the
/// pin jose-rs guesses the key type from its length, rejects a 32-byte
/// secret as an AES key and applies no per-algorithm minimum.
///
/// Only the keys the verifier can use for this token are looked at, chosen
/// as `selection` describes (the token header is untrusted, so a key the
/// token cannot select never raises). Of those, only `oct` keys usable for
/// HMAC verification with the token's algorithm (`alg` absent or equal, `use`
/// absent or `sig`, `key_ops` absent or with `verify`) are checked and
/// pinned; everything else is left to the verifier's own error. `k` must be
/// strict unpadded base64url, else `weak_shared_secret` ("invalid oct key
/// material"). Any other token or key set is returned unchanged.
pub(crate) fn prepare_mac_keys<'a>(
    py: Python<'_>,
    jwks: &'a JwkSet,
    token: &str,
    allowed: &[JwsAlgorithm],
    selection: KeySelection,
) -> PyResult<std::borrow::Cow<'a, JwkSet>> {
    use std::borrow::Cow;
    let Ok(header) = gj::peek_header(token) else {
        return Ok(Cow::Borrowed(jwks));
    };
    let Some(alg) = JwsAlgorithm::from_str(&header.alg)
        .ok()
        .filter(|a| is_mac(*a) && allowed.contains(a))
    else {
        return Ok(Cow::Borrowed(jwks));
    };
    let Some(min) = mac_min_key_bytes(alg) else {
        return Ok(Cow::Borrowed(jwks));
    };
    let compatible = |k: &grindvakt::jose_rs::jwk::Jwk| {
        is_oct_key(k)
            && k.alg.as_deref().is_none_or(|a| a == header.alg)
            && k.use_.as_deref().is_none_or(|u| u == "sig")
            && k.key_ops
                .as_ref()
                .is_none_or(|ops| ops.iter().any(|o| o == "verify"))
    };
    let all = || (0..jwks.keys.len()).collect::<Vec<_>>();
    // Indices of the keys the verifier can use for this token.
    let selected: Vec<usize> = if selection == KeySelection::Single {
        all()
    } else {
        match (&header.kid, selection) {
            (Some(kid), _) => match jwks
                .keys
                .iter()
                .position(|k| k.kid.as_deref() == Some(kid.as_str()))
            {
                Some(i) => vec![i],
                None if matches!(selection, KeySelection::Jose { .. })
                    && jwks.keys.iter().all(|k| k.kid.is_none()) =>
                {
                    all()
                }
                None => Vec::new(),
            },
            // jose-rs refuses the token before touching a key.
            (None, KeySelection::Jose { require_kid: true }) => Vec::new(),
            (None, KeySelection::Jose { .. }) => all(),
            (None, _) if jwks.keys.len() == 1 => all(),
            (None, _) => Vec::new(),
        }
    };
    let candidates: Vec<usize> = selected
        .into_iter()
        .filter(|&i| compatible(&jwks.keys[i]))
        .collect();
    for &i in &candidates {
        // A missing `k` is left to the verifier's own error.
        let Some(k) = jwks.keys[i].k.as_deref() else {
            continue;
        };
        match oct_key_len(k) {
            None => {
                return Err(with_code(
                    py,
                    config_err("invalid oct key material: k must be unpadded base64url"),
                    "weak_shared_secret",
                ));
            }
            Some(len) if len < min => {
                return Err(with_code(
                    py,
                    config_err(format!(
                        "{alg} needs a shared secret of at least {min} bytes (RFC 7518 section \
                         3.2); the oct key in the key set is shorter"
                    )),
                    "weak_shared_secret",
                ));
            }
            Some(_) => {}
        }
    }
    if !candidates.iter().any(|&i| jwks.keys[i].alg.is_none()) {
        return Ok(Cow::Borrowed(jwks));
    }
    let mut pinned = jwks.clone();
    for &i in &candidates {
        if pinned.keys[i].alg.is_none() {
            pinned.keys[i].alg = Some(header.alg.clone());
        }
    }
    Ok(Cow::Owned(pinned))
}

fn jose_selection(validation: &Validation) -> KeySelection {
    KeySelection::Jose {
        require_kid: validation.inner.require_kid,
    }
}

/// Sign a claims dict into a compact JWS with `key`, setting `alg`, `kid` and
/// (optionally) a custom `typ` header.
#[pyfunction]
#[pyo3(signature = (key, claims, typ = None))]
fn sign(key: &SigningKey, claims: &Bound<'_, PyAny>, typ: Option<&str>) -> PyResult<String> {
    let claims = claims_from_py(claims)?;
    gj::sign(&key.inner, &claims, typ).map_err(err)
}

/// Verify a compact JWS against a JWKS dict (`{"keys": [...]}`) and return the
/// validated claims as a dict.
#[pyfunction]
fn verify_with_jwks<'py>(
    py: Python<'py>,
    jwks: &Bound<'py, PyAny>,
    token: &str,
    validation: &Validation,
) -> PyResult<Bound<'py, PyAny>> {
    let jwks = jwks_from_py(jwks)?;
    let jwks = prepare_mac_keys(
        py,
        &jwks,
        token,
        &validation_algorithms(validation),
        jose_selection(validation),
    )?;
    let claims = gj::verify_with_jwks(&jwks, token, &validation.inner).map_err(err)?;
    to_py(py, &claims)
}

/// Verify a compact JWS against a single JWK dict.
#[pyfunction]
fn verify_with_jwk<'py>(
    py: Python<'py>,
    jwk: &Bound<'py, PyAny>,
    token: &str,
    validation: &Validation,
) -> PyResult<Bound<'py, PyAny>> {
    let jwk: Jwk = from_py(jwk)?;
    // Run the shared-secret gate on a one-key set, then verify with the
    // (possibly `alg`-pinned) key it returns.
    let set = JwkSet {
        keys: vec![jwk.clone()],
    };
    let set = prepare_mac_keys(
        py,
        &set,
        token,
        &validation_algorithms(validation),
        KeySelection::Single,
    )?;
    let jwk = set.keys.first().unwrap_or(&jwk);
    let claims = gj::verify_with_jwk(jwk, token, &validation.inner).map_err(err)?;
    to_py(py, &claims)
}

/// The protected header of a compact JWS as a dict, WITHOUT verification.
#[pyfunction]
fn peek_header<'py>(py: Python<'py>, token: &str) -> PyResult<Bound<'py, PyAny>> {
    let h = gj::peek_header(token).map_err(err)?;
    to_py(py, &h)
}

/// The claims of a compact JWS as a dict, WITHOUT verifying the signature.
///
/// SECURITY: only for inspection (e.g. reading `iss` to choose a key). Never
/// trust these values.
#[pyfunction]
fn peek_claims_unverified<'py>(py: Python<'py>, token: &str) -> PyResult<Bound<'py, PyAny>> {
    let c = gj::peek_claims_unverified(token).map_err(err)?;
    to_py(py, &c)
}

/// Parse a JWS `alg` name for the OIDC token-hash helpers.
fn token_hash_alg(alg: &str) -> PyResult<JwsAlgorithm> {
    JwsAlgorithm::from_str(alg).map_err(|e| crypto_err(format!("bad algorithm {alg:?}: {e}")))
}

/// Compute the OIDC Core `at_hash` / `c_hash` value for `value`: the left half
/// of the SHA-2 digest matching the JWS `alg` (SHA-256, SHA-384 or SHA-512),
/// base64url-encoded without padding. It also works for `HS256` / `HS384` /
/// `HS512`, which use the same SHA family.
///
/// It only computes the value; it is NOT verification. Compare the result in
/// constant time with the claim yourself (`pygrindvakt.mac.constant_time_eq`
/// on the encoded bytes), or use the `at_hash` / `c_hash` checks of
/// `rp.verify_id_token`. An unknown or unparseable `alg`, and an algorithm
/// with no defined hash (such as `EdDSA`), both raise `CryptoError`.
#[pyfunction]
fn oidc_token_hash(alg: &str, value: &str) -> PyResult<String> {
    gj::oidc_token_hash(token_hash_alg(alg)?, value).map_err(err)
}

/// Whether OIDC Core defines a token-hash function for the JWS `alg`, i.e.
/// whether `oidc_token_hash` succeeds for it. `False` for `EdDSA` and for an
/// unrecognised `alg` name (it is a predicate and never raises for a `str`).
///
/// Takes the Python `str` itself rather than `&str`: a lone surrogate (for
/// example from decoding JSON `"\ud800"`) cannot become UTF-8, so the
/// argument conversion would raise before this runs. Such a name is simply
/// unrecognised.
#[pyfunction]
fn supports_oidc_token_hash(alg: &Bound<'_, PyString>) -> bool {
    alg.to_cow()
        .is_ok_and(|a| JwsAlgorithm::from_str(&a).is_ok_and(gj::supports_oidc_token_hash))
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = new_submodule(py, parent, "jwt")?;
    m.add_class::<Validation>()?;
    m.add_function(wrap_pyfunction!(sign, &m)?)?;
    m.add_function(wrap_pyfunction!(verify_with_jwks, &m)?)?;
    m.add_function(wrap_pyfunction!(verify_with_jwk, &m)?)?;
    m.add_function(wrap_pyfunction!(peek_header, &m)?)?;
    m.add_function(wrap_pyfunction!(peek_claims_unverified, &m)?)?;
    m.add_function(wrap_pyfunction!(oidc_token_hash, &m)?)?;
    m.add_function(wrap_pyfunction!(supports_oidc_token_hash, &m)?)?;
    Ok(())
}
