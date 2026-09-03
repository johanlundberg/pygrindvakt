//! Bindings for `grindvakt::jwt` - thin JWS sign/verify helpers over jose-rs.
//!
//! Claims and headers cross the boundary as dicts. `Validation` is a small
//! builder mirroring `jose_rs::jwt::Validation`.

use pyo3::prelude::*;
use pyo3::types::PyModule;

use grindvakt::jose_rs::algorithm::JwsAlgorithm;
use grindvakt::jose_rs::jwk::{Jwk, JwkSet};
use grindvakt::jose_rs::jwt::{Claims, Validation as RsValidation};
use grindvakt::jwt as gj;

use crate::convert::{from_py, new_submodule, to_py};
use crate::errors::{crypto_err, err};
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
    let claims = gj::verify_with_jwk(&jwk, token, &validation.inner).map_err(err)?;
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

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = new_submodule(py, parent, "jwt")?;
    m.add_class::<Validation>()?;
    m.add_function(wrap_pyfunction!(sign, &m)?)?;
    m.add_function(wrap_pyfunction!(verify_with_jwks, &m)?)?;
    m.add_function(wrap_pyfunction!(verify_with_jwk, &m)?)?;
    m.add_function(wrap_pyfunction!(peek_header, &m)?)?;
    m.add_function(wrap_pyfunction!(peek_claims_unverified, &m)?)?;
    Ok(())
}
