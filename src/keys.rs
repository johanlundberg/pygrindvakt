//! Bindings for `grindvakt::keys` - signing-key loading (PEM/DER, JWK, PKCS#11).
//!
//! A `SigningKey` is opaque: the private material never crosses into Python.
//! Only the algorithm, key id, and the public JWK / JWKS are exposed.

use std::path::PathBuf;

use pyo3::prelude::*;
use pyo3::types::PyModule;

use grindvakt::jose_rs::algorithm::JwsAlgorithm;
use grindvakt::jose_rs::jwk;
use grindvakt::keys as gk;

use crate::convert::{from_py, new_submodule, to_py};
use crate::errors::{crypto_err, err, jose_err};

/// A loaded signing key (software or HSM-backed). Immutable and cheap to clone;
/// the private material is never exposed to Python.
#[pyclass(
    module = "pygrindvakt.keys",
    name = "SigningKey",
    frozen,
    from_py_object
)]
#[derive(Clone)]
pub struct SigningKey {
    pub inner: gk::SigningKey,
}

impl SigningKey {
    pub fn wrap(inner: gk::SigningKey) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl SigningKey {
    /// The JWS algorithm this key signs with, e.g. `"ES256"`.
    #[getter]
    fn alg(&self) -> &'static str {
        self.inner.alg().as_str()
    }
    /// The key id published in JWKS / JWT headers, if any.
    #[getter]
    fn kid(&self) -> Option<&str> {
        self.inner.kid()
    }
    /// The public JWK (no private components) as a dict.
    fn public_jwk<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        to_py(py, &self.inner.public_jwk())
    }
    /// A one-key JWKS document (`{"keys": [...]}`) as a dict.
    fn to_public_jwks<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        to_py(py, &self.inner.to_public_jwks())
    }
    fn __repr__(&self) -> String {
        format!(
            "SigningKey(alg={:?}, kid={:?})",
            self.inner.alg().as_str(),
            self.inner.kid()
        )
    }
}

/// Load a signing key from PEM (or DER) bytes: PKCS#8, PKCS#1 or SEC1.
///
/// `alg` overrides the algorithm inferred from the key type; `kid` sets the
/// published key id.
#[pyfunction]
#[pyo3(signature = (data, alg = None, kid = None))]
fn signing_key_from_pem(data: &[u8], alg: Option<&str>, kid: Option<&str>) -> PyResult<SigningKey> {
    gk::signing_key_from_pem(data, alg, kid)
        .map(SigningKey::wrap)
        .map_err(err)
}

/// Load a signing key from a private JWK given as a JSON string.
#[pyfunction]
#[pyo3(signature = (json, alg = None, kid = None))]
fn signing_key_from_jwk_json(
    json: &str,
    alg: Option<&str>,
    kid: Option<&str>,
) -> PyResult<SigningKey> {
    gk::signing_key_from_jwk_json(json, alg, kid)
        .map(SigningKey::wrap)
        .map_err(err)
}

/// Load a signing key from a private JWK given as a dict.
#[pyfunction]
#[pyo3(signature = (jwk, alg = None, kid = None))]
fn signing_key_from_jwk(
    jwk: &Bound<'_, PyAny>,
    alg: Option<&str>,
    kid: Option<&str>,
) -> PyResult<SigningKey> {
    let v: serde_json::Value = from_py(jwk)?;
    let json = serde_json::to_string(&v).map_err(jose_err)?;
    gk::signing_key_from_jwk_json(&json, alg, kid)
        .map(SigningKey::wrap)
        .map_err(err)
}

/// Load a signing key whose private material lives on a PKCS#11 token
/// (SoftHSM2, Kryoptic, a hardware HSM).
///
/// `module_path` is the PKCS#11 shared library; `key_label` is the `CKA_LABEL`
/// of the key pair; `alg` is the JWS algorithm to sign with (e.g. `"ES256"`).
///
/// SECURITY: `pin` is a Python `str` and cannot be zeroized after use.
#[pyfunction]
#[pyo3(signature = (module_path, pin, key_label, alg, kid = None))]
fn signing_key_from_pkcs11(
    module_path: PathBuf,
    pin: String,
    key_label: String,
    alg: &str,
    kid: Option<String>,
) -> PyResult<SigningKey> {
    let alg = JwsAlgorithm::from_str(alg)
        .map_err(|e| crypto_err(format!("bad signing algorithm {alg}: {e}")))?;
    let cfg = gk::Pkcs11KeyConfig {
        module_path,
        pin,
        key_label,
        alg,
        kid,
    };
    gk::signing_key_from_pkcs11(&cfg)
        .map(SigningKey::wrap)
        .map_err(err)
}

/// Generate a fresh EC private JWK (`"P-256"` or `"P-384"`) as a dict.
/// Intended for tests and bootstrapping; persist the result yourself.
#[pyfunction]
#[pyo3(signature = (curve = "P-256"))]
fn generate_ec_jwk<'py>(py: Python<'py>, curve: &str) -> PyResult<Bound<'py, PyAny>> {
    let k = jwk::generate_ec(curve).map_err(jose_err)?;
    to_py(py, &k)
}

/// Generate a fresh RSA private JWK as a dict (default 2048 bits).
#[pyfunction]
#[pyo3(signature = (bits = 2048))]
fn generate_rsa_jwk<'py>(py: Python<'py>, bits: usize) -> PyResult<Bound<'py, PyAny>> {
    let k = jwk::generate_rsa(bits).map_err(jose_err)?;
    to_py(py, &k)
}

/// Generate a fresh Ed25519 private JWK as a dict.
#[pyfunction]
fn generate_ed25519_jwk<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
    let k = jwk::generate_ed25519().map_err(jose_err)?;
    to_py(py, &k)
}

/// RFC 7638 SHA-256 JWK thumbprint (base64url) of a JWK dict.
#[pyfunction]
fn jwk_thumbprint(jwk: &Bound<'_, PyAny>) -> PyResult<String> {
    let k: jwk::Jwk = from_py(jwk)?;
    jwk::thumbprint::thumbprint_sha256(&k).map_err(jose_err)
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = new_submodule(py, parent, "keys")?;
    m.add_class::<SigningKey>()?;
    m.add_function(wrap_pyfunction!(signing_key_from_pem, &m)?)?;
    m.add_function(wrap_pyfunction!(signing_key_from_jwk_json, &m)?)?;
    m.add_function(wrap_pyfunction!(signing_key_from_jwk, &m)?)?;
    m.add_function(wrap_pyfunction!(signing_key_from_pkcs11, &m)?)?;
    m.add_function(wrap_pyfunction!(generate_ec_jwk, &m)?)?;
    m.add_function(wrap_pyfunction!(generate_rsa_jwk, &m)?)?;
    m.add_function(wrap_pyfunction!(generate_ed25519_jwk, &m)?)?;
    m.add_function(wrap_pyfunction!(jwk_thumbprint, &m)?)?;
    Ok(())
}
