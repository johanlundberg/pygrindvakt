//! Bindings for `grindvakt::util`, `grindvakt::mac` and `grindvakt::pkce` -
//! small helpers registered as three submodules.

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

use crate::convert::new_submodule;

// --- util -------------------------------------------------------------------

/// Current Unix time in seconds.
#[pyfunction]
fn now_secs() -> u64 {
    grindvakt::util::now_secs()
}

/// RFC 3339 timestamp for "now" (UTC).
#[pyfunction]
fn now_rfc3339() -> String {
    grindvakt::util::now_rfc3339()
}

/// A URL-safe random token from `n` bytes of OS entropy (base64url, no padding).
#[pyfunction]
#[pyo3(signature = (n = 32))]
fn random_token(n: usize) -> String {
    grindvakt::util::random_token(n)
}

pub fn register_util(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = new_submodule(py, parent, "util")?;
    m.add_function(wrap_pyfunction!(now_secs, &m)?)?;
    m.add_function(wrap_pyfunction!(now_rfc3339, &m)?)?;
    m.add_function(wrap_pyfunction!(random_token, &m)?)?;
    Ok(())
}

// --- mac --------------------------------------------------------------------

/// HMAC-SHA256 of `data` under `key`.
#[pyfunction]
fn hmac_sha256<'py>(py: Python<'py>, key: &[u8], data: &[u8]) -> Bound<'py, PyBytes> {
    PyBytes::new(py, &grindvakt::mac::hmac_sha256(key, data))
}

/// SHA-256 digest of `data`.
#[pyfunction]
fn sha256<'py>(py: Python<'py>, data: &[u8]) -> Bound<'py, PyBytes> {
    PyBytes::new(py, &grindvakt::mac::sha256(data))
}

/// Constant-time byte-string equality.
#[pyfunction]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    grindvakt::mac::constant_time_eq(a, b)
}

pub fn register_mac(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = new_submodule(py, parent, "mac")?;
    m.add_function(wrap_pyfunction!(hmac_sha256, &m)?)?;
    m.add_function(wrap_pyfunction!(sha256, &m)?)?;
    m.add_function(wrap_pyfunction!(constant_time_eq, &m)?)?;
    Ok(())
}

// --- pkce -------------------------------------------------------------------

/// The `S256` code challenge for a PKCE verifier (RFC 7636).
#[pyfunction]
fn s256_challenge(verifier: &str) -> String {
    grindvakt::pkce::s256_challenge(verifier)
}

/// Verify a PKCE verifier against a challenge. `method` is `"S256"` or
/// `"plain"`; per RFC 7636 section 4.3 a missing method means `plain`.
#[pyfunction]
#[pyo3(signature = (verifier, challenge, method = None))]
fn verify(verifier: &str, challenge: &str, method: Option<&str>) -> bool {
    grindvakt::pkce::verify(verifier, challenge, method)
}

pub fn register_pkce(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = new_submodule(py, parent, "pkce")?;
    m.add_function(wrap_pyfunction!(s256_challenge, &m)?)?;
    m.add_function(wrap_pyfunction!(verify, &m)?)?;
    Ok(())
}
