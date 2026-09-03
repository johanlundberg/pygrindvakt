//! pygrindvakt - Python bindings for the grindvakt OAuth 2.0 / OpenID Connect /
//! OpenID Federation library.
//!
//! Design invariants (see CLAUDE.md and docs/adr/):
//!
//! * One Rust module per grindvakt module, registered as `pygrindvakt.<name>`.
//! * The Python API is synchronous. grindvakt's `async` calls are driven by a
//!   process-wide tokio runtime with the GIL released (`runtime.rs`).
//! * Python objects may implement the store / http protocols; the adapters fail
//!   closed on any Python exception.
//! * JSON-shaped values cross the boundary as native Python objects.

use pyo3::prelude::*;

mod client;
mod convert;
mod discovery;
mod dpop;
mod errors;
mod federation;
mod http;
mod jwt;
mod keys;
mod metadata;
mod provider;
mod request;
mod rp;
mod runtime;
mod tokens;
mod util;

/// Native extension entry point. Installed as `pygrindvakt._native` and
/// re-exported by the `pygrindvakt` Python package.
#[pymodule]
fn _native(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    errors::register(py, m)?;
    http::register(py, m)?;
    keys::register(py, m)?;
    util::register_util(py, m)?;
    util::register_mac(py, m)?;
    util::register_pkce(py, m)?;
    jwt::register(py, m)?;
    client::register(py, m)?;
    metadata::register(py, m)?;
    request::register(py, m)?;
    tokens::register(py, m)?;
    dpop::register(py, m)?;
    provider::register(py, m)?;
    rp::register(py, m)?;
    federation::register(py, m)?;
    discovery::register(py, m)?;
    Ok(())
}
