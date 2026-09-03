//! Exception hierarchy for pygrindvakt.
//!
//! ```text
//! GrindvaktError(Exception)            status_hint: int (class attribute)
//! ├── BadRequestError (400)            grindvakt::Error::BadRequest
//! ├── AuthnError (401)                 grindvakt::Error::Authn
//! ├── StateError (500)                 grindvakt::Error::State
//! ├── ConfigError (500)                grindvakt::Error::Config
//! ├── CryptoError (500)                grindvakt::Error::Crypto
//! ├── AttributeMappingError (500)      grindvakt::Error::Attribute
//! ├── JoseError (500)                  grindvakt::Error::Jose
//! ├── JsonError (500)                  grindvakt::Error::Json
//! ├── InternalError (500)              grindvakt::Error::Internal
//! ├── NoBoundEndpointError (404)       grindvakt::Error::NoBoundEndpoint
//! ├── UnknownModuleError (404)         grindvakt::Error::UnknownModule
//! ├── OAuthError                       grindvakt::OAuthError (defined in Python,
//! │                                    see python/pygrindvakt/errors.py)
//! └── DpopError                        grindvakt::DpopError
//!     ├── DpopInvalidError
//!     ├── DpopReplayError
//!     ├── DpopNonceRequiredError
//!     └── DpopServerError
//! ```
//!
//! `OAuthError` needs data attributes *and* methods (`to_response()`,
//! `to_redirect()`), and `#[pyclass(extends = PyException)]` is not available
//! under the abi3 limited API below Python 3.12. It is therefore a plain Python
//! class subclassing the native `GrindvaktError`; Rust raises it through a
//! lazily resolved type handle and the rendering is done by the two native
//! helper functions at the bottom of this file.

use std::fmt::Display;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::PyType;
use pyo3::{create_exception, exceptions::PyException};

use grindvakt::OAuthErrorCode;
use grindvakt::{DpopError as RsDpopError, Error as RsError, OAuthError as RsOAuthError};

create_exception!(
    pygrindvakt,
    GrindvaktError,
    PyException,
    "Base class for all pygrindvakt errors."
);
create_exception!(
    pygrindvakt,
    BadRequestError,
    GrindvaktError,
    "The request was malformed."
);
create_exception!(
    pygrindvakt,
    AuthnError,
    GrindvaktError,
    "Authentication failed somewhere in the flow."
);
create_exception!(
    pygrindvakt,
    StateError,
    GrindvaktError,
    "Flow state could not be sealed/unsealed."
);
create_exception!(
    pygrindvakt,
    ConfigError,
    GrindvaktError,
    "Configuration is invalid."
);
create_exception!(
    pygrindvakt,
    CryptoError,
    GrindvaktError,
    "Cryptographic / key-material failure."
);
create_exception!(
    pygrindvakt,
    AttributeMappingError,
    GrindvaktError,
    "Attribute mapping failure."
);
create_exception!(
    pygrindvakt,
    JoseError,
    GrindvaktError,
    "JOSE (JWS/JWE/JWK) error."
);
create_exception!(
    pygrindvakt,
    JsonError,
    GrindvaktError,
    "JSON (de)serialization error."
);
create_exception!(
    pygrindvakt,
    InternalError,
    GrindvaktError,
    "Any other internal error."
);
create_exception!(
    pygrindvakt,
    NoBoundEndpointError,
    GrindvaktError,
    "No endpoint bound to path."
);
create_exception!(
    pygrindvakt,
    UnknownModuleError,
    GrindvaktError,
    "Unknown module."
);

create_exception!(
    pygrindvakt,
    DpopError,
    GrindvaktError,
    "Base class for DPoP proof validation errors."
);
create_exception!(
    pygrindvakt,
    DpopInvalidError,
    DpopError,
    "The DPoP proof is malformed or fails validation."
);
create_exception!(
    pygrindvakt,
    DpopReplayError,
    DpopError,
    "The DPoP proof's jti was already seen."
);
create_exception!(
    pygrindvakt,
    DpopNonceRequiredError,
    DpopError,
    "A server nonce is required; challenge the client with `use_dpop_nonce`."
);
create_exception!(
    pygrindvakt,
    DpopServerError,
    DpopError,
    "The replay store failed; the proof could not be evaluated."
);

/// Map a `grindvakt::Error` onto the typed exception hierarchy.
pub fn err(e: RsError) -> PyErr {
    let msg = e.to_string();
    match e {
        RsError::NoBoundEndpoint(_) => NoBoundEndpointError::new_err(msg),
        RsError::UnknownModule(_) => UnknownModuleError::new_err(msg),
        RsError::BadRequest(_) => BadRequestError::new_err(msg),
        RsError::Authn(_) => AuthnError::new_err(msg),
        RsError::State(_) => StateError::new_err(msg),
        RsError::Config(_) => ConfigError::new_err(msg),
        RsError::Crypto(_) => CryptoError::new_err(msg),
        RsError::Attribute(_) => AttributeMappingError::new_err(msg),
        RsError::Jose(_) => JoseError::new_err(msg),
        RsError::Json(_) => JsonError::new_err(msg),
        RsError::Internal(_) => InternalError::new_err(msg),
    }
}

/// Map a `grindvakt::DpopError` onto the DPoP exception subtree.
pub fn dpop_err(e: RsDpopError) -> PyErr {
    let msg = e.to_string();
    match e {
        RsDpopError::Invalid(_) => DpopInvalidError::new_err(msg),
        RsDpopError::Replay => DpopReplayError::new_err(msg),
        RsDpopError::NonceRequired => DpopNonceRequiredError::new_err(msg),
        RsDpopError::Server(_) => DpopServerError::new_err(msg),
    }
}

/// Generic helpers for errors that only carry a message.
pub fn config_err<E: Display>(e: E) -> PyErr {
    ConfigError::new_err(e.to_string())
}
pub fn crypto_err<E: Display>(e: E) -> PyErr {
    CryptoError::new_err(e.to_string())
}
pub fn internal_err<E: Display>(e: E) -> PyErr {
    InternalError::new_err(e.to_string())
}
pub fn jose_err<E: Display>(e: E) -> PyErr {
    JoseError::new_err(e.to_string())
}

// ---------------------------------------------------------------------------
// OAuthError (Python-defined, raised from Rust)
// ---------------------------------------------------------------------------

static OAUTH_ERROR: PyOnceLock<Py<PyType>> = PyOnceLock::new();

fn oauth_error_type<'py>(py: Python<'py>) -> PyResult<&'py Bound<'py, PyType>> {
    OAUTH_ERROR
        .get_or_try_init(py, || {
            py.import("pygrindvakt.errors")?
                .getattr("OAuthError")?
                .cast_into::<PyType>()
                .map(Bound::unbind)
                .map_err(PyErr::from)
        })
        .map(|t| t.bind(py))
}

/// Raise `pygrindvakt.OAuthError(code, description, state)` for a
/// `grindvakt::OAuthError`.
pub fn oauth_err(py: Python<'_>, e: &RsOAuthError) -> PyErr {
    match oauth_error_type(py)
        .and_then(|t| t.call1((e.code.as_str(), e.description.clone(), e.state.clone())))
    {
        Ok(exc) => PyErr::from_value(exc),
        // The package is broken (errors.py missing); surface that instead.
        Err(import_err) => import_err,
    }
}

/// Inverse of `OAuthErrorCode::as_str` (grindvakt has no `from_str`).
pub fn parse_oauth_code(s: &str) -> PyResult<OAuthErrorCode> {
    use OAuthErrorCode as C;
    Ok(match s {
        "invalid_request" => C::InvalidRequest,
        "invalid_client" => C::InvalidClient,
        "invalid_grant" => C::InvalidGrant,
        "unauthorized_client" => C::UnauthorizedClient,
        "unsupported_grant_type" => C::UnsupportedGrantType,
        "unsupported_response_type" => C::UnsupportedResponseType,
        "invalid_scope" => C::InvalidScope,
        "access_denied" => C::AccessDenied,
        "login_required" => C::LoginRequired,
        "server_error" => C::ServerError,
        "temporarily_unavailable" => C::TemporarilyUnavailable,
        "invalid_dpop_proof" => C::InvalidDpopProof,
        other => {
            return Err(PyValueError::new_err(format!(
                "unknown OAuth error code {other:?}"
            )))
        }
    })
}

pub fn build_oauth_error(
    code: &str,
    description: Option<String>,
    state: Option<String>,
) -> PyResult<RsOAuthError> {
    Ok(RsOAuthError {
        code: parse_oauth_code(code)?,
        description,
        state,
    })
}

/// Render an OAuth error as a direct JSON response (token/userinfo endpoints).
/// Backs `OAuthError.to_response()`.
#[pyfunction]
#[pyo3(signature = (code, description = None, state = None))]
fn oauth_error_response(
    code: &str,
    description: Option<String>,
    state: Option<String>,
) -> PyResult<crate::http::Response> {
    Ok(crate::http::Response::wrap(
        build_oauth_error(code, description, state)?.to_response(),
    ))
}

/// Render an OAuth error as a redirect back to the client (authorization
/// endpoint). Backs `OAuthError.to_redirect(redirect_uri)`.
#[pyfunction]
#[pyo3(signature = (code, redirect_uri, description = None, state = None))]
fn oauth_error_redirect(
    code: &str,
    redirect_uri: &str,
    description: Option<String>,
    state: Option<String>,
) -> PyResult<crate::http::Response> {
    Ok(crate::http::Response::wrap(
        build_oauth_error(code, description, state)?.to_redirect(redirect_uri),
    ))
}

/// HTTP status conventionally paired with an OAuth error code.
#[pyfunction]
fn oauth_error_http_status(code: &str) -> PyResult<u16> {
    Ok(parse_oauth_code(code)?.http_status())
}

/// Register exception types (and the OAuthError helpers) on the top-level module.
pub fn register(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    macro_rules! add {
        ($name:ident, $status:expr) => {{
            let t = py.get_type::<$name>();
            t.setattr("status_hint", $status)?;
            m.add(stringify!($name), t)?;
        }};
    }
    add!(GrindvaktError, 500u16);
    add!(BadRequestError, 400u16);
    add!(AuthnError, 401u16);
    add!(StateError, 500u16);
    add!(ConfigError, 500u16);
    add!(CryptoError, 500u16);
    add!(AttributeMappingError, 500u16);
    add!(JoseError, 500u16);
    add!(JsonError, 500u16);
    add!(InternalError, 500u16);
    add!(NoBoundEndpointError, 404u16);
    add!(UnknownModuleError, 404u16);
    add!(DpopError, 400u16);
    add!(DpopInvalidError, 400u16);
    add!(DpopReplayError, 400u16);
    add!(DpopNonceRequiredError, 400u16);
    add!(DpopServerError, 500u16);

    m.add_function(wrap_pyfunction!(oauth_error_response, m)?)?;
    m.add_function(wrap_pyfunction!(oauth_error_redirect, m)?)?;
    m.add_function(wrap_pyfunction!(oauth_error_http_status, m)?)?;
    Ok(())
}
