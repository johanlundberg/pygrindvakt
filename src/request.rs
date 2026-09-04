//! Bindings for `grindvakt::request` - parsed OIDC authorization requests.

use std::collections::BTreeMap;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyModule;

use grindvakt::request as gr;

use crate::convert::{from_py, new_submodule, protocol_parameter_pairs, to_py};
use crate::errors::oauth_err;

/// A parsed OIDC authorization request.
///
/// Build with `AuthorizationRequest.from_params(query_pairs)`, preserving the
/// framework's ordered pairs so duplicate protocol parameters can be rejected.
/// It is JSON round-trippable (`to_dict` / `from_dict`) so applications can
/// stash it in a session between the authorization request and redirect.
#[pyclass(
    module = "pygrindvakt.request",
    name = "AuthorizationRequest",
    frozen,
    from_py_object
)]
#[derive(Clone)]
pub struct AuthorizationRequest {
    pub inner: gr::AuthorizationRequest,
}

impl AuthorizationRequest {
    pub fn wrap(inner: gr::AuthorizationRequest) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl AuthorizationRequest {
    /// Parse ordered `(name, value)` pairs. Mappings are rejected because they
    /// may already have erased duplicates. Raises
    /// `OAuthError(invalid_request)` on duplicates, missing required fields, or
    /// a malformed `claims` value.
    #[staticmethod]
    fn from_params(py: Python<'_>, params: &Bound<'_, PyAny>) -> PyResult<Self> {
        let params = protocol_parameter_pairs(params, "authorization parameters")?;
        gr::AuthorizationRequest::from_pairs(&params)
            .map(Self::wrap)
            .map_err(|e| oauth_err(py, &e))
    }

    #[staticmethod]
    /// Restore a request previously produced by `to_dict`. This is a trusted
    /// application-state API and must not be used to parse an HTTP request.
    fn from_dict(d: &Bound<'_, PyAny>) -> PyResult<Self> {
        let inner: gr::AuthorizationRequest = from_py(d)
            .map_err(|e| PyValueError::new_err(format!("invalid AuthorizationRequest: {e}")))?;
        Ok(Self { inner })
    }

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        to_py(py, &self.inner)
    }

    #[getter]
    fn client_id(&self) -> &str {
        &self.inner.client_id
    }
    #[getter]
    fn redirect_uri(&self) -> &str {
        &self.inner.redirect_uri
    }
    #[getter]
    fn response_type(&self) -> &str {
        &self.inner.response_type
    }
    #[getter]
    fn scope(&self) -> &str {
        &self.inner.scope
    }
    #[getter]
    fn state(&self) -> Option<&str> {
        self.inner.state.as_deref()
    }
    #[getter]
    fn nonce(&self) -> Option<&str> {
        self.inner.nonce.as_deref()
    }
    #[getter]
    fn code_challenge(&self) -> Option<&str> {
        self.inner.code_challenge.as_deref()
    }
    #[getter]
    fn code_challenge_method(&self) -> Option<&str> {
        self.inner.code_challenge_method.as_deref()
    }
    #[getter]
    fn response_mode(&self) -> Option<&str> {
        self.inner.response_mode.as_deref()
    }
    #[getter]
    fn prompt(&self) -> Option<&str> {
        self.inner.prompt.as_deref()
    }
    #[getter]
    fn acr_values(&self) -> Option<&str> {
        self.inner.acr_values.as_deref()
    }
    /// The parsed `claims` request parameter, if present.
    #[getter]
    fn claims<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyAny>>> {
        match &self.inner.claims {
            Some(c) => Ok(Some(to_py(py, c)?)),
            None => Ok(None),
        }
    }
    /// The raw `request` parameter (RFC 9101 request object JWT), if present.
    #[getter]
    fn request_object(&self) -> Option<&str> {
        self.inner.request_object.as_deref()
    }
    /// RFC 8707 resource indicators, preserving repeated values in request
    /// order. The application must enforce resource policy before minting.
    #[getter]
    fn resources(&self) -> Vec<String> {
        self.inner.resources.clone()
    }
    /// Other parameters preserved verbatim.
    #[getter]
    fn extra(&self) -> BTreeMap<String, String> {
        self.inner.extra.clone()
    }

    /// The scopes as a list.
    fn scopes(&self) -> Vec<String> {
        self.inner.scopes().into_iter().map(String::from).collect()
    }
    /// True if `scope` contains `openid`.
    fn is_oidc(&self) -> bool {
        self.inner.is_oidc()
    }
    /// Whether `prompt` contains `expected` (exact, case-sensitive).
    fn has_prompt(&self, expected: &str) -> bool {
        self.inner.has_prompt(expected)
    }
    /// Validate the `prompt` combinations OIDC Core constrains.
    fn validate_prompt(&self, py: Python<'_>) -> PyResult<()> {
        self.inner.validate_prompt().map_err(|e| oauth_err(py, &e))
    }
    fn wants_code(&self) -> bool {
        self.inner.wants_code()
    }
    fn wants_id_token(&self) -> bool {
        self.inner.wants_id_token()
    }
    fn wants_access_token(&self) -> bool {
        self.inner.wants_access_token()
    }
    /// True when the response must be returned in the URL fragment.
    fn use_fragment(&self) -> bool {
        self.inner.use_fragment()
    }
    /// Validate that `response_type` is one the OP supports.
    fn validate_response_type(&self, py: Python<'_>) -> PyResult<()> {
        self.inner
            .validate_response_type()
            .map_err(|e| oauth_err(py, &e))
    }
    fn validate_response_mode(&self, py: Python<'_>) -> PyResult<()> {
        self.inner
            .validate_response_mode()
            .map_err(|e| oauth_err(py, &e))
    }

    fn __repr__(&self) -> String {
        format!(
            "AuthorizationRequest(client_id={:?}, response_type={:?}, redirect_uri={:?}, scope={:?})",
            self.inner.client_id, self.inner.response_type, self.inner.redirect_uri, self.inner.scope
        )
    }
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = new_submodule(py, parent, "request")?;
    m.add_class::<AuthorizationRequest>()?;
    Ok(())
}
