//! Bindings for `grindvakt::metadata` - the OpenID Provider discovery document.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyModule;

use grindvakt::metadata as gm;

use crate::convert::{from_py, new_submodule, to_py};

const RESERVED_METADATA_FIELDS: &[&str] = &[
    "issuer",
    "authorization_endpoint",
    "token_endpoint",
    "userinfo_endpoint",
    "jwks_uri",
    "registration_endpoint",
    "scopes_supported",
    "response_types_supported",
    "response_modes_supported",
    "grant_types_supported",
    "subject_types_supported",
    "id_token_signing_alg_values_supported",
    "token_endpoint_auth_methods_supported",
    "claims_supported",
    "code_challenge_methods_supported",
    "claims_parameter_supported",
    "request_parameter_supported",
    "dpop_signing_alg_values_supported",
    // Logout is not implemented by this library, so it must not be advertised
    // as though Provider supplied and validated it.
    "end_session_endpoint",
];

fn validate_extra_keys(extra: &serde_json::Map<String, serde_json::Value>) -> PyResult<()> {
    if let Some(key) = extra
        .keys()
        .find(|key| RESERVED_METADATA_FIELDS.contains(&key.as_str()))
    {
        return Err(PyValueError::new_err(format!(
            "metadata extra field {key:?} is reserved or unsupported"
        )));
    }
    Ok(())
}

/// OpenID Provider metadata (the `/.well-known/openid-configuration` document).
///
/// `ProviderMetadata(issuer, base)` fills in the standard endpoints under
/// `base` (`/authorization`, `/token`, `/userinfo`, `/jwks`) and sensible
/// defaults; every field is settable. Unknown / extension fields live in
/// `extra`.
#[pyclass(
    module = "pygrindvakt.metadata",
    name = "ProviderMetadata",
    from_py_object
)]
#[derive(Clone)]
pub struct ProviderMetadata {
    pub inner: gm::ProviderMetadata,
}

impl ProviderMetadata {
    pub fn wrap(inner: gm::ProviderMetadata) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl ProviderMetadata {
    #[new]
    #[pyo3(signature = (issuer, base = None))]
    fn new(issuer: String, base: Option<String>) -> Self {
        let base = base.unwrap_or_else(|| issuer.clone());
        Self {
            inner: gm::ProviderMetadata::new(issuer, &base),
        }
    }

    /// Build from a discovery-document dict.
    #[staticmethod]
    fn from_dict(d: &Bound<'_, PyAny>) -> PyResult<Self> {
        let inner: gm::ProviderMetadata = from_py(d)
            .map_err(|e| PyValueError::new_err(format!("invalid ProviderMetadata: {e}")))?;
        validate_extra_keys(&inner.extra)?;
        Ok(Self { inner })
    }

    /// The discovery document as a dict.
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        to_py(py, &self.inner)
    }

    #[getter]
    fn issuer(&self) -> &str {
        &self.inner.issuer
    }
    #[setter]
    fn set_issuer(&mut self, v: String) {
        self.inner.issuer = v;
    }
    #[getter]
    fn authorization_endpoint(&self) -> &str {
        &self.inner.authorization_endpoint
    }
    #[setter]
    fn set_authorization_endpoint(&mut self, v: String) {
        self.inner.authorization_endpoint = v;
    }
    #[getter]
    fn token_endpoint(&self) -> &str {
        &self.inner.token_endpoint
    }
    #[setter]
    fn set_token_endpoint(&mut self, v: String) {
        self.inner.token_endpoint = v;
    }
    #[getter]
    fn userinfo_endpoint(&self) -> &str {
        &self.inner.userinfo_endpoint
    }
    #[setter]
    fn set_userinfo_endpoint(&mut self, v: String) {
        self.inner.userinfo_endpoint = v;
    }
    #[getter]
    fn jwks_uri(&self) -> &str {
        &self.inner.jwks_uri
    }
    #[setter]
    fn set_jwks_uri(&mut self, v: String) {
        self.inner.jwks_uri = v;
    }

    #[getter]
    fn registration_endpoint(&self) -> Option<&str> {
        self.inner.registration_endpoint.as_deref()
    }
    #[setter]
    fn set_registration_endpoint(&mut self, v: Option<String>) {
        self.inner.registration_endpoint = v;
    }

    #[getter]
    fn scopes_supported(&self) -> Vec<String> {
        self.inner.scopes_supported.clone()
    }
    #[setter]
    fn set_scopes_supported(&mut self, v: Vec<String>) {
        self.inner.scopes_supported = v;
    }
    #[getter]
    fn response_types_supported(&self) -> Vec<String> {
        self.inner.response_types_supported.clone()
    }
    #[setter]
    fn set_response_types_supported(&mut self, v: Vec<String>) {
        self.inner.response_types_supported = v;
    }
    #[getter]
    fn response_modes_supported(&self) -> Vec<String> {
        self.inner.response_modes_supported.clone()
    }
    #[setter]
    fn set_response_modes_supported(&mut self, v: Vec<String>) {
        self.inner.response_modes_supported = v;
    }
    #[getter]
    fn grant_types_supported(&self) -> Vec<String> {
        self.inner.grant_types_supported.clone()
    }
    #[setter]
    fn set_grant_types_supported(&mut self, v: Vec<String>) {
        self.inner.grant_types_supported = v;
    }
    #[getter]
    fn subject_types_supported(&self) -> Vec<String> {
        self.inner.subject_types_supported.clone()
    }
    #[setter]
    fn set_subject_types_supported(&mut self, v: Vec<String>) {
        self.inner.subject_types_supported = v;
    }
    #[getter]
    fn id_token_signing_alg_values_supported(&self) -> Vec<String> {
        self.inner.id_token_signing_alg_values_supported.clone()
    }
    #[setter]
    fn set_id_token_signing_alg_values_supported(&mut self, v: Vec<String>) {
        self.inner.id_token_signing_alg_values_supported = v;
    }
    #[getter]
    fn token_endpoint_auth_methods_supported(&self) -> Vec<String> {
        self.inner.token_endpoint_auth_methods_supported.clone()
    }
    #[setter]
    fn set_token_endpoint_auth_methods_supported(&mut self, v: Vec<String>) {
        self.inner.token_endpoint_auth_methods_supported = v;
    }
    #[getter]
    fn claims_supported(&self) -> Vec<String> {
        self.inner.claims_supported.clone()
    }
    #[setter]
    fn set_claims_supported(&mut self, v: Vec<String>) {
        self.inner.claims_supported = v;
    }
    #[getter]
    fn code_challenge_methods_supported(&self) -> Vec<String> {
        self.inner.code_challenge_methods_supported.clone()
    }
    #[setter]
    fn set_code_challenge_methods_supported(&mut self, v: Vec<String>) {
        self.inner.code_challenge_methods_supported = v;
    }
    #[getter]
    fn dpop_signing_alg_values_supported(&self) -> Vec<String> {
        self.inner.dpop_signing_alg_values_supported.clone()
    }
    #[setter]
    fn set_dpop_signing_alg_values_supported(&mut self, v: Vec<String>) {
        self.inner.dpop_signing_alg_values_supported = v;
    }
    #[getter]
    fn claims_parameter_supported(&self) -> bool {
        self.inner.claims_parameter_supported
    }
    #[setter]
    fn set_claims_parameter_supported(&mut self, v: bool) {
        self.inner.claims_parameter_supported = v;
    }
    #[getter]
    fn request_parameter_supported(&self) -> bool {
        self.inner.request_parameter_supported
    }
    #[setter]
    fn set_request_parameter_supported(&mut self, v: bool) {
        self.inner.request_parameter_supported = v;
    }

    /// Extension fields (anything not modelled above) as a dict.
    #[getter]
    fn extra<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        to_py(py, &self.inner.extra)
    }
    #[setter]
    fn set_extra(&mut self, v: &Bound<'_, PyAny>) -> PyResult<()> {
        let extra = from_py(v)?;
        validate_extra_keys(&extra)?;
        self.inner.extra = extra;
        Ok(())
    }
    /// Set one extension field.
    fn set_extra_field(&mut self, key: String, value: &Bound<'_, PyAny>) -> PyResult<()> {
        if RESERVED_METADATA_FIELDS.contains(&key.as_str()) {
            return Err(PyValueError::new_err(format!(
                "metadata extra field {key:?} is reserved or unsupported"
            )));
        }
        let v: serde_json::Value = from_py(value)?;
        self.inner.extra.insert(key, v);
        Ok(())
    }

    fn __repr__(&self) -> String {
        format!(
            "ProviderMetadata(issuer={:?}, token_endpoint={:?})",
            self.inner.issuer, self.inner.token_endpoint
        )
    }
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = new_submodule(py, parent, "metadata")?;
    m.add_class::<ProviderMetadata>()?;
    Ok(())
}
