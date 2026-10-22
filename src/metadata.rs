//! Bindings for `grindvakt::metadata` - the OpenID Provider discovery document.

use crate::errors::config_err;
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
];

#[derive(Clone, Copy)]
enum ExtraKind {
    StrList,
    Bool,
    Str,
}

/// Known OIDC extension members stored in `extra` (none is modelled as a
/// struct field upstream). Their JSON type is enforced on every write path.
const KNOWN_EXTRA: &[(&str, ExtraKind)] = &[
    ("acr_values_supported", ExtraKind::StrList),
    ("claim_types_supported", ExtraKind::StrList),
    ("display_values_supported", ExtraKind::StrList),
    ("ui_locales_supported", ExtraKind::StrList),
    ("claims_locales_supported", ExtraKind::StrList),
    ("userinfo_signing_alg_values_supported", ExtraKind::StrList),
    (
        "userinfo_encryption_alg_values_supported",
        ExtraKind::StrList,
    ),
    (
        "userinfo_encryption_enc_values_supported",
        ExtraKind::StrList,
    ),
    (
        "id_token_encryption_alg_values_supported",
        ExtraKind::StrList,
    ),
    (
        "id_token_encryption_enc_values_supported",
        ExtraKind::StrList,
    ),
    (
        "request_object_signing_alg_values_supported",
        ExtraKind::StrList,
    ),
    (
        "token_endpoint_auth_signing_alg_values_supported",
        ExtraKind::StrList,
    ),
    ("request_uri_parameter_supported", ExtraKind::Bool),
    ("require_request_uri_registration", ExtraKind::Bool),
    ("require_pushed_authorization_requests", ExtraKind::Bool),
    ("frontchannel_logout_supported", ExtraKind::Bool),
    ("backchannel_logout_supported", ExtraKind::Bool),
    ("revocation_endpoint", ExtraKind::Str),
    ("introspection_endpoint", ExtraKind::Str),
    ("pushed_authorization_request_endpoint", ExtraKind::Str),
    ("check_session_iframe", ExtraKind::Str),
    ("service_documentation", ExtraKind::Str),
    ("op_policy_uri", ExtraKind::Str),
    ("op_tos_uri", ExtraKind::Str),
    ("end_session_endpoint", ExtraKind::Str),
];

/// Members whose value is an endpoint URL the OP would publish for relying
/// parties to call; these are validated like `end_session_endpoint`.
/// `service_documentation`, `op_policy_uri` and `op_tos_uri` are informational
/// links and stay type-checked only (no public upstream helper for them).
fn is_url_member(key: &str) -> bool {
    key.ends_with("_endpoint") || key == "check_session_iframe"
}

/// Validate an endpoint URL against the metadata's issuer (absolute, https or
/// loopback http, no fragment, no userinfo). Raises `ConfigError`.
fn validate_url_member(key: &str, url: &str, issuer: &str) -> PyResult<()> {
    grindvakt::rp::validate_service_endpoint_for_issuer(key, url, issuer)
        .map_err(|e| config_err(format!("metadata field {key:?}: {e}")))
}

/// Validate the issuer itself (it decides whether loopback http is allowed).
fn validate_issuer_value(issuer: &str) -> PyResult<()> {
    grindvakt::rp::validate_issuer(issuer)
        .map_err(|e| config_err(format!("metadata field \"issuer\": {e}")))
}

/// Validate every modelled URL member of `md` against `issuer`.
fn validate_modelled_urls(md: &gm::ProviderMetadata, issuer: &str) -> PyResult<()> {
    validate_url_member("authorization_endpoint", &md.authorization_endpoint, issuer)?;
    validate_url_member("token_endpoint", &md.token_endpoint, issuer)?;
    validate_url_member("jwks_uri", &md.jwks_uri, issuer)?;
    if let Some(u) = &md.userinfo_endpoint {
        validate_url_member("userinfo_endpoint", u, issuer)?;
    }
    if let Some(u) = &md.registration_endpoint {
        validate_url_member("registration_endpoint", u, issuer)?;
    }
    Ok(())
}

fn known_kind(key: &str) -> Option<ExtraKind> {
    KNOWN_EXTRA
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, kind)| *kind)
}

/// Modelled list members that are kept when `[]` (non-empty spec default, or
/// REQUIRED; see `is_spec_default`) but whose absence upstream cannot represent.
const NONEMPTY_DEFAULT_LISTS: &[&str] = &[
    "response_modes_supported",
    "grant_types_supported",
    "token_endpoint_auth_methods_supported",
    // REQUIRED: an explicit `[]` is kept, but a `[]` the source never had
    // (non-conformant source) is not invented either.
    "response_types_supported",
    "subject_types_supported",
    "id_token_signing_alg_values_supported",
];

/// True when `value` is what an absent `key` means per the specs, so dropping
/// the member loses nothing. Members not listed are never dropped.
///
/// Booleans (OIDC Discovery 1.0 s3, OIDC Front-/Back-Channel Logout, RFC 9126
/// s5): `claims_parameter_supported`, `request_parameter_supported`,
/// `require_request_uri_registration`, `frontchannel_logout_supported`,
/// `backchannel_logout_supported`, `require_pushed_authorization_requests`
/// default to `false`; `request_uri_parameter_supported` defaults to `true`
/// (so `false` is kept).
///
/// Arrays: `[]` is dropped only where the spec states no default, so absent
/// also means "nothing advertised". Kept even when `[]`:
/// - `response_modes_supported` (default `["query","fragment"]`),
///   `grant_types_supported` (default `["authorization_code","implicit"]`),
///   `token_endpoint_auth_methods_supported` (default
///   `["client_secret_basic"]`), `claim_types_supported` (default
///   `["normal"]`): there `[]` means "none supported", not the default.
/// - REQUIRED members (`response_types_supported`,
///   `subject_types_supported`, `id_token_signing_alg_values_supported`):
///   absence would make the document non-conformant.
///
/// `to_dict` additionally drops those (and the required lists) when `[]` and absent
/// from the `raw` source (upstream parses absent as `[]`).
///
/// Unconfirmed defaults are kept: nothing here is guessed.
fn is_spec_default(key: &str, value: &serde_json::Value) -> bool {
    use serde_json::Value;
    if value.is_null() {
        return true;
    }
    match key {
        "claims_parameter_supported"
        | "request_parameter_supported"
        | "require_request_uri_registration"
        | "frontchannel_logout_supported"
        | "backchannel_logout_supported"
        | "require_pushed_authorization_requests" => *value == Value::Bool(false),
        "request_uri_parameter_supported" => *value == Value::Bool(true),
        "scopes_supported"
        | "claims_supported"
        | "code_challenge_methods_supported"
        | "dpop_signing_alg_values_supported"
        | "acr_values_supported"
        | "display_values_supported"
        | "ui_locales_supported"
        | "claims_locales_supported"
        | "userinfo_signing_alg_values_supported"
        | "userinfo_encryption_alg_values_supported"
        | "userinfo_encryption_enc_values_supported"
        | "id_token_encryption_alg_values_supported"
        | "id_token_encryption_enc_values_supported"
        | "request_object_signing_alg_values_supported"
        | "token_endpoint_auth_signing_alg_values_supported" => {
            value.as_array().is_some_and(Vec::is_empty)
        }
        _ => false,
    }
}

/// Check that a known extension member has its documented JSON type.
fn validate_known_value(key: &str, value: &serde_json::Value, issuer: &str) -> PyResult<()> {
    let Some(kind) = known_kind(key) else {
        return Ok(());
    };
    let ok = match kind {
        ExtraKind::StrList => value
            .as_array()
            .is_some_and(|a| a.iter().all(serde_json::Value::is_string)),
        ExtraKind::Bool => value.is_boolean(),
        ExtraKind::Str => value.is_string(),
    };
    if ok {
        if is_url_member(key) {
            if let Some(url) = value.as_str() {
                validate_url_member(key, url, issuer)?;
            }
        }
        return Ok(());
    }
    let want = match kind {
        ExtraKind::StrList => "a list of strings",
        ExtraKind::Bool => "a boolean",
        ExtraKind::Str => "a string",
    };
    Err(config_err(format!("metadata field {key:?} must be {want}")))
}

fn validate_extra_key(key: &str) -> PyResult<()> {
    if RESERVED_METADATA_FIELDS.contains(&key) {
        return Err(config_err(format!(
            "metadata extra field {key:?} is reserved or unsupported"
        )));
    }
    Ok(())
}

/// Validate the `extra` map: no reserved names, known members correctly typed.
fn validate_extra(
    extra: &serde_json::Map<String, serde_json::Value>,
    issuer: &str,
) -> PyResult<()> {
    for (key, value) in extra {
        validate_extra_key(key)?;
        validate_known_value(key, value, issuer)?;
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
    /// The source document, kept as a snapshot (see `raw`).
    pub raw: Option<serde_json::Map<String, serde_json::Value>>,
    /// Non-empty-default list members assigned through a setter after
    /// construction. `exclude_defaults` must not treat an explicit `[]` that the
    /// caller assigned as the absent-in-source parse artefact.
    touched: std::collections::BTreeSet<&'static str>,
}

impl ProviderMetadata {
    pub fn wrap(inner: gm::ProviderMetadata) -> Self {
        Self {
            inner,
            raw: None,
            touched: Default::default(),
        }
    }

    pub fn wrap_with_raw(
        inner: gm::ProviderMetadata,
        raw: serde_json::Map<String, serde_json::Value>,
    ) -> Self {
        Self {
            inner,
            raw: Some(raw),
            touched: Default::default(),
        }
    }

    fn extra_str(&self, key: &str) -> Option<String> {
        self.inner.extra.get(key)?.as_str().map(str::to_owned)
    }

    fn extra_str_list(&self, key: &str) -> Option<Vec<String>> {
        self.inner
            .extra
            .get(key)?
            .as_array()?
            .iter()
            .map(|v| v.as_str().map(str::to_owned))
            .collect()
    }

    /// Set (or, for `None`, remove) a known extension member.
    fn set_known(&mut self, key: &str, v: &Bound<'_, PyAny>) -> PyResult<()> {
        if v.is_none() {
            self.inner.extra.remove(key);
            return Ok(());
        }
        let value: serde_json::Value = from_py(v)?;
        validate_known_value(key, &value, &self.inner.issuer)?;
        self.inner.extra.insert(key.to_string(), value);
        Ok(())
    }
}

#[pymethods]
impl ProviderMetadata {
    #[new]
    #[pyo3(signature = (issuer, base = None))]
    fn new(issuer: String, base: Option<String>) -> PyResult<Self> {
        let base = base.unwrap_or_else(|| issuer.clone());
        validate_issuer_value(&issuer)?;
        let inner = gm::ProviderMetadata::new(issuer, &base);
        validate_modelled_urls(&inner, &inner.issuer).map_err(|e| {
            // Use only the message text, not `BadRequestError: ...`.
            let detail = Python::attach(|py| {
                e.value(py)
                    .str()
                    .map_or_else(|_| e.to_string(), |s| s.to_string())
            });
            config_err(format!(
                "base {base:?} yields an invalid endpoint: {detail}"
            ))
        })?;
        Ok(Self {
            inner,
            raw: None,
            touched: Default::default(),
        })
    }

    /// Build from a discovery-document dict. The source dict is kept
    /// verbatim as `raw`.
    #[staticmethod]
    fn from_dict(d: &Bound<'_, PyAny>) -> PyResult<Self> {
        let raw: serde_json::Map<String, serde_json::Value> = from_py(d)
            .map_err(|e| PyValueError::new_err(format!("invalid ProviderMetadata: {e}")))?;
        let inner: gm::ProviderMetadata =
            serde_json::from_value(serde_json::Value::Object(raw.clone()))
                .map_err(|e| PyValueError::new_err(format!("invalid ProviderMetadata: {e}")))?;
        validate_issuer_value(&inner.issuer)?;
        validate_modelled_urls(&inner, &inner.issuer)?;
        validate_extra(&inner.extra, &inner.issuer)?;
        Ok(Self::wrap_with_raw(inner, raw))
    }

    /// The discovery document as a dict. With `exclude_defaults=True`,
    /// members equal to their OIDC Discovery / RFC 8414 / RFC 9126 default
    /// (see `is_spec_default`) and `None` values are dropped; everything else,
    /// including unknown extras, is kept.
    #[pyo3(signature = (*, exclude_defaults = false))]
    fn to_dict<'py>(&self, py: Python<'py>, exclude_defaults: bool) -> PyResult<Bound<'py, PyAny>> {
        if !exclude_defaults {
            return to_py(py, &self.inner);
        }
        let serde_json::Value::Object(mut doc) = self.inner.to_json() else {
            return Err(PyValueError::new_err("metadata is not an object"));
        };
        doc.retain(|key, value| {
            let known =
                RESERVED_METADATA_FIELDS.contains(&key.as_str()) || known_kind(key).is_some();
            if known && is_spec_default(key, value) {
                return false;
            }
            // The upstream model parses an absent list as `[]`. For members
            // whose spec default is non-empty, a `[]` that the source never
            // contained is that artefact (not "none"), so keep it absent.
            let absent_in_source = NONEMPTY_DEFAULT_LISTS.contains(&key.as_str())
                && value.as_array().is_some_and(Vec::is_empty)
                && !self.touched.contains(key.as_str())
                && self.raw.as_ref().is_some_and(|r| !r.contains_key(key));
            !absent_in_source
        });
        to_py(py, &doc)
    }

    /// The source document this object was built from (`from_dict` input, or
    /// the `rp.discover` response body), as a dict; `None` for objects built
    /// with the constructor. It is a snapshot: setters do not change it.
    #[getter]
    fn raw<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyAny>>> {
        self.raw.as_ref().map(|r| to_py(py, r)).transpose()
    }

    /// The OIDC RP-Initiated Logout `end_session_endpoint` (stored in
    /// `extra`), or `None`. The setter validates the URL against the issuer (`ConfigError`, also a
    /// `ValueError`).
    #[getter]
    fn end_session_endpoint(&self) -> Option<String> {
        self.extra_str("end_session_endpoint")
    }
    #[setter]
    fn set_end_session_endpoint(&mut self, v: Option<String>) -> PyResult<()> {
        match v {
            None => {
                self.inner.extra.remove("end_session_endpoint");
            }
            Some(url) => {
                validate_url_member("end_session_endpoint", &url, &self.inner.issuer)?;
                self.inner
                    .extra
                    .insert("end_session_endpoint".into(), url.into());
            }
        }
        Ok(())
    }

    #[getter]
    fn acr_values_supported(&self) -> Option<Vec<String>> {
        self.extra_str_list("acr_values_supported")
    }
    #[setter]
    fn set_acr_values_supported(&mut self, v: &Bound<'_, PyAny>) -> PyResult<()> {
        self.set_known("acr_values_supported", v)
    }
    #[getter]
    fn claim_types_supported(&self) -> Option<Vec<String>> {
        self.extra_str_list("claim_types_supported")
    }
    #[setter]
    fn set_claim_types_supported(&mut self, v: &Bound<'_, PyAny>) -> PyResult<()> {
        self.set_known("claim_types_supported", v)
    }
    #[getter]
    fn display_values_supported(&self) -> Option<Vec<String>> {
        self.extra_str_list("display_values_supported")
    }
    #[setter]
    fn set_display_values_supported(&mut self, v: &Bound<'_, PyAny>) -> PyResult<()> {
        self.set_known("display_values_supported", v)
    }
    #[getter]
    fn ui_locales_supported(&self) -> Option<Vec<String>> {
        self.extra_str_list("ui_locales_supported")
    }
    #[setter]
    fn set_ui_locales_supported(&mut self, v: &Bound<'_, PyAny>) -> PyResult<()> {
        self.set_known("ui_locales_supported", v)
    }
    #[getter]
    fn claims_locales_supported(&self) -> Option<Vec<String>> {
        self.extra_str_list("claims_locales_supported")
    }
    #[setter]
    fn set_claims_locales_supported(&mut self, v: &Bound<'_, PyAny>) -> PyResult<()> {
        self.set_known("claims_locales_supported", v)
    }
    #[getter]
    fn userinfo_signing_alg_values_supported(&self) -> Option<Vec<String>> {
        self.extra_str_list("userinfo_signing_alg_values_supported")
    }
    #[setter]
    fn set_userinfo_signing_alg_values_supported(&mut self, v: &Bound<'_, PyAny>) -> PyResult<()> {
        self.set_known("userinfo_signing_alg_values_supported", v)
    }
    #[getter]
    fn userinfo_encryption_alg_values_supported(&self) -> Option<Vec<String>> {
        self.extra_str_list("userinfo_encryption_alg_values_supported")
    }
    #[setter]
    fn set_userinfo_encryption_alg_values_supported(
        &mut self,
        v: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        self.set_known("userinfo_encryption_alg_values_supported", v)
    }
    #[getter]
    fn userinfo_encryption_enc_values_supported(&self) -> Option<Vec<String>> {
        self.extra_str_list("userinfo_encryption_enc_values_supported")
    }
    #[setter]
    fn set_userinfo_encryption_enc_values_supported(
        &mut self,
        v: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        self.set_known("userinfo_encryption_enc_values_supported", v)
    }
    #[getter]
    fn id_token_encryption_alg_values_supported(&self) -> Option<Vec<String>> {
        self.extra_str_list("id_token_encryption_alg_values_supported")
    }
    #[setter]
    fn set_id_token_encryption_alg_values_supported(
        &mut self,
        v: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        self.set_known("id_token_encryption_alg_values_supported", v)
    }
    #[getter]
    fn id_token_encryption_enc_values_supported(&self) -> Option<Vec<String>> {
        self.extra_str_list("id_token_encryption_enc_values_supported")
    }
    #[setter]
    fn set_id_token_encryption_enc_values_supported(
        &mut self,
        v: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        self.set_known("id_token_encryption_enc_values_supported", v)
    }
    #[getter]
    fn request_object_signing_alg_values_supported(&self) -> Option<Vec<String>> {
        self.extra_str_list("request_object_signing_alg_values_supported")
    }
    #[setter]
    fn set_request_object_signing_alg_values_supported(
        &mut self,
        v: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        self.set_known("request_object_signing_alg_values_supported", v)
    }
    #[getter]
    fn token_endpoint_auth_signing_alg_values_supported(&self) -> Option<Vec<String>> {
        self.extra_str_list("token_endpoint_auth_signing_alg_values_supported")
    }
    #[setter]
    fn set_token_endpoint_auth_signing_alg_values_supported(
        &mut self,
        v: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        self.set_known("token_endpoint_auth_signing_alg_values_supported", v)
    }
    #[getter]
    fn request_uri_parameter_supported(&self) -> Option<bool> {
        self.inner
            .extra
            .get("request_uri_parameter_supported")
            .and_then(|v| v.as_bool())
    }
    #[setter]
    fn set_request_uri_parameter_supported(&mut self, v: &Bound<'_, PyAny>) -> PyResult<()> {
        self.set_known("request_uri_parameter_supported", v)
    }
    #[getter]
    fn require_request_uri_registration(&self) -> Option<bool> {
        self.inner
            .extra
            .get("require_request_uri_registration")
            .and_then(|v| v.as_bool())
    }
    #[setter]
    fn set_require_request_uri_registration(&mut self, v: &Bound<'_, PyAny>) -> PyResult<()> {
        self.set_known("require_request_uri_registration", v)
    }
    #[getter]
    fn require_pushed_authorization_requests(&self) -> Option<bool> {
        self.inner
            .extra
            .get("require_pushed_authorization_requests")
            .and_then(|v| v.as_bool())
    }
    #[setter]
    fn set_require_pushed_authorization_requests(&mut self, v: &Bound<'_, PyAny>) -> PyResult<()> {
        self.set_known("require_pushed_authorization_requests", v)
    }
    #[getter]
    fn frontchannel_logout_supported(&self) -> Option<bool> {
        self.inner
            .extra
            .get("frontchannel_logout_supported")
            .and_then(|v| v.as_bool())
    }
    #[setter]
    fn set_frontchannel_logout_supported(&mut self, v: &Bound<'_, PyAny>) -> PyResult<()> {
        self.set_known("frontchannel_logout_supported", v)
    }
    #[getter]
    fn backchannel_logout_supported(&self) -> Option<bool> {
        self.inner
            .extra
            .get("backchannel_logout_supported")
            .and_then(|v| v.as_bool())
    }
    #[setter]
    fn set_backchannel_logout_supported(&mut self, v: &Bound<'_, PyAny>) -> PyResult<()> {
        self.set_known("backchannel_logout_supported", v)
    }
    #[getter]
    fn revocation_endpoint(&self) -> Option<String> {
        self.extra_str("revocation_endpoint")
    }
    #[setter]
    fn set_revocation_endpoint(&mut self, v: &Bound<'_, PyAny>) -> PyResult<()> {
        self.set_known("revocation_endpoint", v)
    }
    #[getter]
    fn introspection_endpoint(&self) -> Option<String> {
        self.extra_str("introspection_endpoint")
    }
    #[setter]
    fn set_introspection_endpoint(&mut self, v: &Bound<'_, PyAny>) -> PyResult<()> {
        self.set_known("introspection_endpoint", v)
    }
    #[getter]
    fn pushed_authorization_request_endpoint(&self) -> Option<String> {
        self.extra_str("pushed_authorization_request_endpoint")
    }
    #[setter]
    fn set_pushed_authorization_request_endpoint(&mut self, v: &Bound<'_, PyAny>) -> PyResult<()> {
        self.set_known("pushed_authorization_request_endpoint", v)
    }
    #[getter]
    fn check_session_iframe(&self) -> Option<String> {
        self.extra_str("check_session_iframe")
    }
    #[setter]
    fn set_check_session_iframe(&mut self, v: &Bound<'_, PyAny>) -> PyResult<()> {
        self.set_known("check_session_iframe", v)
    }
    #[getter]
    fn service_documentation(&self) -> Option<String> {
        self.extra_str("service_documentation")
    }
    #[setter]
    fn set_service_documentation(&mut self, v: &Bound<'_, PyAny>) -> PyResult<()> {
        self.set_known("service_documentation", v)
    }
    #[getter]
    fn op_policy_uri(&self) -> Option<String> {
        self.extra_str("op_policy_uri")
    }
    #[setter]
    fn set_op_policy_uri(&mut self, v: &Bound<'_, PyAny>) -> PyResult<()> {
        self.set_known("op_policy_uri", v)
    }
    #[getter]
    fn op_tos_uri(&self) -> Option<String> {
        self.extra_str("op_tos_uri")
    }
    #[setter]
    fn set_op_tos_uri(&mut self, v: &Bound<'_, PyAny>) -> PyResult<()> {
        self.set_known("op_tos_uri", v)
    }

    #[getter]
    fn issuer(&self) -> &str {
        &self.inner.issuer
    }
    #[setter]
    fn set_issuer(&mut self, v: String) -> PyResult<()> {
        // Re-validate stored URL members against the new issuer first, so a
        // failure leaves the old issuer in place.
        validate_issuer_value(&v)?;
        validate_modelled_urls(&self.inner, &v)?;
        validate_extra(&self.inner.extra, &v)?;
        self.inner.issuer = v;
        Ok(())
    }
    #[getter]
    fn authorization_endpoint(&self) -> &str {
        &self.inner.authorization_endpoint
    }
    #[setter]
    fn set_authorization_endpoint(&mut self, v: String) -> PyResult<()> {
        validate_url_member("authorization_endpoint", &v, &self.inner.issuer)?;
        self.inner.authorization_endpoint = v;
        Ok(())
    }
    #[getter]
    fn token_endpoint(&self) -> &str {
        &self.inner.token_endpoint
    }
    #[setter]
    fn set_token_endpoint(&mut self, v: String) -> PyResult<()> {
        validate_url_member("token_endpoint", &v, &self.inner.issuer)?;
        self.inner.token_endpoint = v;
        Ok(())
    }
    #[getter]
    fn userinfo_endpoint(&self) -> Option<&str> {
        self.inner.userinfo_endpoint.as_deref()
    }
    #[setter]
    fn set_userinfo_endpoint(&mut self, v: Option<String>) -> PyResult<()> {
        if let Some(u) = &v {
            validate_url_member("userinfo_endpoint", u, &self.inner.issuer)?;
        }
        self.inner.userinfo_endpoint = v;
        Ok(())
    }
    #[getter]
    fn jwks_uri(&self) -> &str {
        &self.inner.jwks_uri
    }
    #[setter]
    fn set_jwks_uri(&mut self, v: String) -> PyResult<()> {
        validate_url_member("jwks_uri", &v, &self.inner.issuer)?;
        self.inner.jwks_uri = v;
        Ok(())
    }

    #[getter]
    fn registration_endpoint(&self) -> Option<&str> {
        self.inner.registration_endpoint.as_deref()
    }
    #[setter]
    fn set_registration_endpoint(&mut self, v: Option<String>) -> PyResult<()> {
        if let Some(u) = &v {
            validate_url_member("registration_endpoint", u, &self.inner.issuer)?;
        }
        self.inner.registration_endpoint = v;
        Ok(())
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
        self.touched.insert("response_types_supported");
    }
    #[getter]
    fn response_modes_supported(&self) -> Vec<String> {
        self.inner.response_modes_supported.clone()
    }
    #[setter]
    fn set_response_modes_supported(&mut self, v: Vec<String>) {
        self.inner.response_modes_supported = v;
        self.touched.insert("response_modes_supported");
    }
    #[getter]
    fn grant_types_supported(&self) -> Vec<String> {
        self.inner.grant_types_supported.clone()
    }
    #[setter]
    fn set_grant_types_supported(&mut self, v: Vec<String>) {
        self.inner.grant_types_supported = v;
        self.touched.insert("grant_types_supported");
    }
    #[getter]
    fn subject_types_supported(&self) -> Vec<String> {
        self.inner.subject_types_supported.clone()
    }
    #[setter]
    fn set_subject_types_supported(&mut self, v: Vec<String>) {
        self.inner.subject_types_supported = v;
        self.touched.insert("subject_types_supported");
    }
    #[getter]
    fn id_token_signing_alg_values_supported(&self) -> Vec<String> {
        self.inner.id_token_signing_alg_values_supported.clone()
    }
    #[setter]
    fn set_id_token_signing_alg_values_supported(&mut self, v: Vec<String>) {
        self.inner.id_token_signing_alg_values_supported = v;
        self.touched.insert("id_token_signing_alg_values_supported");
    }
    #[getter]
    fn token_endpoint_auth_methods_supported(&self) -> Vec<String> {
        self.inner.token_endpoint_auth_methods_supported.clone()
    }
    #[setter]
    fn set_token_endpoint_auth_methods_supported(&mut self, v: Vec<String>) {
        self.inner.token_endpoint_auth_methods_supported = v;
        self.touched.insert("token_endpoint_auth_methods_supported");
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
        validate_extra(&extra, &self.inner.issuer)?;
        self.inner.extra = extra;
        Ok(())
    }
    /// Set one extension field.
    fn set_extra_field(&mut self, key: String, value: &Bound<'_, PyAny>) -> PyResult<()> {
        validate_extra_key(&key)?;
        let v: serde_json::Value = from_py(value)?;
        validate_known_value(&key, &v, &self.inner.issuer)?;
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
