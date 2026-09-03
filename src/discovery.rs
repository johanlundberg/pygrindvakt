//! Bindings for `grindvakt::discovery` - home-organization discovery for
//! OpenID Federation RPs and OpenID Connect Core §4 Third-Party Initiated
//! Login.
//!
//! A discovery service presents a list of OPs (from a trust anchor's
//! collection endpoint, see `pygrindvakt.federation.fetch_collection`) to the
//! user; the selection is returned to the RP's `initiate_login_uri` as a
//! third-party initiated login.
//!
//! - RP side, outgoing call: `discovery_request_url` builds the redirect to
//!   the (out-of-band configured) discovery endpoint.
//! - RP side, return call: `parse_third_party_initiated_login` validates the
//!   request arriving at the RP's `initiate_login_uri`.
//! - Discovery-service side: `initiate_login_uri` /
//!   `initiate_login_uri_from_resolved` / `self_published_initiate_login_uri`
//!   extract the verified RP's return endpoint, `third_party_login_url` builds
//!   the selection link, and `promote_hint` applies the OP-hint promotion rule.

use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};

use pyo3::prelude::*;
use pyo3::types::PyModule;

use grindvakt::discovery as gd;
use grindvakt::federation as gf;

use crate::convert::{from_py, new_submodule, to_py};
use crate::errors::err;
use crate::federation::{CollectionEntity, ResolvedEntity};

// ---------------------------------------------------------------------------
// Entity identifiers
// ---------------------------------------------------------------------------

/// Validate an OpenID Federation Entity Identifier as accepted on a wire
/// parameter (`entity_id`, `iss`, `hint`): an https URL with a host and no
/// query or fragment. Raises `BadRequestError` otherwise.
#[pyfunction]
fn validate_entity_id(s: &str) -> PyResult<()> {
    gd::validate_entity_id(s).map_err(err)
}

// ---------------------------------------------------------------------------
// RP side
// ---------------------------------------------------------------------------

/// Build the URL an RP redirects the browser to in order to start home
/// organization discovery (the *outgoing call*):
/// `<discovery_endpoint>?entity_id=<rp>[&hint=<op>][&target_link_uri=<uri>]`.
///
/// `discovery_endpoint` is the discovery service's absolute endpoint URL.
/// `rp_entity_id` is the RP's own entity identifier; `op_hint` optionally
/// names a preferred OP; `target_link_uri` lets the RP learn where to send the
/// user after login without keeping a session (the discovery service must
/// return it verbatim). Raises `BadRequestError` on an invalid endpoint or
/// entity identifier.
#[pyfunction]
#[pyo3(signature = (discovery_endpoint, rp_entity_id, op_hint = None, target_link_uri = None))]
fn discovery_request_url(
    discovery_endpoint: &str,
    rp_entity_id: &str,
    op_hint: Option<&str>,
    target_link_uri: Option<&str>,
) -> PyResult<String> {
    gd::discovery_request_url(discovery_endpoint, rp_entity_id, op_hint, target_link_uri)
        .map_err(err)
}

/// A parsed and validated Third-Party Initiated Login request (OpenID Connect
/// Core 1.0 §4), as received at the RP's `initiate_login_uri`.
///
/// `target_link_uri` is where to send the user after a successful login; the
/// RP MUST verify it against its own allowlist before redirecting to it.
#[pyclass(
    module = "pygrindvakt.discovery",
    name = "ThirdPartyInitiatedLogin",
    frozen,
    from_py_object
)]
#[derive(Clone)]
pub struct ThirdPartyInitiatedLogin {
    pub inner: gd::ThirdPartyInitiatedLogin,
}

impl ThirdPartyInitiatedLogin {
    pub fn wrap(inner: gd::ThirdPartyInitiatedLogin) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl ThirdPartyInitiatedLogin {
    #[new]
    #[pyo3(signature = (iss, *, login_hint = None, target_link_uri = None))]
    fn new(iss: String, login_hint: Option<String>, target_link_uri: Option<String>) -> Self {
        Self::wrap(gd::ThirdPartyInitiatedLogin {
            iss,
            login_hint,
            target_link_uri,
        })
    }

    /// The issuer (OP) the RP should send the authentication request to.
    #[getter]
    fn iss(&self) -> &str {
        &self.inner.iss
    }
    /// Optional hint about the end-user to be logged in.
    #[getter]
    fn login_hint(&self) -> Option<&str> {
        self.inner.login_hint.as_deref()
    }
    /// Where to send the user after a successful login (verify against your
    /// allowlist first).
    #[getter]
    fn target_link_uri(&self) -> Option<&str> {
        self.inner.target_link_uri.as_deref()
    }

    fn __eq__(&self, other: &Bound<'_, PyAny>) -> bool {
        other
            .extract::<Self>()
            .map(|o| o.inner == self.inner)
            .unwrap_or(false)
    }

    fn __hash__(&self) -> u64 {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        self.inner.iss.hash(&mut h);
        self.inner.login_hint.hash(&mut h);
        self.inner.target_link_uri.hash(&mut h);
        h.finish()
    }

    fn __repr__(&self) -> String {
        format!(
            "ThirdPartyInitiatedLogin(iss={:?}, login_hint={:?}, target_link_uri={:?})",
            self.inner.iss, self.inner.login_hint, self.inner.target_link_uri
        )
    }
}

/// Parse the query parameters arriving at an RP's `initiate_login_uri` into a
/// `ThirdPartyInitiatedLogin`. `iss` is required and must be a valid https
/// entity identifier; empty `login_hint` / `target_link_uri` values are
/// treated as absent. Raises `BadRequestError`.
#[pyfunction]
fn parse_third_party_initiated_login(
    params: BTreeMap<String, String>,
) -> PyResult<ThirdPartyInitiatedLogin> {
    gd::parse_third_party_initiated_login(&params)
        .map(ThirdPartyInitiatedLogin::wrap)
        .map_err(err)
}

// ---------------------------------------------------------------------------
// Discovery-service side
// ---------------------------------------------------------------------------

/// Extract a verified RP's `initiate_login_uri` from its resolved metadata
/// dict (`metadata["openid_relying_party"]["initiate_login_uri"]`). The URI
/// must be https without a fragment: it is the only place a discovery service
/// ever sends a user, so anything weaker would turn the service into an open
/// redirector. Raises `AuthnError`.
#[pyfunction]
fn initiate_login_uri(metadata: &Bound<'_, PyAny>) -> PyResult<String> {
    let v: serde_json::Value = from_py(metadata)?;
    gd::initiate_login_uri(&v).map_err(err)
}

/// `initiate_login_uri` over a `pygrindvakt.federation.ResolvedEntity` (from
/// `resolve_via_trust_anchors`). Raises `AuthnError`.
#[pyfunction]
fn initiate_login_uri_from_resolved(entity: &ResolvedEntity) -> PyResult<String> {
    gd::initiate_login_uri_from_resolved(&entity.inner).map_err(err)
}

/// A verified self-published relying party: the full `metadata` claims object
/// from its entity configuration plus the statement's lifetime.
#[pyclass(
    module = "pygrindvakt.discovery",
    name = "SelfPublishedRp",
    frozen,
    from_py_object
)]
#[derive(Clone)]
pub struct SelfPublishedRp {
    pub inner: gd::SelfPublishedRp,
}

impl SelfPublishedRp {
    pub fn wrap(inner: gd::SelfPublishedRp) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl SelfPublishedRp {
    /// The `metadata` claims object as a dict (contains
    /// `openid_relying_party`, ...).
    #[getter]
    fn metadata<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        to_py(py, &self.inner.metadata)
    }
    /// The entity configuration's `exp` (seconds since epoch), if present;
    /// callers can use it to bound caching.
    #[getter]
    fn exp(&self) -> Option<u64> {
        self.inner.exp
    }
    fn __repr__(&self) -> String {
        let entity_types: Vec<&str> = self
            .inner
            .metadata
            .as_object()
            .map(|m| m.keys().map(String::as_str).collect())
            .unwrap_or_default();
        format!(
            "SelfPublishedRp(metadata={:?}, exp={:?})",
            entity_types, self.inner.exp
        )
    }
}

/// Fetch and verify an RP's *self-published* entity configuration
/// (`<rp_entity_id>/.well-known/openid-federation`, self-signed) and return
/// its metadata and lifetime.
///
/// For discovery services running in an open mode: the RP is not required to
/// chain up to a trust anchor, but anything taken from the result is still
/// limited to what the entity itself publishes under its own identifier,
/// never caller-supplied data. The statement must be issued by (and about)
/// `rp_entity_id` exactly.
///
/// `http` is an `HttpClient` (`None` for the built-in client).
#[pyfunction]
#[pyo3(signature = (http, rp_entity_id))]
fn self_published_rp(
    py: Python<'_>,
    http: Option<&Bound<'_, PyAny>>,
    rp_entity_id: String,
) -> PyResult<SelfPublishedRp> {
    let http = crate::http::extract_http_client(http)?;
    let r = crate::runtime::block_on(py, async move {
        gd::self_published_rp(&http, &rp_entity_id).await
    })?;
    r.map(SelfPublishedRp::wrap).map_err(err)
}

/// `self_published_rp` reduced to the validated `initiate_login_uri`.
///
/// `http` is an `HttpClient` (`None` for the built-in client).
#[pyfunction]
#[pyo3(signature = (http, rp_entity_id))]
fn self_published_initiate_login_uri(
    py: Python<'_>,
    http: Option<&Bound<'_, PyAny>>,
    rp_entity_id: String,
) -> PyResult<String> {
    let http = crate::http::extract_http_client(http)?;
    let r = crate::runtime::block_on(py, async move {
        gd::self_published_initiate_login_uri(&http, &rp_entity_id).await
    })?;
    r.map_err(err)
}

/// Build the third-party initiated login URL the user is sent to after
/// selecting an OP (the *return call*):
/// `<initiate_login_uri>?iss=<op>[&login_hint=...][&target_link_uri=...]`.
///
/// `target_link_uri` is attached verbatim (it is only ever appended to a
/// verified `initiate_login_uri`, never used as a redirect target itself).
#[pyfunction]
#[pyo3(signature = (initiate_login_uri, op_entity_id, login_hint = None, target_link_uri = None))]
fn third_party_login_url(
    initiate_login_uri: &str,
    op_entity_id: &str,
    login_hint: Option<&str>,
    target_link_uri: Option<&str>,
) -> String {
    gd::third_party_login_url(
        initiate_login_uri,
        op_entity_id,
        login_hint,
        target_link_uri,
    )
}

/// If `hint` names one of `entities` (trailing slash ignored), move it to the
/// front: the discovery flow requires a matching OP hint to become the
/// default choice. Returns `(found, entities)` where `entities` is a new,
/// reordered list; the input list is not modified.
#[pyfunction]
fn promote_hint(entities: Vec<CollectionEntity>, hint: &str) -> (bool, Vec<CollectionEntity>) {
    let mut inner: Vec<gf::CollectionEntity> = entities.into_iter().map(|e| e.inner).collect();
    let found = gd::promote_hint(&mut inner, hint);
    (
        found,
        inner.into_iter().map(CollectionEntity::wrap).collect(),
    )
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = new_submodule(py, parent, "discovery")?;
    m.add_class::<ThirdPartyInitiatedLogin>()?;
    m.add_class::<SelfPublishedRp>()?;
    m.add_function(wrap_pyfunction!(validate_entity_id, &m)?)?;
    m.add_function(wrap_pyfunction!(discovery_request_url, &m)?)?;
    m.add_function(wrap_pyfunction!(parse_third_party_initiated_login, &m)?)?;
    m.add_function(wrap_pyfunction!(initiate_login_uri, &m)?)?;
    m.add_function(wrap_pyfunction!(initiate_login_uri_from_resolved, &m)?)?;
    m.add_function(wrap_pyfunction!(promote_hint, &m)?)?;
    m.add_function(wrap_pyfunction!(self_published_rp, &m)?)?;
    m.add_function(wrap_pyfunction!(self_published_initiate_login_uri, &m)?)?;
    m.add_function(wrap_pyfunction!(third_party_login_url, &m)?)?;
    Ok(())
}
