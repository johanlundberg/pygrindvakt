//! Bindings for `grindvakt::dpop` - RFC 9449 sender-constrained tokens.
//!
//! Proof validation is stateless except for jti replay protection, which is
//! delegated to a `ReplayStore`: the built-in `InMemoryReplayStore`,
//! `NoReplayStore` (only safe with `require_nonce=True`), or any Python object
//! with `record(jti: str, ttl_secs: int) -> bool`.

use std::sync::Arc;

use async_trait::async_trait;
use pyo3::prelude::*;
use pyo3::types::PyModule;

use grindvakt::dpop as gd;
use grindvakt::dpop::ReplayStore;
use grindvakt::provider::{InMemoryTokenUseStore as RsTokenUseStore, TokenUseStore};

use crate::convert::{log_unraisable, new_submodule, require_methods, warn};
use crate::errors::dpop_err;

/// Upper bound on a `jti` we are willing to remember (defends the replay
/// store against unbounded keys).
const MAX_JTI_LEN: usize = 256;

// ---------------------------------------------------------------------------
// DpopConfig / DpopProof
// ---------------------------------------------------------------------------

/// DPoP validation settings.
///
/// `nonce_secret` keys the stateless server nonces and MUST be set (to a
/// high-entropy value derived from your master secret) when
/// `require_nonce=True`.
#[pyclass(
    module = "pygrindvakt.dpop",
    name = "DpopConfig",
    frozen,
    from_py_object
)]
#[derive(Clone)]
pub struct DpopConfig {
    pub inner: gd::DpopConfig,
}

#[pymethods]
impl DpopConfig {
    #[new]
    #[pyo3(signature = (*, proof_max_age_secs = 300, require_nonce = false,
                        nonce_lifetime_secs = 300, nonce_secret = None))]
    fn new(
        proof_max_age_secs: i64,
        require_nonce: bool,
        nonce_lifetime_secs: i64,
        nonce_secret: Option<String>,
    ) -> PyResult<Self> {
        let nonce_secret = nonce_secret.unwrap_or_default();
        if require_nonce && nonce_secret.is_empty() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "require_nonce=True needs a non-empty nonce_secret",
            ));
        }
        Ok(Self {
            inner: gd::DpopConfig {
                proof_max_age_secs,
                require_nonce,
                nonce_lifetime_secs,
                nonce_secret,
            },
        })
    }
    #[getter]
    fn proof_max_age_secs(&self) -> i64 {
        self.inner.proof_max_age_secs
    }
    #[getter]
    fn require_nonce(&self) -> bool {
        self.inner.require_nonce
    }
    #[getter]
    fn nonce_lifetime_secs(&self) -> i64 {
        self.inner.nonce_lifetime_secs
    }
    fn __repr__(&self) -> String {
        format!(
            "DpopConfig(proof_max_age_secs={}, require_nonce={}, nonce_lifetime_secs={})",
            self.inner.proof_max_age_secs, self.inner.require_nonce, self.inner.nonce_lifetime_secs
        )
    }
}

/// A validated DPoP proof: the SHA-256 JWK thumbprint of the proof key.
#[pyclass(
    module = "pygrindvakt.dpop",
    name = "DpopProof",
    frozen,
    from_py_object
)]
#[derive(Clone)]
pub struct DpopProof {
    pub inner: gd::DpopProof,
}

#[pymethods]
impl DpopProof {
    #[new]
    fn new(jkt: String) -> Self {
        Self {
            inner: gd::DpopProof { jkt },
        }
    }
    #[getter]
    fn jkt(&self) -> &str {
        &self.inner.jkt
    }
    fn __repr__(&self) -> String {
        format!("DpopProof(jkt={:?})", self.inner.jkt)
    }
}

// ---------------------------------------------------------------------------
// Replay stores
// ---------------------------------------------------------------------------

/// grindvakt's in-memory token-use store has exactly the `record` contract
/// (true iff newly recorded, TTL expiry, periodic purge), so reuse it.
pub struct InMemoryReplay(RsTokenUseStore);

#[async_trait]
impl ReplayStore for InMemoryReplay {
    async fn record(&self, jti: &str, ttl_secs: u64) -> Result<bool, String> {
        if jti.len() > MAX_JTI_LEN {
            tracing::debug!(len = jti.len(), "rejecting over-long DPoP jti");
            return Ok(false);
        }
        self.0.consume(jti, ttl_secs).await
    }
}

/// Process-local TTL replay cache for DPoP `jti`s. Use a shared (Python /
/// Redis-backed) store when running several replicas.
#[pyclass(module = "pygrindvakt.dpop", name = "InMemoryReplayStore", frozen)]
pub struct InMemoryReplayStore {
    pub inner: Arc<InMemoryReplay>,
}

#[pymethods]
impl InMemoryReplayStore {
    #[new]
    fn new() -> Self {
        Self {
            inner: Arc::new(InMemoryReplay(RsTokenUseStore::new())),
        }
    }
    /// Record `jti`; returns True iff it was not already live.
    fn record(&self, py: Python<'_>, jti: String, ttl_secs: u64) -> PyResult<bool> {
        let s = self.inner.clone();
        crate::runtime::block_on(py, async move { s.record(&jti, ttl_secs).await })?
            .map_err(crate::errors::internal_err)
    }
    fn __repr__(&self) -> &'static str {
        "InMemoryReplayStore()"
    }
}

/// A replay store that records nothing. Only safe together with
/// `DpopConfig(require_nonce=True)`, where the short-lived server nonce bounds
/// the replay window; otherwise a `UserWarning` is emitted at validation time.
#[pyclass(module = "pygrindvakt.dpop", name = "NoReplayStore", frozen)]
pub struct NoReplayStore;

#[pymethods]
impl NoReplayStore {
    #[new]
    fn new() -> Self {
        Self
    }
    fn __repr__(&self) -> &'static str {
        "NoReplayStore()"
    }
}

/// Adapter over a Python object implementing `record(jti, ttl_secs) -> bool`.
/// An exception is reported as a store failure (`DpopServerError`).
pub struct PyReplayStore {
    obj: Py<PyAny>,
}

#[async_trait]
impl ReplayStore for PyReplayStore {
    async fn record(&self, jti: &str, ttl_secs: u64) -> Result<bool, String> {
        Python::attach(|py| {
            let obj = self.obj.bind(py);
            match obj
                .call_method1("record", (jti, ttl_secs))
                .and_then(|r| r.extract::<bool>())
            {
                Ok(b) => Ok(b),
                Err(e) => {
                    let msg = format!("python ReplayStore.record raised: {e}");
                    log_unraisable(py, e, obj, "ReplayStore.record");
                    Err(msg)
                }
            }
        })
    }
}

enum Store {
    Rust(Arc<dyn ReplayStore>),
    None,
}

fn extract_replay_store(obj: &Bound<'_, PyAny>) -> PyResult<Store> {
    if let Ok(s) = obj.cast::<InMemoryReplayStore>() {
        return Ok(Store::Rust(s.get().inner.clone()));
    }
    if obj.cast::<NoReplayStore>().is_ok() {
        return Ok(Store::None);
    }
    require_methods(obj, &["record"], "ReplayStore")?;
    Ok(Store::Rust(Arc::new(PyReplayStore {
        obj: obj.clone().unbind(),
    })))
}

fn store_ref(py: Python<'_>, store: &Store, config: &DpopConfig) -> Arc<dyn ReplayStore> {
    match store {
        Store::Rust(s) => s.clone(),
        Store::None => {
            if !config.inner.require_nonce {
                warn(
                    py,
                    "NoReplayStore without DpopConfig(require_nonce=True) leaves DPoP proofs \
                     replayable for proof_max_age_secs; use InMemoryReplayStore or a shared store.",
                );
            }
            Arc::new(gd::NoReplayStore)
        }
    }
}

// ---------------------------------------------------------------------------
// Functions
// ---------------------------------------------------------------------------

/// Validate a `DPoP` header value for a **token-endpoint** request.
///
/// `htm` is the HTTP method and `htu` the absolute token URL the proof must
/// be bound to. Derive `htu` from configuration, never from the `Host`
/// header. On success the proof's `jti` has been recorded in `store`.
///
/// Raises `DpopInvalidError`, `DpopReplayError`, `DpopNonceRequiredError`
/// (respond with `use_dpop_nonce` and a fresh `issue_nonce`) or
/// `DpopServerError`.
#[pyfunction]
fn validate_proof(
    py: Python<'_>,
    store: &Bound<'_, PyAny>,
    config: &DpopConfig,
    proof: String,
    htm: String,
    htu: String,
) -> PyResult<DpopProof> {
    let store = store_ref(py, &extract_replay_store(store)?, config);
    let cfg = config.inner.clone();
    let r = crate::runtime::block_on(py, async move {
        gd::validate_proof(store.as_ref(), &cfg, &proof, &htm, &htu).await
    })?;
    r.map(|inner| DpopProof { inner }).map_err(dpop_err)
}

/// Validate a `DPoP` header value for a **resource** request (e.g. userinfo),
/// additionally binding it to `access_token` through the `ath` claim.
#[pyfunction]
fn validate_resource_proof(
    py: Python<'_>,
    store: &Bound<'_, PyAny>,
    config: &DpopConfig,
    proof: String,
    htm: String,
    htu: String,
    access_token: String,
) -> PyResult<DpopProof> {
    let store = store_ref(py, &extract_replay_store(store)?, config);
    let cfg = config.inner.clone();
    let r = crate::runtime::block_on(py, async move {
        gd::validate_resource_proof(store.as_ref(), &cfg, &proof, &htm, &htu, &access_token).await
    })?;
    r.map(|inner| DpopProof { inner }).map_err(dpop_err)
}

/// Mint a fresh server nonce (stateless HMAC over the current time window) to
/// send in a `DPoP-Nonce` header.
#[pyfunction]
fn issue_nonce(config: &DpopConfig) -> String {
    gd::issue_nonce(&config.inner)
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = new_submodule(py, parent, "dpop")?;
    m.add_class::<DpopConfig>()?;
    m.add_class::<DpopProof>()?;
    m.add_class::<InMemoryReplayStore>()?;
    m.add_class::<NoReplayStore>()?;
    m.add_function(wrap_pyfunction!(validate_proof, &m)?)?;
    m.add_function(wrap_pyfunction!(validate_resource_proof, &m)?)?;
    m.add_function(wrap_pyfunction!(issue_nonce, &m)?)?;
    Ok(())
}
