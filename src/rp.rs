//! Bindings for `grindvakt::rp` - the relying-party (client) side of
//! OIDC / OAuth 2.0: discovery, authorization URL, code exchange, id_token
//! verification, userinfo, and `private_key_jwt` client assertions.
//!
//! Outbound HTTP goes through the `http` argument of the networked functions:
//! `None` for the built-in client, a `pygrindvakt.http.ReqwestClient`, or any
//! Python object implementing the `HttpClient` protocol (see `http.rs`).
//!
//! HARDENING beyond upstream: `verify_id_token` refuses to run without an
//! expected nonce unless `unsafe_skip_nonce_check=True` is passed explicitly
//! (upstream silently skips the check when the nonce is `None`).

use std::collections::BTreeMap;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyModule};

use grindvakt::rp as grp;
use grindvakt::rp::ClientAuth;

use crate::convert::{from_py, new_submodule, to_py, warn};
use crate::errors::{err, AuthnError};
use crate::http::extract_http_client;
use crate::jwt::jwks_from_py;
use crate::keys::SigningKey;
use crate::metadata::ProviderMetadata;

/// Render an optional string the way Python would (`'x'` / `None`).
fn opt_repr(v: Option<&str>) -> String {
    match v {
        Some(s) => format!("{s:?}"),
        None => "None".to_string(),
    }
}

// ---------------------------------------------------------------------------
// ProviderInfo
// ---------------------------------------------------------------------------

/// The minimal upstream-provider information the RP needs: issuer,
/// authorization and token endpoints, and optionally the userinfo endpoint
/// and JWKS URI.
///
/// Build one by hand for a statically configured provider, or with
/// `ProviderInfo.from_metadata(discover(http, issuer))`.
#[pyclass(
    module = "pygrindvakt.rp",
    name = "ProviderInfo",
    frozen,
    from_py_object
)]
#[derive(Clone)]
pub struct ProviderInfo {
    pub inner: grp::ProviderInfo,
}

impl ProviderInfo {
    pub fn wrap(inner: grp::ProviderInfo) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl ProviderInfo {
    #[new]
    #[pyo3(signature = (issuer, authorization_endpoint, token_endpoint, userinfo_endpoint = None, jwks_uri = None))]
    fn new(
        issuer: String,
        authorization_endpoint: String,
        token_endpoint: String,
        userinfo_endpoint: Option<String>,
        jwks_uri: Option<String>,
    ) -> Self {
        Self {
            inner: grp::ProviderInfo {
                issuer,
                authorization_endpoint,
                token_endpoint,
                userinfo_endpoint,
                jwks_uri,
            },
        }
    }

    /// Build from a discovered `ProviderMetadata` document (the userinfo
    /// endpoint and JWKS URI are always set in that case).
    #[staticmethod]
    fn from_metadata(metadata: &ProviderMetadata) -> Self {
        Self::wrap(grp::ProviderInfo::from(metadata.inner.clone()))
    }

    #[getter]
    fn issuer(&self) -> &str {
        &self.inner.issuer
    }
    #[getter]
    fn authorization_endpoint(&self) -> &str {
        &self.inner.authorization_endpoint
    }
    #[getter]
    fn token_endpoint(&self) -> &str {
        &self.inner.token_endpoint
    }
    #[getter]
    fn userinfo_endpoint(&self) -> Option<&str> {
        self.inner.userinfo_endpoint.as_deref()
    }
    #[getter]
    fn jwks_uri(&self) -> Option<&str> {
        self.inner.jwks_uri.as_deref()
    }

    fn __repr__(&self) -> String {
        format!(
            "ProviderInfo(issuer={:?}, authorization_endpoint={:?}, token_endpoint={:?}, \
             userinfo_endpoint={}, jwks_uri={})",
            self.inner.issuer,
            self.inner.authorization_endpoint,
            self.inner.token_endpoint,
            opt_repr(self.inner.userinfo_endpoint.as_deref()),
            opt_repr(self.inner.jwks_uri.as_deref())
        )
    }
}

// ---------------------------------------------------------------------------
// RpClient
// ---------------------------------------------------------------------------

fn auth_method_name(auth: &ClientAuth) -> &'static str {
    match auth {
        ClientAuth::None => "none",
        ClientAuth::ClientSecretBasic(_) => "client_secret_basic",
        ClientAuth::ClientSecretPost(_) => "client_secret_post",
        ClientAuth::PrivateKeyJwt(_) => "private_key_jwt",
    }
}

/// Resolve the token-endpoint authentication method from the constructor
/// arguments. The default mirrors tunnelbana's OIDC backend: `client_secret_basic`
/// when a secret is given, `none` otherwise. Every inconsistent combination is
/// rejected rather than silently ignored.
fn resolve_client_auth(
    auth_method: Option<&str>,
    client_secret: Option<String>,
    signing_key: Option<SigningKey>,
) -> PyResult<ClientAuth> {
    if matches!(client_secret.as_deref(), Some("")) {
        return Err(PyValueError::new_err("client_secret must not be empty"));
    }
    let method = match auth_method {
        Some(m) => m,
        None if client_secret.is_some() => "client_secret_basic",
        None => "none",
    };
    let auth = match method {
        "none" => {
            if client_secret.is_some() {
                return Err(PyValueError::new_err(
                    "auth_method='none' does not take a client_secret",
                ));
            }
            ClientAuth::None
        }
        "client_secret_basic" | "client_secret_post" => {
            let secret = client_secret.ok_or_else(|| {
                PyValueError::new_err(format!("auth_method={method:?} requires client_secret"))
            })?;
            if method == "client_secret_basic" {
                ClientAuth::ClientSecretBasic(secret)
            } else {
                ClientAuth::ClientSecretPost(secret)
            }
        }
        "private_key_jwt" => {
            if client_secret.is_some() {
                return Err(PyValueError::new_err(
                    "auth_method='private_key_jwt' does not take a client_secret",
                ));
            }
            let key = signing_key.clone().ok_or_else(|| {
                PyValueError::new_err("auth_method='private_key_jwt' requires signing_key")
            })?;
            ClientAuth::PrivateKeyJwt(key.inner)
        }
        other => {
            return Err(PyValueError::new_err(format!(
                "unknown auth_method {other:?}; expected one of \
                 'none', 'client_secret_basic', 'client_secret_post', 'private_key_jwt'"
            )))
        }
    };
    if signing_key.is_some() && !matches!(auth, ClientAuth::PrivateKeyJwt(_)) {
        return Err(PyValueError::new_err(format!(
            "signing_key is only used with auth_method='private_key_jwt' (resolved method: {:?})",
            auth_method_name(&auth)
        )));
    }
    Ok(auth)
}

/// RP client configuration: `client_id`, `redirect_uri`, requested `scope`,
/// and how the client authenticates to the upstream token endpoint.
///
/// `auth_method` is one of `"none"`, `"client_secret_basic"`,
/// `"client_secret_post"` or `"private_key_jwt"`. When omitted it defaults to
/// `client_secret_basic` if `client_secret` is given, else `none`.
/// Inconsistent combinations (a secret method without `client_secret`,
/// `private_key_jwt` without `signing_key`, a secret or key that the chosen
/// method would ignore) raise `ValueError`.
///
/// SECURITY: `client_secret` is a credential. Load it from a secret store or
/// environment variable rather than embedding it in source, and note that it
/// is held in memory for the lifetime of the object. It is never included in
/// `repr()`.
#[pyclass(module = "pygrindvakt.rp", name = "RpClient", frozen, from_py_object)]
#[derive(Clone)]
pub struct RpClient {
    pub inner: grp::RpClient,
}

impl RpClient {
    pub fn wrap(inner: grp::RpClient) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl RpClient {
    #[new]
    #[pyo3(signature = (client_id, redirect_uri, *, scope = "openid profile email", client_secret = None, auth_method = None, signing_key = None))]
    fn new(
        client_id: String,
        redirect_uri: String,
        scope: &str,
        client_secret: Option<String>,
        auth_method: Option<&str>,
        signing_key: Option<SigningKey>,
    ) -> PyResult<Self> {
        let auth = resolve_client_auth(auth_method, client_secret, signing_key)?;
        Ok(Self {
            inner: grp::RpClient {
                client_id,
                redirect_uri,
                auth,
                scope: scope.to_string(),
            },
        })
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
    fn scope(&self) -> &str {
        &self.inner.scope
    }
    /// The token-endpoint authentication method as a string.
    #[getter]
    fn auth_method(&self) -> &'static str {
        auth_method_name(&self.inner.auth)
    }

    fn __repr__(&self) -> String {
        format!(
            "RpClient(client_id={:?}, redirect_uri={:?}, scope={:?}, auth_method={:?})",
            self.inner.client_id,
            self.inner.redirect_uri,
            self.inner.scope,
            auth_method_name(&self.inner.auth)
        )
    }
}

// ---------------------------------------------------------------------------
// TokenSet
// ---------------------------------------------------------------------------

/// The result of a successful code exchange. `access_token`, `id_token` and
/// `token_type` are pulled out of the response; `raw` is the full JSON body
/// as a dict (for `refresh_token`, `expires_in`, `scope`, ...).
#[pyclass(module = "pygrindvakt.rp", name = "TokenSet", frozen, from_py_object)]
#[derive(Clone)]
pub struct TokenSet {
    pub inner: grp::TokenSet,
}

#[pymethods]
impl TokenSet {
    #[getter]
    fn access_token(&self) -> Option<&str> {
        self.inner.access_token.as_deref()
    }
    #[getter]
    fn id_token(&self) -> Option<&str> {
        self.inner.id_token.as_deref()
    }
    #[getter]
    fn token_type(&self) -> Option<&str> {
        self.inner.token_type.as_deref()
    }
    /// The complete token-endpoint response as a dict.
    #[getter]
    fn raw<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        to_py(py, &self.inner.raw)
    }

    fn __repr__(&self) -> String {
        format!(
            "TokenSet(token_type={}, access_token={}, id_token={})",
            opt_repr(self.inner.token_type.as_deref()),
            if self.inner.access_token.is_some() {
                "<set>"
            } else {
                "None"
            },
            if self.inner.id_token.is_some() {
                "<set>"
            } else {
                "None"
            },
        )
    }
}

// ---------------------------------------------------------------------------
// Functions
// ---------------------------------------------------------------------------

/// Accept `extra` as either a `dict[str, str]` or a list of `(name, value)`
/// tuples (the list form allows repeated names).
fn extra_params(extra: Option<&Bound<'_, PyAny>>) -> PyResult<Vec<(String, String)>> {
    match extra {
        None => Ok(Vec::new()),
        Some(e) if e.is_none() => Ok(Vec::new()),
        Some(e) => {
            if let Ok(d) = e.cast::<PyDict>() {
                let mut out = Vec::with_capacity(d.len());
                for (k, v) in d.iter() {
                    out.push((k.extract::<String>()?, v.extract::<String>()?));
                }
                Ok(out)
            } else {
                e.extract::<Vec<(String, String)>>().map_err(|_| {
                    PyValueError::new_err(
                        "extra must be a dict[str, str] or a list of (str, str) tuples",
                    )
                })
            }
        }
    }
}

/// Build the authorization request URL to redirect the user to.
///
/// `state` and `nonce` must be fresh random values bound to the user's
/// session; `code_challenge` is the PKCE `S256` challenge
/// (`pygrindvakt.pkce.s256_challenge`). `extra` adds further query
/// parameters (e.g. `{"prompt": "login"}` or a signed `request` object).
#[pyfunction]
#[pyo3(signature = (provider, client, state, nonce, code_challenge = None, extra = None))]
fn authorization_url(
    provider: &ProviderInfo,
    client: &RpClient,
    state: &str,
    nonce: &str,
    code_challenge: Option<&str>,
    extra: Option<&Bound<'_, PyAny>>,
) -> PyResult<String> {
    let extra = extra_params(extra)?;
    let extra_refs: Vec<(&str, &str)> = extra
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    Ok(grp::authorization_url(
        &provider.inner,
        &client.inner,
        state,
        nonce,
        code_challenge,
        &extra_refs,
    ))
}

/// Build a signed request object (RFC 9101, "JAR") carrying the
/// authorization-request parameters as JWT claims, signed with `key`.
///
/// OpenID Federation automatic registration needs this: pass the result as
/// the `request` parameter (via `authorization_url(..., extra={"request": jar})`)
/// alongside the plain parameters. `key` must be one of the RP's published
/// client keys. The object is valid for 300 seconds and carries a `jti`.
#[pyfunction]
#[pyo3(signature = (provider, client, key, state, nonce, code_challenge = None))]
fn signed_request_object(
    provider: &ProviderInfo,
    client: &RpClient,
    key: &SigningKey,
    state: &str,
    nonce: &str,
    code_challenge: Option<&str>,
) -> PyResult<String> {
    grp::signed_request_object(
        &provider.inner,
        &client.inner,
        &key.inner,
        state,
        nonce,
        code_challenge,
    )
    .map_err(err)
}

/// Discover provider metadata from `issuer` (`/.well-known/openid-configuration`).
///
/// The issuer must be an `https` URL (plain `http` only for loopback hosts),
/// and the `issuer` in the returned document must match the requested one
/// exactly (OIDC Discovery section 4.3). `http` is `None` for the built-in
/// client, a `ReqwestClient`, or an object implementing the `HttpClient`
/// protocol.
#[pyfunction]
#[pyo3(signature = (http, issuer))]
fn discover(
    py: Python<'_>,
    http: Option<&Bound<'_, PyAny>>,
    issuer: String,
) -> PyResult<ProviderMetadata> {
    let http = extract_http_client(http)?;
    let r = crate::runtime::block_on(py, async move { grp::discover(&http, &issuer).await })?;
    r.map(ProviderMetadata::wrap).map_err(err)
}

/// Fetch a JWKS document from `jwks_uri` and return it as a dict
/// (`{"keys": [...]}`), ready for `verify_id_token`.
#[pyfunction]
#[pyo3(signature = (http, jwks_uri))]
fn fetch_jwks<'py>(
    py: Python<'py>,
    http: Option<&Bound<'py, PyAny>>,
    jwks_uri: String,
) -> PyResult<Bound<'py, PyAny>> {
    let http = extract_http_client(http)?;
    let r = crate::runtime::block_on(py, async move { grp::fetch_jwks(&http, &jwks_uri).await })?;
    let jwks = r.map_err(err)?;
    to_py(py, &jwks)
}

/// Exchange an authorization `code` for tokens at the provider's token
/// endpoint, authenticating as configured on `client`. `code_verifier` is the
/// PKCE verifier matching the challenge sent in `authorization_url`.
///
/// A non-200 response raises `AuthnError` carrying a sanitized, truncated
/// copy of the upstream error body.
#[pyfunction]
#[pyo3(signature = (http, provider, client, code, code_verifier = None))]
fn exchange_code(
    py: Python<'_>,
    http: Option<&Bound<'_, PyAny>>,
    provider: &ProviderInfo,
    client: &RpClient,
    code: String,
    code_verifier: Option<String>,
) -> PyResult<TokenSet> {
    let http = extract_http_client(http)?;
    let provider = provider.inner.clone();
    let client = client.inner.clone();
    let r = crate::runtime::block_on(py, async move {
        grp::exchange_code(&http, &provider, &client, &code, code_verifier.as_deref()).await
    })?;
    r.map(|inner| TokenSet { inner }).map_err(err)
}

/// Verify an `id_token` against the provider JWKS (a dict `{"keys": [...]}`),
/// `issuer`, audience `client_id`, and `expected_nonce`; `exp` and `iat` are
/// required. Returns the validated claims as a dict.
///
/// `expected_nonce` is the nonce this RP sent in the authorization request.
/// Passing `None` is refused with `AuthnError` unless
/// `unsafe_skip_nonce_check=True` is given as well, which disables the nonce
/// check entirely and emits a `UserWarning`.
///
/// SECURITY: only skip the nonce check for flows that genuinely carry no
/// nonce (e.g. a pure OAuth 2.0 flow that still returns an id_token). Skipping
/// it for the standard code flow allows id_token replay.
#[pyfunction]
#[pyo3(signature = (jwks, id_token, issuer, client_id, expected_nonce, unsafe_skip_nonce_check = false))]
fn verify_id_token<'py>(
    py: Python<'py>,
    jwks: &Bound<'py, PyAny>,
    id_token: &str,
    issuer: &str,
    client_id: &str,
    expected_nonce: Option<&str>,
    unsafe_skip_nonce_check: bool,
) -> PyResult<Bound<'py, PyAny>> {
    if expected_nonce.is_none() {
        if !unsafe_skip_nonce_check {
            return Err(AuthnError::new_err(
                "expected_nonce is required; pass unsafe_skip_nonce_check=True only for flows \
                 without a nonce",
            ));
        }
        warn(
            py,
            "verify_id_token: nonce check skipped (unsafe_skip_nonce_check=True); the id_token \
             is not bound to this authorization request",
        );
    }
    let jwks = jwks_from_py(jwks)?;
    let claims =
        grp::verify_id_token(&jwks, id_token, issuer, client_id, expected_nonce).map_err(err)?;
    to_py(py, &claims)
}

/// Fetch the userinfo document with a Bearer `access_token` and return it as
/// a dict. Raises `AuthnError` on a non-200 response.
#[pyfunction]
#[pyo3(signature = (http, userinfo_endpoint, access_token))]
fn fetch_userinfo<'py>(
    py: Python<'py>,
    http: Option<&Bound<'py, PyAny>>,
    userinfo_endpoint: String,
    access_token: String,
) -> PyResult<Bound<'py, PyAny>> {
    let http = extract_http_client(http)?;
    let r = crate::runtime::block_on(py, async move {
        grp::fetch_userinfo(&http, &userinfo_endpoint, &access_token).await
    })?;
    let v = r.map_err(err)?;
    to_py(py, &v)
}

/// Build a `private_key_jwt` client assertion (RFC 7523) signed with `key`:
/// `iss` = `sub` = `client_id`, `aud` = `audience` (the token endpoint URL),
/// valid for 300 seconds, with a random `jti`.
#[pyfunction]
fn build_client_assertion(key: &SigningKey, client_id: &str, audience: &str) -> PyResult<String> {
    grp::build_client_assertion(&key.inner, client_id, audience).map_err(err)
}

/// Convert a userinfo / id_token claims dict into the proxy's attribute map
/// shape, `{name: [values]}`: strings become one-element lists, lists keep
/// their string members, numbers and booleans are stringified, and anything
/// else (nested objects, null, empty lists) is dropped.
#[pyfunction]
fn claims_to_attributes(claims: &Bound<'_, PyAny>) -> PyResult<BTreeMap<String, Vec<String>>> {
    let v: serde_json::Value = from_py(claims)?;
    Ok(grp::claims_to_attributes(&v))
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = new_submodule(py, parent, "rp")?;
    m.add_class::<ProviderInfo>()?;
    m.add_class::<RpClient>()?;
    m.add_class::<TokenSet>()?;
    m.add_function(wrap_pyfunction!(authorization_url, &m)?)?;
    m.add_function(wrap_pyfunction!(signed_request_object, &m)?)?;
    m.add_function(wrap_pyfunction!(discover, &m)?)?;
    m.add_function(wrap_pyfunction!(fetch_jwks, &m)?)?;
    m.add_function(wrap_pyfunction!(exchange_code, &m)?)?;
    m.add_function(wrap_pyfunction!(verify_id_token, &m)?)?;
    m.add_function(wrap_pyfunction!(fetch_userinfo, &m)?)?;
    m.add_function(wrap_pyfunction!(build_client_assertion, &m)?)?;
    m.add_function(wrap_pyfunction!(claims_to_attributes, &m)?)?;
    Ok(())
}
