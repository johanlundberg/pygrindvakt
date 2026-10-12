//! Bindings for `grindvakt::rp` - the relying-party (client) side of
//! OIDC / OAuth 2.0: discovery, authorization URL, code exchange, id_token
//! verification, userinfo, and `private_key_jwt` client assertions.
//!
//! Outbound HTTP goes through the `http` argument of the networked functions:
//! `None` for the built-in client, a `pygrindvakt.http.ReqwestClient`, or any
//! Python object implementing the `HttpClient` protocol (see `http.rs`).
//!
//! The Python API makes nonce omission explicit: `verify_id_token` refuses to
//! run without an expected nonce unless `unsafe_skip_nonce_check=True` is
//! passed. It also requires a signing-algorithm allowlist and makes additional
//! trusted audiences an explicit policy input.

use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex, OnceLock, RwLock};
use std::time::Instant;

use async_trait::async_trait;
use grindvakt::http::{HttpClient, HttpFetchResponse};
use grindvakt::Error as RsError;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyModule, PyTuple};

use grindvakt::jose_rs::algorithm::JwsAlgorithm;
use grindvakt::jose_rs::jwk::JwkSet;
use grindvakt::jwt as gj;
use grindvakt::rp as grp;
use grindvakt::rp::ClientAuth;

use crate::convert::{from_py, new_submodule, to_py, warn};
use crate::errors::{err, with_code, AuthnError, ConfigError, UnknownKeyError};
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
/// `ProviderInfo.from_metadata(discover(http, issuer))`. Construction rejects
/// unsafe endpoint URLs before an authorization code or credential can be sent.
#[pyclass(
    module = "pygrindvakt.rp",
    name = "ProviderInfo",
    frozen,
    from_py_object
)]
#[derive(Clone)]
pub struct ProviderInfo {
    pub inner: grp::ProviderInfo,
    /// OIDC RP-Initiated Logout endpoint. Upstream `ProviderInfo` has no slot
    /// for it, so the binding carries it alongside.
    pub end_session_endpoint: Option<String>,
}

/// Same-origin test: scheme, host (the `url` crate lower-cases and IDNA-
/// normalises; a trailing dot is NOT stripped, so `op.example.` differs from
/// `op.example`) and effective port (default ports equal explicit ones).
fn same_origin(a: &str, b: &str) -> bool {
    let (Ok(a), Ok(b)) = (url::Url::parse(a), url::Url::parse(b)) else {
        return false;
    };
    a.scheme() == b.scheme()
        && a.host().is_some()
        && a.host() == b.host()
        && a.port_or_known_default().is_some()
        && a.port_or_known_default() == b.port_or_known_default()
}

/// Why an `end_session_endpoint` was refused.
enum EndSessionReject {
    /// Fails the shared scheme/userinfo/fragment/control-char rules.
    Unsafe(RsError),
    /// Safe, but not the issuer's origin and no opt-in.
    CrossOrigin,
}

/// Single validation point: the shared safety rules (upstream), then (unless
/// `allow_cross_origin`) same origin as the issuer, because `id_token_hint`
/// is sent to the endpoint's host.
fn check_end_session_endpoint(
    endpoint: &str,
    issuer: &str,
    allow_cross_origin: bool,
) -> Result<(), EndSessionReject> {
    grp::validate_service_endpoint_for_issuer("end_session_endpoint", endpoint, issuer)
        .map_err(EndSessionReject::Unsafe)?;
    if !allow_cross_origin && !same_origin(endpoint, issuer) {
        return Err(EndSessionReject::CrossOrigin);
    }
    Ok(())
}

/// `check_end_session_endpoint` as a raising Python-facing check.
fn validate_end_session_endpoint(
    endpoint: &str,
    issuer: &str,
    allow_cross_origin: bool,
) -> PyResult<()> {
    check_end_session_endpoint(endpoint, issuer, allow_cross_origin).map_err(|r| match r {
        EndSessionReject::Unsafe(e) => err(e),
        EndSessionReject::CrossOrigin => err(RsError::BadRequest(format!(
            "end_session_endpoint {endpoint:?} is on a different origin than the issuer \
             {issuer:?}; id_token_hint would be sent to that host. Pass \
             allow_cross_origin_end_session=True only if the OP legitimately logs out there"
        ))),
    })
}

#[pymethods]
impl ProviderInfo {
    #[new]
    #[pyo3(signature = (issuer, authorization_endpoint, token_endpoint, userinfo_endpoint = None, jwks_uri = None, *, end_session_endpoint = None, allow_cross_origin_end_session = false))]
    fn new(
        issuer: String,
        authorization_endpoint: String,
        token_endpoint: String,
        userinfo_endpoint: Option<String>,
        jwks_uri: Option<String>,
        end_session_endpoint: Option<String>,
        allow_cross_origin_end_session: bool,
    ) -> PyResult<Self> {
        let inner = grp::ProviderInfo {
            issuer,
            authorization_endpoint,
            token_endpoint,
            userinfo_endpoint,
            jwks_uri,
        };
        inner.validate().map_err(err)?;
        if let Some(e) = &end_session_endpoint {
            validate_end_session_endpoint(e, &inner.issuer, allow_cross_origin_end_session)?;
        }
        Ok(Self {
            inner,
            end_session_endpoint,
        })
    }

    /// Build from a discovered `ProviderMetadata` document (the userinfo
    /// endpoint is `None` if the provider does not advertise one). An
    /// advertised `end_session_endpoint` is carried over; one that is unsafe
    /// or on a different origin than the issuer (unless
    /// `allow_cross_origin_end_session`) is dropped (`None`) so login never
    /// depends on logout.
    #[staticmethod]
    #[pyo3(signature = (metadata, *, allow_cross_origin_end_session = false))]
    fn from_metadata(
        py: Python<'_>,
        metadata: &ProviderMetadata,
        allow_cross_origin_end_session: bool,
    ) -> PyResult<Self> {
        let inner = grp::ProviderInfo::from(metadata.inner.clone());
        inner.validate().map_err(err)?;
        let end_session_endpoint = metadata
            .inner
            .extra
            .get("end_session_endpoint")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        // Login must not depend on logout: an advertised endpoint that fails
        // issuer validation is dropped rather than raised.
        let end_session_endpoint = match end_session_endpoint {
            Some(e) => {
                match check_end_session_endpoint(&e, &inner.issuer, allow_cross_origin_end_session)
                {
                    Ok(()) => Some(e),
                    Err(reject) => {
                        let reason = match reject {
                            EndSessionReject::CrossOrigin => format!(
                                "end_session_endpoint {e:?} is on a different origin than the \
                                 issuer and was ignored; pass \
                                 allow_cross_origin_end_session=True to trust it"
                            ),
                            EndSessionReject::Unsafe(cause) => {
                                format!("end_session_endpoint {e:?} is unsafe ({cause}) and was ignored")
                            }
                        };
                        let msg =
                            std::ffi::CString::new(reason.replace('\0', "?")).expect("NUL removed");
                        // Best effort: a warnings filter of "error" must not
                        // make login depend on logout.
                        let _ = PyErr::warn(
                            py,
                            &py.get_type::<pyo3::exceptions::PyUserWarning>(),
                            &msg,
                            1,
                        );
                        None
                    }
                }
            }
            None => None,
        };
        Ok(Self {
            inner,
            end_session_endpoint,
        })
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
    /// The OIDC RP-Initiated Logout endpoint, or `None`.
    #[getter]
    fn end_session_endpoint(&self) -> Option<&str> {
        self.end_session_endpoint.as_deref()
    }

    fn __repr__(&self) -> String {
        format!(
            "ProviderInfo(issuer={:?}, authorization_endpoint={:?}, token_endpoint={:?}, \
             userinfo_endpoint={}, jwks_uri={}, end_session_endpoint={})",
            self.inner.issuer,
            self.inner.authorization_endpoint,
            self.inner.token_endpoint,
            opt_repr(self.inner.userinfo_endpoint.as_deref()),
            opt_repr(self.inner.jwks_uri.as_deref()),
            opt_repr(self.end_session_endpoint.as_deref())
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
    /// Registered `post_logout_redirect_uris` (binding-side; the upstream
    /// client has no such field).
    pub post_logout_redirect_uris: Vec<String>,
    /// Registered alternative login `redirect_uris` accepted as per-call
    /// overrides (binding-side).
    pub redirect_uris: Vec<String>,
    /// Accept any syntactically valid per-call `redirect_uri` override.
    pub allow_unregistered_redirect_uri: bool,
}

/// Reject plain `http` to a non-loopback host. `https`, loopback `http` and
/// custom / private-use schemes (native apps) pass.
fn check_redirect_uri_transport(uri: &str) -> Result<(), RsError> {
    let u = url::Url::parse(uri)
        .map_err(|_| RsError::BadRequest(format!("redirect_uri {uri:?} is not an absolute URL")))?;
    if u.scheme() == "http" {
        let loopback = match u.host() {
            Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
            Some(url::Host::Ipv4(a)) => a.is_loopback(),
            Some(url::Host::Ipv6(a)) => a.is_loopback(),
            None => false,
        };
        if !loopback {
            return Err(RsError::BadRequest(format!(
                "redirect_uri {uri:?} uses plain http to a non-loopback host; use https"
            )));
        }
    }
    Ok(())
}

impl RpClient {
    pub fn wrap(inner: grp::RpClient) -> Self {
        Self {
            inner,
            post_logout_redirect_uris: Vec::new(),
            redirect_uris: Vec::new(),
            allow_unregistered_redirect_uri: false,
        }
    }
}

#[pymethods]
impl RpClient {
    #[new]
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (client_id, redirect_uri, *, scope = "openid profile email", client_secret = None, auth_method = None, signing_key = None, post_logout_redirect_uris = None, redirect_uris = None, allow_unregistered_redirect_uri = false))]
    fn new(
        client_id: String,
        redirect_uri: String,
        scope: &str,
        client_secret: Option<String>,
        auth_method: Option<&str>,
        signing_key: Option<SigningKey>,
        post_logout_redirect_uris: Option<Vec<String>>,
        redirect_uris: Option<Vec<String>>,
        allow_unregistered_redirect_uri: bool,
    ) -> PyResult<Self> {
        let redirect_uris = redirect_uris.unwrap_or_default();
        for uri in &redirect_uris {
            grp::validate_redirect_uri_syntax(uri).map_err(err)?;
            check_redirect_uri_transport(uri).map_err(err)?;
        }
        let post_logout_redirect_uris = post_logout_redirect_uris.unwrap_or_default();
        for uri in &post_logout_redirect_uris {
            grp::validate_redirect_uri_syntax(uri).map_err(err)?;
        }
        let auth = resolve_client_auth(auth_method, client_secret, signing_key)?;
        Ok(Self {
            inner: grp::RpClient {
                client_id,
                redirect_uri,
                auth,
                scope: scope.to_string(),
            },
            post_logout_redirect_uris,
            redirect_uris,
            allow_unregistered_redirect_uri,
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
    /// Registered post-logout redirect URIs, as a tuple.
    #[getter]
    fn post_logout_redirect_uris<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyTuple>> {
        PyTuple::new(py, &self.post_logout_redirect_uris)
    }
    /// Registered alternative login redirect URIs, as a tuple.
    #[getter]
    fn redirect_uris<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyTuple>> {
        PyTuple::new(py, &self.redirect_uris)
    }
    /// Whether any syntactically valid per-call `redirect_uri` is accepted.
    #[getter]
    fn allow_unregistered_redirect_uri(&self) -> bool {
        self.allow_unregistered_redirect_uri
    }
    /// The token-endpoint authentication method as a string.
    #[getter]
    fn auth_method(&self) -> &'static str {
        auth_method_name(&self.inner.auth)
    }

    fn __repr__(&self) -> String {
        format!(
            "RpClient(client_id={:?}, redirect_uri={:?}, scope={:?}, auth_method={:?}, post_logout_redirect_uris={:?}, redirect_uris={:?}, allow_unregistered_redirect_uri={})",
            self.inner.client_id,
            self.inner.redirect_uri,
            self.inner.scope,
            auth_method_name(&self.inner.auth),
            self.post_logout_redirect_uris,
            self.redirect_uris,
            if self.allow_unregistered_redirect_uri { "True" } else { "False" }
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
    fn access_token(&self) -> &str {
        &self.inner.access_token
    }
    #[getter]
    fn id_token(&self) -> &str {
        &self.inner.id_token
    }
    #[getter]
    fn token_type(&self) -> &str {
        &self.inner.token_type
    }
    /// The complete token-endpoint response as a dict.
    #[getter]
    fn raw<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        to_py(py, &self.inner.raw)
    }

    fn __repr__(&self) -> String {
        format!(
            "TokenSet(token_type={:?}, access_token=<set>, id_token=<set>)",
            self.inner.token_type,
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

/// Return the upstream client, with `redirect_uri` swapped in when given.
///
/// SECURITY: an override is accepted only if it equals the client's
/// configured `redirect_uri` or one of its registered `redirect_uris`
/// (exact string match), or the client opted in with
/// `allow_unregistered_redirect_uri=True` (then it must still be valid and
/// not plain http to a non-loopback host). Otherwise `BadRequestError`.
fn effective_client(client: &RpClient, redirect_uri: Option<String>) -> PyResult<grp::RpClient> {
    let mut inner = client.inner.clone();
    if let Some(r) = redirect_uri {
        if r != inner.redirect_uri {
            let registered = client.redirect_uris.contains(&r);
            if !registered {
                if !client.allow_unregistered_redirect_uri {
                    return Err(err(RsError::BadRequest(
                        "redirect_uri override must be registered on the client \
                         (RpClient(redirect_uris=[...])) and match exactly; \
                         allow_unregistered_redirect_uri=True disables this check \
                         (only for RFC 7591 dynamic registrations, never with \
                         request-supplied values)"
                            .into(),
                    )));
                }
                grp::validate_redirect_uri_syntax(&r).map_err(err)?;
                check_redirect_uri_transport(&r).map_err(err)?;
            }
            inner.redirect_uri = r;
        }
    }
    Ok(inner)
}

/// Build the authorization request URL to redirect the user to.
///
/// `redirect_uri` overrides the client's configured value for this request
/// only; it must equal the client's `redirect_uri` or one of its registered
/// `redirect_uris` (exact match), or the client must be built with
/// `allow_unregistered_redirect_uri=True`. Never take it from request
/// parameters. The same value must be passed to `exchange_code`.
///
/// `state` and `nonce` must be fresh random values bound to the user's
/// session; `code_challenge` is the PKCE `S256` challenge
/// (`pygrindvakt.pkce.s256_challenge`). `extra` adds further query
/// parameters (e.g. `{"prompt": "login"}` or a signed `request` object).
#[pyfunction]
#[pyo3(signature = (provider, client, state, nonce, code_challenge = None, extra = None, *, redirect_uri = None))]
fn authorization_url(
    provider: &ProviderInfo,
    client: &RpClient,
    state: &str,
    nonce: &str,
    code_challenge: Option<&str>,
    extra: Option<&Bound<'_, PyAny>>,
    redirect_uri: Option<String>,
) -> PyResult<String> {
    let client = effective_client(client, redirect_uri)?;
    let extra = extra_params(extra)?;
    let extra_refs: Vec<(&str, &str)> = extra
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    grp::authorization_url(
        &provider.inner,
        &client,
        state,
        nonce,
        code_challenge,
        &extra_refs,
    )
    .map_err(err)
}

/// Build a signed request object (RFC 9101, "JAR") carrying the
/// authorization-request parameters as JWT claims, signed with `key`.
///
/// OpenID Federation automatic registration needs this: pass the result as
/// the `request` parameter (via `authorization_url(..., extra={"request": jar})`)
/// alongside the plain parameters. `key` must be one of the RP's published
/// client keys. The object is valid for 300 seconds and carries a `jti`.
/// `redirect_uri` overrides the client's value, as in `authorization_url`.
#[pyfunction]
#[pyo3(signature = (provider, client, key, state, nonce, code_challenge = None, *, redirect_uri = None))]
fn signed_request_object(
    provider: &ProviderInfo,
    client: &RpClient,
    key: &SigningKey,
    state: &str,
    nonce: &str,
    code_challenge: Option<&str>,
    redirect_uri: Option<String>,
) -> PyResult<String> {
    let client = effective_client(client, redirect_uri)?;
    grp::signed_request_object(
        &provider.inner,
        &client,
        &key.inner,
        state,
        nonce,
        code_challenge,
    )
    .map_err(err)
}

/// Start an authorization-code flow in one call.
///
/// Generates a fresh `state` and `nonce` (32 random bytes each) and, unless
/// `pkce=False`, a PKCE verifier (48 random bytes, 64 characters) with its
/// `S256` challenge. Returns `(url, state, nonce, verifier)`; `verifier` is
/// `None` when `pkce=False`. Store `state`, `nonce` and `verifier` (and
/// `redirect_uri`, if overridden) in the user's session.
///
/// Public clients (`auth_method="none"`) cannot disable PKCE: `pkce=False`
/// raises `BadRequestError`. When `request_object_key` is given, a signed
/// request object (RFC 9101) is added as `extra["request"]`.
#[pyfunction]
#[pyo3(signature = (provider, client, *, extra = None, redirect_uri = None, pkce = true, request_object_key = None))]
fn begin(
    provider: &ProviderInfo,
    client: &RpClient,
    extra: Option<&Bound<'_, PyAny>>,
    redirect_uri: Option<String>,
    pkce: bool,
    request_object_key: Option<&SigningKey>,
) -> PyResult<(String, String, String, Option<String>)> {
    let client = effective_client(client, redirect_uri)?;
    let mut extra = extra_params(extra)?;
    let state = grindvakt::util::random_token(32);
    let nonce = grindvakt::util::random_token(32);
    let verifier = pkce.then(|| grindvakt::util::random_token(48));
    let challenge = verifier.as_deref().map(grindvakt::pkce::s256_challenge);
    if let Some(key) = request_object_key {
        let jar = grp::signed_request_object(
            &provider.inner,
            &client,
            &key.inner,
            &state,
            &nonce,
            challenge.as_deref(),
        )
        .map_err(err)?;
        extra.push(("request".to_string(), jar));
    }
    let extra_refs: Vec<(&str, &str)> = extra
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let url = grp::authorization_url(
        &provider.inner,
        &client,
        &state,
        &nonce,
        challenge.as_deref(),
        &extra_refs,
    )
    .map_err(err)?;
    Ok((url, state, nonce, verifier))
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
    let (http, failures) = extract_http_client(http)?;
    // `grp::discover` returns only the parsed struct. Wrap the client so the
    // body it fetched can be kept as `raw`; all validation stays upstream.
    let recorder = Arc::new(BodyRecorder {
        inner: http,
        last_ok_body: Mutex::new(None),
    });
    let client: Arc<dyn HttpClient> = recorder.clone();
    let r = crate::runtime::block_on(py, async move { grp::discover(&client, &issuer).await })?;
    let metadata = r.map_err(|e| failures.err(py, e))?;
    let raw = recorder
        .last_ok_body
        .lock()
        .ok()
        .and_then(|mut g| g.take())
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| match v {
            serde_json::Value::Object(m) => Some(m),
            _ => None,
        });
    Ok(match raw {
        Some(raw) => ProviderMetadata::wrap_with_raw(metadata, raw),
        // Unreachable in practice (upstream parsed the same body); fall back
        // to the re-serialized document.
        None => {
            let raw = match metadata.to_json() {
                serde_json::Value::Object(m) => Some(m),
                _ => None,
            };
            match raw {
                Some(raw) => ProviderMetadata::wrap_with_raw(metadata, raw),
                None => ProviderMetadata::wrap(metadata),
            }
        }
    })
}

/// `HttpClient` decorator remembering the body of the last 200 GET response.
struct BodyRecorder {
    inner: Arc<dyn HttpClient>,
    last_ok_body: Mutex<Option<Vec<u8>>>,
}

#[async_trait]
impl HttpClient for BodyRecorder {
    async fn get(&self, url: &str) -> grindvakt::Result<HttpFetchResponse> {
        let resp = self.inner.get(url).await?;
        if resp.status == 200 {
            if let Ok(mut g) = self.last_ok_body.lock() {
                *g = Some(resp.body.clone());
            }
        }
        Ok(resp)
    }

    async fn post_form(
        &self,
        url: &str,
        form: &[(String, String)],
        headers: &[(String, String)],
    ) -> grindvakt::Result<HttpFetchResponse> {
        self.inner.post_form(url, form, headers).await
    }

    async fn get_with_headers(
        &self,
        url: &str,
        headers: &[(String, String)],
    ) -> grindvakt::Result<HttpFetchResponse> {
        self.inner.get_with_headers(url, headers).await
    }
}

/// Library-controlled RP-Initiated Logout parameters.
const END_SESSION_RESERVED: &[&str] = &[
    "id_token_hint",
    "client_id",
    "post_logout_redirect_uri",
    "state",
    "logout_hint",
    "ui_locales",
];

fn non_empty(name: &str, v: Option<&str>) -> PyResult<()> {
    if v == Some("") {
        return Err(err(RsError::BadRequest(format!(
            "{name} must not be empty"
        ))));
    }
    Ok(())
}

/// Build the OIDC RP-Initiated Logout 1.0 request URL to redirect the user to.
///
/// Parameters are appended to the provider's `end_session_endpoint` (any
/// existing query is preserved) with proper encoding. `client` adds
/// `client_id`. `post_logout_redirect_uri` is accepted only if `client` is
/// given and the value exactly equals one of
/// `client.post_logout_redirect_uris` (pre-registration with exact match, as
/// RP-Initiated Logout requires); this prevents an open redirect when the
/// value comes from a request parameter. It must also be an absolute URL
/// without a fragment and registered with the OP.
/// `extra` (dict or list of pairs) may not contain the parameters controlled
/// by this function. Raises `ConfigError` if the provider has no
/// `end_session_endpoint`, `BadRequestError` for unsafe or invalid input.
#[pyfunction]
#[pyo3(signature = (provider, *, id_token_hint = None, client = None, post_logout_redirect_uri = None, state = None, logout_hint = None, ui_locales = None, extra = None))]
#[allow(clippy::too_many_arguments)]
fn end_session_url(
    provider: &ProviderInfo,
    id_token_hint: Option<&str>,
    client: Option<&RpClient>,
    post_logout_redirect_uri: Option<&str>,
    state: Option<&str>,
    logout_hint: Option<&str>,
    ui_locales: Option<&str>,
    extra: Option<&Bound<'_, PyAny>>,
) -> PyResult<String> {
    let endpoint = provider.end_session_endpoint.as_deref().ok_or_else(|| {
        err(RsError::Config(
            "provider has no usable end_session_endpoint (the advertised endpoint was missing, \
             unsafe, or on a different origin than the issuer)"
                .into(),
        ))
    })?;
    // Origin binding was decided when the ProviderInfo was built (it may have
    // opted in); re-check only the shared safety rules here.
    validate_end_session_endpoint(endpoint, &provider.inner.issuer, true)?;
    let mut url = url::Url::parse(endpoint).map_err(|e| {
        err(RsError::BadRequest(format!(
            "invalid end_session_endpoint: {e}"
        )))
    })?;
    if url
        .query_pairs()
        .any(|(k, _)| END_SESSION_RESERVED.contains(&k.as_ref()))
    {
        return Err(err(RsError::BadRequest(
            "end_session_endpoint query contains a library-controlled parameter".into(),
        )));
    }
    for (name, v) in [
        ("id_token_hint", id_token_hint),
        ("post_logout_redirect_uri", post_logout_redirect_uri),
        ("state", state),
        ("logout_hint", logout_hint),
        ("ui_locales", ui_locales),
    ] {
        non_empty(name, v)?;
    }
    if let Some(uri) = post_logout_redirect_uri {
        grp::validate_redirect_uri_syntax(uri).map_err(err)?;
        // Exact match against the client's registration, never the caller's
        // say-so: otherwise a request-supplied value makes logout an open
        // redirect that also carries `id_token_hint`.
        let registered = client.is_some_and(|c| {
            c.post_logout_redirect_uris
                .iter()
                .any(|r| r.as_str() == uri)
        });
        if !registered {
            return Err(err(RsError::BadRequest(
                "post_logout_redirect_uri must be registered on the client \
                 (RpClient(post_logout_redirect_uris=[...])) and match exactly"
                    .into(),
            )));
        }
    }
    let extra = extra_params(extra)?;
    if let Some((k, _)) = extra
        .iter()
        .find(|(k, _)| END_SESSION_RESERVED.contains(&k.as_str()))
    {
        return Err(err(RsError::BadRequest(format!(
            "extra must not contain library-controlled parameter {k:?}"
        ))));
    }
    {
        let mut q = url.query_pairs_mut();
        if let Some(v) = id_token_hint {
            q.append_pair("id_token_hint", v);
        }
        if let Some(c) = client {
            q.append_pair("client_id", &c.inner.client_id);
        }
        if let Some(v) = post_logout_redirect_uri {
            q.append_pair("post_logout_redirect_uri", v);
        }
        if let Some(v) = state {
            q.append_pair("state", v);
        }
        if let Some(v) = logout_hint {
            q.append_pair("logout_hint", v);
        }
        if let Some(v) = ui_locales {
            q.append_pair("ui_locales", v);
        }
        for (k, v) in &extra {
            q.append_pair(k, v);
        }
    }
    Ok(url.into())
}

/// Fetch a JWKS document from `jwks_uri` for its associated `issuer` and
/// return it as a dict (`{"keys": [...]}`), ready for `verify_id_token`.
///
/// The issuer is required so loopback HTTP is allowed only for an explicitly
/// loopback HTTP development issuer.
#[pyfunction]
#[pyo3(signature = (http, jwks_uri, issuer))]
fn fetch_jwks<'py>(
    py: Python<'py>,
    http: Option<&Bound<'py, PyAny>>,
    jwks_uri: String,
    issuer: String,
) -> PyResult<Bound<'py, PyAny>> {
    let (http, failures) = extract_http_client(http)?;
    let r = crate::runtime::block_on(py, async move {
        grp::fetch_jwks(&http, &jwks_uri, &issuer).await
    })?;
    let jwks = r.map_err(|e| failures.err(py, e))?;
    to_py(py, &jwks)
}

/// Exchange an authorization `code` for tokens at the provider's token
/// endpoint, authenticating as configured on `client`. `code_verifier` is the
/// PKCE verifier matching the challenge sent in `authorization_url`.
///
/// If the authorization request used a `redirect_uri` override, pass the
/// same value here (RFC 6749 section 4.1.3); store it in the session with
/// the state, nonce and verifier.
///
/// A non-200 response raises `AuthnError` (generic message) with the
/// sanitized upstream details in `code` / `upstream_*`.
#[pyfunction]
#[pyo3(signature = (http, provider, client, code, code_verifier = None, *, redirect_uri = None))]
fn exchange_code(
    py: Python<'_>,
    http: Option<&Bound<'_, PyAny>>,
    provider: &ProviderInfo,
    client: &RpClient,
    code: String,
    code_verifier: Option<String>,
    redirect_uri: Option<String>,
) -> PyResult<TokenSet> {
    let (http, failures) = extract_http_client(http)?;
    let provider = provider.inner.clone();
    let client = effective_client(client, redirect_uri)?;
    let r = crate::runtime::block_on(py, async move {
        grp::exchange_code(&http, &provider, &client, &code, code_verifier.as_deref()).await
    })?;
    r.map(|inner| TokenSet { inner })
        .map_err(|e| failures.err(py, e))
}

/// Convert a Python int option to an unsigned seconds value.
fn seconds(name: &str, v: Option<i64>) -> PyResult<Option<u64>> {
    v.map(|v| {
        u64::try_from(v).map_err(|_| PyValueError::new_err(format!("{name} must not be negative")))
    })
    .transpose()
}

fn parse_algorithms(algs: &[String]) -> PyResult<Vec<JwsAlgorithm>> {
    algs.iter()
        .map(|alg| {
            JwsAlgorithm::from_str(alg)
                .map_err(|e| PyValueError::new_err(format!("invalid JWS algorithm {alg:?}: {e}")))
        })
        .collect()
}

/// Enforce the nonce policy shared by `verify_id_token` and
/// `JwksCache.verify_id_token`.
fn check_nonce_policy(
    py: Python<'_>,
    expected_nonce: Option<&str>,
    unsafe_skip_nonce_check: bool,
) -> PyResult<()> {
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
    Ok(())
}

/// Everything `grindvakt::rp::verify_id_token_with` needs besides the key set
/// and the token itself.
struct IdTokenPolicy {
    algorithms: Vec<JwsAlgorithm>,
    trusted_additional_audiences: Vec<String>,
    leeway: Option<u64>,
    max_age: Option<u64>,
    acr_values: Option<Vec<String>>,
    access_token: Option<String>,
    require_at_hash: bool,
    authorization_code: Option<String>,
    require_c_hash: bool,
    strict_hashes: bool,
}

impl IdTokenPolicy {
    #[allow(clippy::too_many_arguments)]
    fn new(
        allowed_algorithms: &[String],
        trusted_additional_audiences: Option<Vec<String>>,
        leeway: Option<i64>,
        max_age: Option<i64>,
        acr_values: Option<Vec<String>>,
        access_token: Option<String>,
        require_at_hash: bool,
        authorization_code: Option<String>,
        require_c_hash: bool,
        strict_hashes: bool,
    ) -> PyResult<Self> {
        let policy = Self {
            algorithms: parse_algorithms(allowed_algorithms)?,
            trusted_additional_audiences: trusted_additional_audiences.unwrap_or_default(),
            leeway: seconds("leeway", leeway)?,
            max_age: seconds("max_age", max_age)?,
            acr_values,
            access_token,
            require_at_hash,
            authorization_code,
            require_c_hash,
            strict_hashes,
        };
        // Fail on configuration errors before any key-set fetch; upstream
        // repeats these checks.
        if policy.require_at_hash && policy.access_token.is_none() {
            return Err(err(RsError::BadRequest(
                "require_at_hash needs an access_token to check against".into(),
            )));
        }
        if policy.require_c_hash && policy.authorization_code.is_none() {
            return Err(err(RsError::BadRequest(
                "require_c_hash needs an authorization_code to check against".into(),
            )));
        }
        if policy.leeway.is_some_and(|l| l > grp::MAX_ID_TOKEN_LEEWAY) {
            return Err(err(RsError::BadRequest(format!(
                "id_token leeway must be at most {} seconds",
                grp::MAX_ID_TOKEN_LEEWAY
            ))));
        }
        if policy.acr_values.as_ref().is_some_and(Vec::is_empty) {
            return Err(err(RsError::BadRequest(
                "acr_values must not be empty when set".into(),
            )));
        }
        Ok(policy)
    }

    fn verify(
        &self,
        py: Python<'_>,
        jwks: &JwkSet,
        id_token: &str,
        issuer: &str,
        client_id: &str,
        expected_nonce: Option<&str>,
    ) -> PyResult<Py<PyAny>> {
        let trusted = self
            .trusted_additional_audiences
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let acr = self
            .acr_values
            .as_ref()
            .map(|v| v.iter().map(String::as_str).collect::<Vec<_>>());
        // Unless `strict_hashes`, `allow_unchecked_hashes` keeps
        // `verify_id_token`'s historical behaviour: an at_hash / c_hash is
        // checked when the matching value is given and ignored otherwise.
        let mut options = grp::IdTokenOptions::new();
        if !self.strict_hashes {
            options = options.allow_unchecked_hashes();
        }
        if let Some(v) = self.leeway {
            options = options.with_leeway(v);
        }
        if let Some(v) = self.max_age {
            options = options.with_max_age(v);
        }
        if let Some(v) = acr.as_deref() {
            options = options.with_acr_values(v);
        }
        if let Some(v) = self.access_token.as_deref() {
            options = options.with_access_token(v);
        }
        if self.require_at_hash {
            options = options.with_required_at_hash();
        }
        if let Some(v) = self.authorization_code.as_deref() {
            options = options.with_authorization_code(v);
        }
        if self.require_c_hash {
            options = options.with_required_c_hash();
        }
        let claims = grp::verify_id_token_with(
            jwks,
            id_token,
            issuer,
            client_id,
            expected_nonce,
            &self.algorithms,
            &trusted,
            &options,
        )
        .map_err(err)?;
        Ok(to_py(py, &claims)?.unbind())
    }
}

/// Verify an `id_token` against the provider JWKS (a dict `{"keys": [...]}`
/// or a `JwksCache`), `issuer`, audience `client_id`, and `expected_nonce`;
/// `sub`, `exp`, and `iat` are required. The protected algorithm must be
/// explicitly allowed; all other audiences must be explicitly trusted and
/// multi-audience tokens must name this client in `azp`. Returns the validated
/// claims as a dict.
///
/// `expected_nonce` is the nonce this RP sent in the authorization request.
/// Passing `None` is refused with `AuthnError` unless
/// `unsafe_skip_nonce_check=True` is given as well, which disables the nonce
/// check entirely and emits a `UserWarning`.
///
/// SECURITY: only skip the nonce check for flows that genuinely carry no
/// nonce (e.g. a pure OAuth 2.0 flow that still returns an id_token). Skipping
/// it for the standard code flow allows id_token replay.
///
/// Optional extra checks (keyword-only, all off by default):
///
/// * `leeway`: clock-skew tolerance in seconds for `exp` / `nbf` / `iat` and
///   the future-`auth_time` check (default 60; above 300 is `BadRequestError`).
/// * `max_age`: requires a numeric `auth_time` claim no older than `max_age`
///   seconds (`iat` is not used; a missing or non-numeric `auth_time` is an
///   `AuthnError`; leeway is not added).
/// * `acr_values`: the `acr` claim must be present and in this list.
/// * `access_token` / `authorization_code`: validate `at_hash` / `c_hash`
///   when the id_token carries one. `require_at_hash` / `require_c_hash`
///   additionally reject tokens without the claim (they need the matching
///   value, else `BadRequestError`). An `EdDSA` token carrying a hash claim
///   cannot be checked (`CryptoError`).
/// * `strict_hashes`: reject (`AuthnError`) an id_token that carries
///   `at_hash` / `c_hash` when the matching `access_token` /
///   `authorization_code` is not given. Without it such a claim is ignored,
///   so implicit / hybrid flows must pass the values (with `require_*`) or
///   set this.
#[pyfunction]
#[pyo3(signature = (jwks, id_token, issuer, client_id, expected_nonce, allowed_algorithms,
                    trusted_additional_audiences = None, unsafe_skip_nonce_check = false, *,
                    leeway = None, max_age = None, acr_values = None, access_token = None,
                    require_at_hash = false, authorization_code = None, require_c_hash = false,
                    strict_hashes = false))]
// These arguments are deliberately explicit security-policy inputs in the
// public Python API; hiding them in an options bag would make unsafe defaults
// easier to overlook.
#[allow(clippy::too_many_arguments)]
fn verify_id_token<'py>(
    py: Python<'py>,
    jwks: &Bound<'py, PyAny>,
    id_token: &str,
    issuer: &str,
    client_id: &str,
    expected_nonce: Option<&str>,
    allowed_algorithms: Vec<String>,
    trusted_additional_audiences: Option<Vec<String>>,
    unsafe_skip_nonce_check: bool,
    leeway: Option<i64>,
    max_age: Option<i64>,
    acr_values: Option<Vec<String>>,
    access_token: Option<String>,
    require_at_hash: bool,
    authorization_code: Option<String>,
    require_c_hash: bool,
    strict_hashes: bool,
) -> PyResult<Bound<'py, PyAny>> {
    check_nonce_policy(py, expected_nonce, unsafe_skip_nonce_check)?;
    let policy = IdTokenPolicy::new(
        &allowed_algorithms,
        trusted_additional_audiences,
        leeway,
        max_age,
        acr_values,
        access_token,
        require_at_hash,
        authorization_code,
        require_c_hash,
        strict_hashes,
    );
    let set = JwksSource::from_py(jwks)?;
    let policy = policy?;
    let set = set.resolve(py, id_token, issuer)?;
    Ok(policy
        .verify(py, &set, id_token, issuer, client_id, expected_nonce)?
        .into_bound(py))
}

// ---------------------------------------------------------------------------
// JwksCache
// ---------------------------------------------------------------------------

/// A JWKS argument: a literal key set or a `JwksCache`.
enum JwksSource<'py> {
    Set(Arc<JwkSet>),
    Cache(Bound<'py, JwksCache>),
}

impl<'py> JwksSource<'py> {
    fn from_py(obj: &Bound<'py, PyAny>) -> PyResult<Self> {
        if let Ok(cache) = obj.cast::<JwksCache>() {
            return Ok(Self::Cache(cache.clone()));
        }
        Ok(Self::Set(Arc::new(jwks_from_py(obj)?)))
    }

    /// A cache is bound to one issuer. `issuer` is the issuer the caller will
    /// verify against, and it must equal the cache's issuer, so keys of one
    /// provider can never vouch for another provider's `iss`. Call this
    /// before any network request.
    fn check_issuer(&self, issuer: &str) -> PyResult<()> {
        match self {
            Self::Cache(cache) if cache.get().issuer != issuer => Err(err(RsError::BadRequest(
                "JwksCache issuer does not match the issuer argument".into(),
            ))),
            _ => Ok(()),
        }
    }

    /// The key set to verify `token` against (for a cache: refreshed once if
    /// the token's `kid` is unknown). Rejects an issuer mismatch first.
    fn resolve(&self, py: Python<'py>, token: &str, issuer: &str) -> PyResult<Arc<JwkSet>> {
        self.check_issuer(issuer)?;
        match self {
            Self::Set(set) => Ok(set.clone()),
            Self::Cache(cache) => cache.get().resolve_for_token(py, token),
        }
    }
}

/// Monotonic seconds since first use; the default cache clock. Unaffected by
/// wall-clock changes and valid across `fork`.
fn monotonic_now() -> f64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_secs_f64()
}

struct CacheEntry {
    jwks: Arc<JwkSet>,
    expires_at: f64,
}

#[derive(Default)]
struct CacheState {
    entry: Option<Arc<CacheEntry>>,
    /// Clock reading of the latest fetch attempt (successful or not).
    last_attempt: Option<f64>,
}

/// Wraps the fetch client to note whether any response carried headers.
struct HeaderProbe {
    inner: Arc<dyn HttpClient>,
    saw_response: std::sync::atomic::AtomicBool,
    saw_headers: std::sync::atomic::AtomicBool,
}

impl HeaderProbe {
    fn note(
        &self,
        r: grindvakt::Result<HttpFetchResponse>,
    ) -> grindvakt::Result<HttpFetchResponse> {
        use std::sync::atomic::Ordering::Relaxed;
        if let Ok(resp) = &r {
            self.saw_response.store(true, Relaxed);
            if !resp.headers.is_empty() {
                self.saw_headers.store(true, Relaxed);
            }
        }
        r
    }

    /// A response arrived and none of them had any header.
    fn headerless(&self) -> bool {
        use std::sync::atomic::Ordering::Relaxed;
        self.saw_response.load(Relaxed) && !self.saw_headers.load(Relaxed)
    }
}

#[async_trait]
impl HttpClient for HeaderProbe {
    async fn get(&self, url: &str) -> grindvakt::Result<HttpFetchResponse> {
        let r = self.inner.get(url).await;
        self.note(r)
    }

    async fn post_form(
        &self,
        url: &str,
        form: &[(String, String)],
        headers: &[(String, String)],
    ) -> grindvakt::Result<HttpFetchResponse> {
        let r = self.inner.post_form(url, form, headers).await;
        self.note(r)
    }

    async fn get_with_headers(
        &self,
        url: &str,
        headers: &[(String, String)],
    ) -> grindvakt::Result<HttpFetchResponse> {
        let r = self.inner.get_with_headers(url, headers).await;
        self.note(r)
    }
}

/// RAII token for the single in-flight fetch; see `JwksCache::begin_flight`.
struct Flight<'a> {
    cache: &'a JwksCache,
}

impl Drop for Flight<'_> {
    fn drop(&mut self) {
        let mut busy = self.cache.flight.lock().unwrap_or_else(|e| e.into_inner());
        *busy = false;
        self.cache.flight_done.notify_one();
    }
}

/// A caching JWK Set fetcher for one issuer.
///
/// Holds the key set fetched from `jwks_uri` and refetches it when it
/// expires. The lifetime is the response's `Cache-Control: max-age` minus
/// `Age` when present, else `default_ttl`, clamped to `[min_ttl, max_ttl]`
/// (so `no-store` / `no-cache` / `max-age=0` are floored to `min_ttl`; set
/// `min_ttl=0` to leave them uncached). Cache-Control is honoured only when
/// the `HttpClient` reports response headers: the built-in client (`None` /
/// `ReqwestClient`) always does, a Python adapter must return them (see
/// `HttpFetchResponse`); otherwise `default_ttl` applies and a `UserWarning`
/// is emitted on the first fetch. An expired set is never served: a
/// failed refetch raises. Concurrent callers share a single fetch.
///
/// `verify_id_token` refreshes the set at most once when the token's `kid` is
/// not in it (key rotation), but no more often than `min_refresh_interval`
/// seconds after the previous fetch attempt; if the `kid` is still unknown it
/// raises `UnknownKeyError`. The cache is plain in-process memory: it stays
/// valid in a forked child, but fork only while no other thread is inside a
/// cache call.
///
/// `_now` is a private test hook: a zero-argument callable returning the
/// clock in seconds.
#[pyclass(module = "pygrindvakt.rp", name = "JwksCache", frozen)]
pub struct JwksCache {
    http: Option<Py<PyAny>>,
    jwks_uri: String,
    issuer: String,
    default_ttl: u64,
    min_ttl: u64,
    max_ttl: u64,
    min_refresh_interval: u64,
    clock: Option<Py<PyAny>>,
    state: RwLock<CacheState>,
    flight: Mutex<bool>,
    flight_done: Condvar,
    /// The no-response-headers warning is emitted once per cache.
    warned_no_headers: std::sync::atomic::AtomicBool,
}

impl JwksCache {
    fn now(&self) -> f64 {
        match &self.clock {
            Some(clock) => Python::attach(|py| clock.call0(py).and_then(|v| v.extract::<f64>(py)))
                .unwrap_or_else(|_| monotonic_now()),
            None => monotonic_now(),
        }
    }

    fn snapshot(&self) -> Option<Arc<CacheEntry>> {
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .entry
            .clone()
    }

    fn valid_entry(&self, now: f64) -> Option<Arc<CacheEntry>> {
        self.snapshot().filter(|e| now < e.expires_at)
    }

    /// Wait (with the GIL released, because the holder needs the GIL to run a
    /// Python HTTP adapter) until no other thread is fetching, then become the
    /// fetching thread.
    fn begin_flight(&self, py: Python<'_>) -> Flight<'_> {
        py.detach(|| {
            let mut busy = self.flight.lock().unwrap_or_else(|e| e.into_inner());
            while *busy {
                busy = self
                    .flight_done
                    .wait(busy)
                    .unwrap_or_else(|e| e.into_inner());
            }
            *busy = true;
        });
        Flight { cache: self }
    }

    fn rate_limited(&self, now: f64) -> bool {
        let last = self
            .state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .last_attempt;
        last.is_some_and(|t| now - t < self.min_refresh_interval as f64)
    }

    /// Fetch and store the key set. The caller holds the flight.
    fn fetch(&self, py: Python<'_>) -> PyResult<Arc<CacheEntry>> {
        let attempt = self.now();
        self.state
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .last_attempt = Some(attempt);
        // A fresh client (and `Failures` slot) per fetch, so a transport
        // error is chained to this call's failure only.
        let (http, failures) = extract_http_client(self.http.as_ref().map(|h| h.bind(py)))?;
        let (uri, issuer) = (self.jwks_uri.clone(), self.issuer.clone());
        let probe = Arc::new(HeaderProbe {
            inner: http,
            saw_response: Default::default(),
            saw_headers: Default::default(),
        });
        let client: Arc<dyn HttpClient> = probe.clone();
        let r = crate::runtime::block_on(py, async move {
            grp::fetch_jwks_response(&client, &uri, &issuer).await
        })?;
        let resp = r.map_err(|e| failures.err(py, e))?;
        if probe.headerless()
            && !self
                .warned_no_headers
                .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            warn(
                py,
                &format!(
                    "this HttpClient reports no response headers; Cache-Control is ignored and \
                     default_ttl ({}s) applies; return headers from your HttpClient or lower \
                     default_ttl/max_ttl",
                    self.default_ttl
                ),
            );
        }
        let ttl = resp
            .cache_ttl_secs()
            .unwrap_or(self.default_ttl)
            .clamp(self.min_ttl, self.max_ttl);
        let entry = Arc::new(CacheEntry {
            jwks: Arc::new(resp.jwks),
            expires_at: self.now() + ttl as f64,
        });
        self.state.write().unwrap_or_else(|e| e.into_inner()).entry = Some(entry.clone());
        Ok(entry)
    }

    /// The current key set, fetching it first if there is none or it expired.
    fn ensure(&self, py: Python<'_>) -> PyResult<Arc<CacheEntry>> {
        if let Some(e) = self.valid_entry(self.now()) {
            return Ok(e);
        }
        let _flight = self.begin_flight(py);
        // Another thread may have fetched while we waited.
        if let Some(e) = self.valid_entry(self.now()) {
            return Ok(e);
        }
        self.fetch(py)
    }

    fn resolve_for_token(&self, py: Python<'_>, token: &str) -> PyResult<Arc<JwkSet>> {
        let entry = self.ensure(py)?;
        // An unreadable header is left to the verifier's own error.
        let Some(kid) = gj::peek_header(token).ok().and_then(|h| h.kid) else {
            return Ok(entry.jwks.clone());
        };
        if !kid_unknown(&entry.jwks, &kid) {
            return Ok(entry.jwks.clone());
        }
        let _flight = self.begin_flight(py);
        // Re-select through `valid_entry`: the wait may have outlived the old
        // entry, or another thread may have stored a zero-TTL set. Never
        // verify with an expired snapshot; fetch again instead.
        let now = self.now();
        let entry = match self.valid_entry(now) {
            // Another thread refreshed while we waited.
            Some(current) if !Arc::ptr_eq(&current, &entry) => current,
            // Rate-limited: keep the (still valid) entry we already have.
            Some(current) if self.rate_limited(now) => current,
            _ => self.fetch(py)?,
        };
        if kid_unknown(&entry.jwks, &kid) {
            return Err(UnknownKeyError::new_err(
                "token kid does not name a key in the issuer's JWK Set (refresh may have been skipped by the minimum refresh interval)",
            ));
        }
        Ok(entry.jwks.clone())
    }
}

/// The set has keys with a `kid` and none of them is `kid`.
fn kid_unknown(jwks: &JwkSet, kid: &str) -> bool {
    jwks.keys.iter().any(|k| k.kid.is_some())
        && !jwks.keys.iter().any(|k| k.kid.as_deref() == Some(kid))
}

#[pymethods]
impl JwksCache {
    #[new]
    #[pyo3(signature = (http, jwks_uri, issuer, *, default_ttl = 3600, min_ttl = 60,
                        max_ttl = 86400, min_refresh_interval = 30, _now = None))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        http: Option<&Bound<'_, PyAny>>,
        jwks_uri: String,
        issuer: String,
        default_ttl: i64,
        min_ttl: i64,
        max_ttl: i64,
        min_refresh_interval: i64,
        _now: Option<Py<PyAny>>,
    ) -> PyResult<Self> {
        // Validate the client and the URLs now rather than on first use.
        extract_http_client(http)?;
        grp::validate_issuer(&issuer).map_err(err)?;
        grp::validate_service_endpoint_for_issuer("jwks_uri", &jwks_uri, &issuer).map_err(err)?;
        let get = |n: &str, v: i64| seconds(n, Some(v)).map(Option::unwrap_or_default);
        let (default_ttl, min_ttl, max_ttl) = (
            get("default_ttl", default_ttl)?,
            get("min_ttl", min_ttl)?,
            get("max_ttl", max_ttl)?,
        );
        if min_ttl > max_ttl {
            return Err(PyValueError::new_err("min_ttl must not exceed max_ttl"));
        }
        Ok(Self {
            http: http.filter(|h| !h.is_none()).map(|h| h.clone().unbind()),
            jwks_uri,
            issuer,
            default_ttl,
            min_ttl,
            max_ttl,
            min_refresh_interval: get("min_refresh_interval", min_refresh_interval)?,
            clock: _now,
            state: RwLock::default(),
            flight: Mutex::new(false),
            flight_done: Condvar::new(),
            warned_no_headers: Default::default(),
        })
    }

    #[getter]
    fn jwks_uri(&self) -> &str {
        &self.jwks_uri
    }

    #[getter]
    fn issuer(&self) -> &str {
        &self.issuer
    }

    fn __repr__(&self) -> String {
        format!(
            "JwksCache(jwks_uri={:?}, issuer={:?})",
            self.jwks_uri, self.issuer
        )
    }

    /// The cached key set as a dict (`{"keys": [...]}`), fetching it first if
    /// none is cached or it expired. Raises if that fetch fails; an expired
    /// set is never returned.
    fn jwks<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let entry = self.ensure(py)?;
        to_py(py, &*entry.jwks)
    }

    /// Force a refetch. The first fetch always happens; afterwards a call
    /// within `min_refresh_interval` seconds of the previous fetch attempt is
    /// a silent no-op. A failed fetch raises and keeps the cached set.
    fn refresh(&self, py: Python<'_>) -> PyResult<()> {
        let _flight = self.begin_flight(py);
        if self.rate_limited(self.now()) {
            return Ok(());
        }
        self.fetch(py).map(|_| ())
    }

    /// `rp.verify_id_token` against this cache's key set for `issuer`; same
    /// keyword options. If the token's `kid` is not in the (non-empty-kid)
    /// set, the set is refreshed once (rate-limited) and a still-unknown
    /// `kid` raises `UnknownKeyError`. Tokens without `kid` follow
    /// `verify_id_token`.
    #[pyo3(signature = (id_token, client_id, expected_nonce, allowed_algorithms, *,
                        trusted_additional_audiences = None, unsafe_skip_nonce_check = false,
                        leeway = None, max_age = None, acr_values = None, access_token = None,
                        require_at_hash = false, authorization_code = None,
                        require_c_hash = false, strict_hashes = false))]
    #[allow(clippy::too_many_arguments)]
    fn verify_id_token<'py>(
        &self,
        py: Python<'py>,
        id_token: &str,
        client_id: &str,
        expected_nonce: Option<&str>,
        allowed_algorithms: Vec<String>,
        trusted_additional_audiences: Option<Vec<String>>,
        unsafe_skip_nonce_check: bool,
        leeway: Option<i64>,
        max_age: Option<i64>,
        acr_values: Option<Vec<String>>,
        access_token: Option<String>,
        require_at_hash: bool,
        authorization_code: Option<String>,
        require_c_hash: bool,
        strict_hashes: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        check_nonce_policy(py, expected_nonce, unsafe_skip_nonce_check)?;
        let policy = IdTokenPolicy::new(
            &allowed_algorithms,
            trusted_additional_audiences,
            leeway,
            max_age,
            acr_values,
            access_token,
            require_at_hash,
            authorization_code,
            require_c_hash,
            strict_hashes,
        )?;
        let set = self.resolve_for_token(py, id_token)?;
        Ok(policy
            .verify(py, &set, id_token, &self.issuer, client_id, expected_nonce)?
            .into_bound(py))
    }
}

/// Fetch the UserInfo document with a Bearer `access_token` and return its
/// claims as a dict, bound to `expected_sub` (the validated id_token subject).
///
/// `userinfo_endpoint` may be `None` (the OP did not advertise one), which
/// raises `ConfigError`. `method` is `"POST"` (default; empty form body) or
/// `"GET"` (needs an `http` client that supports request headers on GET, see
/// `pygrindvakt.http`).
///
/// A JSON response is parsed directly. A signed (`application/jwt`) response
/// fails closed unless `jwks`, `client_id`, `allowed_algorithms` and `trust`
/// are all given (`AuthnError`, `code == "userinfo_unverifiable"`). `trust`
/// states how the JWT is proven to be UserInfo and not a replayed id_token:
/// `"typed"` (needs `typ`), `"dedicated_keys"` or
/// `"untyped_shared_key_compat"` (weakest). `max_age` bounds the token age
/// from `iat` (default 300 s); `None` removes the bound, leaving replay
/// unbounded. Encrypted (JWE) responses are not supported.
#[pyfunction]
#[pyo3(signature = (http, userinfo_endpoint, access_token, expected_sub, issuer, *,
                    method = "POST", jwks = None, client_id = None,
                    allowed_algorithms = None, trust = None, typ = None,
                    max_age = Some(grp::DEFAULT_USERINFO_JWT_MAX_AGE), require_exp = false))]
#[allow(clippy::too_many_arguments)]
fn fetch_userinfo<'py>(
    py: Python<'py>,
    http: Option<&Bound<'py, PyAny>>,
    userinfo_endpoint: Option<String>,
    access_token: String,
    expected_sub: String,
    issuer: String,
    method: &str,
    jwks: Option<&Bound<'py, PyAny>>,
    client_id: Option<String>,
    allowed_algorithms: Option<Vec<String>>,
    trust: Option<&str>,
    typ: Option<String>,
    max_age: Option<u64>,
    require_exp: bool,
) -> PyResult<Bound<'py, PyAny>> {
    let method = match method {
        "POST" => grp::UserinfoMethod::Post,
        "GET" => grp::UserinfoMethod::Get,
        other => {
            return Err(PyValueError::new_err(format!(
                "method must be \"POST\" or \"GET\", got {other:?}"
            )))
        }
    };
    if let Some(other) =
        trust.filter(|t| !matches!(*t, "typed" | "dedicated_keys" | "untyped_shared_key_compat"))
    {
        return Err(PyValueError::new_err(format!(
            "trust must be \"typed\", \"dedicated_keys\" or \"untyped_shared_key_compat\", \
             got {other:?}"
        )));
    }
    if trust == Some("typed") && typ.is_none() {
        return Err(PyValueError::new_err("trust=\"typed\" requires typ"));
    }
    if typ.is_some() && trust != Some("typed") {
        return Err(PyValueError::new_err(
            "typ is only used with trust=\"typed\"",
        ));
    }
    let jwks = jwks.map(JwksSource::from_py).transpose()?;
    if let Some(jwks) = &jwks {
        jwks.check_issuer(&issuer)?;
    }
    let algs = allowed_algorithms
        .map(|algs| {
            algs.iter()
                .map(|alg| {
                    JwsAlgorithm::from_str(alg).map_err(|e| {
                        PyValueError::new_err(format!("invalid JWS algorithm {alg:?}: {e}"))
                    })
                })
                .collect::<PyResult<Vec<_>>>()
        })
        .transpose()?;
    let Some(userinfo_endpoint) = userinfo_endpoint else {
        return Err(ConfigError::new_err(
            "provider does not advertise a userinfo_endpoint",
        ));
    };

    let (http, failures) = extract_http_client(http)?;
    let resp = crate::runtime::block_on(py, async move {
        grp::fetch_userinfo_response(&http, &userinfo_endpoint, &access_token, &issuer, method)
            .await
            .map(|resp| (resp, issuer))
    })?;
    let (resp, issuer) = resp.map_err(|e| failures.err(py, e))?;

    let content_type = resp
        .content_type
        .as_deref()
        .or(resp.header("content-type"))
        .unwrap_or("");
    let is_jwt = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .eq_ignore_ascii_case("application/jwt");
    let claims = if !is_jwt {
        grp::userinfo_json_claims(&resp, &expected_sub).map_err(err)?
    } else {
        // Five dot-separated segments is a compact JWE.
        if resp.text().trim().split('.').count() == 5 {
            return Err(with_code(
                py,
                AuthnError::new_err(
                    "userinfo is an encrypted JWT (JWE); encrypted UserInfo responses are not supported",
                ),
                "userinfo_encrypted",
            ));
        }
        let unverifiable = |what: &str| {
            with_code(
                py,
                AuthnError::new_err(format!(
                    "userinfo is a signed JWT but cannot be verified: {what} required \
                     (refusing to trust an unverified response)"
                )),
                "userinfo_unverifiable",
            )
        };
        let jwks = jwks.as_ref().ok_or_else(|| unverifiable("jwks"))?;
        let client_id = client_id.ok_or_else(|| unverifiable("client_id"))?;
        let algs = algs
            .filter(|a| !a.is_empty())
            .ok_or_else(|| unverifiable("allowed_algorithms"))?;
        let mut options = match trust {
            Some("typed") => grp::UserinfoJwtOptions::typed(typ.as_deref().unwrap_or_default()),
            Some("dedicated_keys") => grp::UserinfoJwtOptions::dedicated_keys(),
            Some(_) => grp::UserinfoJwtOptions::untyped_shared_key_compat(),
            None => return Err(unverifiable("trust")),
        };
        options = match max_age {
            Some(secs) => options.with_max_age(secs),
            None => options.without_max_age(),
        };
        if require_exp {
            options = options.with_require_exp();
        }
        // A cache refreshes once if the response's `kid` is unknown.
        let jwks = jwks.resolve(py, resp.text().trim(), &issuer)?;
        grp::userinfo_signed_claims(
            &jwks,
            &resp,
            &issuer,
            &client_id,
            &expected_sub,
            &algs,
            &options,
        )
        .map_err(err)?
    };
    to_py(py, &claims)
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
    m.add_class::<JwksCache>()?;
    m.add_function(wrap_pyfunction!(authorization_url, &m)?)?;
    m.add_function(wrap_pyfunction!(signed_request_object, &m)?)?;
    m.add_function(wrap_pyfunction!(begin, &m)?)?;
    m.add_function(wrap_pyfunction!(discover, &m)?)?;
    m.add_function(wrap_pyfunction!(end_session_url, &m)?)?;
    m.add_function(wrap_pyfunction!(fetch_jwks, &m)?)?;
    m.add_function(wrap_pyfunction!(exchange_code, &m)?)?;
    m.add_function(wrap_pyfunction!(verify_id_token, &m)?)?;
    m.add_function(wrap_pyfunction!(fetch_userinfo, &m)?)?;
    m.add_function(wrap_pyfunction!(build_client_assertion, &m)?)?;
    m.add_function(wrap_pyfunction!(claims_to_attributes, &m)?)?;
    Ok(())
}
