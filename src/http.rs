//! Bindings for `grindvakt::http` - the framework-agnostic request / response
//! types, the outbound `HttpClient` protocol, and the built-in reqwest client.
//!
//! `HttpRequestData` is what a web-framework adapter builds from the incoming
//! request (see `examples/`); `Response` is what the application turns back
//! into its framework's response type. Neither depends on any framework.
//!
//! Outbound HTTP (RP discovery, code exchange, federation fetches) goes through
//! an object satisfying the `HttpClient` protocol: either the built-in
//! `ReqwestClient` or any Python object with
//!
//! ```text
//! get(url: str) -> tuple[int, bytes, str | None]
//! post_form(url: str, form: list[tuple[str, str]], headers: list[tuple[str, str]])
//!     -> tuple[int, bytes, str | None]
//! ```
//!
//! SECURITY: an injected client is responsible for timeouts, for *not*
//! following redirects (a 307/308 would re-send token-endpoint form bodies
//! cross-origin), and for bounding response sizes. The built-in client does all
//! three.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

use grindvakt::http as gh;
use grindvakt::http::{HttpClient, HttpFetchResponse as RsFetch};
use grindvakt::Error as RsError;

use crate::convert::{
    from_py, log_unraisable, new_submodule, parameter_pairs, require_methods, to_py,
};
use crate::errors::{err, internal_err};

// ---------------------------------------------------------------------------
// HttpRequestData
// ---------------------------------------------------------------------------

/// A parsed inbound HTTP request, normalized for grindvakt.
///
/// Build one from your framework's request object. `headers` keys must be
/// lower-cased. Pass query/form pair lists from the framework so duplicate
/// OAuth parameters remain available to the protocol parser; the convenience
/// map properties retain the last value only for non-protocol application use.
#[pyclass(module = "pygrindvakt.http", name = "HttpRequestData", from_py_object)]
#[derive(Clone)]
pub struct HttpRequestData {
    pub inner: gh::HttpRequestData,
    query_pairs: Vec<(String, String)>,
    form_pairs: Vec<(String, String)>,
}

#[pymethods]
impl HttpRequestData {
    #[new]
    #[pyo3(signature = (path = "", method = "GET", uri = "", query = None, form = None,
                        body = None, headers = None, cookies = None))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        path: &str,
        method: &str,
        uri: &str,
        query: Option<&Bound<'_, PyAny>>,
        form: Option<&Bound<'_, PyAny>>,
        body: Option<&[u8]>,
        headers: Option<BTreeMap<String, String>>,
        cookies: Option<BTreeMap<String, String>>,
    ) -> PyResult<Self> {
        let query_pairs = query
            .map(|value| parameter_pairs(value, "query"))
            .transpose()?
            .unwrap_or_default();
        let form_pairs = form
            .map(|value| parameter_pairs(value, "form"))
            .transpose()?
            .unwrap_or_default();
        let headers = headers
            .unwrap_or_default()
            .into_iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v))
            .collect();
        Ok(Self {
            inner: gh::HttpRequestData {
                path: path.trim_start_matches('/').to_string(),
                method: method.to_ascii_uppercase(),
                uri: uri.to_string(),
                query_pairs: query_pairs.clone(),
                query: query_pairs.iter().cloned().collect(),
                form_pairs: form_pairs.clone(),
                form: form_pairs.iter().cloned().collect(),
                body: body.map(|b| b.to_vec()).unwrap_or_default(),
                headers,
                cookies: cookies.unwrap_or_default(),
            },
            query_pairs,
            form_pairs,
        })
    }

    #[getter]
    fn path(&self) -> &str {
        &self.inner.path
    }
    #[setter]
    fn set_path(&mut self, v: &str) {
        self.inner.path = v.trim_start_matches('/').to_string();
    }
    #[getter]
    fn method(&self) -> &str {
        &self.inner.method
    }
    #[setter]
    fn set_method(&mut self, v: &str) {
        self.inner.method = v.to_ascii_uppercase();
    }
    #[getter]
    fn uri(&self) -> &str {
        &self.inner.uri
    }
    #[setter]
    fn set_uri(&mut self, v: String) {
        self.inner.uri = v;
    }
    #[getter]
    fn query(&self) -> BTreeMap<String, String> {
        self.inner.query.clone()
    }
    #[setter]
    fn set_query(&mut self, v: BTreeMap<String, String>) {
        self.query_pairs = v.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        self.inner.query = v;
    }
    /// Ordered query parameters, retaining duplicates for protocol validation.
    #[getter]
    fn query_pairs(&self) -> Vec<(String, String)> {
        self.query_pairs.clone()
    }
    #[getter]
    fn form(&self) -> BTreeMap<String, String> {
        self.inner.form.clone()
    }
    #[setter]
    fn set_form(&mut self, v: BTreeMap<String, String>) {
        self.form_pairs = v.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        self.inner.form = v;
    }
    /// Ordered form parameters, retaining duplicates for protocol validation.
    #[getter]
    fn form_pairs(&self) -> Vec<(String, String)> {
        self.form_pairs.clone()
    }
    #[getter]
    fn body<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.body)
    }
    #[setter]
    fn set_body(&mut self, v: &[u8]) {
        self.inner.body = v.to_vec();
    }
    #[getter]
    fn headers(&self) -> BTreeMap<String, String> {
        self.inner.headers.clone()
    }
    #[setter]
    fn set_headers(&mut self, v: BTreeMap<String, String>) {
        self.inner.headers = v
            .into_iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v))
            .collect();
    }
    #[getter]
    fn cookies(&self) -> BTreeMap<String, String> {
        self.inner.cookies.clone()
    }
    #[setter]
    fn set_cookies(&mut self, v: BTreeMap<String, String>) {
        self.inner.cookies = v;
    }

    /// Look up a parameter from the query string first, then the form body.
    fn param(&self, key: &str) -> Option<String> {
        self.inner.param(key).map(String::from)
    }
    /// The value of the `Authorization` header, if present.
    fn authorization(&self) -> Option<String> {
        self.inner.authorization().map(String::from)
    }
    /// Extract a Bearer token from the Authorization header.
    fn bearer_token(&self) -> Option<String> {
        self.inner.bearer_token().map(String::from)
    }

    fn __repr__(&self) -> String {
        format!(
            "HttpRequestData(method={:?}, path={:?}, query={}, form={}, headers={})",
            self.inner.method,
            self.inner.path,
            self.inner.query.len(),
            self.inner.form.len(),
            self.inner.headers.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------

/// A framework-agnostic HTTP response produced by grindvakt.
///
/// `headers` is a list of `(name, value)` pairs (multi-valued headers such as
/// `set-cookie` are supported); `body` is `bytes`.
#[pyclass(module = "pygrindvakt.http", name = "Response", from_py_object)]
#[derive(Clone)]
pub struct Response {
    pub inner: gh::Response,
}

impl Response {
    pub fn wrap(inner: gh::Response) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl Response {
    #[new]
    #[pyo3(signature = (status, headers = None, body = None))]
    fn new(status: u16, headers: Option<Vec<(String, String)>>, body: Option<&[u8]>) -> Self {
        Self {
            inner: gh::Response {
                status,
                headers: headers.unwrap_or_default(),
                body: body.map(|b| b.to_vec()).unwrap_or_default(),
            },
        }
    }

    #[getter]
    fn status(&self) -> u16 {
        self.inner.status
    }
    #[setter]
    fn set_status(&mut self, v: u16) {
        self.inner.status = v;
    }
    #[getter]
    fn headers(&self) -> Vec<(String, String)> {
        self.inner.headers.clone()
    }
    #[setter]
    fn set_headers(&mut self, v: Vec<(String, String)>) {
        self.inner.headers = v;
    }
    #[getter]
    fn body<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.body)
    }
    #[setter]
    fn set_body(&mut self, v: &[u8]) {
        self.inner.body = v.to_vec();
    }

    /// Body decoded as UTF-8 (lossy).
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.inner.body).into_owned()
    }

    /// First value of header `name` (case-insensitive), if any.
    fn header(&self, name: &str) -> Option<String> {
        self.inner
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    }

    /// Return a copy with an extra header appended.
    fn with_header(&self, name: String, value: String) -> Self {
        Self::wrap(self.inner.clone().with_header(name, value))
    }
    /// Return a copy with the body replaced.
    fn with_body(&self, body: &[u8]) -> Self {
        Self::wrap(self.inner.clone().with_body(body.to_vec()))
    }

    /// 302 redirect to `location`.
    #[staticmethod]
    fn redirect(location: String) -> Self {
        Self::wrap(gh::Response::redirect(location))
    }
    /// A `text/html` response.
    #[staticmethod]
    fn html(body: String) -> Self {
        Self::wrap(gh::Response::html(body))
    }
    /// An `application/json` response from any JSON-serializable value.
    #[staticmethod]
    #[pyo3(signature = (value, status = 200))]
    fn json(value: &Bound<'_, PyAny>, status: u16) -> PyResult<Self> {
        let v: serde_json::Value = from_py(value)?;
        gh::Response::json_status(status, &v)
            .map(Self::wrap)
            .map_err(err)
    }
    /// A plain-text response.
    #[staticmethod]
    #[pyo3(signature = (status, body))]
    fn text_response(status: u16, body: String) -> Self {
        Self::wrap(gh::Response::text(status, body))
    }

    fn __repr__(&self) -> String {
        format!(
            "Response(status={}, headers={:?}, body=<{} bytes>)",
            self.inner.status,
            self.inner.headers,
            self.inner.body.len()
        )
    }
}

// ---------------------------------------------------------------------------
// HttpFetchResponse
// ---------------------------------------------------------------------------

/// The result of an outbound fetch made through an `HttpClient`.
#[pyclass(
    module = "pygrindvakt.http",
    name = "HttpFetchResponse",
    frozen,
    from_py_object
)]
#[derive(Clone)]
pub struct HttpFetchResponse {
    pub inner: RsFetch,
}

#[pymethods]
impl HttpFetchResponse {
    #[new]
    #[pyo3(signature = (status, body, content_type = None))]
    fn new(status: u16, body: &[u8], content_type: Option<String>) -> Self {
        Self {
            inner: RsFetch {
                status,
                body: body.to_vec(),
                content_type,
            },
        }
    }
    #[getter]
    fn status(&self) -> u16 {
        self.inner.status
    }
    #[getter]
    fn body<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.body)
    }
    #[getter]
    fn content_type(&self) -> Option<&str> {
        self.inner.content_type.as_deref()
    }
    fn text(&self) -> String {
        self.inner.text()
    }
    /// Parse the body as JSON into native Python objects.
    fn json<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let v: serde_json::Value = self.inner.json().map_err(err)?;
        to_py(py, &v)
    }
    fn __repr__(&self) -> String {
        format!(
            "HttpFetchResponse(status={}, content_type={:?}, body=<{} bytes>)",
            self.inner.status,
            self.inner.content_type,
            self.inner.body.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Built-in reqwest client
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Limits {
    connect_timeout: u64,
    read_timeout: u64,
    request_timeout: u64,
    user_agent: String,
}

fn build_client(l: &Limits) -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent(l.user_agent.clone())
        .connect_timeout(Duration::from_secs(l.connect_timeout))
        .read_timeout(Duration::from_secs(l.read_timeout))
        .timeout(Duration::from_secs(l.request_timeout))
        // Never follow redirects: a 307/308 would re-send token-endpoint form
        // bodies (client_secret, authorization code) cross-origin. Call sites
        // treat the resulting 3xx status as an error.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to build reqwest client")
}

/// reqwest-backed `HttpClient`. The pool is keyed by PID and rebuilt after
/// `fork`, since inherited connections are dead in the child.
pub struct ReqwestHttpClient {
    inner: RwLock<(u32, reqwest::Client)>,
    limits: Limits,
    max_response_bytes: usize,
}

impl ReqwestHttpClient {
    fn new(limits: Limits, max_response_bytes: usize) -> Self {
        let client = build_client(&limits);
        Self {
            inner: RwLock::new((std::process::id(), client)),
            limits,
            max_response_bytes,
        }
    }

    fn client(&self) -> reqwest::Client {
        let pid = std::process::id();
        if let Ok(g) = self.inner.read() {
            if g.0 == pid {
                return g.1.clone();
            }
        }
        let fresh = build_client(&self.limits);
        *self.inner.write().unwrap_or_else(|e| e.into_inner()) = (pid, fresh.clone());
        fresh
    }
}

fn request_error(method: &str, url: &str, error: RsError) -> RsError {
    RsError::Internal(format!("{method} {url}: {error}"))
}

async fn into_fetch(mut resp: reqwest::Response, max: usize) -> grindvakt::Result<RsFetch> {
    let status = resp.status().as_u16();
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    if resp.content_length().is_some_and(|l| l > max as u64) {
        return Err(RsError::Internal(format!(
            "outbound response exceeds {max} byte limit"
        )));
    }
    // Content-Length is optional and cannot be trusted on its own: stream the
    // body and check before every extension.
    let mut body = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| RsError::Internal(format!("reading body: {e}")))?
    {
        let new_len = body
            .len()
            .checked_add(chunk.len())
            .filter(|l| *l <= max)
            .ok_or_else(|| {
                RsError::Internal(format!("outbound response exceeds {max} byte limit"))
            })?;
        body.reserve(new_len - body.len());
        body.extend_from_slice(&chunk);
    }
    Ok(RsFetch {
        status,
        body,
        content_type,
    })
}

#[async_trait]
impl HttpClient for ReqwestHttpClient {
    async fn get(&self, url: &str) -> grindvakt::Result<RsFetch> {
        let resp = self
            .client()
            .get(url)
            .send()
            .await
            .map_err(|e| RsError::Internal(format!("GET {url}: {e}")))?;
        into_fetch(resp, self.max_response_bytes)
            .await
            .map_err(|e| request_error("GET", url, e))
    }

    async fn post_form(
        &self,
        url: &str,
        form: &[(String, String)],
        headers: &[(String, String)],
    ) -> grindvakt::Result<RsFetch> {
        let mut req = self.client().post(url).form(form);
        for (k, v) in headers {
            req = req.header(k.as_str(), v.as_str());
        }
        let resp = req
            .send()
            .await
            .map_err(|e| RsError::Internal(format!("POST {url}: {e}")))?;
        into_fetch(resp, self.max_response_bytes)
            .await
            .map_err(|e| request_error("POST", url, e))
    }
}

const DEFAULT_MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// The built-in outbound HTTP client (reqwest + rustls).
///
/// Never follows redirects, enforces connect/read/total timeouts and a
/// streaming response-size cap. Also exposes `get` / `post_form` so it
/// satisfies the Python `HttpClient` protocol itself.
#[pyclass(module = "pygrindvakt.http", name = "ReqwestClient", frozen)]
pub struct ReqwestClient {
    pub inner: Arc<ReqwestHttpClient>,
}

#[pymethods]
impl ReqwestClient {
    #[new]
    #[pyo3(signature = (connect_timeout = 10, read_timeout = 15, request_timeout = 30,
                        max_response_bytes = DEFAULT_MAX_RESPONSE_BYTES, user_agent = None))]
    fn new(
        connect_timeout: u64,
        read_timeout: u64,
        request_timeout: u64,
        max_response_bytes: usize,
        user_agent: Option<String>,
    ) -> PyResult<Self> {
        if connect_timeout == 0 || read_timeout == 0 || request_timeout == 0 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "timeouts must be greater than zero",
            ));
        }
        if max_response_bytes == 0 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "max_response_bytes must be greater than zero",
            ));
        }
        let limits = Limits {
            connect_timeout,
            read_timeout,
            request_timeout,
            user_agent: user_agent
                .unwrap_or_else(|| concat!("pygrindvakt/", env!("CARGO_PKG_VERSION")).to_string()),
        };
        Ok(Self {
            inner: Arc::new(ReqwestHttpClient::new(limits, max_response_bytes)),
        })
    }

    /// Issue a GET. Returns `(status, body, content_type)`.
    fn get<'py>(
        &self,
        py: Python<'py>,
        url: String,
    ) -> PyResult<(u16, Bound<'py, PyBytes>, Option<String>)> {
        let client = self.inner.clone();
        let r =
            crate::runtime::block_on(py, async move { client.get(&url).await })?.map_err(err)?;
        Ok((r.status, PyBytes::new(py, &r.body), r.content_type))
    }

    /// Issue a form-encoded POST. Returns `(status, body, content_type)`.
    #[pyo3(signature = (url, form, headers = None))]
    fn post_form<'py>(
        &self,
        py: Python<'py>,
        url: String,
        form: Vec<(String, String)>,
        headers: Option<Vec<(String, String)>>,
    ) -> PyResult<(u16, Bound<'py, PyBytes>, Option<String>)> {
        let client = self.inner.clone();
        let headers = headers.unwrap_or_default();
        let r =
            crate::runtime::block_on(
                py,
                async move { client.post_form(&url, &form, &headers).await },
            )?
            .map_err(err)?;
        Ok((r.status, PyBytes::new(py, &r.body), r.content_type))
    }

    fn __repr__(&self) -> String {
        format!(
            "ReqwestClient(connect_timeout={}, read_timeout={}, request_timeout={}, max_response_bytes={})",
            self.inner.limits.connect_timeout,
            self.inner.limits.read_timeout,
            self.inner.limits.request_timeout,
            self.inner.max_response_bytes
        )
    }
}

fn default_http_client() -> Arc<ReqwestHttpClient> {
    static DEFAULT: OnceLock<Arc<ReqwestHttpClient>> = OnceLock::new();
    DEFAULT
        .get_or_init(|| {
            Arc::new(ReqwestHttpClient::new(
                Limits {
                    connect_timeout: 10,
                    read_timeout: 15,
                    request_timeout: 30,
                    user_agent: concat!("pygrindvakt/", env!("CARGO_PKG_VERSION")).to_string(),
                },
                DEFAULT_MAX_RESPONSE_BYTES,
            ))
        })
        .clone()
}

// ---------------------------------------------------------------------------
// Python-implemented HttpClient adapter
// ---------------------------------------------------------------------------

/// Adapter that lets any Python object with `get` / `post_form` act as the
/// outbound client. The blocking Python call runs on the thread that is
/// already inside `runtime::block_on`, so it re-acquires the GIL briefly.
pub struct PyHttpClient {
    obj: Py<PyAny>,
}

fn py_http_err(e: PyErr) -> RsError {
    RsError::Internal(format!("python http client: {e}"))
}

fn extract_fetch(r: &Bound<'_, PyAny>) -> PyResult<RsFetch> {
    if let Ok(f) = r.extract::<HttpFetchResponse>() {
        return Ok(f.inner);
    }
    let (status, body, content_type): (u16, Vec<u8>, Option<String>) =
        r.extract().map_err(|e| {
            internal_err(format!(
                "HttpClient method must return (status: int, body: bytes, content_type: str | None) \
                 or an HttpFetchResponse: {e}"
            ))
        })?;
    Ok(RsFetch {
        status,
        body,
        content_type,
    })
}

#[async_trait]
impl HttpClient for PyHttpClient {
    async fn get(&self, url: &str) -> grindvakt::Result<RsFetch> {
        Python::attach(|py| {
            let obj = self.obj.bind(py);
            obj.call_method1("get", (url,))
                .and_then(|r| extract_fetch(&r))
                .map_err(|e| {
                    log_unraisable(py, e.clone_ref(py), obj, "HttpClient.get");
                    py_http_err(e)
                })
        })
    }

    async fn post_form(
        &self,
        url: &str,
        form: &[(String, String)],
        headers: &[(String, String)],
    ) -> grindvakt::Result<RsFetch> {
        Python::attach(|py| {
            let obj = self.obj.bind(py);
            obj.call_method1("post_form", (url, form.to_vec(), headers.to_vec()))
                .and_then(|r| extract_fetch(&r))
                .map_err(|e| {
                    log_unraisable(py, e.clone_ref(py), obj, "HttpClient.post_form");
                    py_http_err(e)
                })
        })
    }
}

/// Resolve the `http` argument of networked functions: `None` -> the shared
/// built-in client, a `ReqwestClient` -> its inner client, anything else ->
/// a Python protocol adapter (validated to have `get` and `post_form`).
pub fn extract_http_client(obj: Option<&Bound<'_, PyAny>>) -> PyResult<Arc<dyn HttpClient>> {
    match obj {
        None => Ok(default_http_client()),
        Some(o) if o.is_none() => Ok(default_http_client()),
        Some(o) => {
            if let Ok(h) = o.cast::<ReqwestClient>() {
                return Ok(h.get().inner.clone());
            }
            require_methods(o, &["get", "post_form"], "HttpClient")?;
            Ok(Arc::new(PyHttpClient {
                obj: o.clone().unbind(),
            }))
        }
    }
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = new_submodule(py, parent, "http")?;
    m.add_class::<HttpRequestData>()?;
    m.add_class::<Response>()?;
    m.add_class::<HttpFetchResponse>()?;
    m.add_class::<ReqwestClient>()?;
    Ok(())
}
