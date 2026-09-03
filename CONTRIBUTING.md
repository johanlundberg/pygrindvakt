# Contributing to pygrindvakt

Read src/http.rs, src/client.rs, src/provider.rs, src/dpop.rs, src/jwt.rs first: they are the reference implementations.

- One `src/<mod>.rs` per grindvakt module, exposing `pub fn register(py, parent)` that calls
  `crate::convert::new_submodule(py, parent, "<mod>")` and adds classes/functions. `lib.rs` already
  declares the module and calls register; do NOT edit lib.rs.
- Wrap upstream types as `#[pyclass(module = "pygrindvakt.<mod>", name = "X", frozen, from_py_object)] #[derive(Clone)] pub struct X { pub inner: grindvakt::<mod>::X }`
  with `pub fn wrap(inner) -> Self`. Handles holding Arc use `frozen` + `skip_from_py_object`.
- Getters via `#[getter]`; `&str`/`Option<&str>` returned by borrow from &self; Vec/BTreeMap cloned.
- JSON-shaped values (serde_json::Value, Jwk, JwkSet, Claims, Map) cross as native Python objects via
  `crate::convert::{to_py, from_py}` (pythonize). JwkSet in = dict `{"keys": [...]}`; use `crate::jwt::jwks_from_py`.
- Errors: `grindvakt::Error` -> `crate::errors::err`; `OAuthError` -> `crate::errors::oauth_err(py, &e)`;
  Display-only -> `crate::errors::{config_err, crypto_err, internal_err, jose_err}`.
- Async upstream functions: clone/own all inputs, then
  `let r = crate::runtime::block_on(py, async move { ... })?;` (returns PyResult<Output>), then map errors.
  Functions taking `http: &Arc<dyn HttpClient>` accept a Python arg `http: Option<&Bound<PyAny>>` and call
  `crate::http::extract_http_client(http)?` (None -> built-in default client). Put `http` as the FIRST
  positional parameter with default None (`#[pyo3(signature = (http = None, ...))]` is NOT allowed since
  later params are required — so instead make `http` a required positional that accepts None:
  `#[pyo3(signature = (http, issuer))]` with `http: Option<&Bound<'_, PyAny>>`).
- Optional parameters: always explicit `#[pyo3(signature = (...))]`. Keyword-only struct constructors use `*`.
- Enums become lowercase strings; enum-like Rust values built via static constructors.
- `__repr__` on every class: `Name(field=..., field=...)` with identifying fields only.
- Security downgrades need an explicit `unsafe_*=False` kwarg and, when enabled, `crate::convert::warn(py, "...")`.
- Secrets passed as `str` get a `/// SECURITY:` doc note. Bytes in as `&[u8]`, out as `PyBytes`.
- No `py.detach` for CPU work; only runtime::block_on detaches.
- Doc comments on every pyclass/pyfunction (they become `__doc__`).
- Build: `cargo build --release`. Install + test: `VIRTUAL_ENV=$PWD/.venv .venv/bin/maturin develop --release --uv && .venv/bin/python -m pytest tests/<your file> -q`.
- Re-entrant calls (an adapter calling back into pygrindvakt) are handled by runtime::block_on on a helper thread.
- If a build error is in a file you do not own, another contributor is mid-edit: wait ~60s and retry.
