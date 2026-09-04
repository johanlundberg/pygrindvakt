# ADR 0002: Python protocol adapters for stores and outbound HTTP, failing closed

- **Status:** Amended by the 0.8 OIDC conformance hardening
- **Date:** 2026-09-02
- **Deciders:** pygrindvakt maintainers

## Context

grindvakt defines four injection points as async traits and ships only partial
implementations: `HttpClient` (no implementation at all; tunnelbana brings
reqwest), `ClientStore` (`InMemoryClientStore`), `TokenUseStore`
(`InMemoryTokenUseStore`, `RedisStore`), and `ReplayStore` (historically only
the no-op `NoReplayStore`). Real deployments need shared state across gunicorn workers
(Redis, a database) and often already have an HTTP client with proxies, custom
CAs, or test fakes.

## Decision

Each injection point accepts **either** a built-in class **or** any Python
object implementing a small duck-typed protocol:

| Protocol | Methods | Built-ins |
|---|---|---|
| `HttpClient` | `get(url) -> (status, body, content_type)`, `post_form(url, form, headers) -> same` | `http.ReqwestClient` (also the default when `None` is passed) |
| `ClientStore` | `get(client_id) -> Client \| dict \| None`, `put(client)`, optional `put_with_ttl(client, ttl)` | `client.InMemoryClientStore` |
| `TokenUseStore` | `consume(token_hash, ttl_secs) -> bool` | `provider.InMemoryTokenUseStore`, `provider.RedisStore` |
| `ReplayStore` | `record(jti, ttl_secs) -> bool` | `dpop.InMemoryReplayStore` |

Implementation rules:

- The adapter holds a `Py<PyAny>` and calls the method inside `Python::attach`.
  Because the future is polled on the Python thread already inside
  `runtime::block_on` (ADR 0001), the call re-acquires the GIL briefly on that
  thread; no worker thread is involved.
- `extract_*` helpers first `cast::<BuiltIn>()` and share the inner `Arc`, then
  validate the required methods exist (`TypeError` at construction time).
- **Fail closed.** Any Python exception is logged through `sys.unraisablehook`
  (`PyErr::write_unraisable`, so operators see the traceback) and then:
  - `TokenUseStore.consume` / `ReplayStore.record` return `Err(message)`, which
    grindvakt renders as `server_error` / `DpopError::Server`. Returning
    `Ok(false)` ("already used") was rejected because it disguises an outage
    as a replay and misleads operators.
  - `ClientStore.get` returns `None` (unknown client -> `invalid_client`).
  - `HttpClient.*` return `Error::Internal` (surfaces as `InternalError`).
- `InMemoryReplayStore` is a newtype over grindvakt's `InMemoryTokenUseStore`,
  whose `consume` already has `record`'s contract (true iff newly recorded, TTL,
  periodic purge), plus a `MAX_JTI_LEN` guard.

## Consequences

- Django ORM / cache-backed client registries and redis-py-backed replay stores
  need no Rust changes.
- Adapter calls are blocking; a slow Python store slows the request, as it
  would in any sync framework.
- An adapter may call back into pygrindvakt; the nested call runs on a helper
  thread (ADR 0001). This costs a thread spawn per nested call, which is fine
  for tests and rare in production.
- Bodies returned by a Python HTTP client must be `bytes` (not `bytearray` or
  `memoryview`); an `HttpFetchResponse` is accepted too.
