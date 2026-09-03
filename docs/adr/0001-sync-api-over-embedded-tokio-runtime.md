# ADR 0001: Synchronous Python API over an embedded, PID-keyed tokio runtime

- **Status:** Accepted
- **Date:** 2026-09-02
- **Deciders:** pygrindvakt maintainers

## Context

grindvakt is runtime-agnostic async Rust. `Provider::validate_authorization_request`,
`handle_token_request`, `userinfo`, `authenticate_client`, the `ClientStore` /
`TokenUseStore` / `ReplayStore` / `HttpClient` traits, and every networked
`rp::`, `federation::` and `discovery::` function are `async fn`. The `redis`
feature's `RedisStore` additionally spawns a background task (`redis::aio::
ConnectionManager`) at construction.

The Python consumers we care about are mostly synchronous (Flask, Django views,
gunicorn workers) with FastAPI/Starlette as the async exception, where blocking
calls are conventionally pushed to a thread pool. Three options were considered:

1. Sync-only API with a runtime inside the extension.
2. Sync now, structured so an `aio` module returning awaitables can be added later.
3. Sync and async variants from day one (`pyo3-async-runtimes`).

## Decision

Option 2. The Python API is synchronous. The extension owns one **multi-thread**
tokio runtime (two workers; the request future itself is polled on the calling
Python thread), created lazily and stored in a PID-keyed slot.

- `runtime::block_on(py, fut)` is the only entry point. It releases the GIL
  (`py.detach`) before `Runtime::block_on`, so other Python threads run
  concurrently and a Python protocol adapter can re-attach on the same thread
  without deadlock.
- Re-entrant use (`Handle::try_current().is_ok()`, i.e. a protocol adapter
  calling back into pygrindvakt from inside an outer call) is supported by
  running the nested future on a scoped helper thread while the caller waits
  with the GIL released. tokio forbids nested `block_on` on one thread; this
  keeps in-process fakes (an `HttpClient` that drives a local `Provider`, the
  standard way to unit-test RP code) working without special casing.
- Every async wrapper clones its inputs into an owned `async move` block, so the
  future is `'static + Send`. A future `pygrindvakt.aio` can hand those same
  futures to `pyo3_async_runtimes::tokio::future_into_py` on `runtime::handle()`
  without touching the sync surface.
- After `fork`, only the forking thread survives: an inherited runtime has no
  workers and any future depending on a spawned task would hang. `handle()`
  compares PIDs and builds a fresh runtime in the child, leaking the stale one
  (dropping it would join non-existent threads). `ReqwestHttpClient` rebuilds
  its pool on PID change; `RedisStore` records its creating PID and fails closed
  afterwards (see ADR 0002). `os.register_at_fork` was rejected because it only
  covers forks initiated through Python and still needs the Rust-side reset.
- A `current_thread` runtime was rejected: spawned tasks (redis reconnects,
  hyper connections) must be polled between Python calls, and concurrent
  `block_on`s from gunicorn `gthread` workers would serialize.

## Consequences

- Works identically under Flask, Django, FastAPI (via `run_in_threadpool`),
  gunicorn sync/gthread/preload, uwsgi, and `multiprocessing` (fork).
- `KeyboardInterrupt` is delayed until the current call returns; bounded by the
  HTTP client timeouts (30 s total by default) and Redis command timeouts.
- Worker threads never touch Python, so interpreter shutdown cannot hang on
  them. Rule: never `tokio::spawn` a future that calls `Python::attach`.
- A `RedisStore` must be constructed after fork (gunicorn `post_fork` hook or
  lazily in the worker).
