//! Process-wide tokio runtime backing the synchronous Python API.
//!
//! grindvakt's `Provider` endpoints, its store traits, and every networked
//! `rp::` / `federation::` / `discovery::` function are `async`. The Python
//! surface is synchronous, so each such call is driven to completion here.
//!
//! INVARIANTS
//!
//! * `block_on` below is the **only** place that calls `Runtime::block_on`, and
//!   it always releases the GIL first (`py.detach`). Blocking on the runtime
//!   while holding the GIL could deadlock a worker that needs it.
//! * Re-entrant calls (an adapter calling back into pygrindvakt) are run on a
//!   helper thread; see `block_on`.
//! * The future is polled on the *calling* Python thread (tokio's `block_on`
//!   does not hand it to a worker). Python protocol adapters therefore run
//!   their `Python::attach` on the same thread that released the GIL, which is
//!   permitted and cannot deadlock. Worker threads only service redis / hyper /
//!   timer tasks and must never call into Python.
//! * The runtime is created lazily and keyed by PID: after `fork` only the
//!   forking thread survives, so a runtime inherited from the parent has no
//!   workers. We detect that and build a fresh one; the stale runtime is leaked
//!   on purpose because dropping it would try to join threads that do not exist
//!   in the child.
//! * `fork` is supported only while no other thread is inside a pygrindvakt
//!   call. `SLOT` (and `ReqwestHttpClient::inner`) are `std::sync::RwLock`s: a
//!   lock held by another thread at fork time stays locked in the child with
//!   no owner, and the PID check never runs because `handle()` blocks on the
//!   lock first. No at-fork reset is attempted; it would not cover the locks
//!   inside tokio, hyper and the allocator anyway.

use std::future::Future;
use std::sync::RwLock;

use pyo3::prelude::*;
use tokio::runtime::{Builder, EnterGuard, Handle, Runtime};

use crate::errors::GrindvaktError;

struct Slot {
    pid: u32,
    rt: &'static Runtime,
}

static SLOT: RwLock<Option<Slot>> = RwLock::new(None);

fn build() -> Runtime {
    Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("pygrindvakt-tokio")
        .enable_all()
        .build()
        .expect("failed to build tokio runtime")
}

/// The runtime for *this* process. Created lazily; recreated after `fork`.
pub fn handle() -> &'static Runtime {
    let pid = std::process::id();
    if let Some(s) = SLOT.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
        if s.pid == pid {
            return s.rt;
        }
    }
    let mut w = SLOT.write().unwrap_or_else(|e| e.into_inner());
    match w.as_ref() {
        Some(s) if s.pid == pid => s.rt,
        _ => {
            let rt: &'static Runtime = Box::leak(Box::new(build()));
            *w = Some(Slot { pid, rt });
            rt
        }
    }
}

/// Drive `fut` to completion with the GIL released.
///
/// Normally the future is polled on the calling thread. When we are already
/// inside a runtime context, this call is *re-entrant*: a Python protocol
/// adapter (store / http client) running inside an outer `block_on` has called
/// back into pygrindvakt (typical in tests, where a fake `HttpClient` talks to
/// an in-process `Provider`). tokio forbids nested `block_on` on one thread, so
/// the nested future runs on a short-lived helper thread while this thread
/// waits with the GIL released, so the nested call's own adapters can attach.
pub fn block_on<F>(py: Python<'_>, fut: F) -> PyResult<F::Output>
where
    F: Future + Send,
    F::Output: Send,
{
    if Handle::try_current().is_ok() {
        return py.detach(|| {
            std::thread::scope(|s| {
                s.spawn(|| handle().block_on(fut))
                    .join()
                    .map_err(|_| GrindvaktError::new_err("nested runtime call panicked"))
            })
        });
    }
    Ok(py.detach(|| handle().block_on(fut)))
}

/// Enter the runtime context on the current thread without awaiting anything.
/// Needed by constructors that `tokio::spawn` at construction time
/// (`RedisStore::new`).
pub fn enter() -> EnterGuard<'static> {
    handle().enter()
}
