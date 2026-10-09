Stores, workers and the runtime
===============================

An OpenID Provider keeps very little state, but the state it does keep must
be shared correctly across every process that serves requests. This guide
covers which stores exist, how to choose, how ``fork`` interacts with them,
and the runtime model behind the synchronous API.

.. contents::
   :local:
   :depth: 1

What state an OP has
--------------------

grindvakt's provider is stateless by design: codes and tokens are
self-contained sealed payloads (:doc:`../api/tokens`). Three things remain:

.. list-table::
   :header-rows: 1
   :widths: 22 40 38

   * - State
     - Protocol
     - Built-ins
   * - **Token-use store**: hashes of consumed authorization codes, refresh
       tokens and ``private_key_jwt`` ``jti`` values.
     - :class:`pygrindvakt.provider.TokenUseStoreProtocol`:
       ``consume(token_hash, ttl_secs) -> bool``
     - :class:`~pygrindvakt.provider.InMemoryTokenUseStore` (per process),
       :class:`~pygrindvakt.provider.RedisStore` (shared)
   * - **Client store**: the registered clients.
     - :class:`pygrindvakt.client.ClientStoreProtocol`: ``get(client_id)``,
       ``put(client)``, optional ``put_with_ttl(client, ttl_secs)``
     - :class:`~pygrindvakt.client.InMemoryClientStore` (per process)
   * - **DPoP replay store**: seen proof ``jti`` values.
     - :class:`pygrindvakt.dpop.ReplayStoreProtocol`:
       ``record(jti, ttl_secs) -> bool``
     - :class:`~pygrindvakt.dpop.InMemoryReplayStore` (per process), or a
       shared protocol implementation

Outbound HTTP (:class:`pygrindvakt.http.HttpClientProtocol`) is injectable
the same way, though it holds no state that matters here.

Choosing a store
----------------

**One process** (development, a single-worker container): the in-memory
stores are correct and fastest.

**Several processes** (gunicorn workers, uvicorn workers, several
containers): the token-use store and the DPoP replay store **must** be
shared, otherwise a code consumed in one worker is still fresh in every
other, which defeats single-use codes and refresh-token rotation. The client
store only needs to be shared if it changes at runtime (federation
auto-registration, dynamic registration); a static list is fine per process.

Options for the shared stores:

* :class:`~pygrindvakt.provider.RedisStore`: Redis from Rust, ``SET NX EX``
  semantics, no Python Redis package needed. Construct it after fork (below).
* **A Python object** over whatever you already run: redis-py, Django's cache
  framework, a database table with a unique key. The same ``SET NX EX``
  shape works for both the token-use store and the replay store:

  .. code-block:: python

     class RedisPyStore:
         """Serves as TokenUseStore (consume) and ReplayStore (record)."""

         def __init__(self, r, prefix):
             self.r, self.prefix = r, prefix

         def _once(self, key, ttl):
             return bool(self.r.set(self.prefix + key, 1, ex=ttl, nx=True))

         def consume(self, token_hash, ttl_secs):
             return self._once(token_hash, ttl_secs)

         def record(self, jti, ttl_secs):
             return self._once(jti, ttl_secs)

Python-implemented stores **fail closed**: an exception, or a return value
that is not a ``bool``, is logged through ``sys.unraisablehook`` (so the
traceback reaches your logs) and reported to grindvakt as a store failure,
which the client sees as ``server_error`` (token endpoint) or
:class:`pygrindvakt.DpopServerError` (DPoP). Returning "already used" was
deliberately rejected: it would disguise an outage as a replay and mislead
operators. A ``ClientStore.get`` that raises is treated as "unknown client".

Objects missing the protocol methods are rejected with ``TypeError`` when the
``Provider`` is built, not at the first request.

The provider deliberately has no implicit token-use store: construction
fails until the application chooses one. Likewise, DPoP never permits a
no-op replay store. A server nonce is useful defense in depth, but replaying
the same proof also replays the same valid nonce, so it cannot replace atomic
``jti`` tracking.

Fork semantics
--------------

Prefork servers (gunicorn, uwsgi) import the application in a master
process and ``fork`` workers. The rules:

* **The** ``Provider`` **survives fork.** The tokio runtime backing the API is
  keyed by process id and rebuilt lazily in each child; the built-in HTTP
  client rebuilds its connection pool the same way. A ``Provider`` built in
  the master keeps working in every worker. This holds only if the fork
  happens while no other thread is inside a pygrindvakt call. An internal
  lock held by another thread at fork time stays locked in the child and can
  deadlock it. Forking concurrently with active calls is not supported.
* **In-memory stores are copied, not shared.** After fork each worker has a
  private copy of an ``InMemoryTokenUseStore``. That is exactly the
  multi-process problem above; it is not a crash, it is a silent security
  gap.
* :class:`~pygrindvakt.provider.RedisStore` **must be constructed after
  fork.** Its connection manager runs background tasks on the runtime of the
  process that created it; those tasks do not exist in a forked child. The
  binding records the creating PID and **fails closed**: a ``RedisStore``
  used from another process reports a store failure (``server_error``) with
  a message saying to construct it in the worker, rather than hanging.

The gunicorn ``post_fork`` hook is the natural place. In ``gunicorn.conf.py``:

.. code-block:: python

   import os
   from pygrindvakt import provider

   def post_fork(server, worker):
       # Runs in the worker, after fork: build the shared store here.
       from myapp import op_state
       op_state.token_use_store = provider.RedisStore(os.environ["REDIS_URL"], key_prefix="op:used:")
       op_state.build_provider()          # constructs the Provider with that store

Alternatively build everything lazily on the first request in each worker, or
run gunicorn without ``--preload`` and build at import time (each worker then
imports, and therefore constructs, after fork). With uvicorn or FastAPI, a
lifespan handler runs in the worker and serves the same purpose.

``multiprocessing`` with the ``fork`` start method behaves identically; with
``spawn`` nothing is inherited and every process builds its own objects.

The runtime model
-----------------

grindvakt is ``async`` Rust; the Python API is synchronous. Each store-backed
or networked call is driven to completion on a process-wide multi-thread
tokio runtime (two worker threads), created lazily and keyed by PID.

* **The GIL is released** for the duration of each call, so Python threads
  (gunicorn ``gthread``, FastAPI's threadpool, your own
  ``ThreadPoolExecutor``) run provider calls in parallel. All wrapped
  objects are safe to share across threads.
* **The request future is polled on the calling Python thread** (or, for a
  nested call made from inside an adapter, on a short-lived helper thread).
  The two runtime workers only service Redis, HTTP and timer tasks and never
  touch Python, so interpreter shutdown cannot hang on them.
* **KeyboardInterrupt is delayed** until the current call returns. The delay
  is bounded by the HTTP client timeouts (30 seconds total by default) and
  Redis command timeouts; a ``Ctrl-C`` during a discovery fetch to an
  unreachable host waits for the connect timeout (10 seconds).
* **Async frameworks** should run provider calls in a threadpool
  (``run_in_threadpool`` in FastAPI); a future ``pygrindvakt.aio`` module
  returning awaitables is planned on top of the same futures.

Nested calls from adapters
--------------------------

A Python protocol object (store or HTTP client) is called **from inside** a
pygrindvakt call, on the same thread, with the GIL briefly re-acquired. That
thread is already inside the runtime, and tokio forbids nesting ``block_on``
on one thread. The binding handles this for you: when an adapter calls back
into pygrindvakt, the runtime detects the nested context and runs the nested
future on a helper thread while the adapter waits with the GIL released. The
nested call behaves exactly like a top-level one; the only cost is one thread
spawn per nested call.

This is what makes two common patterns work without special care:

* A ``ClientStore.get`` that delegates to an
  :class:`~pygrindvakt.client.InMemoryClientStore` (whose ``get`` is itself
  runtime-backed).
* A test ``HttpClient`` that routes an RP's outbound requests into an
  in-process ``Provider``, calling ``handle_token_request`` and ``userinfo``
  directly from inside ``get`` / ``post_form``. ``tests/test_rp.py`` and
  ``tests/test_frameworks.py`` test the RP end to end this way.

The thread spawn is negligible for tests and occasional delegation. An
adapter on a hot production path should avoid nesting where it can (keep
client data in a plain dict rather than delegating to another store), but
correctness does not depend on it.

Pure-Python work inside an adapter (a database query, redis-py, ``httpx``)
simply blocks the request for its duration, as it would in any synchronous
framework.
