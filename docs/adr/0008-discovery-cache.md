# ADR 0008: Discovery cache

- **Status:** Accepted
- **Date:** 2026-10-26
- **Deciders:** pygrindvakt maintainers
- **Relates to:** ADR 0003 (extended, not superseded), ADR 0005, ADR 0006

## Context

`rp.discover` is one HTTP round trip with no memory. The RP guide told
integrators to "keep `info` for the process lifetime and refresh it on a
timer", so every long-running RP wrote its own refresh loop around it, and
those loops go wrong in predictable ways:

1. **No lifetime.** The document is either fetched once at startup and never
   again (a moved `jwks_uri` or token endpoint is noticed at the next restart)
   or fetched per login (a dependency on the well-known endpoint for every
   login, and a request amplifier against the OP).
2. **Stampede and hammering.** Every worker thread that finds the document
   expired fetches it. When the endpoint is down, every login retries it.
3. **Outage policy by accident.** A hand-written loop either fails every login
   while the well-known endpoint is down or keeps the old document forever. Both are
   wrong: the first turns a brief outage of a rarely-changing document into
   a login outage, the second is fail-open (an OP that retired an endpoint or
   moved its keys is trusted indefinitely).
4. **The `JwksCache` is bound to a `jwks_uri` that came from the document.**
   When the document is refreshed and the OP has moved `jwks_uri`, a cache that
   is kept around keeps fetching keys from the old location.
5. **Headers.** `grindvakt::discover` returns only the parsed document, so
   `Cache-Control` and `Age`, the OP's own statement of how long the document
   is good for, are not available to a caller of `rp.discover`.

## Decision

1. **`rp.DiscoveryCache(http, issuer, *, default_ttl=3600, min_ttl=60,
   max_ttl=86400, failure_backoff=10, stale_on_error=True, max_stale=86400,
   fetch_timeout=45.0, allow_cross_origin_end_session=False)`** is a frozen,
   thread-safe cache of one issuer's discovery document with
   `metadata()`, `info()` (`ProviderInfo.from_metadata(metadata())`, built once
   per fetch so its `UserWarning`s fire once per fetch), `jwks()`, `refresh()`
   and the read-only properties `issuer`, `failure_backoff` and
   `fetch_timeout`. `rp.discover` and `ProviderInfo.from_metadata` keep their
   behaviour and signatures. Construction validates like `JwksCache` (the
   issuer with `validate_issuer` and the backslash gate, negative values,
   `min_ttl > max_ttl`, `fetch_timeout`), all as `ConfigError`; a `default_ttl`
   outside `[min_ttl, max_ttl]` is clamped, not rejected.
2. **Lifetime.** `Cache-Control: max-age` minus `Age` when the `HttpClient`
   reports headers, else `default_ttl`, clamped to `[min_ttl, max_ttl]`;
   `no-store` / `no-cache` / `max-age=0` are floored to `min_ttl`, as in
   `JwksCache`. Headers are captured by wrapping the client
   (`RecordingClient`, the generalisation of the body recorder behind
   `rp.discover`'s `raw`), and the directives are parsed by the upstream
   quote-aware parser through a `grindvakt::rp::JwksResponse` shim with
   `cache_ttl_secs_max(max_ttl)` rather than a second copy. A client that
   reports no headers gets the same one-time `UserWarning` as `JwksCache`.
3. **Binding side, not upstream.** The cache is built in the binding, because
   the policy is deployment policy (how stale, how long to back off) and
   needs Python objects (the `HttpClient` adapter, the clock hook, warnings,
   `__cause__` chaining). It reuses the single-flight machinery of
   `JwksCache` (the `Flight` guard and `begin_flight`, now shared): callers
   share one fetch and waiters, with the GIL released, are bounded by
   `fetch_timeout` and then raise `InternalError(code="discovery_fetch_timeout")`
   while the fetch continues and its result is cached. State is behind an
   `RwLock`, the clock is monotonic (valid across `fork`), and the private
   `_now` hook has the same shape as `JwksCache`'s.
4. **Issuer binding.** Every fetch runs `grindvakt::discover`, which requires
   the document's `issuer` to equal the configured one exactly. A mismatch
   raises the same error as `rp.discover`; the document is not stored and is
   never served, not even as stale metadata (only an earlier, correctly bound
   document can be). `jwks()` returns a `JwksCache` bound to `info().jwks_uri`
   and `info().issuer`: the SAME object across refreshes (its cached keys
   survive), rebuilt only when either value differs in the new document, and
   the old object is then never returned again, so keys cached for one
   location cannot be returned for another. It shares the cache's client,
   clock and `fetch_timeout` and uses the `JwksCache` constructor defaults for
   its TTL parameters (one set of constants shared with that constructor).
   Each fetched metadata entry gets a monotonically increasing generation, and
   the installed `JwksCache` is stored with the generation it was built for.
   A caller holding an older entry (it read it before another thread installed
   a newer one) never replaces a cache of a newer generation; it is served that
   newer cache instead, because its own entry is stale. Reusing a matching
   cache raises the stored generation, so a slow thread holding an older entry
   cannot displace it later either.
5. **Failure policy.** A failed fetch stores the error and the time. For
   `failure_backoff` seconds after it no network call is made. In that window,
   and when the refetch of an expired entry fails (the refresh runs in the
   foreground), the previous metadata is served if `stale_on_error` is true
   and the entry expired less than `max_stale` seconds ago; a one-time
   `UserWarning` (once per outage) says so. Otherwise the call that hit the
   network raises the original error and calls inside the window raise
   `InternalError(code="discovery_backoff")` whose `__cause__` is the stored
   original. `discovery_backoff` takes the `retryable` of that stored cause
   (transport or upstream 5xx/429: true; issuer mismatch, malformed document,
   other permanent failures: false), because it only reports that the cause
   is still in force; the cause's value was itself derived under ADR 0005
   (never from upstream text). `discovery_fetch_timeout` is retryable. The
   stored cause is a copy without traceback (its `__cause__` chain is copied
   likewise, capped), so it does not pin frames, locals or HTTP requests for
   the window, and repeated backoff errors do not grow it; the first call
   still raises the original with its traceback. A waiter that times out on
   another thread's fetch applies the stale policy first: it is served the
   previous document under the same `stale_on_error` / `max_stale` rules (and
   one-time warning), else it raises `discovery_fetch_timeout`; the timeout is
   not recorded as a failure.
   `stale_on_error=False` never serves expired metadata. `refresh()` forces a
   refetch, except inside the back-off window of a failed fetch, where it is a
   silent no-op; a failing forced refresh raises the original error and keeps
   the cached document.
6. **Why stale metadata is allowed, unlike stale keys.** `JwksCache` refuses
   to serve an expired key set: keys are what a token is verified against, and
   a revoked key that is still trusted is a direct forgery path. Discovery
   metadata is different. It changes rarely (endpoint URLs, supported
   algorithms), the validated values in `ProviderInfo` still pass the same
   checks, and an outage of the well-known endpoint, often a separate, less
   monitored path than the login path, should not break login for a day.
   Unbounded stale serving would be fail-open, so it is bounded by
   `max_stale` (default 24 hours past expiry), can be switched off with
   `stale_on_error=False`, and is surfaced (the warning, and the stored
   failure as `__cause__`). The security-relevant key material stays
   never-stale because `jwks()` returns a real `JwksCache` with its own
   policy: a stale `jwks_uri` can at worst point at a location the OP has
   stopped serving, where the fetch fails closed.

## Consequences

- A long-running RP replaces its own refresh loop with one object and gets
  single flight, back-off, bounded stale serving and key-cache survival across
  refreshes. The guide shows `discovery.info()` and `discovery.jwks()` called
  per request.
- During an OP discovery outage with `stale_on_error=True`, a deployment can
  keep using endpoints the OP has since changed for up to `max_stale` seconds
  plus the document lifetime. Raising `max_stale` widens that window;
  `stale_on_error=False` closes it. This is recorded in the security guide.
- An object obtained from `jwks()` is bound to the `jwks_uri` it was built
  for; a caller that keeps it across a `jwks_uri` change verifies against the
  old location. The documentation says to call `jwks()` each time.
- The retryable code list grows by `discovery_fetch_timeout`;
  `discovery_backoff` inherits `retryable` from its cause (it is no longer
  unconditionally retryable).
- Inside the back-off window waiters of a failed fetch get
  `discovery_backoff` (chained to the original), not a second copy of the
  original error: exactly one request is made per window.
- A forked child keeps the cache state; fork only while no other thread is
  inside a cache call, as for `JwksCache`.
- `jwks_uri` is required by the metadata schema, so `jwks()` always has a
  location; the binding still raises `ConfigError` defensively if it were
  absent.
