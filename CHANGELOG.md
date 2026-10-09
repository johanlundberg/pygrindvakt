# Changelog

All notable changes to `pygrindvakt` are documented in this file.

The project is pre-1.0, so minor releases may include behavior changes where
needed to track the upstream `grindvakt` library and correct protocol or
security handling. `pygrindvakt` is a thin PyO3 binding; most entries reflect
adopting a change made in `grindvakt` / `jose-rs` and surfacing it to Python.

## Unreleased

### Changed

- `JwksCache` now emits one `UserWarning` (per cache, on its first fetch) when
  the `HttpClient` returns a response with no headers at all. Such a client
  cannot report `Cache-Control` / `Age`, so the cache silently used
  `default_ttl` and a revoked key could stay trusted for that long. The
  built-in client is unaffected. Docs now state that `Cache-Control` is
  honoured only when the client reports response headers, and that
  `no-store` / `no-cache` / `max-age=0` are floored to `min_ttl`.

- **Breaking:** `end_session_endpoint` and related OIDC extension members
  (`revocation_endpoint`, `introspection_endpoint`,
  `pushed_authorization_request_endpoint`, `check_session_iframe`,
  `frontchannel_logout_supported`, `backchannel_logout_supported`, ...) were
  previously refused on the OP side because the library implements no logout.
  They are now accepted (RP-Initiated Logout needs `end_session_endpoint`).
  URL-typed members (every `*_endpoint` and `check_session_iframe`) are
  validated against the metadata's issuer (https or loopback http, no
  fragment, no userinfo) on every write path: `from_dict`, the `extra` setter,
  `set_extra_field` and the typed setters. Inputs that were accepted (for
  example `"javascript:x"` or non-loopback `http://` via `from_dict` /
  `extra` / `set_extra_field`) now raise `ValueError`. The dedicated
  `end_session_endpoint` setter now raises `ValueError` instead of a
  `GrindvaktError` subclass, so all paths agree. `rp.discover` still never
  fails over these members. `service_documentation`, `op_policy_uri` and
  `op_tos_uri` remain type-checked only.
- **Breaking:** `ProviderMetadata.issuer = ...` now re-validates the URL-typed
  members already stored in `extra` against the new issuer and raises
  `ValueError` (naming the member, old issuer kept) if one no longer passes.
- `Provider(...)` emits a `UserWarning` when its metadata advertises
  `end_session_endpoint`, `revocation_endpoint`, `introspection_endpoint`,
  `pushed_authorization_request_endpoint`, `check_session_iframe`, or sets
  `frontchannel_logout_supported` / `backchannel_logout_supported` /
  `require_pushed_authorization_requests` to true: the engine implements none
  of them. Publishing is still allowed; `ProviderMetadata` setters stay silent.

### Added

- Python `HttpClient` adapters can report response headers: the tuple form
  accepts an optional 4th element `headers: list[tuple[str, str]]` (3-tuples
  keep working) and `HttpFetchResponse` takes an optional `headers` argument
  and exposes a read-only `headers` attribute (names lower-cased, order and
  repeats kept). `JwksCache` uses them for `Cache-Control` / `Age`.

- `rp.JwksCache(http, jwks_uri, issuer, *, default_ttl=3600, min_ttl=60,
  max_ttl=86400, min_refresh_interval=30)`: thread-safe, single-flight JWK Set
  cache honouring `Cache-Control: max-age` minus `Age` (clamped; `no-store` /
  `no-cache` are floored by `min_ttl`), never serving an expired set, with
  `jwks()`, `refresh()` and `verify_id_token(...)`. An unknown `kid` triggers
  one rate-limited refresh, then `UnknownKeyError`. A cache is accepted as
  `jwks=` by `rp.verify_id_token` and `rp.fetch_userinfo`; the `issuer`
  argument must equal the cache's issuer (`BadRequestError` otherwise, before
  any request), so one provider's keys cannot vouch for another's `iss`. A Python
  `HttpClient` cannot report response headers, so it always gets `default_ttl`.
- `UnknownKeyError(JoseError)`, `code == "unknown_kid"`, `status_hint` 401.
- `rp.verify_id_token` keyword-only options `leeway` (<= 300), `max_age`
  (checked against `auth_time`, which must be present), `acr_values`,
  `access_token` / `require_at_hash`, `authorization_code` / `require_c_hash`.
  Calls without them behave as before.
- RP-Initiated Logout (OIDC 1.0): `rp.end_session_url(provider, *, id_token_hint,
  client, post_logout_redirect_uri, state, logout_hint, ui_locales, extra)`;
  `ProviderInfo(..., *, end_session_endpoint=None)` and a read-only
  `ProviderInfo.end_session_endpoint` (copied by `from_metadata`, validated
  like other endpoints); `ProviderMetadata.end_session_endpoint` (validated
  setter). A `Provider` advertises it when the caller sets it (with a
  `UserWarning`); no logout endpoint is implemented on the OP side.
- `ProviderInfo.from_metadata` drops an advertised `end_session_endpoint` that
  fails issuer validation (it becomes `None`) instead of raising, so login never
  depends on logout; the `ProviderInfo` constructor stays strict.
- `ProviderMetadata.raw` (source document snapshot; for `rp.discover` it is the
  fetched body) and `to_dict(*, exclude_defaults=False)`.
- Typed accessors (`None` when absent) for known extension members stored in
  `extra`: `acr_values_supported`, `claim_types_supported`,
  `revocation_endpoint`, `introspection_endpoint`,
  `pushed_authorization_request_endpoint`, `backchannel_logout_supported`,
  `request_uri_parameter_supported` and others (see the metadata API docs).

- Every pygrindvakt exception has a machine-readable `code` attribute (class
  default, overridden per instance where known, e.g. the upstream OAuth
  `error` such as `invalid_client`, `transport`, `response_too_large`);
  `OAuthError.code` is unchanged. See "Error codes" in the exceptions docs.
- Upstream HTTP failures expose `upstream_status`, `upstream_error`,
  `upstream_error_description` and `upstream_body` (all `None` otherwise).
  The description and body may echo secrets: do not log them or show them to
  end users. `str(exc)` stays generic.
- Outbound transport failures are chained as `__cause__` on the raised
  `InternalError` (`code == "transport"`): the original exception from a
  Python `HttpClient`, or `TimeoutError` / `ConnectionError` / `OSError` from
  `ReqwestClient`. Captured per call, so concurrent calls never mix causes.
- `rp.begin(provider, client, *, extra, redirect_uri, pkce, request_object_key)`
  generates `state`, `nonce` and a PKCE verifier, and returns
  `(url, state, nonce, verifier)`. `pkce=False` is refused for public clients;
  `request_object_key` adds a signed request object.
- Keyword-only `redirect_uri` override on `rp.authorization_url`,
  `rp.signed_request_object` and `rp.exchange_code` (absolute URL, no
  fragment; the same value must be passed to `exchange_code`).

- `rp.fetch_userinfo(..., method="GET")` sends the access token on a GET, and
  signed `application/jwt` UserInfo responses are verified with new keyword
  arguments `jwks`, `client_id`, `allowed_algorithms`, `trust`
  (`"typed"` / `"dedicated_keys"` / `"untyped_shared_key_compat"`), `typ`,
  `max_age` (default 300; `None` disables the age bound and makes replay
  unbounded) and `require_exp`. A signed response without the verification
  inputs raises `AuthnError` with `code == "userinfo_unverifiable"`; JWE is
  rejected (`userinfo_encrypted`). Defaults (POST, JSON) are unchanged.
- `ReqwestClient.get(url, headers=None)` accepts request headers (invalid
  names or values raise `BadRequestError`). Python `HttpClient`s may support
  headers on GET via a `headers` parameter / `**kwargs` on `get`, or a
  `get_with_headers(url, headers)` method (preferred); the capability is
  decided once, never by catching `TypeError`. Stub-only
  `HttpClientWithHeadersProtocol` / `HttpClientGetWithHeadersProtocol`.
- Tests (two local servers) that credentials and form bodies are never
  forwarded on cross-origin 301/302/303/307/308 redirects.

### Changed

- **Breaking:** known extension members in `ProviderMetadata.extra` are now
  type-checked: a wrong-typed `acr_values_supported`, `backchannel_logout_supported`,
  `revocation_endpoint`, etc. raises `ValueError` from `from_dict`,
  `extra = ...` and `set_extra_field` (previously accepted silently).
- `ProviderMetadata.extra` may now contain `end_session_endpoint`, fixing
  `from_dict(md.to_dict())` raising `ValueError` for discovered documents that
  carry it. `from_dict(md.to_dict()).to_dict() == md.to_dict()` now holds.
- **Breaking:** `rp.fetch_userinfo` now takes `userinfo_endpoint: str | None`
  and raises `ConfigError` for `None`; a signed (`application/jwt`) UserInfo
  response that previously failed generically now raises `AuthnError` with a
  precise code unless verification inputs are supplied. A GET with a Python
  client that supports no headers raises `ConfigError`.

- **Breaking:** exception instances now always have `code` and `upstream_*`
  attributes; code that set or relied on the absence of an attribute named
  `code` on non-`OAuthError` exceptions is affected. `InternalError` raised
  for transport failures now has a `__cause__` where it previously had none.
- Updated to `grindvakt` 0.9 (see its changelog for the full list; notable
  effects for Python users below).
- **Breaking:** `ProviderMetadata.userinfo_endpoint` is now `str | None`
  (and settable to `None`); providers that do not advertise UserInfo are
  accepted by `rp.discover`, and `ProviderInfo.from_metadata` then yields
  `userinfo_endpoint = None`.
- **Breaking:** `rp.verify_id_token` requires the id_token to carry a `kid`
  when the JWK Set has more than one key (OIDC Core 10.1).
- Failures from the token, UserInfo, JWKS, discovery and federation
  endpoints are reported upstream as `Error::UpstreamHttp`; the binding maps
  token/UserInfo failures to `AuthnError` and the rest to `InternalError`,
  as before. Messages are unchanged except that the token-endpoint message
  no longer embeds the upstream body (`token endpoint returned 400`), and
  the federation resolve failure now reads `resolve endpoint returned N ...`
  under `InternalError`.
- State parameters over 1024 characters or outside printable ASCII are
  rejected, and `OAuthError` wire descriptions are normalized (upstream
  hardening).
- The built-in `ReqwestClient` now records lower-cased response headers on
  the internal fetch response; Python HTTP clients supply none. Headers are
  not exposed on the Python `HttpFetchResponse`.
- `py.typed` is now empty (the package is fully typed) instead of `partial`.
- The `http` argument of `rp`, `federation` and `discovery` functions is typed
  as `HttpClientProtocol | ReqwestClient | None` instead of `Any | None`, and
  `HttpClientProtocol` methods are typed as returning a
  `(status, body, content_type)` tuple or an `HttpFetchResponse`.

### Documentation

- Documented that `from pygrindvakt import http` shadows the standard-library
  `http` package, with `from pygrindvakt import http as gv_http` /
  `import pygrindvakt.http` as alternatives.
- Documented `ReqwestClient` thread safety and fork behaviour (PID-keyed pool,
  per-process runtime, `RedisStore` after fork), and the threading contract of
  Python HTTP clients. Fork is supported only while no other thread is inside
  a pygrindvakt call; a lock held by another thread at fork time is inherited
  locked by the child and can deadlock it.

### Added

- CI job running `mypy --strict` over `tests/typecheck_usage.py`.

## [0.1.0] - 2026-09-15

Initial release, binding `grindvakt` 0.8.0 with the `pkcs11` and `redis`
features compiled in.

### Added

- **Breaking:** ``OAuthError.to_redirect`` now requires an explicit response
  mode. Provider construction rejects symmetric ``HS*`` ID-token signing
  keys, and token requests presenting multiple client-authentication methods
  fail with ``invalid_client``.
- **Breaking:** ``rp.fetch_jwks`` and ``rp.fetch_userinfo`` require their
  associated issuer. Loopback HTTP service endpoints are accepted only for
  loopback HTTP issuers
  or federation entities, preventing remote metadata from redirecting token,
  UserInfo, or JWKS traffic to a local plaintext endpoint.
- Updated the protocol engine to `grindvakt` 0.8.0 and added fail-closed OIDC
  validation for endpoints, ID-token algorithms/audiences/subjects, PKCE,
  UserInfo subject binding, response modes, duplicate parameters, and replay
  stores.
- Implemented complete implicit/hybrid authorization responses with OIDC
  `c_hash` / `at_hash`, and stopped issuing ID tokens or UserInfo responses for
  non-OpenID scopes.
- Provider construction now requires an explicit token-use store; DPoP proofs
  can only be obtained through successful validation.
- **Breaking:** Authorization, token, and client-authentication protocol entry
  points require ordered parameter pairs and reject mappings, ensuring duplicate
  names cannot be erased before validation. Trusted session restoration remains
  available through ``AuthorizationRequest.from_dict``.
- ID-token validation now accepts a single-element JSON array in ``aud``
  without requiring ``azp``; a supplied ``azp`` and all multi-audience trust
  checks remain enforced.
- **Breaking:** Authorization requests expose repeated RFC 8707 ``resource``
  parameters via ``AuthorizationRequest.resources`` instead of ``extra``, while
  continuing to reject duplicates of every single-valued protocol parameter.
- One Python submodule per grindvakt module: `http`, `keys`, `client`,
  `metadata`, `request`, `tokens`, `provider`, `dpop`, `rp`, `federation`,
  `discovery`, `jwt`, `pkce`, `mac`, `util`.
- Synchronous Python API over grindvakt's async Rust, driven by a process-wide
  tokio runtime with the GIL released; PID-keyed so it survives `fork`
  (ADR 0001).
- Python protocol adapters for `HttpClient`, `ClientStore`, `TokenUseStore` and
  `ReplayStore`, all failing closed (ADR 0002).
- Built-in `http.ReqwestClient` (rustls, timeouts, no redirects, streamed size
  cap) and `provider.RedisStore` (fork-guarded).
- `dpop.InMemoryReplayStore`, which grindvakt itself does not ship.
- `OAuthError` exception carrying `code` / `description` / `state` with
  `to_response()` / `to_redirect()`; typed `GrindvaktError` and `DpopError`
  subclasses.
- Fail-closed hardening beyond upstream (ADR 0003): nonce required in
  `rp.verify_id_token`, duplicate `client_id` rejected, unknown `Client`
  fields rejected, reserved id_token claims in `extra_claims` rejected,
  `NoReplayStore` without `require_nonce` warns.
- Type stubs for every submodule; Sphinx documentation; Flask, Django and
  FastAPI OpenID Provider examples plus a Flask Relying Party.
