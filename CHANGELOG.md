# Changelog

All notable changes to `pygrindvakt` are documented in this file.

The project is pre-1.0, so minor releases may include behavior changes where
needed to track the upstream `grindvakt` library and correct protocol or
security handling. `pygrindvakt` is a thin PyO3 binding; most entries reflect
adopting a change made in `grindvakt` / `jose-rs` and surfacing it to Python.

## Unreleased

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
