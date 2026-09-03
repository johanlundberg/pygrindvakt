# Changelog

All notable changes to `pygrindvakt` are documented in this file.

The project is pre-1.0, so minor releases may include behavior changes where
needed to track the upstream `grindvakt` library and correct protocol or
security handling. `pygrindvakt` is a thin PyO3 binding; most entries reflect
adopting a change made in `grindvakt` / `jose-rs` and surfacing it to Python.

## [0.1.0] - 2026-09-02

Initial release, binding `grindvakt` 0.7.2 (with the `pkcs11` and `redis`
features compiled in).

### Added

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
