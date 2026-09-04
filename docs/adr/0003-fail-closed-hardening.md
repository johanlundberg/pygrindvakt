# ADR 0003: Fail-closed hardening added at the binding boundary

- **Status:** Amended by the 0.8 OIDC conformance hardening
- **Date:** 2026-09-02
- **Deciders:** pygrindvakt maintainers

## Context

Reviewing tunnelbana, the reference Rust consumer of grindvakt, showed several
guards implemented in *caller* code around sharp edges of the library:

1. `rp::verify_id_token(..., expected_nonce: Option<&str>)` silently skips the
   nonce check on `None`; tunnelbana fails closed when its stored nonce is missing.
2. `InMemoryClientStore::with_clients` keeps the last entry on duplicate
   `client_id` (`client_loader.rs` rejects duplicates first).
3. `Client` does not `deny_unknown_fields`, so `redirect_uri` (singular) yields
   an unusable client (`client_loader.rs` uses `serde_ignored`).
4. `authorization_redirect_with_claims` silently drops the ten reserved
   id_token claim names from `extra_claims` (`oidc_common.rs` rejects them).
5. The outbound HTTP client must not follow redirects (token-endpoint bodies
   would be re-sent cross-origin) and must cap response sizes.
6. `NoReplayStore` was documented as unsafe unless `require_nonce` was set.
   A nonce cannot replace unique-`jti` tracking because it is replayed with
   the proof.

Every Flask/Django user would rediscover these. Fixing them upstream would block
the binding on a grindvakt release and change Rust API behaviour.

## Decision

Bake the guards into the binding, following pygamlastan's `unsafe_*` convention:

1. `rp.verify_id_token(jwks, id_token, issuer, client_id, expected_nonce,
   unsafe_skip_nonce_check=False)`: `None` raises `AuthnError` unless the flag
   is set, in which case a `UserWarning` is emitted.
2. `client.InMemoryClientStore([...])` raises `ValueError` on duplicate ids.
3. `client.Client(...)` is keyword-only after `client_id` (so unknown keywords
   are a `TypeError`); `Client.from_dict` raises `ValueError` on unknown keys.
4. `provider.Provider.authorization_redirect(..., extra_claims=...)` raises
   `ValueError` for any reserved claim name (`provider.RESERVED_ID_TOKEN_CLAIMS`).
5. `http.ReqwestClient` uses `redirect::Policy::none()`, connect/read/total
   timeouts, and a streamed body cap; all are validated to be non-zero.
6. `dpop.NoReplayStore` can no longer be constructed, and any residual use
   fails closed. DPoP always requires an atomic replay store.
7. `token_url` / `htu` are explicit parameters everywhere and documented as
   "derive from configuration, never from the `Host` header".
8. Documentation states that `str(exc)` of a `GrindvaktError` must never be sent
   to a client; only `OAuthError.to_response()` / `.to_redirect()` are client-safe.

## Consequences

- The nonce guard is escapable only through the explicit, warning-emitting
  `unsafe_skip_nonce_check` argument. Replay protection is not optional.
- If grindvakt later adopts these guards upstream, the binding's checks become
  redundant but harmless.
