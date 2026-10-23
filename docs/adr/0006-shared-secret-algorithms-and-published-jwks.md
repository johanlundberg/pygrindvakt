# ADR 0006: Shared-secret algorithms and published JWKS

- **Status:** Accepted
- **Date:** 2026-10-23
- **Deciders:** pygrindvakt maintainers
- **Relates to:** ADR 0003 (extended, not superseded)

## Context

`rp.verify_id_token` takes the key set as a dict and a mandatory
`allowed_algorithms` list, and `HS256` / `HS384` / `HS512` parse like any other
name. Reviewing that surface showed two problems that mirror each other:

1. **A published JWK Set can supply a shared secret.** If an OP's `jwks_uri`
   document contains an `{"kty": "oct", ...}` key, the dict returned by
   `rp.fetch_jwks` (or the set held by `JwksCache`) contains it, and a caller
   who allows `HS256` verifies against it. Whoever can alter or control that
   document, or who simply reads it (it is public), can mint ID tokens that
   pass. The proof of concept is an `HS256` token signed with the key from a
   published `oct` entry.
2. **The MAC key for `HS*` ID tokens does not come from the OP's JWK Set at
   all.** OIDC Core section 10.1 says that symmetric signatures use a key
   derived from the `client_secret` (the octets of its UTF-8 representation),
   and that the OP must not publish symmetric keys. Legitimate
   `HS*` use therefore always involves a key set the *caller* builds, for
   example `{"keys": [{"kty": "oct", "k": base64url(client_secret)}]}`.

A third gap sat next to them. RFC 7518 section 3.2 requires an HMAC key at
least as long as the hash output (32, 48 and 64 bytes for `HS256`, `HS384`
and `HS512`). jose-rs enforces that only when the JWK pins `alg`. With no
`alg`, it guesses the key type from the length: 16, 24 and 32 byte keys are
AES keys (an `HS256` token with a 32-byte secret failed with a `JoseError`),
shorter keys are rejected, and 33 bytes or more is an HMAC key with no
per-algorithm minimum (an `HS512` token verified against a 48-byte key).

## Decision

1. **No flag.** An early proposal added an
   `unsafe_allow_shared_secret_algorithms` escape hatch. It was dropped: the
   one legitimate use of `HS*` already works without any override (below), so
   a flag could only re-enable the unsafe case, and the specification says
   that case must never happen. This is a deliberate departure from the
   `unsafe_*` convention of ADR 0003: that convention covers downgrades that
   some deployment can legitimately need, and none can need this one.
2. **Caller-built key sets keep working, unchanged.** `rp.verify_id_token` and
   `rp.fetch_userinfo` with a dict and `HS*` in `allowed_algorithms` verify as
   before, with no flag and no warning.
3. **Anything sourced from a published JWKS refuses shared-secret material,
   with no override.**
   - `JwksCache.verify_id_token`, and `rp.verify_id_token` /
     `rp.fetch_userinfo` given a `JwksCache`, raise `ConfigError` with
     `code == "shared_secret_algorithm"` when `allowed_algorithms` contains
     `HS256`, `HS384` or `HS512`. The message names OIDC Core section 10.1 and
     points at the caller-built key set. The check runs before any fetch.
   - Every `oct` key is dropped when a key set is ingested from a `jwks_uri`:
     in `rp.fetch_jwks`, in `JwksCache` (so also `JwksCache.jwks()` and the
     cached set), and in `federation.entity_metadata_jwks` /
     `federation.fetch_signed_jwks`. A `UserWarning` is emitted once per fetch.
     Because `rp.fetch_jwks` returns a plain dict, filtering at ingest is what
     carries the rule to `rp.verify_id_token(fetched_dict, ...)`: the dict
     simply has no key to verify an `HS256` token with.
   - The same drop applies to every key set that is a *verifier* in federation
     code, because core federation verification applies no algorithm
     allow-list and would verify an `HS256`-signed statement with a published
     `oct` key (an attacker-controlled entity could then inject its own key
     as the OP's signing key). Covered entry points: `federation.verify`,
     `verify_typed`, `verify_self_signed` (token header), `resolve_via_trust_anchors`
     (the `trust_anchors` map), `entity_metadata_jwks` and `fetch_signed_jwks`
     (`subject_fed_jwks`), and the getters `EntityStatement.jwks()` and
     `ResolvedEntity.subject_jwks`. `verify`, `verify_typed` and
     `verify_self_signed` additionally refuse a token with header `alg`
     `HS256` / `HS384` / `HS512` / `none` with `AuthnError`
     (`code == "symmetric_algorithm"`). Federation entities sign with
     asymmetric keys; symmetric keys cannot be published.
4. **The minimum key length is enforced in the binding.** For an `HS*` token
   whose algorithm is allowed, `rp.verify_id_token`, `rp.fetch_userinfo`,
   `jwt.verify_with_jwks` and `jwt.verify_with_jwk` (one gate,
   `prepare_mac_keys` in `src/jwt.rs`; a `Validation` without an allow-list
   counts as allowing every HMAC algorithm, a single JWK is checked as a
   one-key set, whatever its `kid`) check the `oct` key the token selects
   and raise `ConfigError` with
   `code == "weak_shared_secret"` for a key shorter than the hash output. The
   message does not contain the key. The check is scoped to the key the
   verifier will use, mirroring its selection: with a `kid`, the first key
   with that `kid`; without one, the only key of a one-key set, or every key
   when jose-rs tries them all (`jwt.verify_with_jwks` without
   `require_kid`; `rp.*` refuses a `kid`-less token against several keys
   itself). A `kid` that names no key, or names an EC/RSA key, checks
   nothing: the verifier then fails with its own error (`JoseError` or
   `AuthnError`), never `ConfigError`, so an anonymous token cannot trigger
   a config fault by naming another key. The selected key is checked only if
   it is a candidate: an `oct` key (`kty` matched case-insensitively) usable
   for HMAC verification with the token's algorithm (`alg` absent or equal,
   `use` absent or `sig`, `key_ops` absent or containing `verify`). Other
   `oct` keys are left untouched. `k` must be strict unpadded
   base64url; anything else is refused with `weak_shared_secret` ("invalid oct
   key material") and is never length-counted. The binding also pins the token's `alg`
   on `oct` keys that carry none, which makes jose-rs apply the same
   minimum and treats a 32-byte `HS256` secret as the HMAC key it is.
5. **`none` stays refused** where the algorithm list is parsed
   (`ConfigError`, "invalid JWS algorithm"); nothing here changes that.
6. **Config fault, not request input.** All of these are `ConfigError`
   (ADR 0005): the algorithm list and the key set are integrator
   configuration, never request data. The token header is request data, so
   the gate only fires for the key the header selects (Decision 4), never
   because of a different weak key in the set. Residual: a weak `oct` key in a
   verifier set can still be selected by its `kid` and then raises; keep weak
   keys out of verifier sets.

## Consequences

- **Behaviour change for `JwksCache` callers.** `HS*` in `allowed_algorithms`
  now raises. A caller that fetched a cache and allowed `HS256` was verifying
  against a published (or attacker-controlled) key and must switch to a
  caller-built key set.
- **Behaviour change for fetched sets.** An OP that really does publish an
  `oct` key now yields a `UserWarning` and a set without it. Its `HS*` tokens
  then fail verification; that OP is out of specification and the right fix is
  on its side.
- **Behaviour change for `HS*` callers with short secrets.** A `client_secret`
  shorter than 32, 48 or 64 bytes (for `HS256`, `HS384`, `HS512`) is now refused
  with `weak_shared_secret`. This is fail-closed and follows RFC 7518
  section 3.2; the remedy is a longer secret at the OP. Callers whose
  secret was exactly 32 bytes for `HS256` now verify instead of failing.
- **Behaviour change for `jwt.verify_with_*` callers (0.3.0).** The key-length
  invariant now holds for `rp.*` and `jwt.*` alike. The first version of this
  decision gated only `rp.*`, leaving a gap: `jwt.verify_with_jwks` /
  `verify_with_jwk` verified an `HS512` token with an unpinned 40-byte `oct`
  key (the spec needs 64) and refused a 16-byte `HS256` key only through
  jose-rs' key-type heuristic. Short keys, and `k` that is not strict
  unpadded base64url, are now refused with `weak_shared_secret`; an unpinned
  32-byte `HS256` key now verifies. No opt-out.
- The `oct` drop is unconditional and fail-closed: it also happens when
  `warnings` is configured as errors (the error is discarded; the key is
  dropped regardless).
- The ingest filter applies to key sets this library fetches from a
  `jwks_uri`, and to inline `jwks` and `signed_jwks_uri` documents handled by
  `federation.entity_metadata_jwks`. A JWKS dict the caller fetched or
  assembled is a caller-built key set by definition; the library cannot tell
  it from a `client_secret`-derived one, so a fetched set must never be fed
  into an `HS*` allow-list.
- Residual: keys embedded in statements that core fetches and verifies
  internally during `resolve_via_trust_anchors` are not reachable from the
  binding and are not filtered; the chain is anchored on the (filtered) trust
  anchor keys. `fetch_signed_jwks` / `entity_metadata_jwks` download the token
  themselves, so only the key-set filter (not the header check) protects them.
- The publish side warns and does not refuse. `federation.build_entity_configuration`
  emits a `UserWarning` when the `public_jwks` it is given contains an `oct` key
  and still publishes it: the document contains what the caller configured.
  `Provider.jwks_document()` needs no check: the constructor refuses `HS*`
  signing keys and an `oct` JWK cannot carry another algorithm, so the
  document is always asymmetric. `SigningKey.to_public_jwks()` /
  `public_jwk()` of an `HS*` key return an `oct` entry without `k`; they are
  accessors, not publishing calls, and do not warn.
- The `oct` filter lives in the binding. It does not change what the dict
  `rp.verify_id_token` accepts when the caller builds it; trust in that dict
  is the caller's.
- A warning once per fetch may repeat on every refetch of a cache that keeps
  fetching a document with an `oct` key. That is intended: the OP stays
  non-compliant until it is fixed.
