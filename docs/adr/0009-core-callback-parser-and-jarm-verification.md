# ADR 0009: Core callback parser and JARM verification

- **Status:** Accepted
- **Date:** 2026-10-29
- **Deciders:** pygrindvakt maintainers
- **Relates to:** ADR 0005, ADR 0006; supersedes ADR 0007 decision 6 (JARM is
  unsupported, `accept_jarm` exposes the raw JWT) in part

## Context

ADR 0007 implemented the authorization-response shape rules in the binding
because grindvakt had no callback parser. grindvakt 0.9.1 ships
`grindvakt::callback`: `parse_authorization_response` with the same fail-closed
rules, `matches_state` / `matches_iss`, and signed JARM verification. Keeping a
second copy of the rules in the binding means two parsers that can drift, and
ADR 0007 decision 6 ("the core library has no JARM support") stopped being true.

Two behaviours of the binding were also fail-open compared with core: an empty
JARM `response` was accepted as a stub, and `matches_state` / `matches_iss` on
an unverified JARM stub could return True with `required=False`.

## Decision

1. **Delegate the shape rules to core.** `rp.AuthorizationResponse` wraps
   `grindvakt::callback::AuthorizationResponse`. Duplicate parameters failing
   closed, blank values, the character set and length caps, both / neither of
   `code` and `error`, `state` / `iss` matching and the known-error list come
   from `grindvakt::callback::parse_authorization_response`. The behaviour
   described in ADR 0007 decisions 1, 4 and 5 is unchanged; only its
   implementation moved.
2. **The binding keeps** what core cannot or should not decide:
   * the Python input adapter (`HttpRequestData`, pairs, multi-dict,
     `.lists()`) and its `TypeError` for mappings that hide duplicates;
   * the channel / `response_mode` messages and the transport
     `response_mode` label;
   * an additive JARM pre-check with our wording (plaintext parameters beside
     `response`, `accept_jarm` gating);
   * `error_description_safe` with OUR escaper. Core's `escape_upstream_text`
     does not escape `\`, so a backslash can forge an escape sequence in a
     log line, and its output format and cap differ from the escaper behind
     `OAuthError.__str__` that ADR 0007 documents (256 characters);
   * `error_uri` rejection of a fragment (ADR 0007 decision 3);
   * `__repr__` (ADR 0007 decision 7).
3. **Fix two fail-open cases.** An empty JARM `response` is a
   `BadRequestError`. `matches_state` and `matches_iss` on a JARM stub whose
   JWT is not verified are always False, even with `required=False`. Both
   match core.
4. **Add `AuthorizationResponse.verify_jarm`** (since the parser is unreleased,
   no compatibility concern):
   * `verify_jarm(jwks, *, issuer, client_id, allowed_algorithms, trust="typed",
     typ=None, leeway=None)`. `jwks` is a key set dict or a `JwksCache`
     (which must belong to `issuer`; refreshed once for an unknown `kid`).
     `allowed_algorithms` is required; `rp.JARM_ASYMMETRIC_ALGORITHMS` is the
     recommended value. `rp.JARM_TYP` is `oauth-authz-resp+jwt`.
   * `trust` uses the vocabulary of `fetch_userinfo`: `"typed"` (default; the
     JOSE `typ` must equal `typ`, default `JARM_TYP`), `"dedicated_keys"` and
     `"untyped_shared_key_compat"`. In grindvakt 0.9.1 core treats the two
     opt-ins identically (a missing `typ` or `JWT` is tolerated); the
     documentation does not promise a difference. `typ` is only valid with
     `"typed"`.
   * `leeway` is capped at `MAX_ID_TOKEN_LEEWAY`.
   * `HS*` in `allowed_algorithms` with a `JwksCache` is a `ConfigError`
     (`code == "shared_secret_algorithm"`, ADR 0006).
   * Errors: `BadRequestError` for a response that is not an unverified JARM
     stub, a JWE, or a bad inner shape; `ConfigError` for bad arguments (empty
     `allowed_algorithms`, `issuer` or `client_id`, issuer mismatch with the
     cache, bad leeway), raised before any fetch; `AuthnError` for a bad
     signature, `typ`, `kid`, `iss`, `aud` or `exp`.
   * The result is a new `AuthorizationResponse` with `jarm_verified` True and
     the original `response_mode`. A verified response is not a stub, so
     `matches_state` / `matches_iss` compare the inner values.
5. **Read the raw inner `error_description` after verification.** Core
   applies its own escaper to the inner `error_description`. To use ours, the
   binding calls core's `peek_claims_unverified` on the JWT only AFTER the
   signature has been verified, and escapes the raw claim itself. An upstream
   request is open for a raw accessor or a pluggable escaper, which would
   remove the second parse.
6. **Not adopted from core:**
   * the `_str` variant: it decodes `+` as a space and the tests pin
     `TypeError` for a `str` input;
   * the `_request` variant: the binding already has its own channel logic;
   * an `error_code` getter: `error` already carries the string;
   * `jarm_verified` in `repr()`: ADR 0007 decision 7 keeps the repr minimal;
     the property is available.

## Consequences

- One implementation of the callback rules, maintained in core. A core
  release that changes a message or a rule can break the binding's
  exact-message tests; those tests are the tripwire. `Cargo.toml` requires
  `^0.9.1`, so a core bump must be reviewed against them.
- A verified JARM response is replayable until `exp`: core checks `exp` but
  has no `iat` / max-age bound. The callback is single-use only if the caller
  makes it so (the `state` is consumed once).
- `verify_jarm` does not compare `state` or the inner `iss` against the
  session. The caller MUST call `matches_state` and `matches_iss` on the
  VERIFIED result; calling them on the stub is always False.
- Using `peek_claims_unverified` couples the binding to the order "verify,
  then peek". The code keeps the two in one function.
- `trust` modes beyond `"typed"` are caller attestations. An ID token signed
  by the same key can be replayed as a JARM response where `typ` is not
  required; `"typed"` stays the default for that reason.
