# ADR 0004: Redirect registration and opt-in hash binding at the binding boundary

- **Status:** Accepted
- **Date:** 2026-10-13
- **Deciders:** pygrindvakt maintainers
- **Relates to:** ADR 0003 (extended, not superseded)

## Context

pygrindvakt 0.2.0 (grindvakt 0.9.0) added RP-Initiated Logout and relaxed
metadata handling, and reviewing those paths turned up four sharp edges that a
framework integration would walk straight into:

1. `rp.authorization_url` / `rp.signed_request_object` / `rp.begin` /
   `rp.exchange_code` take a per-call `redirect_uri` override for apps that
   serve several callback paths. Until the registration check landed (released in 0.2.0) any syntactically valid URL was
   accepted, and the natural way to fill it in is from a request parameter —
   which lets the caller point the authorization request (and the code that
   comes back) at a host they control.
2. `rp.end_session_url` sends `id_token_hint`, the whole ID token. A
   `post_logout_redirect_uri` that came from anywhere other than a registration
   makes the logout endpoint an open redirect that ships that token to the
   chosen host.
3. `ProviderMetadata` URL-validated only its extension `*_endpoint` members;
   the five modelled endpoints and the `issuer` could be set to a non-https,
   fragment-bearing or `javascript:` URL through the constructor or
   `from_dict`.
4. `rp.verify_id_token` silently ignored an `at_hash` / `c_hash` claim it had
   no `access_token` / `authorization_code` to check, so an id_token not bound
   to the token in hand was accepted.

As in ADR 0003, fixing these only upstream would block the binding on a
grindvakt release and change Rust behaviour for every consumer.

## Decision

1. **Login redirect URIs are registered, not passed.**
   `RpClient(..., redirect_uris=[...])` holds the allowed set; a per-call
   override must exactly equal (plain string comparison) the client's
   `redirect_uri` or one entry, and may not be plaintext `http` to a
   non-loopback host. `RpClient(..., allow_unregistered_redirect_uri=True)` is
   the escape hatch for RFC 7591 dynamic registrations.
2. **Post-logout redirect URIs are registered too.**
   `RpClient(..., post_logout_redirect_uris=[...])`; `end_session_url` accepts
   `post_logout_redirect_uri` only with a `client` and an exact match, and
   `ProviderInfo` binds `end_session_endpoint` to the issuer's origin
   (`allow_cross_origin_end_session=True` for OPs that legitimately log out on
   another host, e.g. Cognito's hosted UI). The `id_token_hint`-only path for
   `post_logout_redirect_uri` was removed before any release carried it.
3. **Metadata URLs are validated on every write path**, modelled endpoints and
   `issuer` included. `rp.discover` stays exempt: consuming someone else's
   document must not fail at the binding level, so validation is for documents
   the operator builds or re-publishes.
4. **Hash binding is opt-in:** `strict_hashes=True` on `rp.verify_id_token` /
   `JwksCache.verify_id_token` refuses an `at_hash` / `c_hash` that cannot be
   checked and requires one when the matching value is passed. The default
   stays lenient.

## Consequences

- Registration is *structural*, not authoritative: the operator must mirror
  what is registered at the OP. Drift surfaces as a `BadRequestError` at
  runtime rather than as a silent fallback, which is the point.
- `allow_unregistered_redirect_uri` is the one guard whose escape hatch emits no
  `UserWarning`, because it is a constructor-time property of a shared object
  rather than a per-call argument. It is recorded in `repr()` and in the
  constructor call site; code review carries the burden the warning would
  otherwise carry. This is a deliberate departure from the `unsafe_*`
  convention in ADR 0003.
- `strict_hashes` defaults to `False`, so 0.2.0 refuses nothing new to
  existing callers: a code-flow RP whose OP omits `at_hash` keeps working, and
  implicit / hybrid flows must ask for the strict behaviour.
- The metadata checks make an empty-string optional endpoint
  (`"userinfo_endpoint": ""`, which some OPs emit) a `ValueError` in
  `from_dict`; callers who build metadata from a foreign document drop the key
  first.
