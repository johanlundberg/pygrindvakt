# ADR 0005: Error layout: BadRequestError and ConfigError are ValueErrors, plus error attributes

- **Status:** Accepted
- **Date:** 2026-10-22
- **Deciders:** pygrindvakt maintainers
- **Relates to:** ADR 0003, ADR 0004

## Context

Until 0.2.0 the binding raised a plain `ValueError` for invalid arguments
(`RpClient(auth_method="x")`, a bad algorithm name, a malformed metadata URL)
and `BadRequestError` for grindvakt's `Error::BadRequest`. Callers needed two
`except` clauses for what is conceptually one class of mistake, and neither
clause caught upstream failures a caller wants to branch on: whether the failure
was an authentication step, and whether a retry is sensible.

## Decision

1. **`BadRequestError` and `ConfigError` derive from `GrindvaktError` and
   `ValueError`.** The binding's argument validation is split by who is at
   fault. A configuration or wiring fault (unknown `auth_method`, bad
   algorithm list, `JwksCache` numeric arguments, a `leeway` outside its range,
   `ProviderInfo` / `RpClient` / `ProviderMetadata` URL and extra-field
   validation, `fetch_userinfo` options) raises `ConfigError`, `status_hint`
   500. A value that may arrive with a request (an unregistered `redirect_uri`
   or `post_logout_redirect_uri`, reserved `extra` parameters) raises
   `BadRequestError`, `status_hint` 400. A configuration fault is never a client
   error and its message is log-only. Existing `except ValueError` handlers
   keep working. `create_exception!` supports one base only, so both types are
   built once with `type(name, (GrindvaktError, ValueError), ...)`, with
   `code` and `status_hint` in the class dict; Rust raises them through
   `errors::bad_request_err` and `errors::config_err`.
2. **`GrindvaktError.auth_failure`** mirrors grindvakt's `Error::is_auth_failure()`
   (class default `False`; `True` on `AuthnError`). Core defines it narrowly: an
   authentication step (token or UserInfo request) as opposed to metadata
   retrieval. It is deliberately not set on `UnknownKeyError` or the DPoP
   subtree, so it is not a general "authentication failed" flag; callers
   branch on the class for those.
3. **`GrindvaktError.retryable`** is defined by the binding, not by grindvakt:
   upstream status >= 500 or 429, or code `transport`, `jwks_fetch_timeout`,
   `discovery_backoff`. The code rule applies only to codes the binding itself
   sets; a `code` adopted from upstream OAuth text never makes a failure
   retryable (a hostile IdP returning `error=transport` stays non-retryable).
   Attributes are applied best-effort and the typed error is never replaced: if a
   `setattr` ever failed, a note is attached and the class-level defaults apply
   (`auth_failure` and `retryable` False, so a failed override for a 503 reads
   as not retryable).
4. **`GrindvaktError.log_summary`** gives one escaped, capped line for logs. It
   never contains `upstream_body` or `upstream_error_description`, the two
   attributes that are unsafe to log. The escaper covers the full invisible and
   format character set of grindvakt's `is_invisible_format` (tag characters,
   variation selectors, bidi controls and others), copied locally until core
   exposes it, and is shared with `OAuthError.__str__`.
5. **`str(OAuthError)`** escapes and caps (512) the description through the same
   escaper (`_native.escape_untrusted_text`), because the description can carry
   attacker-influenced text. `OAuthError.description` stays raw and untrusted;
   the wire output (`to_response`, `to_redirect`) is untouched. This is a
   behaviour change for code that parsed `str(e)`.

## Consequences

- `except GrindvaktError` now also catches argument-validation errors that used
  to escape it. Handlers must catch `ConfigError` first, log
  `e.log_summary` and re-raise, so a deployment fault is not rendered as a
  failed login (or a 4xx/503); only then `except GrindvaktError` for genuine
  login failures. `BadRequestError` from our own wiring is a bug of the same
  kind and is handled the same way.
- `ConfigError` was a plain `GrindvaktError` subclass and is now also a
  `ValueError`; `except ValueError` blocks that used to miss it now catch it.
- These sites still raise a plain `ValueError` and can move over later without
  another decision: `ProviderMetadata.from_dict`/`from_json` parse failures, rp
  `extra` and `extra_params`, `parse_oauth_code`/`oauth_error_redirect` in
  `errors.rs`, and the `client`, `tokens`, `dpop`, `provider`, `request` and
  `http` modules. Until they move, `except ValueError` is the catch-all for
  argument errors; `except BadRequestError`/`ConfigError` only cover `rp` and
  `ProviderMetadata`.
- `retryable` is a hint about the failure class, not a promise of idempotency.
