# ADR 0007: Authorization response parsing

- **Status:** Accepted
- **Date:** 2026-10-23
- **Deciders:** pygrindvakt maintainers
- **Relates to:** ADR 0003 (extended, not superseded), ADR 0005

## Context

`request.AuthorizationRequest` parses the authorization *request* on the OP
side, but nothing parsed the *response* on the RP side. Every relying party
hand-wrote the callback handler around `request.args`, and the examples in the
docs did the same. That code goes wrong in predictable ways:

1. **Duplicates and mappings.** `request.args["state"]` or `dict(parse_qsl(...))`
   silently keeps one value of a repeated parameter. A second `code` or
   `state` hidden behind the first is exactly what a parameter-smuggling
   attacker wants, and a `form_post` callback can carry extra values in its
   query string while the body looks clean.
2. **Both or neither of `code` and `error`.** Hand parsers branch on
   `"error" in args` and then read `args["code"]`, so a response with both,
   or with neither, takes an unintended path.
3. **Provider text reaches logs and pages.** `error_description` and
   `error_uri` are free text chosen by the OP (or by whoever crafted the
   callback URL). RPs log them raw: ANSI sequences, bidi controls and
   newlines forge log lines, and an `error_uri` of `javascript:` is rendered
   as a link.
4. **Mix-up.** RFC 9207 adds `iss` to the response so an RP can tell which OP
   answered. It is only a defence if the RP compares it.
5. **Interop.** OPs return error codes outside RFC 6749 (OIDC Core, JAR,
   proprietary). Rejecting unknown codes would turn a provider quirk into a
   hard failure.

## Decision

1. **`rp.parse_authorization_response` parses the callback fail closed.** It
   returns a frozen `rp.AuthorizationResponse` or raises `BadRequestError` (the
   input is per-request, ADR 0005). It refuses: any of `code`, `state`,
   `error`, `error_description`, `error_uri`, `iss`, `response` appearing more
   than once; `code` together with `error`; neither of them; an empty `code`,
   `state` or `error`; control characters, bidi or invisible formatting
   characters (the shared `is_invisible_format` set) or backslashes in `code`,
   `state` and `iss` (kept verbatim otherwise, no trimming); a `code`, `state`
   or `iss` longer than 2048 characters (the message never echoes the value);
   an `error` longer than 64 characters or outside the RFC 6749 section 5.2
   character set.
2. **Inputs that can carry duplicates only.** `http.HttpRequestData` (GET uses
   `query_pairs`, POST uses `form_pairs`), an ordered list of pairs, a
   multi-dict (`parse_qs` shape) or an object with a `.lists()` method
   (werkzeug `MultiDict`, read by duck typing), all flattened with duplicates
   preserved. A mapping with a non-list value (a plain `dict[str, str]`, or a
   `MultiDict` subclass without `.lists()`) raises `TypeError` naming the
   offending key and, for dict subclasses, suggesting
   `request.args.items(multi=True)` or `request.args.lists()`: a mapping has
   already discarded the duplicates, so no later check can restore them. The
   same holds for an `HttpRequestData` whose `query` / `form` was built from,
   or last assigned, a mapping (`query={"code": ...}`,
   `request.args.to_dict()`): the object records this per channel, and the
   parser raises `TypeError` when the channel it reads is non-empty and was
   set from a mapping (an empty mapping cannot hide a duplicate). Assigning a
   list of pairs through the setter clears the flag. Only the channel read is
   checked: a mapping cannot hide that a protocol name is present in the other
   channel, so the smuggling guard below still applies. For
   an `HttpRequestData`, a response parameter in the channel that is not
   selected is a `BadRequestError` for both methods (smuggling guard: the
   query string of a POST, the form body of a GET). A POST with no form
   parameters says that a form_post callback needs a parsed form body.
3. **`error_description` is never exposed raw.** There is no
   `error_description` attribute; `error_description_safe` is the existing
   escaper (control, bidi and invisible characters) capped at 256 characters.
   `error_uri` is exposed only if it is an absolute `https` URL (plain `http`
   only to a loopback host, the same transport rule as redirect URIs) with a
   host, at most 2048 characters, that passes the redirect-URI character gate
   (no whitespace, control characters, backslash, userinfo or fragment); the
   NORMALISED form is returned (`https:evil.example/x` becomes
   `https://evil.example/x`), so the caller sees what was validated.
   Otherwise it is `None`, without an exception, because the callback can still be handled. The docs state that
   it must not be followed or rendered as a link without validation. Binding
   it to the issuer's origin would need an expected-issuer input, which the
   pure parser does not have; that is out of scope, so `error_uri` stays
   untrusted and is never to be followed automatically.
4. **Unknown error codes are kept.** `error_known` tells known codes (RFC 6749
   sections 4.1.2.1 and 5.2, OIDC Core section 3.1.2.6, `invalid_dpop_proof`)
   from the rest. The charset and length check keeps a hostile code out of
   logs; the value is otherwise passed through. The known list is a SUPERSET of
   the 12 codes `OAuthError` accepts (the 8 others, such as `consent_required`,
   are response-only); `OAuthError(resp.error)` therefore raises `ValueError`
   for them. `OAuthError` is deliberately not widened (core defines no mapping
   for those codes); callers branch on the `error` string. Tests lock in the
   superset.
5. **`iss` is compared by the caller.** `AuthorizationResponse.matches_iss(expected,
   *, required=True)` is an exact string comparison that fails closed: an absent
   `iss` gives `not required`, so False by default. Pass `required=False` only
   when the OP does not advertise `authorization_response_iss_parameter_supported`
   (RFC 9207 section 2.4). The first draft of the API defaulted to
   `required=False`; that was changed before release (0.3.0) because a missing
   `iss` is exactly what a mix-up attacker's OP sends. The parser cannot know
   the issuer or whether the OP advertises the parameter, so the check is
   explicit and documented as mandatory (RFC 9207). An empty `expected` is a
   configuration fault and returns False regardless of `required`; an empty
   `iss` in the response is a `BadRequestError`.
   **`state` has the same shape.** `matches_state(expected, *, required=True)`
   compares the UTF-8 bytes in constant time (the primitive behind
   `mac.constant_time_eq`) and fails closed: an absent `state` gives
   `not required`, so False by default. `rp.authorization_url` and `rp.begin`
   always send `state`, so `required=True` is right; `required=False` is for a
   request deliberately built without it (RFC 6749 section 4.1.2.3: `state` in
   the response is conditional on the request). It is a method and not a parse
   kwarg (no `require_state`) because the parser is pure: it cannot know the
   session value, and a flag that only checks presence would invite callers to
   skip the comparison. The hand-written `resp.state is None or not
   constant_time_eq(...)` branch was the most exploited omission, so the
   library now provides the comparison. It must still be called before the
   code is exchanged; the parse alone proves nothing. An empty `expected`
   returns False regardless of `required`.
6. **JARM is refused by default.** A `response` parameter raises
   `BadRequestError` unless `accept_jarm=True`, in which case it is exposed raw
   as `.response`, documented as UNVERIFIED, and `code` / `error` are not
   required. A JARM response carries everything inside the JWT, so `code`,
   `state`, `error`, `error_description`, `error_uri` or `iss` next to it is a
   `BadRequestError` (plaintext parameters beside the JWT are a downgrade /
   confusion vector). The core library has no JARM support, and a parser that silently
   ignored `response` would let a signed-but-unchecked callback look like an
   empty one.
7. **`repr()` redacts.** It shows `is_error`, `error`, `iss`, `response_mode`
   and only `<set>` or `None` for `code`, `state` and `response`. Quoted
   fields (`error`, `iss`) escape `'` as `\'`, so a value cannot forge the
   quote boundary.

## Consequences

- The recommended callback handler is shorter and has one place where
  duplicates, shape and provider text are handled. It does not remove the
  RP's duty to call `matches_state`, call `matches_iss` and exchange the code; the
  documentation says so in the API reference, the RP guide and the security
  guide.
- Framework adapters must pass pairs (`request.args.items(multi=True)` in
  Flask, `parse_qsl` elsewhere), not a dict. A `werkzeug` `MultiDict` is
  accepted directly through its `.lists()` method; a dict subclass without it
  whose `items()` yields first values only is rejected with `TypeError`
  naming the key rather than trusted.
- A fragment response (implicit and hybrid flows) arrives client-side; the
  caller must forward `location.hash` and label it with `response_mode="fragment"`.
  The parser does not make those flows safe.
- `code`, `state` and `iss` are capped at 2048 characters, the JARM `response`
  at 32768 and `error` at 64; `error_description_safe` at 256. The web server's request-size limits still
  apply to the rest.
- Known codes are a fixed list. A code that later becomes standard stays
  accepted, with `error_known` false until the list is updated.
- No new exception class or `code`: failures use `BadRequestError`
  (`code == "bad_request"`).
