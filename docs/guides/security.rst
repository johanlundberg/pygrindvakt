Security guide
==============

OAuth 2.0 and OpenID Connect are security protocols whose value depends on a
handful of checks being exactly right. ``pygrindvakt`` is a thin binding: the
protocol logic, the JOSE cryptography and the validation rules live upstream in
``grindvakt``, ``jose-rs`` and ``kryptering``. This guide describes the
security properties the **binding** preserves, the guards it adds on top of
grindvakt, the escape hatches it deliberately leaves reachable, and the rules
an integrator must follow that no library can enforce.

Read this before wiring pygrindvakt into an authentication flow.

.. contents::
   :local:
   :depth: 1


Fail-closed hardening added by the binding
------------------------------------------

Reviewing tunnelbana, the reference Rust consumer of grindvakt, showed several
guards that every caller had to re-implement around sharp edges of the
library. Rather than have every Flask and Django user rediscover them, the
binding bakes them in (ADR 0003). Each guard is stricter than grindvakt, and
each is escapable only through an explicit, warning-emitting ``unsafe_*``
argument or by dropping to a lower-level primitive.

.. list-table::
   :header-rows: 1
   :widths: 34 40 26

   * - Guard
     - What grindvakt does
     - Escape hatch
   * - :func:`pygrindvakt.rp.verify_id_token` refuses ``expected_nonce=None``
       with :class:`pygrindvakt.AuthnError`.
     - Silently skips the nonce check when the nonce is ``None``, which
       allows id_token replay in the code flow.
     - ``unsafe_skip_nonce_check=True`` disables the check and emits a
       ``UserWarning``. Only for flows that genuinely carry no nonce.
   * - :class:`pygrindvakt.client.InMemoryClientStore` raises ``ValueError``
       on duplicate ``client_id`` values.
     - Keeps the last entry, so a copy-paste error silently changes which
       secret or redirect URI is live.
     - Use ``put()`` after construction if you really want to overwrite.
   * - :class:`pygrindvakt.client.Client` is keyword-only after ``client_id``
       and rejects unknown keywords (``TypeError``);
       :meth:`~pygrindvakt.client.Client.from_dict` rejects unknown keys
       (``ValueError``).
     - Ignores unknown fields, so ``redirect_uri`` (singular) yields a
       client with no redirect URIs that fails every authorization request.
     - None; fix the field name.
   * - :meth:`pygrindvakt.provider.Provider.authorization_redirect` raises
       ``ValueError`` for reserved id_token claim names in ``extra_claims``
       (:data:`pygrindvakt.provider.RESERVED_ID_TOKEN_CLAIMS`).
     - Silently drops ``iss``, ``sub``, ``aud``, ``exp``, ``iat``, ``nbf``,
       ``jti``, ``nonce``, ``auth_time`` and ``acr`` from ``extra_claims``,
       hiding an attempt to override the subject or nonce.
     - None; use ``sub`` and ``acr`` parameters for those, and
       ``external_claims`` for user attributes.
   * - :class:`pygrindvakt.http.ReqwestClient` never follows redirects,
       enforces connect / read / total timeouts, and caps response bodies
       (streamed, so ``Content-Length`` cannot lie). Zero values are
       rejected.
     - grindvakt ships no HTTP client at all; a naive one would re-send
       token-endpoint bodies (``client_secret``, code) cross-origin on a
       307 / 308 and read unbounded responses.
     - Inject your own ``HttpClient``; then these become **your**
       responsibilities.
   * - :class:`pygrindvakt.dpop.NoReplayStore` used with
       ``DpopConfig(require_nonce=False)`` emits a ``UserWarning``.
     - Documents the combination as unsafe but accepts it silently.
     - Set ``require_nonce=True`` (with a ``nonce_secret``) or use a real
       replay store.
   * - ``token_url`` / ``htu`` are explicit, documented as "from
       configuration, never from ``Host``".
     - Same requirement, but easy to miss.
     - None; see below.
   * - Python protocol adapters fail closed: an exception in a store or HTTP
       client is logged via ``sys.unraisablehook`` and reported as
       ``server_error`` / :class:`pygrindvakt.InternalError`.
     - Not applicable (Rust traits).
     - None.

If grindvakt later adopts these guards upstream, the binding's checks become
redundant but harmless.


``token_url`` comes from configuration, never from ``Host``
------------------------------------------------------------

:meth:`pygrindvakt.provider.Provider.handle_token_request`,
:meth:`~pygrindvakt.provider.Provider.authenticate_client`,
:func:`pygrindvakt.dpop.validate_proof` and
:func:`pygrindvakt.dpop.validate_resource_proof` all take the absolute URL of
the endpoint being served. That URL is compared against:

* the ``aud`` of a ``private_key_jwt`` client assertion, and
* the ``htu`` of a DPoP proof.

If you build it from the incoming request (``request.host``,
``request.url``, ``build_absolute_uri()``), an attacker who can influence the
``Host`` header, or who sits behind a misconfigured reverse proxy, chooses
what those checks compare against: an assertion or proof minted for
``https://attacker.example/token`` would validate on your OP. Derive the URL
from the same setting that produced
:class:`pygrindvakt.metadata.ProviderMetadata`:

.. code-block:: python

   ISSUER = os.environ["OP_ISSUER"]            # configuration
   TOKEN_URL = f"{ISSUER}/token"               # what clients are told in discovery

   op.handle_token_request(form, TOKEN_URL, auth_header=auth)      # correct
   op.handle_token_request(form, request.url, auth_header=auth)    # WRONG

The examples under ``examples/`` all follow this rule; the Flask, Django and
FastAPI guides call it out at the token endpoint.


Never send ``str(exc)`` to a client
-----------------------------------

The message of a :class:`pygrindvakt.GrindvaktError` is an operator-facing
diagnostic. It may quote an upstream error body, name an internal host, say
which key or algorithm was rejected, or describe why a signature failed. None
of that belongs in an HTTP response.

Exactly two things are client-safe:

* :meth:`pygrindvakt.OAuthError.to_response` for direct (JSON) errors at the
  token and userinfo endpoints, and for authorization-endpoint errors raised
  **before** the ``redirect_uri`` was validated.
* :meth:`pygrindvakt.OAuthError.to_redirect` for authorization-endpoint
  errors **after** validation succeeded.

Everything else should become a generic ``server_error``:

.. code-block:: python

   try:
       tr = op.handle_token_request(form, TOKEN_URL, auth_header=auth)
   except OAuthError as e:
       return to_flask(e.to_response())
   except GrindvaktError:
       log.exception("token endpoint failure")             # str(e) goes to the log
       return to_flask(OAuthError("server_error").to_response())

On the RP side the same applies to :class:`pygrindvakt.AuthnError` raised by
:func:`~pygrindvakt.rp.exchange_code` or
:func:`~pygrindvakt.rp.verify_id_token`: log it, show the user a generic
"login failed" page.


The redirect policy
-------------------

Two different redirect rules matter.

**Inbound (authorization endpoint).** The ``redirect_uri`` in an authorization
request is attacker-controlled until
:meth:`~pygrindvakt.provider.Provider.validate_authorization_request` has
confirmed it exactly matches one registered for the client. Before that
point, render errors with ``to_response()``; after it, ``to_redirect()`` is
safe. The split is deliberate: an OP that redirects unvalidated URIs is an
open redirector and a phishing tool.

.. code-block:: python

   try:
       req = AuthorizationRequest.from_params(query)
       op.validate_authorization_request(req)
   except OAuthError as e:
       return e.to_response()                  # NOT to_redirect: redirect_uri is untrusted
   session["authz"] = req.to_dict()
   # ... later, after login ...
   except OAuthError as e:
       return e.to_redirect(req.redirect_uri)  # safe: validated above

Matching is exact, with no prefix or wildcard support, and there is no
``localhost`` exception.

**Outbound (HTTP client).** The built-in client refuses to follow redirects,
because a 307 / 308 from a token endpoint would re-send the form body
(``client_secret``, the authorization code, a ``client_assertion``) to
wherever the redirect points. The RP functions treat a ``3xx`` as a failed
request. If you inject your own ``HttpClient``, keep that property:
``follow_redirects=False`` in ``httpx``, ``allow_redirects=False`` in
``requests``.


TLS: rustls, not the system OpenSSL
-----------------------------------

Outbound HTTPS uses ``rustls`` compiled into the extension, with the bundled
Mozilla root store (``webpki-roots``). There is no OpenSSL dependency, no
environment variable that disables verification, and no ``verify=False``.
Two consequences:

* A private CA is not picked up from the system trust store,
  ``SSL_CERT_FILE`` or ``REQUESTS_CA_BUNDLE``. To talk to an OP with a
  private certificate,
  inject an ``HttpClient`` built on a Python library configured with that CA
  (see :doc:`rp`), keeping the no-redirect and size-cap rules.
* :func:`pygrindvakt.rp.discover` requires an ``https`` issuer. Plain ``http``
  is accepted only for loopback hosts, which is what the examples use on
  ``127.0.0.1``.


Secrets are Python strings
--------------------------

The token codec secret, client secrets, the DPoP nonce secret and a PKCS#11
PIN are passed as ``str``. A Python string is immutable and cannot be
zeroized: it stays in memory until the garbage collector reclaims it, and it
may be copied by string operations along the way. The Rust side copies the
value into its own buffers and never exposes it back (no getter, nothing in
``repr()``), but the original Python object is beyond the binding's control.

Practical rules:

* Read secrets from a secret store or the environment at startup, pass them
  straight into the constructor, and do not keep other references.
* Prefer :func:`pygrindvakt.keys.signing_key_from_pkcs11` for the OP signing
  key in production: the private key never leaves the token, so only the PIN
  is exposed to this problem.
* Rotate the codec secret with ``previous_secrets`` rather than restarting
  with a new one; see :class:`pygrindvakt.tokens.TokenCodec`.


Input hardening the binding inherits from grindvakt
---------------------------------------------------

* **JWT verification** rejects ``alg: none`` and symmetric algorithms against
  public keys, requires ``exp`` where the protocol does, and enforces
  ``typ`` where a type is defined (entity statements, resolve responses,
  signed JWK sets, DPoP proofs), so a token issued for one purpose cannot be
  presented for another.
* **Discovery** requires the ``issuer`` in the fetched document to equal the
  requested one exactly (OIDC Discovery section 4.3), which stops a
  compromised or mis-served document from redirecting the RP to another
  provider's endpoints.
* **PKCE** defaults to ``S256`` and the OP advertises only ``S256``.
* **Authorization codes, refresh tokens and assertion** ``jti`` **values are
  single-use**, enforced through the token-use store. Refresh tokens rotate.
* **Federation** verifies the whole trust chain: the trust anchor's entity
  configuration against the keys you configured, the resolve response's
  ``typ``, the chain's start (the subject) and end (the anchor), every
  subordinate statement's signature, and the ``sub`` you asked for.
* **Discovery-service URLs** (``initiate_login_uri``) must be ``https``
  without a fragment before a user is ever sent to them.


Footguns the API leaves reachable (and why)
-------------------------------------------

Each is named so it stands out in a code review.

``unsafe_skip_nonce_check=True``
   Disables the nonce check in :func:`pygrindvakt.rp.verify_id_token` and
   emits a ``UserWarning``. Exists for pure OAuth 2.0 flows that return an
   id_token without ever having sent a nonce. In the standard code flow it
   allows id_token replay. See :doc:`rp`.

:class:`pygrindvakt.dpop.NoReplayStore`
   Records nothing. Acceptable only with ``require_nonce=True``, where the
   server nonce bounds the replay window; otherwise warns. See :doc:`dpop`.

:func:`pygrindvakt.jwt.peek_claims_unverified` and :func:`pygrindvakt.federation.decode_unverified`
   Return claims without checking any signature. For inspection only (which
   key set to fetch, which authority to ask). Never make a decision on their
   output.

Python protocol adapters
   A ``ClientStore``, ``TokenUseStore``, ``ReplayStore`` or ``HttpClient``
   you write yourself is inside the trust boundary. The binding guarantees
   that an *exception* fails closed; it cannot guarantee that a ``consume``
   that always returns ``True`` is a bug. Test them.

In-memory stores
   :class:`~pygrindvakt.provider.InMemoryTokenUseStore`,
   :class:`~pygrindvakt.dpop.InMemoryReplayStore` and
   :class:`~pygrindvakt.client.InMemoryClientStore` are per process. Behind
   a multi-worker server, a code consumed by one worker is fresh in every
   other one. See :doc:`stores`.


Checklist for a production OP
-----------------------------

#. Derive the issuer and every endpoint URL, in particular ``token_url``,
   from configuration; never from ``Host``.
#. Use a shared, fail-closed token-use store
   (:class:`~pygrindvakt.provider.RedisStore`, constructed after fork, or a
   Python-backed one) whenever more than one process serves the token
   endpoint.
#. Render authorization-endpoint errors with ``to_response()`` until
   ``validate_authorization_request`` has succeeded, then with
   ``to_redirect()``.
#. Send only ``OAuthError.to_response()`` / ``to_redirect()`` output to
   clients; log everything else.
#. Keep the signing key on a PKCS#11 token where you can; otherwise load it
   from a file with restrictive permissions, never from source.
#. If you enable DPoP, use a shared replay store or ``require_nonce=True``
   with a high-entropy ``nonce_secret``.
#. Do not set any ``unsafe_*`` argument.

Checklist for a production RP
-----------------------------

#. Generate fresh ``state``, ``nonce`` and PKCE verifier per login, store
   them in the user's session, and check ``state`` on the callback before
   doing anything else.
#. Always pass the stored nonce to ``verify_id_token``; never
   ``unsafe_skip_nonce_check``.
#. Prefer ``private_key_jwt`` over shared secrets; the OP then holds only
   your public key.
#. Keep the built-in HTTP client, or make sure your own never follows
   redirects, enforces timeouts and caps bodies.
#. Treat ``AuthnError`` messages as log material.
