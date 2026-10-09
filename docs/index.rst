pygrindvakt
===========

**pygrindvakt** is a Python binding for `grindvakt
<https://github.com/kushaldas/grindvakt>`_ 0.7.x, a runtime-agnostic Rust
library for **OAuth 2.0**, **OpenID Connect** and **OpenID Federation 1.1**. It
exposes grindvakt's OpenID Provider engine, its Relying Party toolkit,
federation trust-chain resolution, DPoP (RFC 9449) proof validation, and the
JOSE / key primitives underneath to Python, including PKCS#11 (HSM) signing.

.. important::

   OAuth 2.0 and OpenID Connect are security protocols, and this binding hands
   attacker-controlled request parameters, tokens and JWTs straight into
   authentication decisions. Before integrating, read the
   :doc:`security guide <guides/security>`: it covers the fail-closed guards
   the binding adds on top of grindvakt, the ``unsafe_*`` escape hatches, why
   ``token_url`` must come from configuration and never from the ``Host``
   header, and why ``str(exc)`` must never be sent to a client.

What the binding adds
---------------------

grindvakt itself is a library of ``async`` Rust functions and traits. The
binding turns that into something a Python web application can call directly:

* **A synchronous API over an embedded tokio runtime.** Every networked or
  store-backed call is driven to completion on a process-wide runtime with the
  GIL released, so threads run in parallel and the same objects keep working
  after a quiescent ``fork`` (gunicorn, uwsgi, ``multiprocessing``). See
  :doc:`guides/stores`.
* **Framework agnosticism.** Requests come in as plain dicts and strings,
  responses go out as a :class:`pygrindvakt.http.Response` (``status``,
  ``headers``, ``body``). The same :class:`pygrindvakt.provider.Provider`
  works under Flask, Django, FastAPI, or anything else; the framework adapters
  are a few lines each (:doc:`guides/op_flask`, :doc:`guides/op_django`,
  :doc:`guides/op_fastapi`).
* **Python protocol adapters.** The client store, token-use store, DPoP replay
  store and outbound HTTP client can each be a built-in class *or* any Python
  object implementing a small duck-typed protocol (Django ORM, redis-py, an
  ``httpx`` client with custom CAs). Adapters **fail closed**: a Python
  exception is logged through ``sys.unraisablehook`` and reported to the
  client as ``server_error``, never as a silent pass.
* **Fail-closed hardening beyond upstream.** The binding refuses several
  things grindvakt silently accepts: an id_token verified without a nonce,
  duplicate client ids, unknown ``Client`` fields, reserved id_token claims in
  ``extra_claims``, and outbound redirects. Each guard is escapable only
  through an explicit, warning-emitting ``unsafe_*`` argument.

The binding mirrors grindvakt's modules as Python submodules:

.. list-table::
   :header-rows: 1
   :widths: 24 76

   * - Submodule
     - Purpose
   * - :doc:`pygrindvakt.http <api/http>`
     - Framework-agnostic request / response types, the ``HttpClient``
       protocol, and the built-in reqwest client.
   * - :doc:`pygrindvakt.keys <api/keys>`
     - Signing keys from PEM / DER, JWK, or a PKCS#11 token; JWK generation
       and thumbprints.
   * - :doc:`pygrindvakt.client <api/client>`
     - Registered relying parties and the ``ClientStore`` protocol.
   * - :doc:`pygrindvakt.metadata <api/metadata>`
     - The OpenID Provider discovery document.
   * - :doc:`pygrindvakt.request <api/request>`
     - Parsed OIDC authorization requests.
   * - :doc:`pygrindvakt.tokens <api/tokens>`
     - The stateless token codec and its sealed payloads.
   * - :doc:`pygrindvakt.provider <api/provider>`
     - The OpenID Provider engine and the ``TokenUseStore`` protocol.
   * - :doc:`pygrindvakt.dpop <api/dpop>`
     - RFC 9449 DPoP proof validation and the ``ReplayStore`` protocol.
   * - :doc:`pygrindvakt.rp <api/rp>`
     - The Relying Party side: discovery, code exchange, id_token
       verification, userinfo, client assertions.
   * - :doc:`pygrindvakt.federation <api/federation>`
     - OpenID Federation entity statements, trust-chain resolution, signed
       JWKS, collections, metadata policy.
   * - :doc:`pygrindvakt.discovery <api/discovery>`
     - Home-organization discovery and Third-Party Initiated Login.
   * - :doc:`pygrindvakt.jwt <api/jwt>`
     - Thin JWS sign / verify helpers.
   * - :doc:`pygrindvakt.pkce <api/pkce>`
     - RFC 7636 PKCE helpers.
   * - :doc:`pygrindvakt.mac <api/mac>`
     - HMAC-SHA256, SHA-256, constant-time comparison.
   * - :doc:`pygrindvakt.util <api/util>`
     - Time and randomness helpers.

Design in one sentence: JSON-shaped values (claims, JWKs, metadata) cross the
boundary as native Python dicts and lists, wrapped Rust objects are immutable
handles you can share freely across threads, and private key material never
crosses into Python at all.

.. toctree::
   :maxdepth: 2
   :caption: Getting started

   installation
   quickstart

.. toctree::
   :maxdepth: 2
   :caption: Guides

   guides/security
   guides/op_flask
   guides/op_django
   guides/op_fastapi
   guides/rp
   guides/federation
   guides/dpop
   guides/stores

.. toctree::
   :maxdepth: 2
   :caption: API reference

   api/index

.. toctree::
   :maxdepth: 1
   :caption: Reference

   exceptions

Architecture decision records
-----------------------------

The design decisions behind the binding are recorded as Markdown ADRs in the
repository rather than in this manual:

* `ADR 0001 <https://github.com/kushaldas/pygrindvakt/blob/main/docs/adr/0001-sync-api-over-embedded-tokio-runtime.md>`_:
  synchronous Python API over an embedded, PID-keyed tokio runtime.
* `ADR 0002 <https://github.com/kushaldas/pygrindvakt/blob/main/docs/adr/0002-python-protocol-adapters.md>`_:
  Python protocol adapters for stores and outbound HTTP, failing closed.
* `ADR 0003 <https://github.com/kushaldas/pygrindvakt/blob/main/docs/adr/0003-fail-closed-hardening.md>`_:
  fail-closed hardening added at the binding boundary.

The full list lives in the `docs/adr
<https://github.com/kushaldas/pygrindvakt/tree/main/docs/adr>`_ directory.

Indices
-------

* :ref:`genindex`
* :ref:`search`
