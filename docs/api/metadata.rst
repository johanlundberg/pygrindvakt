pygrindvakt.metadata
====================

.. py:module:: pygrindvakt.metadata

The OpenID Provider discovery document
(``/.well-known/openid-configuration``), as configured on the OP side and as
returned by :func:`pygrindvakt.rp.discover` on the RP side.

.. py:class:: ProviderMetadata(issuer: str, base: str | None = None)

   OpenID Provider metadata. ``ProviderMetadata(issuer, base)`` fills in the
   standard endpoints under ``base`` (``/authorization``, ``/token``,
   ``/userinfo``, ``/jwks``) and sensible defaults for the ``*_supported``
   lists; ``base`` defaults to ``issuer``. Every field is settable, so the
   object is **mutable**: configure it before passing it to a
   :class:`pygrindvakt.provider.Provider`, which copies it. Unknown and
   extension fields live in :attr:`extra`.

   .. py:staticmethod:: from_dict(d: dict[str, Any]) -> ProviderMetadata

      Build from a discovery-document dict. Raises ``ValueError`` if the
      required members are missing or mistyped.

   .. py:method:: to_dict(*, exclude_defaults: bool = False) -> dict[str, Any]

      The discovery document as a dict, with ``extra`` merged in at the top
      level. :meth:`pygrindvakt.provider.Provider.discovery_document` returns
      the same shape. Absent list and flag members are emitted as ``[]`` /
      ``False``. With ``exclude_defaults=True`` members equal to their OIDC
      Discovery / RFC 8414 / RFC 9126 default are omitted; this is **not**
      "omit falsy values". Dropped: ``None``; ``false`` for
      ``claims_parameter_supported``, ``request_parameter_supported``,
      ``require_request_uri_registration``, ``frontchannel_logout_supported``,
      ``backchannel_logout_supported`` and
      ``require_pushed_authorization_requests``; ``true`` for
      ``request_uri_parameter_supported`` (its default is ``true``, so
      ``false`` is kept); and ``[]`` for list members with no spec default
      (``scopes_supported``, ``claims_supported``,
      ``code_challenge_methods_supported``, ``acr_values_supported`` and the
      other ``*_supported`` extension lists). Kept even when ``[]``: members
      with a non-empty default, where ``[]`` means "none"
      (``response_modes_supported``, ``grant_types_supported``,
      ``token_endpoint_auth_methods_supported``, ``claim_types_supported``),
      and the required ``response_types_supported``,
      ``subject_types_supported`` and
      ``id_token_signing_alg_values_supported``. Unknown extras are always
      kept.

      .. versionchanged:: 0.2.0
         Added the ``exclude_defaults`` parameter. It omits only members equal
         to their spec default, so a source
         ``request_uri_parameter_supported: false`` (default ``true``) stays
         in the output instead of being dropped, which would flip policy.

      The full ``to_dict()`` still emits ``[]`` for absent members of these
      lists, including the three required ones (the upstream model cannot represent absence; a proper fix needs
      ``Option<Vec<_>>`` upstream), but ``exclude_defaults=True`` keeps them
      absent when ``raw`` is available, the source lacked the key and the value
      is still ``[]``. Constructor-built metadata has no ``raw``, so an
      empty list is kept there. A list assigned through its setter is never treated as
      absent, even when assigned ``[]``: that means "none", not the spec default.
      Note that this serialization choice reads ``raw``, which for discovered
      metadata is the OP-controlled document: an OP decides whether a
      re-publishing proxy emits ``[]`` ("none") or omits the member (the spec
      default) for these lists. Do not use ``raw`` or ``exclude_defaults``
      output for any policy decision. Re-parsing the output yields the same effective values.
      ``from_dict(md.to_dict()).to_dict() == md.to_dict()``
      holds for metadata built through the validated paths (the constructor,
      ``from_dict`` and the setters), including ``end_session_endpoint`` and
      extras. It does **not** hold for metadata returned by
      :func:`pygrindvakt.rp.discover` when the discovered document carries a
      malformed known extension member: ``to_dict()`` preserves it and
      ``from_dict()`` rejects it (see below).

   .. py:attribute:: raw
      :type: dict[str, Any] | None

      The source document: the ``from_dict`` argument, or the body fetched by
      :func:`pygrindvakt.rp.discover`; ``None`` for objects built with the
      constructor (or returned by ``Provider.metadata``). It is a **snapshot**:
      setters do not update it, so it is the way to see what the OP actually
      sent (including members that ``to_dict`` fills with defaults).

      .. warning::

         ``raw`` is an **unvalidated** copy of the source document, meant for
         display and audit, **not** for reading policy. Known extension
         members read from ``raw`` bypass the type checks applied to the typed
         properties, so a value there may have any type. Use the typed
         properties (``acr_values_supported``, ``end_session_endpoint``, ...)
         instead. A malformed member from discovery reads back ``None`` from
         its typed getter, is re-emitted verbatim by ``to_dict()``, and then
         makes ``from_dict()`` raise :class:`~pygrindvakt.ConfigError`; this asymmetry is pinned
         by ``test_discovered_malformed_known_extra_getter_none_roundtrip_raises``
         in ``tests/test_metadata.py``.

   Core endpoints, all ``str`` and writable:

   .. py:attribute:: issuer
      :type: str

      Setting it re-validates every URL-typed member already in ``extra``
      (see below) against the new issuer; on failure :class:`~pygrindvakt.ConfigError` names the
      member and the old issuer is kept.

   .. py:attribute:: authorization_endpoint
      :type: str
   .. py:attribute:: token_endpoint
      :type: str
   .. py:attribute:: userinfo_endpoint
      :type: str | None
   .. py:attribute:: jwks_uri
      :type: str
   .. py:attribute:: registration_endpoint
      :type: str | None

   Capability lists, all ``list[str]`` and writable:

   .. py:attribute:: scopes_supported
      :type: list[str]
   .. py:attribute:: response_types_supported
      :type: list[str]
   .. py:attribute:: response_modes_supported
      :type: list[str]
   .. py:attribute:: grant_types_supported
      :type: list[str]
   .. py:attribute:: subject_types_supported
      :type: list[str]
   .. py:attribute:: id_token_signing_alg_values_supported
      :type: list[str]
   .. py:attribute:: token_endpoint_auth_methods_supported
      :type: list[str]
   .. py:attribute:: claims_supported
      :type: list[str]
   .. py:attribute:: code_challenge_methods_supported
      :type: list[str]

      Defaults to ``["S256"]``.

   .. py:attribute:: dpop_signing_alg_values_supported
      :type: list[str]

   Flags:

   .. py:attribute:: claims_parameter_supported
      :type: bool
   .. py:attribute:: request_parameter_supported
      :type: bool

   Extension fields:

   .. py:attribute:: extra
      :type: dict[str, Any]

      Extension fields (anything not modelled above) as a dict. Assigning
      replaces the whole set. Modelled protocol members cannot be duplicated
      through ``extra``. Known extension members (below) must have their
      documented JSON type; a wrong type raises :class:`~pygrindvakt.ConfigError` from
      ``from_dict``, ``extra`` and ``set_extra_field``.

   .. py:method:: set_extra_field(key: str, value: Any) -> None

      Set one non-protocol extension field. ``value`` may be any
      JSON-serializable object (known extension members must have the right
      type); reserved names raise :class:`~pygrindvakt.ConfigError`.

   Known extension members are **type-checked** on every write path
   (``from_dict``, the ``extra`` setter, ``set_extra_field`` and the typed
   setters). The following members are additionally **URL-validated** on
   every one of those paths, and in the constructor for the modelled ones:
   the five modelled fields (``authorization_endpoint``, ``token_endpoint``,
   ``jwks_uri``, ``userinfo_endpoint``, ``registration_endpoint``), every known
   extension ``*_endpoint`` member (``end_session_endpoint``,
   ``revocation_endpoint``, ``introspection_endpoint``,
   ``pushed_authorization_request_endpoint``, ...) and
   ``check_session_iframe``. The check is: an absolute https URL (http only
   for a loopback URL under a loopback issuer), no userinfo, no fragment, no
   control characters. A bad value raises :class:`~pygrindvakt.ConfigError` (also a
   ``ValueError``) naming the member.
   The ``issuer`` itself is validated too (constructor, ``from_dict`` and
   the setter; ``ConfigError``), since it decides whether loopback http is
   allowed. ``authorization_endpoint`` query parameters are not checked by
   ``ProviderMetadata`` (the upstream query check is not public). Strictness
   note: an empty-string optional endpoint (``"registration_endpoint": ""``
   or ``"userinfo_endpoint": ""``, which some OPs emit) is rejected by
   ``from_dict``; drop the key before calling ``from_dict`` (``rp.discover``
   does not apply this check). A trailing ``/`` on ``base`` is ignored.
   Assigning ``issuer`` re-validates all of these against the new issuer and
   keeps the old issuer on failure. ``ProviderMetadata(issuer, base)``
   validates the endpoints it builds from ``base``. The host is **not**
   compared with the issuer: an OP may publish any https host (``base`` may
   be on another host), so ``ProviderMetadata`` stays origin-permissive. An RP
   that consumes metadata from anything other than its own TLS discovery of
   the issuer must pin the host itself. ``rp.discover`` does not run these
   checks at the binding level (upstream validates the modelled endpoints
   itself). The RP side binds only
   ``end_session_endpoint``, in :class:`~pygrindvakt.rp.ProviderInfo` (same
   origin as the issuer unless ``allow_cross_origin_end_session=True``), because
   ``id_token_hint`` is sent there. ``revocation_endpoint``,
   ``introspection_endpoint``, ``pushed_authorization_request_endpoint`` and
   ``check_session_iframe`` are not origin-checked anywhere. ``service_documentation``,
   ``op_policy_uri`` and ``op_tos_uri`` are informational links and are
   type-checked only. :class:`~pygrindvakt.provider.Provider` emits a
   ``UserWarning`` at construction when the metadata advertises logout,
   revocation, introspection, PAR or session members the engine does not
   implement; publishing is still allowed. Building a
   :class:`~pygrindvakt.rp.ProviderInfo` (the constructor raises on an unsafe or cross-origin
   ``end_session_endpoint``; ``from_metadata`` drops it) and calling
   :func:`~pygrindvakt.rp.end_session_url` validate it again.

   .. versionchanged:: 0.2.0
      The five modelled endpoints became URL-validated in the constructor and
      ``from_dict`` (previously only the extension members were), the
      ``issuer`` became validated, and an empty-string
      ``userinfo_endpoint`` / ``registration_endpoint`` now makes
      ``from_dict`` raise.

   Documents returned by :func:`~pygrindvakt.rp.discover` are not type-checked
   against the known extension members (discovery never fails over them). For a
   malformed member, e.g. ``acr_values_supported: "urn:x"``, the typed getter
   returns ``None`` while :attr:`raw` and ``to_dict()`` still carry the original
   value, and ``from_dict(md.to_dict())`` of such a document raises
   :class:`~pygrindvakt.ConfigError`.

   Known extension members live in ``extra`` but have typed accessors.
   Getters return ``None`` when the member is absent (distinct from ``[]`` /
   ``False``); setters take the value or ``None`` to remove it, and raise
   :class:`~pygrindvakt.ConfigError` for a wrong type.

   .. py:attribute:: end_session_endpoint
      :type: str | None

      OIDC RP-Initiated Logout endpoint. The setter validates it as an https
      URL (loopback http only for a loopback issuer) without comparing its host
      to the issuer; the origin rule lives on
      :class:`~pygrindvakt.rp.ProviderInfo`. A
      :class:`~pygrindvakt.provider.Provider` advertises it in its discovery
      document when set; the provider does not implement a logout endpoint
      itself.

   .. py:attribute:: acr_values_supported
      :type: list[str] | None
   .. py:attribute:: claim_types_supported
      :type: list[str] | None
   .. py:attribute:: display_values_supported
      :type: list[str] | None
   .. py:attribute:: ui_locales_supported
      :type: list[str] | None
   .. py:attribute:: claims_locales_supported
      :type: list[str] | None
   .. py:attribute:: userinfo_signing_alg_values_supported
      :type: list[str] | None
   .. py:attribute:: userinfo_encryption_alg_values_supported
      :type: list[str] | None
   .. py:attribute:: userinfo_encryption_enc_values_supported
      :type: list[str] | None
   .. py:attribute:: id_token_encryption_alg_values_supported
      :type: list[str] | None
   .. py:attribute:: id_token_encryption_enc_values_supported
      :type: list[str] | None
   .. py:attribute:: request_object_signing_alg_values_supported
      :type: list[str] | None
   .. py:attribute:: token_endpoint_auth_signing_alg_values_supported
      :type: list[str] | None
   .. py:attribute:: request_uri_parameter_supported
      :type: bool | None
   .. py:attribute:: require_request_uri_registration
      :type: bool | None
   .. py:attribute:: require_pushed_authorization_requests
      :type: bool | None
   .. py:attribute:: frontchannel_logout_supported
      :type: bool | None
   .. py:attribute:: backchannel_logout_supported
      :type: bool | None
   .. py:attribute:: revocation_endpoint
      :type: str | None
   .. py:attribute:: introspection_endpoint
      :type: str | None
   .. py:attribute:: pushed_authorization_request_endpoint
      :type: str | None
   .. py:attribute:: check_session_iframe
      :type: str | None
   .. py:attribute:: service_documentation
      :type: str | None
   .. py:attribute:: op_policy_uri
      :type: str | None
   .. py:attribute:: op_tos_uri
      :type: str | None

   .. code-block:: python

      from pygrindvakt import metadata

      md = metadata.ProviderMetadata("https://issuer.example", "https://issuer.example/oidc")
      md.token_endpoint                       # "https://issuer.example/oidc/token"
      md.scopes_supported = ["openid", "email"]
      md.set_extra_field("organization_name", "Example University")

      doc = md.to_dict()
      assert metadata.ProviderMetadata.from_dict(doc).token_endpoint == md.token_endpoint

   .. note::

      :class:`pygrindvakt.provider.Provider` publishes only capabilities it
      actually implements. At construction it normalizes response types,
      response modes, grants, subject types, client authentication methods,
      PKCE methods and the ID-token signing algorithm to the effective engine
      configuration.

   .. note::

      The issuer and the endpoint URLs are **configuration**. Derive them
      from a setting, never from the incoming ``Host`` header: the token
      endpoint URL is also the audience of ``private_key_jwt`` assertions and
      the ``htu`` of DPoP proofs, so an attacker who controls ``Host`` would
      control what those checks compare against. See :doc:`../guides/security`.
