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
      ``False``. With ``exclude_defaults=True`` modelled and known-extension
      members that are empty lists, ``False`` or ``None`` are dropped; unknown
      extras are kept as-is. ``from_dict(md.to_dict()).to_dict() == md.to_dict()``
      holds for any metadata, including ``end_session_endpoint`` and extras.

   .. py:attribute:: raw
      :type: dict[str, Any] | None

      The source document: the ``from_dict`` argument, or the body fetched by
      :func:`pygrindvakt.rp.discover`; ``None`` for objects built with the
      constructor (or returned by ``Provider.metadata``). It is a **snapshot**:
      setters do not update it, so it is the way to see what the OP actually
      sent (including members that ``to_dict`` fills with defaults).

   Core endpoints, all ``str`` and writable:

   .. py:attribute:: issuer
      :type: str
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
      documented JSON type; a wrong type raises ``ValueError`` from
      ``from_dict``, ``extra`` and ``set_extra_field``.

   .. py:method:: set_extra_field(key: str, value: Any) -> None

      Set one non-protocol extension field. ``value`` may be any
      JSON-serializable object (known extension members must have the right
      type); reserved names raise ``ValueError``.

   ``extra``, ``set_extra_field`` and ``from_dict`` only **type-check** extras;
   they never validate URLs, so a bad advertised value cannot make ``from_dict``
   fail. ``end_session_endpoint`` is validated against the issuer when the
   dedicated setter is used, when a :class:`~pygrindvakt.rp.ProviderInfo` is
   built (the constructor raises; ``from_metadata`` drops it) and when
   :func:`~pygrindvakt.rp.end_session_url` is called.

   Documents returned by :func:`~pygrindvakt.rp.discover` are not type-checked
   against the known extension members (discovery never fails over them). For a
   malformed member, e.g. ``acr_values_supported: "urn:x"``, the typed getter
   returns ``None`` while :attr:`raw` and ``to_dict()`` still carry the original
   value, and ``from_dict(md.to_dict())`` of such a document raises
   ``ValueError``.

   Known extension members live in ``extra`` but have typed accessors.
   Getters return ``None`` when the member is absent (distinct from ``[]`` /
   ``False``); setters take the value or ``None`` to remove it, and raise
   ``ValueError`` for a wrong type.

   .. py:attribute:: end_session_endpoint
      :type: str | None

      OIDC RP-Initiated Logout endpoint. The setter validates it as an https
      URL for the issuer (loopback http only for a loopback issuer). A
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
