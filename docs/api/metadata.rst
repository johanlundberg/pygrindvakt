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

   .. py:method:: to_dict() -> dict[str, Any]

      The discovery document as a dict, with ``extra`` merged in at the top
      level. :meth:`pygrindvakt.provider.Provider.discovery_document` returns
      the same shape.

   Core endpoints, all ``str`` and writable:

   .. py:attribute:: issuer
      :type: str
   .. py:attribute:: authorization_endpoint
      :type: str
   .. py:attribute:: token_endpoint
      :type: str
   .. py:attribute:: userinfo_endpoint
      :type: str
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
      through ``extra``. ``end_session_endpoint`` is also rejected because
      this provider does not implement OIDC logout.

   .. py:method:: set_extra_field(key: str, value: Any) -> None

      Set one non-protocol extension field. ``value`` may be any
      JSON-serializable object; reserved and unsupported names raise
      ``ValueError``.

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
