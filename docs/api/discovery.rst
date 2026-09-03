pygrindvakt.discovery
=====================

.. py:module:: pygrindvakt.discovery

Home-organization discovery for OpenID Federation RPs and OpenID Connect Core
section 4 Third-Party Initiated Login.

A discovery service presents a list of OPs (from a trust anchor's collection
endpoint, see :func:`pygrindvakt.federation.fetch_collection`) to the user;
the selection is returned to the RP's ``initiate_login_uri`` as a
third-party initiated login. The module has functions for each side:

* **RP side, outgoing call:** :func:`discovery_request_url` builds the
  redirect to the (out-of-band configured) discovery endpoint.
* **RP side, return call:** :func:`parse_third_party_initiated_login`
  validates the request arriving at the RP's ``initiate_login_uri``.
* **Discovery-service side:** :func:`initiate_login_uri`,
  :func:`initiate_login_uri_from_resolved` and
  :func:`self_published_initiate_login_uri` extract the verified RP's return
  endpoint, :func:`third_party_login_url` builds the selection link, and
  :func:`promote_hint` applies the OP-hint promotion rule.

Entity identifiers
------------------

.. py:function:: validate_entity_id(s: str) -> None

   Validate an OpenID Federation Entity Identifier as accepted on a wire
   parameter (``entity_id``, ``iss``, ``hint``): an ``https`` URL with a
   host and no query or fragment. Raises :class:`pygrindvakt.BadRequestError`
   otherwise.

RP side
-------

.. py:function:: discovery_request_url(discovery_endpoint: str, rp_entity_id: str, op_hint: str | None = None, target_link_uri: str | None = None) -> str

   Build the URL an RP redirects the browser to in order to start home
   organization discovery (the *outgoing call*):
   ``<discovery_endpoint>?entity_id=<rp>[&hint=<op>][&target_link_uri=<uri>]``.
   An endpoint that already has a query string is extended, and a fragment
   is kept after the query.

   ``discovery_endpoint`` is the discovery service's absolute endpoint URL.
   ``rp_entity_id`` is the RP's own entity identifier; ``op_hint``
   optionally names a preferred OP; ``target_link_uri`` lets the RP learn
   where to send the user after login without keeping a session (the
   discovery service returns it verbatim). Raises
   :class:`pygrindvakt.BadRequestError` on an invalid endpoint or entity
   identifier.

.. py:class:: ThirdPartyInitiatedLogin(iss: str, *, login_hint: str | None = None, target_link_uri: str | None = None)

   A parsed and validated Third-Party Initiated Login request (OpenID
   Connect Core section 4), as received at the RP's ``initiate_login_uri``.
   Immutable, comparable with ``==`` and hashable.

   .. py:property:: iss
      :type: str

      The issuer (OP) the RP should send the authentication request to.

   .. py:property:: login_hint
      :type: str | None

      Optional hint about the end-user to be logged in.

   .. py:property:: target_link_uri
      :type: str | None

      Where to send the user after a successful login. The RP **must**
      verify it against its own allowlist before redirecting to it.

.. py:function:: parse_third_party_initiated_login(params: Mapping[str, str]) -> ThirdPartyInitiatedLogin

   Parse the query parameters arriving at an RP's ``initiate_login_uri``
   into a :class:`ThirdPartyInitiatedLogin`. ``iss`` is required and must be
   a valid ``https`` entity identifier; empty ``login_hint`` /
   ``target_link_uri`` values are treated as absent; unknown parameters are
   ignored. Raises :class:`pygrindvakt.BadRequestError`.

   .. code-block:: python

      @app.get("/initiate")
      def initiate_login():
          try:
              login = discovery.parse_third_party_initiated_login(request.args.to_dict())
          except BadRequestError:
              abort(400)
          if login.target_link_uri and not allowed_target(login.target_link_uri):
              abort(400)
          # Resolve login.iss through the federation and start the code flow with it.
          return start_login(op_entity_id=login.iss, after=login.target_link_uri)

Discovery-service side
----------------------

.. py:function:: initiate_login_uri(metadata: Mapping[str, Any]) -> str

   Extract a verified RP's ``initiate_login_uri`` from its resolved metadata
   dict (``metadata["openid_relying_party"]["initiate_login_uri"]``). The
   URI must be ``https`` without a fragment: it is the only place a
   discovery service ever sends a user, so anything weaker would turn the
   service into an open redirector. Raises :class:`pygrindvakt.AuthnError`.

.. py:function:: initiate_login_uri_from_resolved(entity: ResolvedEntity) -> str

   :func:`initiate_login_uri` over a
   :class:`pygrindvakt.federation.ResolvedEntity` (from
   :func:`pygrindvakt.federation.resolve_via_trust_anchors`). Raises
   :class:`pygrindvakt.AuthnError`.

.. py:class:: SelfPublishedRp

   A verified self-published relying party: the full ``metadata`` claims
   object from its entity configuration plus the statement's lifetime.
   Immutable. Returned by :func:`self_published_rp`.

   .. py:property:: metadata
      :type: dict[str, Any]

      The ``metadata`` claims object as a dict (contains
      ``openid_relying_party``, ...).

   .. py:property:: exp
      :type: int | None

      The entity configuration's ``exp`` (seconds since epoch), if present;
      use it to bound caching.

.. py:function:: self_published_rp(http: HttpClientProtocol | None, rp_entity_id: str) -> SelfPublishedRp

   Fetch and verify an RP's *self-published* entity configuration
   (``<rp_entity_id>/.well-known/openid-federation``, self-signed) and
   return its metadata and lifetime.

   For discovery services running in an open mode: the RP is not required
   to chain up to a trust anchor, but anything taken from the result is
   still limited to what the entity itself publishes under its own
   identifier, never caller-supplied data. The statement must be issued by
   (and about) ``rp_entity_id`` exactly; the identifier is validated before
   anything is fetched. Raises :class:`pygrindvakt.BadRequestError`,
   :class:`pygrindvakt.AuthnError` or :class:`pygrindvakt.InternalError`.

.. py:function:: self_published_initiate_login_uri(http: HttpClientProtocol | None, rp_entity_id: str) -> str

   :func:`self_published_rp` reduced to the validated
   ``initiate_login_uri``.

.. py:function:: third_party_login_url(initiate_login_uri: str, op_entity_id: str, login_hint: str | None = None, target_link_uri: str | None = None) -> str

   Build the third-party initiated login URL the user is sent to after
   selecting an OP (the *return call*):
   ``<initiate_login_uri>?iss=<op>[&login_hint=...][&target_link_uri=...]``.

   ``target_link_uri`` is attached verbatim: it is only ever appended to a
   verified ``initiate_login_uri``, never used as a redirect target itself.

.. py:function:: promote_hint(entities: list[CollectionEntity], hint: str) -> tuple[bool, list[CollectionEntity]]

   If ``hint`` names one of ``entities`` (trailing slash ignored), move it
   to the front: the discovery flow requires a matching OP hint to become
   the default choice. Returns ``(found, entities)`` where ``entities`` is a
   new, reordered list; the input list is not modified.

Example: a discovery service
----------------------------

.. code-block:: python

   from pygrindvakt import AuthnError, BadRequestError, discovery, federation

   TRUST_ANCHORS = {...}
   COLLECTION = "https://ta.example.org/collection"

   @app.get("/discovery")
   def choose_op():
       rp_id = request.args.get("entity_id", "")
       try:
           discovery.validate_entity_id(rp_id)
           rp_entity = federation.resolve_via_trust_anchors(None, rp_id, TRUST_ANCHORS)
           return_to = discovery.initiate_login_uri_from_resolved(rp_entity)
       except (BadRequestError, AuthnError):
           abort(400)
       ops = federation.fetch_collection(None, COLLECTION, "openid_provider")
       found, ops = discovery.promote_hint(ops, request.args.get("hint", ""))
       links = [
           (e.display_name, discovery.third_party_login_url(return_to, e.entity_id,
                                                            target_link_uri=request.args.get("target_link_uri")))
           for e in ops
       ]
       return render_template("choose.html", links=links, preselected=found)
