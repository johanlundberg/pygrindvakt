pygrindvakt.request
===================

.. py:module:: pygrindvakt.request

Parsed OIDC authorization requests.

.. py:class:: AuthorizationRequest

   A parsed OIDC authorization request. Immutable.

   Build one with :meth:`from_params` from the query-string dict (or the
   merged parameters of a request object). It is JSON round-trippable
   (:meth:`to_dict` / :meth:`from_dict`) so an application can stash it in a
   session between showing the login page and redirecting back to the
   client.

   .. py:staticmethod:: from_params(params: dict[str, str]) -> AuthorizationRequest

      Parse from a flat parameter dict. Raises
      :class:`pygrindvakt.OAuthError` with code ``invalid_request`` when
      ``client_id``, ``response_type`` or ``redirect_uri`` is missing, or
      when the ``claims`` parameter is not valid JSON. The raised error
      carries the request's ``state`` when one was present.

      Parsing does **not** check the request against any registered client;
      that is :meth:`pygrindvakt.provider.Provider.validate_authorization_request`.

   .. py:staticmethod:: from_dict(d: dict[str, Any]) -> AuthorizationRequest

      Rebuild from a :meth:`to_dict` result (``ValueError`` on a malformed
      dict).

   .. py:method:: to_dict() -> dict[str, Any]

   Parameters:

   .. py:property:: client_id
      :type: str
   .. py:property:: redirect_uri
      :type: str
   .. py:property:: response_type
      :type: str
   .. py:property:: scope
      :type: str
   .. py:property:: state
      :type: str | None
   .. py:property:: nonce
      :type: str | None
   .. py:property:: code_challenge
      :type: str | None
   .. py:property:: code_challenge_method
      :type: str | None
   .. py:property:: response_mode
      :type: str | None
   .. py:property:: prompt
      :type: str | None
   .. py:property:: acr_values
      :type: str | None
   .. py:property:: claims
      :type: dict[str, Any] | None

      The parsed ``claims`` request parameter, if present.

   .. py:property:: request_object
      :type: str | None

      The raw ``request`` parameter (an RFC 9101 request object JWT), if
      present. It is carried verbatim; unpacking and verifying it is the
      application's job (see :doc:`../guides/federation`).

   .. py:property:: extra
      :type: dict[str, str]

      Other parameters preserved verbatim.

   Helpers:

   .. py:method:: scopes() -> list[str]

      The scopes as a list.

   .. py:method:: is_oidc() -> bool

      ``True`` if ``scope`` contains ``openid``.

   .. py:method:: has_prompt(expected: str) -> bool

      Whether ``prompt`` contains ``expected`` (exact, case-sensitive).

   .. py:method:: validate_prompt() -> None

      Validate the ``prompt`` combinations OIDC Core constrains (for example
      ``none`` may not be combined with ``login``). Raises
      :class:`pygrindvakt.OAuthError`.

   .. py:method:: wants_code() -> bool
   .. py:method:: wants_id_token() -> bool

   .. py:method:: use_fragment() -> bool

      ``True`` when the response must be returned in the URL fragment
      (implicit and hybrid response types, or ``response_mode=fragment``).

   .. py:method:: validate_response_type() -> None

      Validate that ``response_type`` is one the OP supports. Raises
      :class:`pygrindvakt.OAuthError`.

   .. code-block:: python

      from pygrindvakt import OAuthError
      from pygrindvakt.request import AuthorizationRequest

      try:
          req = AuthorizationRequest.from_params(flask.request.args.to_dict())
      except OAuthError as e:
          return to_flask(e.to_response())     # redirect_uri is not trusted yet

      req.scopes()          # ["openid", "email"]
      req.is_oidc()         # True
      req.has_prompt("login")

      session["authz"] = req.to_dict()
      # ... later ...
      req = AuthorizationRequest.from_dict(session.pop("authz"))
