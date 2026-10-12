"""Tests for ``pygrindvakt.metadata``: round-trip, raw/exclude_defaults views,
typed known-extension fields and ``end_session_endpoint``."""

from __future__ import annotations

import pytest

from pygrindvakt import metadata

ISSUER = "https://op.example.com"


def minimal_doc():
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authz",
        "token_endpoint": f"{ISSUER}/token",
        "jwks_uri": f"{ISSUER}/jwks",
    }


def test_round_trip_with_end_session_and_extras():
    doc = minimal_doc() | {
        "end_session_endpoint": f"{ISSUER}/logout",
        "acr_values_supported": ["a", "b"],
        "organization_name": "Example",
    }
    md = metadata.ProviderMetadata.from_dict(doc)
    again = metadata.ProviderMetadata.from_dict(md.to_dict())
    assert again.to_dict() == md.to_dict()
    assert again.end_session_endpoint == f"{ISSUER}/logout"
    assert again.extra["organization_name"] == "Example"


def test_round_trip_constructed_metadata():
    md = metadata.ProviderMetadata(ISSUER)
    md.end_session_endpoint = f"{ISSUER}/logout"
    assert metadata.ProviderMetadata.from_dict(md.to_dict()).to_dict() == md.to_dict()


def test_exclude_defaults_drops_spec_defaults_only():
    md = metadata.ProviderMetadata.from_dict(minimal_doc() | {"unknown_empty": [], "frontchannel_logout_supported": False})
    full = md.to_dict()
    assert full["scopes_supported"] == [] and full["claims_parameter_supported"] is False
    slim = md.to_dict(exclude_defaults=True)
    assert "scopes_supported" not in slim and "frontchannel_logout_supported" not in slim
    assert "claims_parameter_supported" not in slim and slim["unknown_empty"] == []
    md.scopes_supported = ["openid"]
    md.claims_parameter_supported = True
    slim = md.to_dict(exclude_defaults=True)
    assert slim["scopes_supported"] == ["openid"] and slim["claims_parameter_supported"] is True


def test_exclude_defaults_request_uri_parameter_supported_defaults_true():
    false_doc = minimal_doc() | {"request_uri_parameter_supported": False}
    slim = metadata.ProviderMetadata.from_dict(false_doc).to_dict(exclude_defaults=True)
    assert slim["request_uri_parameter_supported"] is False
    true_doc = minimal_doc() | {"request_uri_parameter_supported": True}
    slim = metadata.ProviderMetadata.from_dict(true_doc).to_dict(exclude_defaults=True)
    assert "request_uri_parameter_supported" not in slim


# Spec defaults, so the equivalence check below is independently verifiable.
# Sources: OIDC Discovery 1.0 section 3, RFC 8414 section 2, OIDC Front-/Back-
# Channel Logout 1.0 (discovery metadata), RFC 9126 section 5.
BOOL_DEFAULTS = {
    "claims_parameter_supported": False,
    "request_parameter_supported": False,
    "request_uri_parameter_supported": True,
    "require_request_uri_registration": False,
    "frontchannel_logout_supported": False,
    "backchannel_logout_supported": False,
    "require_pushed_authorization_requests": False,
}
# Members whose spec default is a NON-empty list: an explicit [] means "none"
# and must survive exclude_defaults.
NONEMPTY_LIST_DEFAULTS = {
    "response_modes_supported": ["query", "fragment"],
    "grant_types_supported": ["authorization_code", "implicit"],
    "token_endpoint_auth_methods_supported": ["client_secret_basic"],
    "claim_types_supported": ["normal"],
}
# List members with no spec default (absent == nothing advertised == []).
EMPTY_LIST_DEFAULT = [
    "scopes_supported",
    "claims_supported",
    "code_challenge_methods_supported",
    "dpop_signing_alg_values_supported",
    "acr_values_supported",
    "display_values_supported",
    "ui_locales_supported",
    "claims_locales_supported",
    "userinfo_signing_alg_values_supported",
    "userinfo_encryption_alg_values_supported",
    "userinfo_encryption_enc_values_supported",
    "id_token_encryption_alg_values_supported",
    "id_token_encryption_enc_values_supported",
    "request_object_signing_alg_values_supported",
    "token_endpoint_auth_signing_alg_values_supported",
]
# REQUIRED lists: no default, [] is kept as is.
REQUIRED_LISTS = [
    "response_types_supported",
    "subject_types_supported",
    "id_token_signing_alg_values_supported",
]


def effective(doc):
    """Apply the spec defaults for members absent from ``doc``."""
    out = dict(doc)
    for k, v in BOOL_DEFAULTS.items():
        out.setdefault(k, v)
    for k, v in NONEMPTY_LIST_DEFAULTS.items():
        out.setdefault(k, list(v))
    for k in EMPTY_LIST_DEFAULT:
        out.setdefault(k, [])
    return out


def _equivalence_docs():
    docs = [minimal_doc()]
    docs.append(minimal_doc() | {k: v for k, v in BOOL_DEFAULTS.items()})
    docs.append(minimal_doc() | {k: (not v) for k, v in BOOL_DEFAULTS.items()})
    docs.append(minimal_doc() | {k: [] for k in NONEMPTY_LIST_DEFAULTS | dict.fromkeys(EMPTY_LIST_DEFAULT)})
    docs.append(minimal_doc() | {k: ["x"] for k in NONEMPTY_LIST_DEFAULTS | dict.fromkeys(EMPTY_LIST_DEFAULT)})
    docs.append(minimal_doc() | {k: list(v) for k, v in NONEMPTY_LIST_DEFAULTS.items()})
    for k, v in BOOL_DEFAULTS.items():
        docs.append(minimal_doc() | {k: v})
        docs.append(minimal_doc() | {k: not v})
    for k in [*NONEMPTY_LIST_DEFAULTS, *EMPTY_LIST_DEFAULT, *REQUIRED_LISTS]:
        docs.append(minimal_doc() | {k: []})
        docs.append(minimal_doc() | {k: ["x"]})
    return docs


@pytest.mark.parametrize("doc", _equivalence_docs())
def test_exclude_defaults_is_effectively_lossless(doc):
    md = metadata.ProviderMetadata.from_dict(doc)
    slim = md.to_dict(exclude_defaults=True)
    # Expected values come from the ORIGINAL SOURCE with defaults applied to
    # absent keys, not from to_dict() (which fills [] for absent lists).
    expected = effective(doc)
    # Re-parsed: from_dict keeps the slim doc as raw, so absence is preserved.
    reparsed = metadata.ProviderMetadata.from_dict(slim)
    assert effective(reparsed.raw) == expected
    assert effective(reparsed.to_dict(exclude_defaults=True)) == expected
    assert effective(slim) == expected


@pytest.mark.parametrize("key", [*NONEMPTY_LIST_DEFAULTS, *REQUIRED_LISTS])
def test_exclude_defaults_keeps_explicit_empty_list_without_empty_default(key):
    md = metadata.ProviderMetadata.from_dict(minimal_doc() | {key: []})
    slim = md.to_dict(exclude_defaults=True)
    assert slim[key] == []


ABSENT_AS_EMPTY = [
    "response_modes_supported",
    "grant_types_supported",
    "token_endpoint_auth_methods_supported",
    *REQUIRED_LISTS,
]


def test_exclude_defaults_minimal_doc_gains_no_empty_default_lists():
    md = metadata.ProviderMetadata.from_dict(minimal_doc())
    assert all(md.to_dict()[k] == [] for k in ABSENT_AS_EMPTY)  # upstream limit
    slim = md.to_dict(exclude_defaults=True)
    for k in [*ABSENT_AS_EMPTY, "claim_types_supported"]:
        assert k not in slim


@pytest.mark.parametrize("key", ABSENT_AS_EMPTY)
def test_exclude_defaults_explicit_empty_kept_and_modified_value_kept(key):
    md = metadata.ProviderMetadata.from_dict(minimal_doc() | {key: []})
    assert md.to_dict(exclude_defaults=True)[key] == []
    md = metadata.ProviderMetadata.from_dict(minimal_doc())
    setattr(md, key, ["x"])
    assert md.to_dict(exclude_defaults=True)[key] == ["x"]


def test_exclude_defaults_constructor_built_keeps_empty_lists():
    md = metadata.ProviderMetadata(ISSUER)
    for k in ABSENT_AS_EMPTY:
        setattr(md, k, [])
    slim = md.to_dict(exclude_defaults=True)
    assert all(slim[k] == [] for k in ABSENT_AS_EMPTY)  # no raw: cannot tell


@pytest.mark.parametrize("key", EMPTY_LIST_DEFAULT)
def test_exclude_defaults_drops_empty_list_with_no_default(key):
    md = metadata.ProviderMetadata.from_dict(minimal_doc() | {key: []})
    assert key not in md.to_dict(exclude_defaults=True)


def test_raw_is_source_document_and_snapshot():
    doc = minimal_doc() | {"x_vendor": {"a": 1}}
    md = metadata.ProviderMetadata.from_dict(doc)
    assert md.raw == doc
    md.token_endpoint = f"{ISSUER}/other"
    assert md.raw == doc  # snapshot: setters do not change it
    assert metadata.ProviderMetadata(ISSUER).raw is None


def test_userinfo_endpoint_optional():
    md = metadata.ProviderMetadata.from_dict(minimal_doc())
    assert md.userinfo_endpoint is None
    assert md.registration_endpoint is None


def test_known_extra_wrong_types_rejected():
    with pytest.raises(ValueError, match="acr_values_supported"):
        metadata.ProviderMetadata.from_dict(minimal_doc() | {"acr_values_supported": "abc"})
    with pytest.raises(ValueError, match="acr_values_supported"):
        metadata.ProviderMetadata.from_dict(minimal_doc() | {"acr_values_supported": [1]})
    with pytest.raises(ValueError, match="backchannel_logout_supported"):
        metadata.ProviderMetadata.from_dict(minimal_doc() | {"backchannel_logout_supported": "yes"})
    with pytest.raises(ValueError, match="revocation_endpoint"):
        metadata.ProviderMetadata.from_dict(minimal_doc() | {"revocation_endpoint": 5})
    md = metadata.ProviderMetadata(ISSUER)
    with pytest.raises(ValueError):
        md.acr_values_supported = "abc"
    with pytest.raises(ValueError):
        md.acr_values_supported = [1, 2]
    with pytest.raises(ValueError):
        md.set_extra_field("acr_values_supported", "abc")
    with pytest.raises(ValueError):
        md.extra = {"request_uri_parameter_supported": 1}
    with pytest.raises(ValueError):
        md.request_uri_parameter_supported = "true"
    assert md.acr_values_supported is None


def test_known_extra_getters_distinguish_absent_from_empty():
    md = metadata.ProviderMetadata(ISSUER)
    assert md.acr_values_supported is None
    assert md.backchannel_logout_supported is None
    assert md.revocation_endpoint is None
    md.acr_values_supported = []
    md.backchannel_logout_supported = False
    md.revocation_endpoint = f"{ISSUER}/revoke"
    assert md.acr_values_supported == []
    assert md.backchannel_logout_supported is False
    assert md.revocation_endpoint == f"{ISSUER}/revoke"
    assert md.extra["acr_values_supported"] == []
    md.acr_values_supported = None
    assert md.acr_values_supported is None
    assert "acr_values_supported" not in md.extra
    md.set_extra_field("claim_types_supported", ["normal"])
    assert md.claim_types_supported == ["normal"]


def test_end_session_endpoint_property():
    md = metadata.ProviderMetadata(ISSUER)
    assert md.end_session_endpoint is None
    md.end_session_endpoint = f"{ISSUER}/logout"
    assert md.extra["end_session_endpoint"] == f"{ISSUER}/logout"
    md.end_session_endpoint = None
    assert "end_session_endpoint" not in md.extra
    for bad in ["http://op.example.com/l", "https://op.example.com/l#f", "https://u:p@op.example.com/l", "not a url"]:
        with pytest.raises(ValueError):
            md.end_session_endpoint = bad
    md.extra = {"end_session_endpoint": f"{ISSUER}/logout"}
    assert md.end_session_endpoint == f"{ISSUER}/logout"


def test_reserved_modelled_fields_still_rejected_in_extra():
    md = metadata.ProviderMetadata(ISSUER)
    with pytest.raises(ValueError, match="reserved"):
        md.set_extra_field("token_endpoint", "x")


URL_MEMBERS = [
    "end_session_endpoint",
    "revocation_endpoint",
    "introspection_endpoint",
    "pushed_authorization_request_endpoint",
    "check_session_iframe",
]
BAD_URLS = [
    "javascript:x",
    "http://evil.example/l",
    f"{ISSUER}/l#frag",
    "https://u:p@op.example.com/l",
    "nonsense",
]


@pytest.mark.parametrize("name", URL_MEMBERS)
@pytest.mark.parametrize("bad", BAD_URLS)
def test_url_members_rejected_on_every_write_path(name, bad):
    md = metadata.ProviderMetadata(ISSUER)
    with pytest.raises(ValueError, match=name):
        metadata.ProviderMetadata.from_dict(minimal_doc() | {name: bad})
    with pytest.raises(ValueError, match=name):
        md.extra = {name: bad}
    with pytest.raises(ValueError, match=name):
        md.set_extra_field(name, bad)
    with pytest.raises(ValueError, match=name):
        setattr(md, name, bad)
    assert name not in md.extra


@pytest.mark.parametrize("name", URL_MEMBERS)
def test_url_members_accept_valid_https_url(name):
    good = f"{ISSUER}/x"
    assert metadata.ProviderMetadata.from_dict(minimal_doc() | {name: good}).extra[name] == good
    md = metadata.ProviderMetadata(ISSUER)
    md.extra = {name: good}
    md.set_extra_field(name, good)
    setattr(md, name, good)
    assert getattr(md, name) == good


def test_non_url_extras_are_type_checked_only():
    md = metadata.ProviderMetadata.from_dict(
        minimal_doc() | {"service_documentation": "nonsense", "op_policy_uri": "javascript:x"}
    )
    assert md.extra["service_documentation"] == "nonsense"
    md.set_extra_field("op_tos_uri", "http://evil.example/t")
    md.extra = {"service_documentation": "nonsense"}
    with pytest.raises(ValueError, match="a string"):
        md.set_extra_field("service_documentation", 1)
    with pytest.raises(ValueError, match="a string"):
        md.set_extra_field("end_session_endpoint", 1)


def test_discover_does_not_validate_url_members():
    from pygrindvakt import rp
    import json

    class Http:
        def get(self, url):
            body = minimal_doc() | {"end_session_endpoint": "http://evil.example/l", "revocation_endpoint": "nonsense"}
            return 200, json.dumps(body).encode(), "application/json"

        def post_form(self, url, form, headers):
            raise AssertionError

    md = rp.discover(Http(), ISSUER)
    assert md.revocation_endpoint == "nonsense"


def test_discovered_malformed_known_extra_getter_none_roundtrip_raises():
    from pygrindvakt import rp
    import json

    class Http:
        def get(self, url):
            return 200, json.dumps(minimal_doc() | {"acr_values_supported": "urn:x"}).encode(), "application/json"

        def post_form(self, url, form, headers):
            raise AssertionError

    md = rp.discover(Http(), ISSUER)
    assert md.acr_values_supported is None
    assert md.raw["acr_values_supported"] == "urn:x"
    assert md.to_dict()["acr_values_supported"] == "urn:x"
    with pytest.raises(ValueError, match="acr_values_supported"):
        metadata.ProviderMetadata.from_dict(md.to_dict())


def test_set_issuer_revalidates_url_members():
    md = metadata.ProviderMetadata("http://localhost:8000")
    md.revocation_endpoint = "http://localhost:8000/revoke"
    md.end_session_endpoint = "http://localhost:8000/logout"
    with pytest.raises(ValueError, match="_endpoint"):
        md.issuer = "https://op.example"
    assert md.issuer == "http://localhost:8000"
    md.revocation_endpoint = None
    md.end_session_endpoint = None
    md.revocation_endpoint = "https://op.example/revoke"
    md.issuer = "https://op.example"
    assert md.issuer == "https://op.example"
    md.issuer = "https://op.example"


@pytest.mark.parametrize("key", ABSENT_AS_EMPTY)
def test_exclude_defaults_explicit_empty_assigned_after_parse_is_kept(key):
    """An explicit [] set by the caller is "none", not the absent-in-source artefact."""
    md = metadata.ProviderMetadata.from_dict(minimal_doc())
    assert key not in md.to_dict(exclude_defaults=True)  # untouched: stays absent
    setattr(md, key, [])
    assert md.to_dict(exclude_defaults=True)[key] == []
    assert key not in (md.raw or {})  # raw stays an unmodified snapshot
    # Other untouched lists are still suppressed.
    others = [k for k in ABSENT_AS_EMPTY if k != key]
    slim = md.to_dict(exclude_defaults=True)
    assert all(k not in slim for k in others)
