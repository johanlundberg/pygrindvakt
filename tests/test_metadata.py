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


def test_exclude_defaults_drops_empty_false_and_none():
    md = metadata.ProviderMetadata.from_dict(minimal_doc() | {"unknown_empty": [], "frontchannel_logout_supported": False})
    full = md.to_dict()
    assert full["scopes_supported"] == [] and full["claims_parameter_supported"] is False
    slim = md.to_dict(exclude_defaults=True)
    assert slim == minimal_doc() | {"unknown_empty": []}
    assert "scopes_supported" not in slim and "frontchannel_logout_supported" not in slim
    md.scopes_supported = ["openid"]
    md.claims_parameter_supported = True
    slim = md.to_dict(exclude_defaults=True)
    assert slim["scopes_supported"] == ["openid"] and slim["claims_parameter_supported"] is True


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
