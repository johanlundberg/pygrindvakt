"""Package-level checks: version, submodule registration, exception hierarchy."""

import pytest

import pygrindvakt
from pygrindvakt import OAuthError

SUBMODULES = [
    "client", "discovery", "dpop", "federation", "http", "jwt", "keys", "mac",
    "metadata", "pkce", "provider", "request", "rp", "tokens", "util",
]


def test_version():
    """The version is pinned in Cargo.toml and pyproject.toml; keep them in sync."""
    assert pygrindvakt.__version__ == "0.1.0"


def test_submodules_importable():
    """Every grindvakt area is a real importable submodule (registered in sys.modules)."""
    import importlib

    for name in SUBMODULES:
        assert hasattr(pygrindvakt, name), name
        mod = importlib.import_module(f"pygrindvakt.{name}")
        assert mod is getattr(pygrindvakt, name)
        assert mod.__name__ == f"pygrindvakt.{name}"


def test_exception_hierarchy():
    """All errors derive from GrindvaktError; DPoP errors form their own subtree."""
    E = pygrindvakt
    for cls in (E.BadRequestError, E.AuthnError, E.StateError, E.ConfigError, E.CryptoError,
                E.AttributeMappingError, E.JoseError, E.JsonError, E.InternalError,
                E.NoBoundEndpointError, E.UnknownModuleError, E.DpopError, OAuthError):
        assert issubclass(cls, E.GrindvaktError), cls
    for cls in (E.DpopInvalidError, E.DpopReplayError, E.DpopNonceRequiredError, E.DpopServerError):
        assert issubclass(cls, E.DpopError), cls
    assert E.AuthnError.status_hint == 401
    assert E.NoBoundEndpointError.status_hint == 404
    assert E.BadRequestError.status_hint == 400
    assert E.GrindvaktError.status_hint == 500


def test_oauth_error_is_constructible_and_renders():
    """Applications raise OAuthError themselves; it carries data and renders both ways."""
    e = OAuthError("access_denied", "nope", state="xyz")
    assert (e.code, e.description, e.state) == ("access_denied", "nope", "xyz")
    assert e.http_status == 400 and e.status_hint == 400
    assert str(e) == "access_denied: nope"
    r = e.to_response()
    assert r.status == 400
    assert r.header("content-type") == "application/json"
    assert r.header("cache-control") == "no-store"
    assert b'"error":"access_denied"' in r.body and b'"state":"xyz"' in r.body
    rd = e.to_redirect("https://rp.example.com/cb?x=1", "query")
    assert rd.status == 302
    assert rd.header("location") == "https://rp.example.com/cb?x=1&error=access_denied&error_description=nope&state=xyz"
    fragment = e.to_redirect("https://rp.example.com/cb", "fragment")
    assert fragment.header("location") == (
        "https://rp.example.com/cb#error=access_denied&error_description=nope&state=xyz"
    )
    with pytest.raises(ValueError, match="response_mode"):
        e.to_redirect("https://rp.example.com/cb", "form_post")
    with pytest.raises(TypeError):
        e.to_redirect("https://rp.example.com/cb")


def test_oauth_error_invalid_client_gets_www_authenticate():
    """invalid_client is a 401 with a WWW-Authenticate challenge (RFC 6749 section 5.2)."""
    r = OAuthError("invalid_client").to_response()
    assert r.status == 401
    assert r.header("www-authenticate") == "Basic"
    assert OAuthError("server_error").http_status == 500
    assert OAuthError("temporarily_unavailable").http_status == 503


def test_oauth_error_rejects_unknown_code():
    """A typo in the code fails at raise time, not at render time."""
    import pytest

    with pytest.raises(ValueError):
        OAuthError("not_a_code")


def test_oauth_error_with_state_copies():
    e = OAuthError("invalid_request", "bad").with_state("s1")
    assert e.state == "s1" and e.description == "bad"


def test_py_typed_is_not_partial():
    """The package is fully typed: py.typed must not carry the ``partial`` marker."""
    import pathlib

    marker = pathlib.Path(pygrindvakt.__file__).parent / "py.typed"
    assert marker.exists()
    assert "partial" not in marker.read_text()
