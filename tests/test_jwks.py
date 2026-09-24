"""JWKSCache unit tests — key lookup vs upstream failure."""

from __future__ import annotations

import pytest

from cloudforge_auth_core import AuthConfig
from cloudforge_auth_core.jwks import JWKSCache, JWKSUnavailableError, SigningKey


def _config() -> AuthConfig:
    return AuthConfig(
        issuer="https://identity.cloudforge.internal",
        audience="cloudforge-platform",
        jwks_url="https://identity.cloudforge.internal/.well-known/jwks.json",
    )


def test_signing_key_wrapper():
    key = object()
    sk = SigningKey(key)
    assert sk.key is key


def test_jwks_unavailable_error_is_distinct():
    """Callers must be able to catch JWKSUnavailableError without catching all Exceptions."""
    with pytest.raises(JWKSUnavailableError):
        raise JWKSUnavailableError("down")


def test_get_signing_key_propagates_unavailable(monkeypatch):
    """
    When the underlying client raises a connection-like error,
    JWKSCache must raise JWKSUnavailableError (→ 503), not a generic exception.
    """
    cache = JWKSCache(_config())

    def _boom(token):
        raise ConnectionError("connection refused")

    monkeypatch.setattr(cache, "_client", type("C", (), {"get_signing_key_from_jwt": staticmethod(_boom)})())

    with pytest.raises(JWKSUnavailableError, match="unavailable"):
        cache.get_signing_key("any.jwt.token")


def test_get_signing_key_kid_not_found_is_not_unavailable(monkeypatch):
    """
    'kid not found' after refresh is a token problem (→ 401), not 503.
    PyJWKClientError without connection hints must propagate as-is.
    """
    import jwt

    cache = JWKSCache(_config())

    def _kid_miss(token):
        raise jwt.PyJWKClientError("Unable to find a signing key that matches")

    monkeypatch.setattr(cache, "_client", type("C", (), {"get_signing_key_from_jwt": staticmethod(_kid_miss)})())

    with pytest.raises(jwt.PyJWKClientError):
        cache.get_signing_key("any.jwt.token")
