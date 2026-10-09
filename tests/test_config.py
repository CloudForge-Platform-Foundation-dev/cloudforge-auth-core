"""
Tests for AuthConfig RS256 invariant.
"""
import pytest
from cloudforge_auth_core.config import AuthConfig


def test_auth_config_default_algorithms():
    """Test that default algorithms is RS256."""
    config = AuthConfig(
        issuer="https://test.cloudforge.internal",
        audience="cloudforge-platform",
        jwks_url="http://localhost:8080/.well-known/jwks.json",
    )
    assert config.algorithms == ("RS256",)


def test_auth_config_accepts_rs256():
    """Test that AuthConfig accepts RS256."""
    config = AuthConfig(
        issuer="https://test.cloudforge.internal",
        audience="cloudforge-platform",
        jwks_url="http://localhost:8080/.well-known/jwks.json",
        algorithms=["RS256"],
    )
    assert config.algorithms == ["RS256"]


def test_auth_config_rejects_hs256():
    """Test that AuthConfig rejects HS256."""
    with pytest.raises(ValueError, match="RS256 only"):
        AuthConfig(
            issuer="https://test.cloudforge.internal",
            audience="cloudforge-platform",
            jwks_url="http://localhost:8080/.well-known/jwks.json",
            algorithms=["HS256"],
        )


def test_auth_config_rejects_multiple_algorithms():
    """Test that AuthConfig rejects multiple algorithms."""
    with pytest.raises(ValueError, match="RS256 only"):
        AuthConfig(
            issuer="https://test.cloudforge.internal",
            audience="cloudforge-platform",
            jwks_url="http://localhost:8080/.well-known/jwks.json",
            algorithms=["RS256", "HS256"],
        )


def test_auth_config_rejects_empty_algorithms():
    """Test that AuthConfig rejects empty algorithms list."""
    with pytest.raises(ValueError, match="RS256 only"):
        AuthConfig(
            issuer="https://test.cloudforge.internal",
            audience="cloudforge-platform",
            jwks_url="http://localhost:8080/.well-known/jwks.json",
            algorithms=[],
        )
