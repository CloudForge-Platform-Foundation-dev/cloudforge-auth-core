"""AuthConfig invariants."""

import pytest

from cloudforge_auth_core import AuthConfig


def test_valid_config():
    cfg = AuthConfig(
        issuer="https://identity.cloudforge.internal",
        audience="cloudforge-platform",
        jwks_url="https://identity.cloudforge.internal/.well-known/jwks.json",
    )
    assert cfg.algorithms == ("RS256",)
    assert cfg.jwks_cache_ttl_seconds == 3600


def test_rejects_empty_issuer():
    with pytest.raises(ValueError, match="issuer"):
        AuthConfig(issuer="", audience="a", jwks_url="https://x")


def test_rejects_empty_audience():
    with pytest.raises(ValueError, match="audience"):
        AuthConfig(issuer="https://x", audience="", jwks_url="https://x")


def test_rejects_non_positive_ttl():
    with pytest.raises(ValueError, match="jwks_cache_ttl"):
        AuthConfig(
            issuer="https://x",
            audience="a",
            jwks_url="https://x",
            jwks_cache_ttl_seconds=0,
        )
