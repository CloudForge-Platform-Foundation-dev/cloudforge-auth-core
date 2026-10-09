"""
Unit tests for scopes.parse_scopes() — Identity Contract v1 §3.
"""
import pytest
from cloudforge_auth_core.scopes import parse_scopes, ScopeFormatError


def test_parse_scopes_valid_space_separated():
    """Test valid space-separated scope string."""
    claims = {"scope": "nova:query knowledge:read"}
    result = parse_scopes(claims)
    assert result == frozenset({"nova:query", "knowledge:read"})


def test_parse_scopes_single_scope():
    """Test single scope."""
    claims = {"scope": "nova:query"}
    result = parse_scopes(claims)
    assert result == frozenset({"nova:query"})


def test_parse_scopes_empty_string():
    """Test empty scope string."""
    claims = {"scope": ""}
    result = parse_scopes(claims)
    assert result == frozenset()


def test_parse_scopes_missing_scope_claim():
    """Test missing scope claim returns empty set."""
    claims = {"iss": "test", "sub": "client"}
    result = parse_scopes(claims)
    assert result == frozenset()


def test_parse_scopes_deprecated_scopes_claim_raises():
    """Test deprecated 'scopes' (plural) claim raises ScopeFormatError."""
    claims = {"scopes": ["nova:query"]}
    with pytest.raises(ScopeFormatError, match="Deprecated"):
        parse_scopes(claims)


def test_parse_scopes_non_string_value_raises():
    """Test non-string scope value raises ScopeFormatError."""
    claims = {"scope": 123}
    with pytest.raises(ScopeFormatError, match="Invalid scope claim type"):
        parse_scopes(claims)


def test_parse_scopes_list_value_raises():
    """Test list scope value raises ScopeFormatError."""
    claims = {"scope": ["nova:query"]}
    with pytest.raises(ScopeFormatError, match="Invalid scope claim type"):
        parse_scopes(claims)


def test_parse_scopes_extra_whitespace():
    """Test scope string with extra whitespace."""
    claims = {"scope": "  nova:query   knowledge:read  "}
    result = parse_scopes(claims)
    assert result == frozenset({"nova:query", "knowledge:read"})


def test_parse_scopes_studio_permission_format():
    """Test studio:permission format."""
    claims = {"scope": "ingest:read ingest:write knowledge:read"}
    result = parse_scopes(claims)
    assert "ingest:read" in result
    assert "ingest:write" in result
    assert "knowledge:read" in result
