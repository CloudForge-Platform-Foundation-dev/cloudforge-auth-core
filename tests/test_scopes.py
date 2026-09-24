"""Scope parsing — contract v1 §3."""

import pytest

from cloudforge_auth_core.scopes import ScopeFormatError, parse_scopes


def test_space_separated_string():
    assert parse_scopes({"scope": "ingest:read ingest:write"}) == frozenset(
        {"ingest:read", "ingest:write"}
    )


def test_empty_scope_string():
    assert parse_scopes({"scope": ""}) == frozenset()


def test_missing_scope_claim():
    assert parse_scopes({}) == frozenset()


def test_rejects_scopes_list_form():
    with pytest.raises(ScopeFormatError, match="deprecated"):
        parse_scopes({"scopes": ["ingest:read"]})


def test_rejects_non_string_scope():
    with pytest.raises(ScopeFormatError, match="must be a string"):
        parse_scopes({"scope": ["ingest:read"]})
