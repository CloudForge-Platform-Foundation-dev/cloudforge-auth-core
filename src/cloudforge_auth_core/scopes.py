"""Scope claim parsing — Identity Contract v1 §3."""

from __future__ import annotations

from typing import Any, Mapping


class ScopeFormatError(ValueError):
    """Raised when the ``scope`` claim is present but not a valid string."""


def parse_scopes(claims: Mapping[str, Any]) -> frozenset[str]:
    """
    Extract scopes from JWT claims per Contract v1 §3.

    - Missing ``scope`` → empty set (caller may still require a scope → 403).
    - ``scope`` must be a space-separated string (OAuth 2.0 style).
    - List/other types → ScopeFormatError → mapped to HTTP 401.
    """
    raw = claims.get("scope")
    if raw is None:
        return frozenset()
    if not isinstance(raw, str):
        raise ScopeFormatError(
            f"Invalid scope claim type: expected str, got {type(raw).__name__}"
        )
    parts = [p for p in raw.split() if p]
    return frozenset(parts)
