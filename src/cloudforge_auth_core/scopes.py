"""Scope claim parsing — Identity Contract v1 §3."""

from __future__ import annotations

from typing import Any, Mapping


class ScopeFormatError(ValueError):
    """Raised when the scope claim is missing the contract shape or uses a deprecated form."""


def parse_scopes(claims: Mapping[str, Any]) -> frozenset[str]:
    """
    Extract scopes from JWT claims per Contract v1 §3.

    - Only the singular ``scope`` claim is accepted (OAuth 2.0 style).
    - Value must be a space-separated string.
    - Deprecated ``scopes`` claim (plural / list) is rejected → 401.
    - Non-string ``scope`` values are rejected → 401.
    - Missing ``scope`` → empty set (403 handled by require_scope).
    """
    if "scopes" in claims:
        raise ScopeFormatError(
            "Deprecated 'scopes' claim is not accepted; use space-separated 'scope' string"
        )

    raw = claims.get("scope")
    if raw is None:
        return frozenset()
    if not isinstance(raw, str):
        raise ScopeFormatError(
            f"Invalid scope claim type: expected str, got {type(raw).__name__}"
        )
    parts = [p for p in raw.split() if p]
    return frozenset(parts)
