"""Authenticated principal — Identity Contract v1 §3."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence


@dataclass(frozen=True)
class Principal:
    """
    Result of a successful JWT verification.

    Attributes
    ----------
    sub:
        Subject claim (user / service identity).
    scopes:
        Parsed scope set from the token.
    raw_claims:
        Full decoded claims dict (for auditing / advanced checks).
    iss / aud:
        Issuer and audience the token was bound to (aud is the first
        value when the claim is a list).
    """

    sub: str
    scopes: frozenset[str]
    raw_claims: Mapping[str, Any] = field(default_factory=dict)
    iss: str | None = None
    aud: str | None = None

    def has_scope(self, required: str) -> bool:
        """Return True if *required* is present in the token's scopes."""
        return required in self.scopes
