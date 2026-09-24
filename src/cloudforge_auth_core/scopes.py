"""Scope parsing — Identity Contract v1 §3."""

from __future__ import annotations

from typing import Any


class ScopeFormatError(ValueError):
    """Raised when the token carries a non-contract scope claim shape."""


def parse_scopes(claims: dict[str, Any]) -> frozenset[str]:
    """
    Extract scopes from JWT claims per Identity Contract v1.

    Rules
    -----
    - Claim must be named ``scope`` (singular) and be a **string**.
    - Values are space-separated; empty string → empty set.
    - The deprecated ``scopes`` (list/array) form is **rejected** — this is
      the exact drift that contract v1 was written to close.

    Decision: missing ``scope`` claim entirely
    ------------------------------------------
    Treated as authenticated with **zero scopes** (empty set), not 401.

    Rationale: keep authentication (is the token valid?) separate from
    authorization (does it grant this permission?). A valid token with no
    scopes will fail every ``require_scope(...)`` with 403 — it cannot
    silently gain access. Identity Service SHOULD always emit ``scope``;
    if it forgets, the failure mode is "no permissions" not "accept as
    full-access" (the class of bug this contract exists to prevent).

    Contract note: §2 marks ``scope`` as required at *issuance*. Enforcement
    of that duty belongs to the Identity Service, not to every Studio
    rejecting otherwise-valid tokens.
    """
    if "scopes" in claims and "scope" not in claims:
        raise ScopeFormatError(
            "Token uses deprecated 'scopes' (list) claim. "
            "Identity Contract v1 requires a space-separated 'scope' string."
        )

    raw = claims.get("scope")
    if raw is None:
        return frozenset()

    if not isinstance(raw, str):
        raise ScopeFormatError(
            f"Claim 'scope' must be a string (got {type(raw).__name__}). "
            "Identity Contract v1 forbids list/array form."
        )

    parts = [p for p in raw.split(" ") if p]
    return frozenset(parts)
