"""Principal — authenticated identity returned by get_current_user()."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class Principal:
    """
    Authenticated caller.

    Attributes
    ----------
    sub:
        Subject claim (user or service account id).
    scopes:
        Parsed set of scope strings from the space-separated ``scope`` claim.
        Missing ``scope`` claim → empty set (authenticated, zero permissions).
        See scopes.py / Contract note: auth vs authz separation.
    iss:
        Issuer claim. Optional for backward compatibility with Studio test
        fixtures that construct Principal(iss=..., aud=...) directly.
        Populated from the verified token by get_current_user().
    aud:
        Audience claim. Same compatibility note as ``iss``.
    raw_claims:
        Full JWT payload. **Escape hatch only** — Studios must not build
        Studio-specific authorization logic from arbitrary claims
        (``role``, ``email``, ``tenant``, …). Allowed uses:

        - Reading contract-defined claims that are not yet promoted to
          first-class Principal fields.
        - Audit / logging of the original token payload.

        If a claim becomes part of the authorization model it must be
        added to Identity Contract and exposed as an explicit field on
        Principal — not read ad-hoc via ``raw_claims``.
    """

    sub: str
    scopes: frozenset[str] = field(default_factory=frozenset)
    raw_claims: dict[str, Any] = field(default_factory=dict)
    # Optional for backward-compat with Ingest/Knowledge test fixtures
    # that already construct Principal(iss=..., aud=...). Validated
    # tokens always populate these from claims.
    iss: str | None = None
    aud: str | None = None

    def has_scope(self, required: str) -> bool:
        """Return True if this principal holds the given scope string."""
        return required in self.scopes

    def has_all_scopes(self, *required: str) -> bool:
        return all(s in self.scopes for s in required)
