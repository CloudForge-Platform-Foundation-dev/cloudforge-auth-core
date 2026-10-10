"""Auth configuration â€” Identity Contract v1 Â§2."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence


@dataclass(frozen=True)
class AuthConfig:
    """
    Shared auth settings consumed by JWKSCache and build_auth_dependencies.

    Studios translate their environment-specific settings into this object
    (see e.g. Nova's ``src/auth/config.py``) and never re-implement JWT
    verification themselves.
    """

    issuer: str
    audience: str
    jwks_url: str
    jwks_cache_ttl_seconds: int = 3600
    # Contract v1: RS256 only.
    algorithms: Sequence[str] = field(default_factory=lambda: ("RS256",))

    def __post_init__(self):
        """Enforce RS256-only per Identity Contract v1 and freeze algorithms."""
        algs = tuple(self.algorithms)
        if algs != ("RS256",):
            raise ValueError(
                f"CloudForge Identity Contract v1 requires RS256 only. "
                f"Got: {list(algs)}"
            )
        object.__setattr__(self, "algorithms", algs)
