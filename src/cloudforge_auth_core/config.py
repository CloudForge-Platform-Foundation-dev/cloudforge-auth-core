"""AuthConfig — shared shape required by Identity Contract v1."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class AuthConfig:
    """
    Immutable configuration shared across Studios.

    Studios supply issuer / audience / jwks_url from their own env settings;
    this class enforces contract-level invariants (RS256-only, non-empty
    issuer/audience, positive cache TTL).
    """

    issuer: str
    audience: str
    jwks_url: str
    jwks_cache_ttl_seconds: int = 3600
    # Contract v1 §4: RS256 only. Exposed as a tuple so callers can assert it.
    algorithms: tuple[str, ...] = field(default=("RS256",), init=False)

    def __post_init__(self) -> None:
        if not self.issuer:
            raise ValueError("AuthConfig.issuer must be a non-empty string")
        if not self.audience:
            raise ValueError("AuthConfig.audience must be a non-empty string")
        if not self.jwks_url:
            raise ValueError("AuthConfig.jwks_url must be a non-empty string")
        if self.jwks_cache_ttl_seconds <= 0:
            raise ValueError("AuthConfig.jwks_cache_ttl_seconds must be > 0")
        # algorithms is init=False and fixed to RS256 — nothing else to check.
