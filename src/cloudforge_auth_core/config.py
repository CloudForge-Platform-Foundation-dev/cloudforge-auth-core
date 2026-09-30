"""Auth configuration — Identity Contract v1 §2."""

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
