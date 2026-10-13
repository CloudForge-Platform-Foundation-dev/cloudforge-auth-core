from dataclasses import dataclass
from typing import Tuple

@dataclass(frozen=True)
class AuthConfig:
    algorithms: Tuple[str, ...] = ("RS256",)
    jwks_url: str = ""
    issuer: str = ""
    audience: str = ""
    jwks_cache_ttl_seconds: int = 300

    def __post_init__(self):
        # Enforce RS256 invariant
        algs = list(self.algorithms)
        if algs != ["RS256"]:
            raise ValueError("Only RS256 algorithm is supported by contract v1")
        # Force tuple immutability
        if not isinstance(self.algorithms, tuple):
            object.__setattr__(self, 'algorithms', tuple(self.algorithms))
