"""
cloudforge-auth-core — Identity Contract v1 implementation.

Public API used by every CloudForge Studio:

    from cloudforge_auth_core import (
        AuthConfig,
        Principal,
        build_auth_dependencies,
        JWKSUnavailableError,
    )
    from cloudforge_auth_core.jwks import JWKSCache
"""

from cloudforge_auth_core.config import AuthConfig
from cloudforge_auth_core.dependencies import build_auth_dependencies
from cloudforge_auth_core.jwks import JWKSUnavailableError
from cloudforge_auth_core.principal import Principal

__all__ = [
    "AuthConfig",
    "Principal",
    "build_auth_dependencies",
    "JWKSUnavailableError",
]

__version__ = "1.1.0"
