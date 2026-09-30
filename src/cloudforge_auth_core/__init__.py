"""
cloudforge-auth-core
===================

Shared JWT verification and scope enforcement implementing
CloudForge Identity Contract v1.

Studios must not re-implement JWT verification. Import from here:

    from cloudforge_auth_core import (
        AuthConfig,
        Principal,
        build_auth_dependencies,
        JWKSCache,
    )
"""

from cloudforge_auth_core.config import AuthConfig
from cloudforge_auth_core.dependencies import build_auth_dependencies
from cloudforge_auth_core.jwks import JWKSCache, JWKSUnavailableError
from cloudforge_auth_core.principal import Principal
from cloudforge_auth_core.scopes import ScopeFormatError, parse_scopes

__all__ = [
    "AuthConfig",
    "Principal",
    "build_auth_dependencies",
    "JWKSCache",
    "JWKSUnavailableError",
    "ScopeFormatError",
    "parse_scopes",
]

__version__ = "1.1.2"
