"""
FastAPI dependency factories — Identity Contract v1 §§2, 4, 5.

Studios call::

    get_current_user, require_scope = build_auth_dependencies(config, jwks_cache=...)

and wire the returned callables into FastAPI ``Depends(...)``.

HTTP semantics (Contract v1 §5 + JWKS failure clarification)
------------------------------------------------------------
- Missing / malformed / bad signature / expired / wrong iss|aud|alg → **401**
- Valid token, insufficient scope                                  → **403**
- JWKS endpoint unavailable (network / timeout / upstream)         → **503**
"""

from __future__ import annotations

import logging
from typing import Callable

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from cloudforge_auth_core.config import AuthConfig
from cloudforge_auth_core.jwks import JWKSCache, JWKSUnavailableError
from cloudforge_auth_core.principal import Principal
from cloudforge_auth_core.scopes import ScopeFormatError, parse_scopes

logger = logging.getLogger(__name__)

_bearer_scheme = HTTPBearer(auto_error=False)


def build_auth_dependencies(
    config: AuthConfig,
    *,
    jwks_cache: JWKSCache | None = None,
) -> tuple[Callable, Callable]:
    """
    Build ``get_current_user`` and ``require_scope`` bound to *config*.

    Parameters
    ----------
    config:
        Shared AuthConfig (issuer, audience, algorithms, …).
    jwks_cache:
        Optional pre-built cache. If omitted a new ``JWKSCache(config)``
        is created. Tests inject a fake cache here (or monkey-patch the
        instance that the Studio holds at module level).

    Returns
    -------
    (get_current_user, require_scope)
        Both are FastAPI-compatible callables.
    """
    cache = jwks_cache if jwks_cache is not None else JWKSCache(config)

    def get_current_user(
        credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    ) -> Principal:
        """
        Verify Bearer JWT and return a Principal.

        Raises
        ------
        HTTPException 401
            Missing token, malformed, bad signature, expired, wrong
            iss/aud/alg, or non-contract scope claim shape.
        HTTPException 503
            Identity Service JWKS endpoint unreachable (upstream failure).
        """
        if credentials is None or not credentials.credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        token = credentials.credentials

        # --- Resolve signing key (may raise JWKSUnavailableError → 503) ---
        try:
            signing = cache.get_signing_key(token)
        except JWKSUnavailableError as exc:
            logger.error("JWKS upstream failure: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Identity service temporarily unavailable",
            ) from None

        # --- Verify signature + required claims ---
        try:
            claims = jwt.decode(
                token,
                key=signing.key,
                algorithms=list(config.algorithms),  # RS256 only
                issuer=config.issuer,
                audience=config.audience,
                options={
                    "require": ["exp", "iat", "iss", "aud", "sub"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iss": True,
                    "verify_aud": True,
                },
            )
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token expired",
                headers={"WWW-Authenticate": "Bearer"},
            ) from None
        except jwt.InvalidIssuerError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token issuer",
                headers={"WWW-Authenticate": "Bearer"},
            ) from None
        except jwt.InvalidAudienceError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token audience",
                headers={"WWW-Authenticate": "Bearer"},
            ) from None
        except jwt.MissingRequiredClaimError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Missing required claim: {exc.claim}",
                headers={"WWW-Authenticate": "Bearer"},
            ) from None
        except jwt.PyJWTError as exc:
            # Covers InvalidSignatureError, InvalidAlgorithmError,
            # DecodeError, ImmatureSignatureError, etc.
            logger.debug("JWT verification failed: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            ) from None

        # --- Scope shape (Contract v1 §3) ---
        try:
            scopes = parse_scopes(claims)
        except ScopeFormatError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(exc),
                headers={"WWW-Authenticate": "Bearer"},
            ) from None

        # iss/aud are populated so Studio test fixtures that construct
        # Principal(iss=..., aud=...) stay compatible, and so callers can
        # audit which issuer/audience the token was bound to.
        aud_claim = claims["aud"]
        if isinstance(aud_claim, (list, tuple)):
            aud_value = str(aud_claim[0]) if aud_claim else None
        else:
            aud_value = str(aud_claim)
        return Principal(
            sub=str(claims["sub"]),
            scopes=scopes,
            raw_claims=dict(claims),
            iss=str(claims["iss"]),
            aud=aud_value,
        )

    def require_scope(required_scope: str) -> Callable:
        """
        Dependency factory: token must carry *required_scope*.

        Missing scope → HTTP 403 (token itself was valid → 401 already
        handled by get_current_user).
        """

        def _checker(
            principal: Principal = Depends(get_current_user),
        ) -> Principal:
            if not principal.has_scope(required_scope):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Missing required scope: {required_scope}",
                )
            return principal

        return _checker

    return get_current_user, require_scope
