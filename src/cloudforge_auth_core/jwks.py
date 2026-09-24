"""JWKS fetch + cache — Identity Contract v1 §4."""

from __future__ import annotations

import logging
from typing import Any

import jwt
from jwt import PyJWK

from cloudforge_auth_core.config import AuthConfig

logger = logging.getLogger(__name__)


class JWKSUnavailableError(Exception):
    """
    Raised when the Identity Service JWKS endpoint cannot be reached
    or returns an unusable response (network error, timeout, empty keys).

    Mapped to HTTP 503 by the dependency layer — this is an upstream
    dependency failure, not an invalid-token condition (which is 401).
    """


class SigningKey:
    """Thin wrapper so callers can rely on ``.key`` regardless of source."""

    __slots__ = ("key",)

    def __init__(self, key: Any) -> None:
        self.key = key


class JWKSCache:
    """
    Fetches and caches JWKS from the Identity Service.

    - Cache TTL is taken from ``AuthConfig.jwks_cache_ttl_seconds``.
    - On ``kid`` miss after a successful cache hit, PyJWKClient refreshes
      once before failing (handles key rotation).
    - Network / upstream failures raise ``JWKSUnavailableError`` so the
      dependency layer can map them to HTTP 503 (not 401).
    """

    def __init__(self, config: AuthConfig) -> None:
        self._config = config
        self._client = jwt.PyJWKClient(
            config.jwks_url,
            cache_keys=True,
            lifespan=config.jwks_cache_ttl_seconds,
        )

    def get_signing_key(self, token: str) -> SigningKey:
        """
        Resolve the signing key for ``token``.

        Returns
        -------
        SigningKey
            Object with a ``.key`` attribute (public key).

        Raises
        ------
        JWKSUnavailableError
            Network / timeout / empty JWKS response from Identity Service.
        jwt.PyJWKClientError / jwt.PyJWTError
            Key not found for the token's ``kid`` after refresh attempt
            (treated as invalid token → 401 by the dependency layer).
        """
        try:
            jwk: PyJWK = self._client.get_signing_key_from_jwt(token)
            return SigningKey(jwk.key)
        except JWKSUnavailableError:
            raise
        except (ConnectionError, TimeoutError, OSError) as exc:
            logger.warning("JWKS endpoint unreachable: %s", exc)
            raise JWKSUnavailableError(
                f"JWKS endpoint unavailable: {exc}"
            ) from exc
        except jwt.PyJWKClientError as exc:
            # PyJWKClient raises this both for "key not found" and for
            # transport failures. Distinguish by message / cause when possible.
            msg = str(exc).lower()
            if any(
                hint in msg
                for hint in (
                    "connection",
                    "timeout",
                    "timed out",
                    "unreachable",
                    "name or service not known",
                    "failed to fetch",
                    "http",
                )
            ):
                logger.warning("JWKS fetch failed: %s", exc)
                raise JWKSUnavailableError(
                    f"JWKS endpoint unavailable: {exc}"
                ) from exc
            # Genuine "kid not found after refresh" → let caller map to 401.
            logger.debug("JWKS key lookup failed: %s", exc)
            raise
        except Exception as exc:
            # Unexpected — treat as upstream failure to avoid leaking
            # internal errors as "invalid token".
            logger.warning("Unexpected JWKS error: %s", exc)
            raise JWKSUnavailableError(
                f"JWKS endpoint unavailable: {exc}"
            ) from exc
