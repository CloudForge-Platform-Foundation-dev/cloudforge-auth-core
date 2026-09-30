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
            # Real socket/transport failure — upstream problem, not the token.
            logger.warning("JWKS endpoint unreachable: %s", exc)
            raise JWKSUnavailableError(
                f"JWKS endpoint unavailable: {exc}"
            ) from exc
        except jwt.exceptions.PyJWKClientConnectionError as exc:
            # PyJWT's own dedicated network-failure exception (urllib
            # URLError/TimeoutError while fetching the JWKS document).
            logger.warning("JWKS endpoint unreachable: %s", exc)
            raise JWKSUnavailableError(
                f"JWKS endpoint unavailable: {exc}"
            ) from exc
        except __import__("json").JSONDecodeError as exc:
            # JWKS endpoint responded but the body wasn't valid JSON.
            logger.warning("JWKS endpoint returned invalid JSON: %s", exc)
            raise JWKSUnavailableError(
                f"JWKS endpoint returned invalid response: {exc}"
            ) from exc
        except jwt.PyJWKSetError as exc:
            # Raised earlier in the pipeline than PyJWKClientError below
            # (while parsing the JWKS document itself, before per-key
            # filtering) when the "keys" array is empty. PyJWT makes this
            # a SIBLING of PyJWKClientError, not a subclass of it (both
            # extend PyJWTError directly) -- so it needs its own branch or
            # it silently falls through as an unclassified PyJWTError and
            # gets mapped to 401 by the caller instead of 503. Always an
            # upstream misconfiguration, never the client's fault.
            logger.warning("JWKS endpoint has no usable keys: %s", exc)
            raise JWKSUnavailableError(
                f"JWKS endpoint misconfigured: {exc}"
            ) from exc
        except jwt.PyJWKClientError as exc:
            # PyJWT raises this SAME class for two very different cases:
            #   (a) "The JWKS endpoint did not contain any signing keys"
            #       → upstream misconfiguration → 503.
            #   (b) "Unable to find a signing key that matches: <kid>"
            #       → the token's own kid is unknown/bad → 401.
            # We distinguish by checking for the FIXED substring PyJWT
            # itself uses for case (a) — never by scanning for generic
            # keywords like "connection"/"http"/"timeout", because case
            # (b)'s message embeds the token's own attacker-controlled
            # `kid` value verbatim. A token with kid="connection-lost"
            # must still be a 401, not a 503, and previously wasn't.
            if "did not contain any signing keys" in str(exc):
                logger.warning("JWKS endpoint has no usable keys: %s", exc)
                raise JWKSUnavailableError(
                    f"JWKS endpoint misconfigured: {exc}"
                ) from exc
            # Genuine "kid not found after refresh" — the client's
            # token is bad, not our infrastructure. Let it propagate;
            # dependencies.py maps jwt.PyJWKClientError → 401.
            logger.debug("JWKS key lookup failed: %s", exc)
            raise
        # NOTE: jwt.DecodeError (malformed token structure, raised by
        # get_signing_key_from_jwt's own unverified-header decode) is
        # deliberately NOT caught here — it propagates as a normal
        # PyJWTError, which dependencies.py already maps to 401. Do not
        # add a catch-all `except Exception` here: previously that turned
        # every malformed-token error into a fabricated 503, which is
        # both wrong (a bad token is not "the service is unavailable")
        # and gave callers an oracle for probing this code path.
