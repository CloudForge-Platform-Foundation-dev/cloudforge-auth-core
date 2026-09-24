"""End-to-end JWT verification via build_auth_dependencies.

Covers:
- Happy path (valid RS256 token + scopes)
- 401: missing/malformed/expired/wrong iss/aud/alg/missing claims/scopes-list
- 403: insufficient scope
- 503: JWKS upstream unavailable
"""

from __future__ import annotations

import time

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

from cloudforge_auth_core import AuthConfig, build_auth_dependencies
from cloudforge_auth_core.jwks import JWKSCache, JWKSUnavailableError, SigningKey

# ---------------------------------------------------------------------------
# RSA keypair for the whole module
# ---------------------------------------------------------------------------
_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PUBLIC_KEY = _PRIVATE_KEY.public_key()
_PRIVATE_PEM = _PRIVATE_KEY.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)

ISSUER = "https://identity.cloudforge.internal"
AUDIENCE = "cloudforge-platform"


def _config() -> AuthConfig:
    return AuthConfig(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks_url="https://identity.cloudforge.internal/.well-known/jwks.json",
    )


def _make_token(scope: str = "", alg: str = "RS256", key=None, **overrides) -> str:
    now = int(time.time())
    payload = {
        "sub": "test-user",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + 3600,
        "scope": scope,
    }
    payload.update(overrides)
    sign_key = key if key is not None else _PRIVATE_PEM
    return pyjwt.encode(payload, sign_key, algorithm=alg)


class _FakeCredentials:
    def __init__(self, token: str | None):
        self.credentials = token


@pytest.fixture
def auth_pair():
    """Normal pair: JWKS returns our test RSA public key."""
    cfg = _config()
    cache = JWKSCache(cfg)
    cache.get_signing_key = lambda token: SigningKey(_PUBLIC_KEY)  # type: ignore[method-assign]
    return build_auth_dependencies(cfg, jwks_cache=cache)


@pytest.fixture
def auth_pair_jwks_down():
    """Pair where JWKS always raises JWKSUnavailableError → expect 503."""
    cfg = _config()
    cache = JWKSCache(cfg)

    def _boom(token: str):
        raise JWKSUnavailableError("simulated JWKS outage")

    cache.get_signing_key = _boom  # type: ignore[method-assign]
    return build_auth_dependencies(cfg, jwks_cache=cache)


# ---------------------------------------------------------------------------
# 401 — authentication failures
# ---------------------------------------------------------------------------

def test_missing_credentials_is_401(auth_pair):
    get_current_user, _ = auth_pair
    with pytest.raises(HTTPException) as exc:
        get_current_user(credentials=None)
    assert exc.value.status_code == 401


def test_garbage_token_is_401(auth_pair):
    get_current_user, _ = auth_pair
    with pytest.raises(HTTPException) as exc:
        get_current_user(credentials=_FakeCredentials("not.a.jwt"))
    assert exc.value.status_code == 401


def test_expired_token_is_401(auth_pair):
    get_current_user, _ = auth_pair
    token = _make_token(exp=int(time.time()) - 10)
    with pytest.raises(HTTPException) as exc:
        get_current_user(credentials=_FakeCredentials(token))
    assert exc.value.status_code == 401
    assert "expired" in exc.value.detail.lower()


def test_wrong_issuer_is_401(auth_pair):
    get_current_user, _ = auth_pair
    token = _make_token(iss="https://evil.example")
    with pytest.raises(HTTPException) as exc:
        get_current_user(credentials=_FakeCredentials(token))
    assert exc.value.status_code == 401


def test_wrong_audience_is_401(auth_pair):
    get_current_user, _ = auth_pair
    token = _make_token(aud="other-audience")
    with pytest.raises(HTTPException) as exc:
        get_current_user(credentials=_FakeCredentials(token))
    assert exc.value.status_code == 401


def test_missing_sub_is_401(auth_pair):
    get_current_user, _ = auth_pair
    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + 3600,
        "scope": "ingest:read",
    }
    token = pyjwt.encode(payload, _PRIVATE_PEM, algorithm="RS256")
    with pytest.raises(HTTPException) as exc:
        get_current_user(credentials=_FakeCredentials(token))
    assert exc.value.status_code == 401


def test_missing_exp_is_401(auth_pair):
    get_current_user, _ = auth_pair
    now = int(time.time())
    payload = {
        "sub": "test-user",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "scope": "ingest:read",
    }
    token = pyjwt.encode(payload, _PRIVATE_PEM, algorithm="RS256")
    with pytest.raises(HTTPException) as exc:
        get_current_user(credentials=_FakeCredentials(token))
    assert exc.value.status_code == 401


def test_missing_iat_is_401(auth_pair):
    get_current_user, _ = auth_pair
    now = int(time.time())
    payload = {
        "sub": "test-user",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": now + 3600,
        "scope": "ingest:read",
    }
    token = pyjwt.encode(payload, _PRIVATE_PEM, algorithm="RS256")
    with pytest.raises(HTTPException) as exc:
        get_current_user(credentials=_FakeCredentials(token))
    assert exc.value.status_code == 401


def test_hs256_algorithm_is_rejected(auth_pair):
    """
    Security regression: Nova previously accepted HS256/shared-secret.
    Contract v1 allows RS256 only — HS256 must be 401 even if signature
    would otherwise verify against a shared secret.
    """
    get_current_user, _ = auth_pair
    token = pyjwt.encode(
        {
            "sub": "test-user",
            "iss": ISSUER,
            "aud": AUDIENCE,
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "scope": "ingest:read",
        },
        key="super-secret-shared-key",
        algorithm="HS256",
    )
    with pytest.raises(HTTPException) as exc:
        get_current_user(credentials=_FakeCredentials(token))
    assert exc.value.status_code == 401


def test_invalid_signature_is_401(auth_pair):
    """Token signed with a different RSA key must be rejected."""
    get_current_user, _ = auth_pair
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_pem = other_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    token = _make_token(scope="ingest:read", key=other_pem)
    with pytest.raises(HTTPException) as exc:
        get_current_user(credentials=_FakeCredentials(token))
    assert exc.value.status_code == 401


def test_deprecated_scopes_list_is_401(auth_pair):
    """Regression: pre-migration Ingest used scopes=[...] — must reject."""
    get_current_user, _ = auth_pair
    now = int(time.time())
    payload = {
        "sub": "test-user",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + 3600,
        "scopes": ["ingest:read"],
    }
    token = pyjwt.encode(payload, _PRIVATE_PEM, algorithm="RS256")
    with pytest.raises(HTTPException) as exc:
        get_current_user(credentials=_FakeCredentials(token))
    assert exc.value.status_code == 401
    assert "scope" in exc.value.detail.lower() or "deprecated" in exc.value.detail.lower()


# ---------------------------------------------------------------------------
# 403 — authorization
# ---------------------------------------------------------------------------

def test_valid_token_returns_principal(auth_pair):
    get_current_user, _ = auth_pair
    token = _make_token(scope="ingest:read knowledge:write")
    principal = get_current_user(credentials=_FakeCredentials(token))
    assert principal.sub == "test-user"
    assert principal.has_scope("ingest:read")
    assert principal.has_scope("knowledge:write")
    assert not principal.has_scope("nova:admin")


def test_require_scope_passes(auth_pair):
    get_current_user, require_scope = auth_pair
    token = _make_token(scope="knowledge:write")
    principal = get_current_user(credentials=_FakeCredentials(token))
    result = require_scope("knowledge:write")(principal=principal)
    assert result.sub == "test-user"


def test_require_scope_missing_is_403(auth_pair):
    get_current_user, require_scope = auth_pair
    token = _make_token(scope="knowledge:read")
    principal = get_current_user(credentials=_FakeCredentials(token))
    with pytest.raises(HTTPException) as exc:
        require_scope("knowledge:write")(principal=principal)
    assert exc.value.status_code == 403


# ---------------------------------------------------------------------------
# 503 — JWKS upstream failure (NOT 401)
# ---------------------------------------------------------------------------

def test_jwks_unavailable_is_503(auth_pair_jwks_down):
    """
    Identity Service / JWKS down must surface as 503 Service Unavailable,
    not 401 Invalid token — otherwise operators mis-diagnose client auth.
    """
    get_current_user, _ = auth_pair_jwks_down
    token = _make_token(scope="ingest:read")
    with pytest.raises(HTTPException) as exc:
        get_current_user(credentials=_FakeCredentials(token))
    assert exc.value.status_code == 503
    assert "unavailable" in exc.value.detail.lower()


# ---------------------------------------------------------------------------
# Principal backward-compat (Ingest / Knowledge test fixtures)
# ---------------------------------------------------------------------------

def test_principal_accepts_iss_aud_kwargs():
    """
    Knowledge conftest and Ingest test_main construct:
        Principal(sub=..., iss=..., aud=..., scopes=..., raw_claims={})
    These kwargs must not raise — otherwise publishing this package
    breaks already-merged Studio tests immediately.
    """
    from cloudforge_auth_core import Principal

    p = Principal(
        sub="test-user",
        iss="https://identity.cloudforge.internal",
        aud="cloudforge-platform",
        scopes=frozenset({"ingest:read"}),
        raw_claims={},
    )
    assert p.sub == "test-user"
    assert p.iss == "https://identity.cloudforge.internal"
    assert p.aud == "cloudforge-platform"
    assert p.has_scope("ingest:read")


def test_verified_token_populates_iss_aud(auth_pair):
    get_current_user, _ = auth_pair
    token = _make_token(scope="ingest:read")
    principal = get_current_user(credentials=_FakeCredentials(token))
    assert principal.iss == ISSUER
    assert principal.aud == AUDIENCE


def test_missing_scope_claim_is_authenticated_with_empty_scopes(auth_pair):
    """
    Documented decision: no ``scope`` claim → valid Principal, scopes={}.
    Authorization still fails via require_scope → 403.
    """
    get_current_user, require_scope = auth_pair
    now = int(time.time())
    payload = {
        "sub": "test-user",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + 3600,
        # no scope claim
    }
    token = pyjwt.encode(payload, _PRIVATE_PEM, algorithm="RS256")
    principal = get_current_user(credentials=_FakeCredentials(token))
    assert principal.sub == "test-user"
    assert principal.scopes == frozenset()
    with pytest.raises(HTTPException) as exc:
        require_scope("ingest:read")(principal=principal)
    assert exc.value.status_code == 403
