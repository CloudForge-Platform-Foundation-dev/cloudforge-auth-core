# cloudforge-auth-core

Shared JWT verification and scope enforcement implementing **CloudForge Identity Contract v1**.

Studios (Ingest / Knowledge / Nova / …) must **not** re-implement JWT verification.
They consume this package and supply environment-specific config only.

## Install

```bash
pip install "cloudforge-auth-core @ git+https://github.com/CloudForge-Platform-Foundation-dev/cloudforge-auth-core.git@v1.1.8"
```

## Usage

```python
from cloudforge_auth_core import AuthConfig, build_auth_dependencies, JWKSCache

config = AuthConfig(
    issuer="https://identity.cloudforge.internal",
    audience="cloudforge-platform",
    jwks_url="https://identity.cloudforge.internal/.well-known/jwks.json",
)
jwks_cache = JWKSCache(config)
get_current_user, require_scope = build_auth_dependencies(config, jwks_cache=jwks_cache)
```

## HTTP semantics (Contract v1 §5)

| Condition | Status |
|-----------|--------|
| Missing / malformed / bad signature / expired / wrong iss\|aud\|alg / bad scope shape | **401** |
| Valid token, insufficient scope | **403** |
| JWKS endpoint unreachable / empty keys / non-JSON | **503** |

Unknown `kid` (including attacker-controlled values) is always **401**, never 503.

## Version

**1.1.8** — version metadata aligned: tag `v1.1.7` (immutable, commit `d2740025895549d435608a46f54301f17d45b156`) still reports `1.1.6` in `pyproject.toml` / `__version__`; this release makes the reported version match the tag. Also: removed UTF-8 BOM and unused imports (`config.py`, `principal.py`), refreshed `ci.yml` header comment. No change to verification, scope, or HTTP semantics.

**1.1.7** — tuple-freeze of `AuthConfig.algorithms` + FastAPI error-mapping tests.

**1.1.6** — removed UTF-8 BOM (scopes.py, pyproject.toml), versions aligned (v1.1.5 tag was broken: TOML parse error); complete package (config / principal / scopes / `__init__` + proper packaging).
Previous `v1.1.1` tag was incomplete (missing modules → ImportError in CI).
