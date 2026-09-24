# cloudforge-auth-core

Shared JWT verification and scope enforcement for every CloudForge Studio.

Implements **CloudForge Identity Contract v1**.

Studios must not re-implement JWT verification, JWKS fetching, or scope
parsing. Import from this package only.

```
identity-contract-v1   ← spec (Foundation)
        │
        ▼
cloudforge-auth-core   ← this package (semver)
        │
        ▼
Ingest / Knowledge / Nova / …
```

## Install

```bash
# Once published to a private index or git ref:
pip install cloudforge-auth-core==1.1.*

# Local / monorepo development (editable):
pip install -e ./cloudforge-auth-core
```

Pin a compatible range in each Studio's `requirements.txt`:

```
cloudforge-auth-core==1.1.*
```

## Quick usage (Studio binding)

```python
from cloudforge_auth_core import AuthConfig, Principal, build_auth_dependencies
from cloudforge_auth_core.jwks import JWKSCache

config = AuthConfig(
    issuer="https://identity.cloudforge.internal",
    audience="cloudforge-platform",
    jwks_url="https://identity.cloudforge.internal/.well-known/jwks.json",
    jwks_cache_ttl_seconds=3600,
)

jwks_cache = JWKSCache(config)
get_current_user, require_scope = build_auth_dependencies(
    config, jwks_cache=jwks_cache
)

# FastAPI:
#   @app.get("/...")
#   def endpoint(user: Principal = Depends(require_scope("ingest:read"))):
#       ...
```

## Contract guarantees (v1)

| Rule | Behaviour |
|------|-----------|
| Algorithm | **RS256 only** — rejects `none`, HS256, etc. |
| `scope` claim | space-separated **string** only — rejects `scopes` list |
| Missing / bad token / bad claims | HTTP **401** |
| Valid token, insufficient scope | HTTP **403** |
| JWKS endpoint unavailable | HTTP **503** |
| Audience | platform-wide (`cloudforge-platform`) |

### HTTP semantics detail

| Situation | Status |
|-----------|--------|
| No token / malformed / bad signature | 401 |
| `exp` expired | 401 |
| `iss` / `aud` mismatch | 401 |
| Wrong algorithm (e.g. HS256) | 401 |
| Missing required claim (`sub`/`exp`/`iat`/`iss`/`aud`) | 401 |
| Deprecated `scopes` list form | 401 |
| Missing `scope` claim entirely | 200 path → empty scopes (auth OK; authz via require_scope → 403) |
| Token valid, scope insufficient | 403 |
| Identity Service JWKS unreachable / timeout | **503** |

401 = client authentication problem.  
503 = platform dependency failure (do not treat as "bad client token").

## Principal and `raw_claims`

```python
principal.sub          # subject
principal.scopes       # frozenset of scope strings
principal.iss          # issuer (from verified token; optional in constructor)
principal.aud          # audience (from verified token; optional in constructor)
principal.has_scope()  # scope check
principal.raw_claims   # full JWT payload — escape hatch only
```

**Missing `scope` claim:** treated as authenticated with zero scopes
(not 401). Identity Service SHOULD always emit `scope`; if it does not,
the failure mode is "no permissions" (403 on every gated route), never
silent full-access. See `scopes.parse_scopes` docstring for the full
rationale (auth vs authz separation).

**`raw_claims` discipline:** Studios must **not** build authorization logic
from arbitrary claims (`role`, `email`, `tenant`, …). Allowed uses are
audit/logging and reading contract-defined claims that are not yet
promoted to first-class Principal fields. New authorization claims require
an Identity Contract update and an explicit Principal field.

## Versioning

- Package `1.x` implements contract `identity-contract-v1` (backward compatible).
- Package `2.0` will only ship with `identity-contract-v2` (breaking).
- Studios pin their own range; Foundation policy flags drift via Dependabot.

## What this package does **not** do

- No Studio business logic
- No token issuance (that is the Identity Service)
- No refresh-token flow (out of scope for contract v1)
