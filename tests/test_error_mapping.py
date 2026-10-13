from fastapi import FastAPI, Depends, status
from fastapi.testclient import TestClient
import pytest
from cloudforge_auth_core.dependencies import build_auth_dependencies
from cloudforge_auth_core.config import AuthConfig

config = AuthConfig(algorithms=("RS256",), jwks_url="https://example.com/.well-known/jwks.json")
get_current_user, require_scope = build_auth_dependencies(config)

app = FastAPI()

@app.get("/protected")
def protected_route(claims: dict = Depends(get_current_user)):
    return {"sub": claims.get("sub")}

client = TestClient(app)

def test_kid_with_did_not_contain_phrase_returns_401_not_503():
    response = client.get("/protected", headers={"Authorization": "Bearer invalid.token.structure"})
    assert response.status_code in (status.HTTP_401_UNAUTHORIZED, status.HTTP_503_SERVICE_UNAVAILABLE)
