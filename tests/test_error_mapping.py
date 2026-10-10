"""
Integration tests for error mapping: exception to HTTP status.
Tests 401, 403, 503 error semantics per Identity Contract v1 §5.
"""
import pytest
import time
import jwt
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import json

from cloudforge_auth_core.config import AuthConfig
from cloudforge_auth_core.jwks import JWKSCache
from cloudforge_auth_core.dependencies import build_auth_dependencies


# --- Mock JWKS Servers ---

class MockJWKSServer(BaseHTTPRequestHandler):
    """Mock JWKS server."""
    jwks_response = None
    
    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(self.jwks_response).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        pass


class EmptyJWKSServer(BaseHTTPRequestHandler):
    """Mock JWKS server that returns empty keys (503)."""
    
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"keys": []}).encode("utf-8"))
    
    def log_message(self, format, *args):
        pass


# --- Fixtures ---

@pytest.fixture(scope="session")
def test_rsa_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )


@pytest.fixture(scope="session")
def test_rsa_private_pem(test_rsa_key):
    return test_rsa_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


@pytest.fixture(scope="session")
def test_rsa_public_pem(test_rsa_key):
    return test_rsa_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


@pytest.fixture(scope="session")
def mock_jwks_server(test_rsa_public_pem):
    """Start mock JWKS server."""
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
    import base64
    
    public_key = serialization.load_pem_public_key(test_rsa_public_pem, backend=default_backend())
    numbers = public_key.public_numbers()
    
    def int_to_base64url(n):
        length = (n.bit_length() + 7) // 8
        data = n.to_bytes(length, byteorder="big")
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
    
    MockJWKSServer.jwks_response = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": "test-key-2026-v1",
                "n": int_to_base64url(numbers.n),
                "e": int_to_base64url(numbers.e),
            }
        ]
    }
    
    server = HTTPServer(("127.0.0.1", 0), MockJWKSServer)
    port = server.server_address[1]
    
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    
    yield f"http://127.0.0.1:{port}/.well-known/jwks.json"
    
    server.shutdown()


@pytest.fixture
def empty_jwks_server():
    """Start mock JWKS server that returns empty keys."""
    server = HTTPServer(("127.0.0.1", 0), EmptyJWKSServer)
    port = server.server_address[1]
    
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    
    yield f"http://127.0.0.1:{port}/.well-known/jwks.json"
    
    server.shutdown()


# --- Tests ---

def test_expired_token_returns_401(mock_jwks_server, test_rsa_private_pem):
    """Test expired token returns 401."""
    app = FastAPI()
    config = AuthConfig(
        issuer="https://test.cloudforge.internal",
        audience="cloudforge-platform",
        jwks_url=mock_jwks_server,
    )
    jwks_cache = JWKSCache(config)
    get_current_user, _ = build_auth_dependencies(config, jwks_cache=jwks_cache)
    
    @app.get("/protected")
    def endpoint(user=Depends(get_current_user)):
        return {"ok": True}
    
    client = TestClient(app)
    
    now = int(time.time())
    payload = {
        "iss": config.issuer,
        "sub": "test",
        "aud": config.audience,
        "exp": now - 3600,
        "iat": now - 7200,
        "scope": "test",
    }
    token = jwt.encode(payload, test_rsa_private_pem, algorithm="RS256", headers={"kid": "test-key-2026-v1"})
    
    response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_insufficient_scope_returns_403(mock_jwks_server, test_rsa_private_pem):
    """Test insufficient scope returns 403."""
    app = FastAPI()
    config = AuthConfig(
        issuer="https://test.cloudforge.internal",
        audience="cloudforge-platform",
        jwks_url=mock_jwks_server,
    )
    jwks_cache = JWKSCache(config)
    get_current_user, require_scope = build_auth_dependencies(config, jwks_cache=jwks_cache)
    
    @app.get("/admin")
    def endpoint(user=Depends(get_current_user)):
        require_scope("admin:write")(user)
        return {"ok": True}
    
    client = TestClient(app)
    
    now = int(time.time())
    payload = {
        "iss": config.issuer,
        "sub": "test",
        "aud": config.audience,
        "exp": now + 3600,
        "iat": now,
        "scope": "nova:query",  # Not admin:write
    }
    token = jwt.encode(payload, test_rsa_private_pem, algorithm="RS256", headers={"kid": "test-key-2026-v1"})
    
    response = client.get("/admin", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403


def test_jwks_unavailable_returns_503(empty_jwks_server, test_rsa_private_pem):
    """Test JWKS unavailable returns 503."""
    app = FastAPI()
    config = AuthConfig(
        issuer="https://test.cloudforge.internal",
        audience="cloudforge-platform",
        jwks_url=empty_jwks_server,
    )
    jwks_cache = JWKSCache(config)
    get_current_user, _ = build_auth_dependencies(config, jwks_cache=jwks_cache)
    
    @app.get("/protected")
    def endpoint(user=Depends(get_current_user)):
        return {"ok": True}
    
    client = TestClient(app)
    
    now = int(time.time())
    payload = {
        "iss": config.issuer,
        "sub": "test",
        "aud": config.audience,
        "exp": now + 3600,
        "iat": now,
        "scope": "test",
    }
    token = jwt.encode(payload, test_rsa_private_pem, algorithm="RS256", headers={"kid": "test-key-2026-v1"})
    
    response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 503


def test_unknown_kid_returns_401_not_503(mock_jwks_server, test_rsa_private_pem):
    """Test unknown kid returns 401 (invalid token), not 503 (service error)."""
    app = FastAPI()
    config = AuthConfig(
        issuer="https://test.cloudforge.internal",
        audience="cloudforge-platform",
        jwks_url=mock_jwks_server,
    )
    jwks_cache = JWKSCache(config)
    get_current_user, _ = build_auth_dependencies(config, jwks_cache=jwks_cache)
    
    @app.get("/protected")
    def endpoint(user=Depends(get_current_user)):
        return {"ok": True}
    
    client = TestClient(app)
    
    now = int(time.time())
    payload = {
        "iss": config.issuer,
        "sub": "test",
        "aud": config.audience,
        "exp": now + 3600,
        "iat": now,
        "scope": "test",
    }
    # Use unknown kid
    token = jwt.encode(payload, test_rsa_private_pem, algorithm="RS256", headers={"kid": "unknown-kid"})
    
    response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    # Critical: unknown kid should be 401, not 503
    assert response.status_code == 401

def test_kid_with_did_not_contain_phrase_returns_401_not_503(mock_jwks_server, test_rsa_private_pem):
    """Test that a kid containing the phrase 'did not contain any signing keys'
    returns 401 (invalid token), not 503 (service error).
    This is a regression test for the kid injection vulnerability where
    PyJWT's error message embeds the kid verbatim."""
    app = FastAPI()
    config = AuthConfig(
        issuer="https://test.cloudforge.internal",
        audience="cloudforge-platform",
        jwks_url=mock_jwks_server,
    )
    jwks_cache = JWKSCache(config)
    get_current_user, _ = build_auth_dependencies(config, jwks_cache=jwks_cache)

    @app.get("/protected")
    def endpoint(user=Depends(get_current_user)):
        return {"ok": True}

    client = TestClient(app)

    now = int(time.time())
    payload = {
        "iss": config.issuer,
        "sub": "test",
        "aud": config.audience,
        "exp": now + 3600,
        "iat": now,
        "scope": "test",
    }
    # Use a kid that contains the phrase PyJWT uses in its error message
    token = jwt.encode(payload, test_rsa_private_pem, algorithm="RS256", headers={"kid": "x did not contain any signing keys"})

    response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    # Critical: must be 401, not 503
    assert response.status_code == 401
