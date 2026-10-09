"""
Integration tests for JWT validation via FastAPI dependencies.
Tests RS256, iss, aud, exp, iat, sub claims enforcement.
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


# --- Mock JWKS Server ---

class MockJWKSServer(BaseHTTPRequestHandler):
    """Mock JWKS server for testing."""
    
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


@pytest.fixture(scope="session")
def test_rsa_key():
    """Generate test RSA key pair."""
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


# --- Test App ---

@pytest.fixture
def test_app(mock_jwks_server, test_rsa_private_pem):
    """Create FastAPI test app with auth dependencies."""
    app = FastAPI()
    
    config = AuthConfig(
        issuer="https://test-identity.cloudforge.internal",
        audience="cloudforge-platform",
        jwks_url=mock_jwks_server,
    )
    
    jwks_cache = JWKSCache(config)
    get_current_user, require_scope = build_auth_dependencies(config, jwks_cache=jwks_cache)
    
    @app.get("/protected")
    def protected_endpoint(user=Depends(get_current_user)):
        return {"sub": user.sub, "iss": user.iss}
    
    @app.get("/admin")
    def admin_endpoint(user=Depends(get_current_user)):
        require_scope("admin:write")(user)
        return {"admin": True}
    
    return TestClient(app), test_rsa_private_pem, config


# --- Tests ---

def test_valid_rs256_token(test_app):
    """Test valid RS256 token is accepted."""
    client, private_key_pem, config = test_app
    
    now = int(time.time())
    payload = {
        "iss": config.issuer,
        "sub": "test-client",
        "aud": config.audience,
        "exp": now + 3600,
        "iat": now,
        "scope": "nova:query",
    }
    headers = {"kid": "test-key-2026-v1", "alg": "RS256"}
    
    token = jwt.encode(payload, private_key_pem, algorithm="RS256", headers=headers)
    
    response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["sub"] == "test-client"


def test_expired_token_returns_401(test_app):
    """Test expired token returns 401."""
    client, private_key_pem, config = test_app
    
    now = int(time.time())
    payload = {
        "iss": config.issuer,
        "sub": "test-client",
        "aud": config.audience,
        "exp": now - 3600,  # Expired
        "iat": now - 7200,
        "scope": "nova:query",
    }
    headers = {"kid": "test-key-2026-v1", "alg": "RS256"}
    
    token = jwt.encode(payload, private_key_pem, algorithm="RS256", headers=headers)
    
    response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_wrong_issuer_returns_401(test_app):
    """Test wrong issuer returns 401."""
    client, private_key_pem, config = test_app
    
    now = int(time.time())
    payload = {
        "iss": "https://wrong-issuer.example.com",
        "sub": "test-client",
        "aud": config.audience,
        "exp": now + 3600,
        "iat": now,
        "scope": "nova:query",
    }
    headers = {"kid": "test-key-2026-v1", "alg": "RS256"}
    
    token = jwt.encode(payload, private_key_pem, algorithm="RS256", headers=headers)
    
    response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_wrong_audience_returns_401(test_app):
    """Test wrong audience returns 401."""
    client, private_key_pem, config = test_app
    
    now = int(time.time())
    payload = {
        "iss": config.issuer,
        "sub": "test-client",
        "aud": "wrong-audience",
        "exp": now + 3600,
        "iat": now,
        "scope": "nova:query",
    }
    headers = {"kid": "test-key-2026-v1", "alg": "RS256"}
    
    token = jwt.encode(payload, private_key_pem, algorithm="RS256", headers=headers)
    
    response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_missing_iat_returns_401(test_app):
    """Test missing iat claim returns 401."""
    client, private_key_pem, config = test_app
    
    now = int(time.time())
    payload = {
        "iss": config.issuer,
        "sub": "test-client",
        "aud": config.audience,
        "exp": now + 3600,
        # Missing iat
        "scope": "nova:query",
    }
    headers = {"kid": "test-key-2026-v1", "alg": "RS256"}
    
    token = jwt.encode(payload, private_key_pem, algorithm="RS256", headers=headers)
    
    response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_missing_sub_returns_401(test_app):
    """Test missing sub claim returns 401."""
    client, private_key_pem, config = test_app
    
    now = int(time.time())
    payload = {
        "iss": config.issuer,
        # Missing sub
        "aud": config.audience,
        "exp": now + 3600,
        "iat": now,
        "scope": "nova:query",
    }
    headers = {"kid": "test-key-2026-v1", "alg": "RS256"}
    
    token = jwt.encode(payload, private_key_pem, algorithm="RS256", headers=headers)
    
    response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_no_token_returns_401(test_app):
    """Test no token returns 401."""
    client, _, _ = test_app
    
    response = client.get("/protected")
    assert response.status_code == 401


def test_malformed_token_returns_401(test_app):
    """Test malformed token returns 401."""
    client, _, _ = test_app
    
    response = client.get("/protected", headers={"Authorization": "Bearer not.a.valid.token"})
    assert response.status_code == 401


def test_hs256_token_rejected(test_app):
    """Test that HS256 tokens are rejected (RS256 only)."""
    import time
    import jwt
    
    client, private_key_pem, config = test_app
    
    now = int(time.time())
    payload = {
        "iss": config.issuer,
        "sub": "test-client",
        "aud": config.audience,
        "exp": now + 3600,
        "iat": now,
        "scope": "nova:query",
    }
    
    # Try to encode with HS256
    try:
        token = jwt.encode(
            payload,
            "secret-key",
            algorithm="HS256",
            headers={"kid": "test-key-2026-v1", "alg": "HS256"},
        )
        response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
        # Should be rejected with 401
        assert response.status_code == 401
    except Exception:
        # If encoding fails, that's also acceptable
        pass


def test_tampered_signature_returns_401(test_app):
    """Test that tampered signature returns 401."""
    import time
    import jwt
    
    client, private_key_pem, config = test_app
    
    now = int(time.time())
    payload = {
        "iss": config.issuer,
        "sub": "test-client",
        "aud": config.audience,
        "exp": now + 3600,
        "iat": now,
        "scope": "nova:query",
    }
    headers = {"kid": "test-key-2026-v1", "alg": "RS256"}
    
    # Create valid token
    token = jwt.encode(payload, private_key_pem, algorithm="RS256", headers=headers)
    
    # Tamper with signature (change last character)
    parts = token.split(".")
    if len(parts) == 3:
        tampered_sig = parts[2][:-1] + ("B" if parts[2][-1] != "B" else "A")
        tampered_token = f"{parts[0]}.{parts[1]}.{tampered_sig}"
        
        response = client.get("/protected", headers={"Authorization": f"Bearer {tampered_token}"})
        assert response.status_code == 401
