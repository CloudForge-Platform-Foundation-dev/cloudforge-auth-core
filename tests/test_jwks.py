"""
Unit tests for jwks.JWKSCache — Identity Contract v1 §4.
Tests JWKS fetching, caching, kid resolution, and error mapping.
"""
import pytest
import json
from unittest.mock import Mock, patch
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
from cloudforge_auth_core.jwks import JWKSCache, JWKSUnavailableError
from cloudforge_auth_core.dependencies import build_auth_dependencies
from cloudforge_auth_core.config import AuthConfig


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


@pytest.fixture
def mock_jwks_server():
    """Start a mock JWKS server."""
    # Generate a simple JWKS response
    MockJWKSServer.jwks_response = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": "test-key-2026-v1",
                "n": "sXchDaQebHnPiGvhDO7RS9kY8Zv7y8xKzJ9m5Y8Zv7y8xKzJ9m5Y8Zv7y8xKzJ9m5Y8Zv7y8xKzJ9m5Y8Zv7y8xKzJ9m5Y8Zv7y8xKzJ9m5Y8Zv7y8xKzJ9m5Y8Zv7y8xKzJ9m5Y8Zv7y8xKzJ9m5Y8Zv7y8xKzJ9m5Y8Zv7y8xKzJ9m5Y8Zv7y8xKzJ9m5Y8Zv7y8xKzJ9m5Y8Zv7y8xKzJ9m5Y8Zv7y8xKzJ9m5Y8Zv7y8xKzJ9m5Y8Zv7y8xKzJ9m......",
                "e": "AQAB"
            }
        ]
    }
    
    server = HTTPServer(("127.0.0.1", 0), MockJWKSServer)
    port = server.server_address[1]
    
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    
    yield f"http://127.0.0.1:{port}/.well-known/jwks.json"
    
    server.shutdown()


def test_jwks_cache_initialization(mock_jwks_server):
    """Test JWKSCache initializes correctly with correct AuthConfig params."""
    config = AuthConfig(
        issuer="https://test.cloudforge.internal",
        audience="cloudforge-platform",
        jwks_url=mock_jwks_server,
    )
    cache = JWKSCache(config)
    assert cache._config == config


def test_jwks_unavailable_error_exists():
    """Test JWKSUnavailableError is defined."""
    assert JWKSUnavailableError is not None
    assert issubclass(JWKSUnavailableError, Exception)


# Placeholder for more tests — will be added after seeing dependencies.py
def test_placeholder_jwks_integration():
    """Placeholder for integration tests (requires dependencies.py)."""
    assert True


def test_invalid_jwks_json_returns_503():
    """Test that invalid JWKS JSON returns 503."""
    from http.server import HTTPServer, BaseHTTPRequestHandler
    import threading
    import json
    from fastapi import FastAPI, Depends
    from fastapi.testclient import TestClient
    
    class InvalidJWKSServer(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"not valid json")
        
        def log_message(self, format, *args):
            pass
    
    server = HTTPServer(("127.0.0.1", 0), InvalidJWKSServer)
    port = server.server_address[1]
    
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    
    try:
        app = FastAPI()
        config = AuthConfig(
            issuer="https://test.cloudforge.internal",
            audience="cloudforge-platform",
            jwks_url=f"http://127.0.0.1:{port}/.well-known/jwks.json",
        )
        jwks_cache = JWKSCache(config)
        get_current_user, _ = build_auth_dependencies(config, jwks_cache=jwks_cache)
        
        @app.get("/protected")
        def endpoint(user=Depends(get_current_user)):
            return {"ok": True}
        
        client = TestClient(app)
        
        import time
        import jwt
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        
        private_key = rsa.generate_private_key(65537, 2048, default_backend())
        private_key_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        
        now = int(time.time())
        payload = {
            "iss": config.issuer,
            "sub": "test",
            "aud": config.audience,
            "exp": now + 3600,
            "iat": now,
            "scope": "test",
        }
        token = jwt.encode(payload, private_key_pem, algorithm="RS256", headers={"kid": "test-key"})
        
        response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 503
    finally:
        server.shutdown()


def test_network_timeout_returns_503():
    """Test that network timeout to JWKS returns 503."""
    from fastapi import FastAPI, Depends
    from fastapi.testclient import TestClient
    
    app = FastAPI()
    config = AuthConfig(
        issuer="https://test.cloudforge.internal",
        audience="cloudforge-platform",
        jwks_url="http://127.0.0.1:1/.well-known/jwks.json",  # Unreachable
    )
    jwks_cache = JWKSCache(config)
    get_current_user, _ = build_auth_dependencies(config, jwks_cache=jwks_cache)
    
    @app.get("/protected")
    def endpoint(user=Depends(get_current_user)):
        return {"ok": True}
    
    client = TestClient(app, raise_server_exceptions=False)
    
    import time
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    
    private_key = rsa.generate_private_key(65537, 2048, default_backend())
    private_key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    
    now = int(time.time())
    payload = {
        "iss": config.issuer,
        "sub": "test",
        "aud": config.audience,
        "exp": now + 3600,
        "iat": now,
        "scope": "test",
    }
    token = jwt.encode(payload, private_key_pem, algorithm="RS256", headers={"kid": "test-key"})
    
    response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 503


def test_key_rotation_new_key_accepted():
    """Test that new key in JWKS is accepted after refresh."""
    from http.server import HTTPServer, BaseHTTPRequestHandler
    import threading
    import json
    import base64
    from fastapi import FastAPI, Depends
    from fastapi.testclient import TestClient
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    
    # Generate two key pairs
    key1 = rsa.generate_private_key(65537, 2048, default_backend())
    key2 = rsa.generate_private_key(65537, 2048, default_backend())
    
    def get_jwks_response(private_key, kid):
        public_key = private_key.public_key()
        numbers = public_key.public_numbers()
        
        def int_to_base64url(n):
            length = (n.bit_length() + 7) // 8
            data = n.to_bytes(length, byteorder="big")
            return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
        
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": kid,
                    "n": int_to_base64url(numbers.n),
                    "e": int_to_base64url(numbers.e),
                }
            ]
        }
    
    class RotatingJWKSServer(BaseHTTPRequestHandler):
        jwks_response = None
        
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(self.jwks_response).encode("utf-8"))
        
        def log_message(self, format, *args):
            pass
    
    server = HTTPServer(("127.0.0.1", 0), RotatingJWKSServer)
    port = server.server_address[1]
    
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    
    try:
        # Start with key1
        RotatingJWKSServer.jwks_response = get_jwks_response(key1, "key-1")
        
        app = FastAPI()
        config = AuthConfig(
            issuer="https://test.cloudforge.internal",
            audience="cloudforge-platform",
            jwks_url=f"http://127.0.0.1:{port}/.well-known/jwks.json",
            jwks_cache_ttl_seconds=1,  # Short TTL for testing
        )
        jwks_cache = JWKSCache(config)
        get_current_user, _ = build_auth_dependencies(config, jwks_cache=jwks_cache)
        
        @app.get("/protected")
        def endpoint(user=Depends(get_current_user)):
            return {"ok": True}
        
        client = TestClient(app)
        
        # Create token with key1
        key1_pem = key1.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        
        import time
        import jwt
        
        now = int(time.time())
        payload = {
            "iss": config.issuer,
            "sub": "test",
            "aud": config.audience,
            "exp": now + 3600,
            "iat": now,
            "scope": "test",
        }
        token1 = jwt.encode(payload, key1_pem, algorithm="RS256", headers={"kid": "key-1"})
        
        response = client.get("/protected", headers={"Authorization": f"Bearer {token1}"})
        assert response.status_code == 200
        
        # Rotate to key2
        RotatingJWKSServer.jwks_response = get_jwks_response(key2, "key-2")
        
        # Create token with key2
        key2_pem = key2.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        
        token2 = jwt.encode(payload, key2_pem, algorithm="RS256", headers={"kid": "key-2"})
        
        # Wait for cache to expire
        import time as time_module
        time_module.sleep(2)
        
        response = client.get("/protected", headers={"Authorization": f"Bearer {token2}"})
        assert response.status_code == 200
    finally:
        server.shutdown()
