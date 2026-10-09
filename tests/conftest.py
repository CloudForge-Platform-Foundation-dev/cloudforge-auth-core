"""
Test fixtures for cloudforge-auth-core tests.
"""
import time
import pytest
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import json


@pytest.fixture(scope="session")
def test_rsa_key():
    """Generate a test RSA private key."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )


@pytest.fixture(scope="session")
def test_rsa_public_key(test_rsa_key):
    """Get the public key from the private key."""
    return test_rsa_key.public_key()


@pytest.fixture(scope="session")
def test_rsa_private_pem(test_rsa_key):
    """Get the private key in PEM format."""
    return test_rsa_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


@pytest.fixture(scope="session")
def test_rsa_public_pem(test_rsa_public_key):
    """Get the public key in PEM format."""
    return test_rsa_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


@pytest.fixture(scope="session")
def test_key_id():
    """Test key ID."""
    return "test-key-2026-v1"


@pytest.fixture(scope="session")
def test_issuer():
    """Test issuer."""
    return "https://test-identity.cloudforge.internal"


@pytest.fixture(scope="session")
def test_audience():
    """Test audience."""
    return "cloudforge-platform"
