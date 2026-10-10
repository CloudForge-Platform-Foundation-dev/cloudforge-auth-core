"""
Regression tests: an attacker-controlled ``kid`` must never change the HTTP
status class of a failed key lookup.

Contract (Identity Contract v1): an unknown or malformed ``kid`` is an invalid
token -> 401. Only a real upstream problem (JWKS unreachable, invalid JSON,
no usable signing keys) is 503.

These tests need only PyJWT, cryptography and pytest (no fastapi); they serve
a JWKS document from a throwaway local HTTP server.
"""
import base64
import json
import logging
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from cloudforge_auth_core.config import AuthConfig
from cloudforge_auth_core.jwks import JWKSCache, JWKSUnavailableError

_PHRASE = "did not contain any signing keys"
_SENTINEL = "ATTACKER-KID-SENTINEL"

_KEYS = {}


def _key(name):
    if name not in _KEYS:
        _KEYS[name] = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return _KEYS[name]


def _b64u(number):
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _jwks_document(kid="good", use="sig"):
    numbers = _key("good").public_key().public_numbers()
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": use,
                "alg": "RS256",
                "kid": kid,
                "n": _b64u(numbers.n),
                "e": _b64u(numbers.e),
            }
        ]
    }


@contextmanager
def _jwks_server(document):
    body = json.dumps(document).encode()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/.well-known/jwks.json"
    finally:
        server.shutdown()
        server.server_close()


def _token_with_kid(kid):
    # Signed by a key that is NOT in the JWKS; only the header kid matters here.
    return jwt.encode(
        {"sub": "s"}, _key("attacker"), algorithm="RS256", headers={"kid": kid}
    )


def _cache(url):
    return JWKSCache(AuthConfig(issuer="i", audience="a", jwks_url=url))


def test_plain_unknown_kid_is_an_invalid_token():
    with _jwks_server(_jwks_document()) as url:
        with pytest.raises(jwt.PyJWKClientError):
            _cache(url).get_signing_key(_token_with_kid("unknown-kid"))


def test_kid_containing_the_no_signing_keys_phrase_is_still_401():
    # The PyJWT message for an unknown kid embeds this kid verbatim. A kid
    # that contains the "no signing keys" phrase must NOT be classified 503.
    with _jwks_server(_jwks_document()) as url:
        try:
            _cache(url).get_signing_key(_token_with_kid(f"x {_PHRASE}"))
        except JWKSUnavailableError:
            raise AssertionError(
                "attacker-chosen kid forced a 503 (JWKSUnavailableError)"
            )
        except jwt.PyJWKClientError:
            return  # correct: invalid token -> 401
        raise AssertionError("expected PyJWKClientError for an unknown kid")


def test_jwks_without_any_signing_keys_is_503():
    # Real upstream misconfiguration: the only key is for encryption, so there
    # are no signing keys. This must still be reported as unavailable (503).
    with _jwks_server(_jwks_document(use="enc")) as url:
        with pytest.raises(JWKSUnavailableError):
            _cache(url).get_signing_key(_token_with_kid("good"))


def test_attacker_kid_is_not_written_to_logs():
    records = []

    class Capture(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    logger = logging.getLogger("cloudforge_auth_core.jwks")
    handler = Capture(level=logging.DEBUG)
    previous_level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        with _jwks_server(_jwks_document()) as url:
            try:
                _cache(url).get_signing_key(_token_with_kid(f"{_SENTINEL} {_PHRASE}"))
            except (jwt.PyJWKClientError, JWKSUnavailableError):
                pass
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)

    assert not any(_SENTINEL in message for message in records), records
