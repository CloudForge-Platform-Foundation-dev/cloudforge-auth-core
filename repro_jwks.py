"""Reproduce with the REAL JWKSCache + REAL local JWKS HTTP server (no fake key resolver).
usage: python3 repro_jwks.py <path-to-package-src>"""
import sys, types, json, time, threading, socket
from http.server import BaseHTTPRequestHandler, HTTPServer

SRC = sys.argv[1]

# --- stub only fastapi (jwt/cryptography/urllib are all real) ---
f = types.ModuleType("fastapi")
class HTTPException(Exception):
    def __init__(self, status_code, detail=None, headers=None):
        self.status_code, self.detail, self.headers = status_code, detail, headers
class Depends:
    def __init__(self, d=None): self.dep = d
f.HTTPException, f.Depends = HTTPException, Depends
class _S:
    HTTP_401_UNAUTHORIZED=401; HTTP_403_FORBIDDEN=403; HTTP_503_SERVICE_UNAVAILABLE=503
f.status = _S
sys.modules["fastapi"] = f
fs = types.ModuleType("fastapi.security")
class HTTPBearer:
    def __init__(self, auto_error=True): pass
class HTTPAuthorizationCredentials:
    def __init__(self, credentials=""): self.credentials = credentials
fs.HTTPBearer, fs.HTTPAuthorizationCredentials = HTTPBearer, HTTPAuthorizationCredentials
sys.modules["fastapi.security"] = fs
import logging; logging.disable(logging.CRITICAL)
sys.path.insert(0, SRC)

import jwt
from jwt.algorithms import RSAAlgorithm
from cryptography.hazmat.primitives.asymmetric import rsa
from cloudforge_auth_core import AuthConfig, build_auth_dependencies

def newkey(): return rsa.generate_private_key(public_exponent=65537, key_size=2048)
GOOD, OTHER = newkey(), newkey()
jwk = json.loads(RSAAlgorithm.to_jwk(GOOD.public_key())); jwk.update(kid="k1", use="sig", alg="RS256")

STATE = {"body": json.dumps({"keys":[jwk]}).encode(), "count": 0}
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        STATE["count"] += 1
        self.send_response(200); self.send_header("Content-Type","application/json"); self.end_headers()
        self.wfile.write(STATE["body"])
    def log_message(self,*a): pass
srv = HTTPServer(("127.0.0.1", 0), H); PORT = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()

ISS, AUD = "https://identity.cloudforge.internal", "cloudforge-platform"
def deps(url=None):
    cfg = AuthConfig(issuer=ISS, audience=AUD, jwks_url=url or f"http://127.0.0.1:{PORT}/jwks.json")
    return build_auth_dependencies(cfg)[0]
def tok(key=GOOD, kid="k1"):
    now = int(time.time())
    return jwt.encode({"iss":ISS,"aud":AUD,"sub":"s","iat":now,"exp":now+600,"scope":"a:b"}, key, algorithm="RS256", headers={"kid":kid} if kid else None)
def call(gcu, token):
    try: return f"OK sub={gcu(credentials=HTTPAuthorizationCredentials(token)).sub}"
    except HTTPException as e: return f"HTTP {e.status_code}"
    except Exception as e: return f"UNHANDLED {type(e).__name__} (-> HTTP 500)"

def closed_port():
    s = socket.socket(); s.bind(("127.0.0.1",0)); p = s.getsockname()[1]; s.close(); return p

rows = []
rows.append(("garbage token 'invalid.token.string'",            "401", call(deps(), "invalid.token.string")))
rows.append(("well-formed, unknown kid",                        "401", call(deps(), tok(OTHER, "unknown-kid"))))
for k in ("connection", "http://x", "timeout"):
    rows.append((f"attacker-chosen kid={k!r}",                  "401", call(deps(), tok(OTHER, k))))
rows.append(("no kid header at all",                            "401", call(deps(), tok(OTHER, None))))
rows.append(("valid token",                                     "OK",  call(deps(), tok())))
rows.append(("JWKS server down",                                "503", call(deps(f"http://127.0.0.1:{closed_port()}/j"), tok())))
STATE["body"] = b'{"keys": []}';  rows.append(("JWKS returns empty key set", "503", call(deps(), tok())))
STATE["body"] = b'<html>oops</html>'; rows.append(("JWKS returns non-JSON", "503", call(deps(), tok())))
STATE["body"] = json.dumps({"keys":[jwk]}).encode()

bad = 0
print(f"{'case':44} {'expected':9} actual")
for name, exp, got in rows:
    ok = got.startswith("OK") if exp == "OK" else got == f"HTTP {exp}"
    bad += (not ok)
    print(f"{name:44} {exp:9} {got}   {'' if ok else '<-- WRONG'}")

g = deps(); call(g, tok()); STATE["count"] = 0
for i in range(20): call(g, tok(OTHER, f"rand-{i}"))
print(f"\noutbound JWKS fetches caused by 20 unauthenticated unknown-kid tokens: {STATE['count']}")
print(f"WRONG rows: {bad}")
