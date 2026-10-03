"""Security primitives built on the Python standard library only.

* Password hashing: PBKDF2-HMAC-SHA256 with per-user salt (OWASP-recommended iterations).
* Tokens: compact HMAC-SHA256 signed tokens (JWT-like) with expiry.
* RBAC: explicit role -> permission map, deny by default.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from enum import Enum

PBKDF2_ITERATIONS = 600_000


class Role(str, Enum):
    REGULATOR = "regulator"
    MANUFACTURER = "manufacturer"
    DISTRIBUTOR = "distributor"
    PHARMACY = "pharmacy"


PERMISSIONS: dict[Role, set[str]] = {
    Role.REGULATOR: {"drug:approve", "audit:read", "ledger:verify", "anomaly:read"},
    Role.MANUFACTURER: {"drug:register", "unit:create", "unit:transfer"},
    Role.DISTRIBUTOR: {"unit:transfer"},
    Role.PHARMACY: {"unit:transfer", "unit:dispense"},
}


class AuthError(Exception):
    """Raised for any authentication / authorization failure."""


def hash_password(password: str, *, iterations: int = PBKDF2_ITERATIONS) -> str:
    if len(password) < 10:
        raise ValueError("password must be at least 10 characters")
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${dk.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algo, iters, salt_hex, hash_hex = encoded.split("$")
    except ValueError:
        return False
    if algo != "pbkdf2_sha256":
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iters))
    return hmac.compare_digest(dk.hex(), hash_hex)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


class TokenSigner:
    def __init__(self, secret: str | None = None, ttl_seconds: int = 3600):
        self.secret = (secret or secrets.token_hex(32)).encode()
        self.ttl = ttl_seconds

    def issue(self, user_id: str, role: Role, org_id: str) -> str:
        payload = {"sub": user_id, "role": role.value, "org": org_id,
                   "exp": int(time.time()) + self.ttl, "jti": secrets.token_hex(8)}
        body = _b64(json.dumps(payload, separators=(",", ":")).encode())
        sig = _b64(hmac.new(self.secret, body.encode(), hashlib.sha256).digest())
        return f"{body}.{sig}"

    def verify(self, token: str) -> dict:
        try:
            body, sig = token.split(".")
        except (ValueError, AttributeError):
            raise AuthError("malformed token")
        expected = _b64(hmac.new(self.secret, body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            raise AuthError("invalid signature")
        payload = json.loads(_unb64(body))
        if payload.get("exp", 0) < time.time():
            raise AuthError("token expired")
        if payload.get("role") not in {r.value for r in Role}:
            raise AuthError("unknown role")
        return payload


def require(claims: dict, permission: str) -> None:
    role = Role(claims["role"])
    if permission not in PERMISSIONS.get(role, set()):
        raise AuthError(f"role '{role.value}' lacks permission '{permission}'")
