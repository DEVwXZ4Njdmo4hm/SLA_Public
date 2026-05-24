#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         tokens.py
Description:  JWT (HS256) and API Key generation, hashing, and validation utilities.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import hashlib
import hmac
import json
import base64
import secrets
import time
from typing import Any, Optional


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def create_jwt(
    payload: dict[str, Any],
    secret: str,
    expire_seconds: int = 86400,
) -> str:
    """Create an HS256-signed JWT.

    *payload* is extended with ``iat`` and ``exp`` claims automatically.
    """
    now = int(time.time())
    payload = {**payload, "iat": now, "exp": now + expire_seconds}

    header = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header}.{body}"
    sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url_encode(sig)}"


def decode_jwt(token: str, secret: str) -> Optional[dict[str, Any]]:
    """Decode and verify an HS256 JWT.  Returns the payload dict on
    success or ``None`` on any failure (bad signature, expired, malformed)."""
    parts = token.split(".")
    if len(parts) != 3:
        return None

    signing_input = f"{parts[0]}.{parts[1]}"
    expected_sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()

    try:
        actual_sig = _b64url_decode(parts[2])
    except Exception:
        return None

    if not hmac.compare_digest(expected_sig, actual_sig):
        return None

    try:
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:
        return None

    exp = payload.get("exp")
    if exp is not None and int(exp) < int(time.time()):
        return None

    return payload


def generate_api_key() -> str:
    """Generate a cryptographically secure API key (URL-safe, 43 chars)."""
    return secrets.token_urlsafe(32)


def hash_api_key(raw_key: str) -> str:
    """Return a SHA-256 hex digest of an API key for storage."""
    return hashlib.sha256(raw_key.encode()).hexdigest()
