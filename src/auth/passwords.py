#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         passwords.py
Description:  Password hashing utilities with bcrypt or PBKDF2-HMAC-SHA256 fallback.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import hashlib
import hmac
import os

try:
    import bcrypt
    _HAS_BCRYPT = True
except ImportError:  # pragma: no cover
    _HAS_BCRYPT = False


def hash_password(password: str) -> str:
    """Return a hashed password string.

    Uses bcrypt when available; otherwise falls back to
    PBKDF2-HMAC-SHA256 (stdlib).
    """
    if _HAS_BCRYPT:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260_000)
    return f"pbkdf2:sha256:260000${salt.hex()}${dk.hex()}"


def verify_password(password: str, hashed: str) -> bool:
    """Verify *password* against *hashed*.  Supports both bcrypt and
    the PBKDF2 fallback produced by :func:`hash_password`."""
    if _HAS_BCRYPT and hashed.startswith("$2"):
        return bcrypt.checkpw(password.encode(), hashed.encode())

    if hashed.startswith("pbkdf2:"):
        parts = hashed.split("$")
        if len(parts) != 3:
            return False
        salt = bytes.fromhex(parts[1])
        expected = bytes.fromhex(parts[2])
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260_000)
        return hmac.compare_digest(dk, expected)

    return False
