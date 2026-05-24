#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         test_auth_passwords.py
Description:  Tests for password hashing and verification with bcrypt and PBKDF2.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

from src.auth.passwords import hash_password, verify_password


class TestHashPassword:
    def test_hash_uses_known_scheme(self):
        h = hash_password("secret123")
        assert h.startswith("$2") or h.startswith("pbkdf2:"), (
            f"Expected bcrypt ($2) or pbkdf2 prefix, got {h[:20]}"
        )

    def test_different_passwords_different_hashes(self):
        h1 = hash_password("alpha")
        h2 = hash_password("beta")
        assert h1 != h2

    def test_same_password_different_salt(self):
        h1 = hash_password("same")
        h2 = hash_password("same")
        assert h1 != h2  # each call should use a fresh salt


class TestVerifyPassword:
    def test_correct_password(self):
        h = hash_password("hunter2")
        assert verify_password("hunter2", h) is True

    def test_wrong_password(self):
        h = hash_password("hunter2")
        assert verify_password("wrong", h) is False

    def test_empty_password(self):
        h = hash_password("")
        assert verify_password("", h) is True
        assert verify_password("x", h) is False

    def test_unicode_password(self):
        pw = "密码テスト🔒"
        h = hash_password(pw)
        assert verify_password(pw, h) is True
        assert verify_password("wrong", h) is False

    def test_unknown_hash_format_returns_false(self):
        assert verify_password("anything", "not-a-real-hash") is False

    def test_pbkdf2_fallback_format(self):
        """Verify that PBKDF2 hashes (stdlib fallback) are accepted."""
        import hashlib, hmac, os
        password = "fallback-test"
        salt = os.urandom(16)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260_000)
        hashed = f"pbkdf2:sha256:260000${salt.hex()}${dk.hex()}"
        assert verify_password(password, hashed) is True
        assert verify_password("wrong", hashed) is False

    def test_pbkdf2_malformed_returns_false(self):
        assert verify_password("x", "pbkdf2:sha256:260000$bad") is False
