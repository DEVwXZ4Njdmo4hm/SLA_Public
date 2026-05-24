#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         test_auth_tokens.py
Description:  Tests for JWT and API key encoding, decoding, and validation.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import time

from src.auth.tokens import (
    _b64url_decode,
    _b64url_encode,
    create_jwt,
    decode_jwt,
    generate_api_key,
    hash_api_key,
)


class TestBase64Url:
    def test_roundtrip(self):
        data = b"hello world"
        assert _b64url_decode(_b64url_encode(data)) == data

    def test_no_padding(self):
        encoded = _b64url_encode(b"abc")
        assert "=" not in encoded


class TestCreateAndDecodeJWT:
    SECRET = "test-secret-key-for-unit-tests"

    def test_roundtrip(self):
        payload = {"sub": "42", "role": "Owner"}
        token = create_jwt(payload, self.SECRET, expire_seconds=3600)
        decoded = decode_jwt(token, self.SECRET)
        assert decoded is not None
        assert decoded["sub"] == "42"
        assert decoded["role"] == "Owner"
        assert "iat" in decoded
        assert "exp" in decoded

    def test_expired_token_returns_none(self):
        token = create_jwt({"sub": "1"}, self.SECRET, expire_seconds=-1)
        assert decode_jwt(token, self.SECRET) is None

    def test_bad_signature_returns_none(self):
        token = create_jwt({"sub": "1"}, self.SECRET)
        decoded = decode_jwt(token, "wrong-secret")
        assert decoded is None

    def test_malformed_token_returns_none(self):
        assert decode_jwt("not.valid", self.SECRET) is None
        assert decode_jwt("a.b.c.d", self.SECRET) is None
        assert decode_jwt("", self.SECRET) is None

    def test_tampered_payload_returns_none(self):
        token = create_jwt({"sub": "1"}, self.SECRET)
        parts = token.split(".")
        # tamper with the payload portion
        parts[1] = _b64url_encode(b'{"sub":"hacked","iat":0,"exp":9999999999}')
        tampered = ".".join(parts)
        assert decode_jwt(tampered, self.SECRET) is None

    def test_iat_and_exp_set_correctly(self):
        before = int(time.time())
        token = create_jwt({"sub": "1"}, self.SECRET, expire_seconds=600)
        after = int(time.time())
        decoded = decode_jwt(token, self.SECRET)
        assert decoded is not None
        assert before <= decoded["iat"] <= after
        assert decoded["exp"] == decoded["iat"] + 600


class TestGenerateApiKey:
    def test_length(self):
        key = generate_api_key()
        assert len(key) == 43  # token_urlsafe(32) produces 43 chars

    def test_uniqueness(self):
        keys = {generate_api_key() for _ in range(50)}
        assert len(keys) == 50


class TestHashApiKey:
    def test_deterministic(self):
        key = generate_api_key()
        assert hash_api_key(key) == hash_api_key(key)

    def test_hex_digest_length(self):
        h = hash_api_key("anything")
        assert len(h) == 64  # SHA-256 hex digest

    def test_different_keys_different_hashes(self):
        h1 = hash_api_key("key-a")
        h2 = hash_api_key("key-b")
        assert h1 != h2
