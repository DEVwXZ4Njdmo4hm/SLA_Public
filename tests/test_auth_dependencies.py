#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         test_auth_dependencies.py
Description:  Tests for FastAPI authentication dependency injection and resolvers.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from src.auth.dependencies import get_current_user, init_auth_dependencies, require_role
from src.auth.models import Role, User
from src.auth.tokens import create_jwt


# ── Helpers ──────────────────────────────────────────────────────────

SECRET = "dep-test-secret"

def _make_user(**kw) -> User:
    defaults = dict(id=1, username="tester", email="t@t.com",
                    role=Role.ADMINISTRATOR, password_hash="x")
    defaults.update(kw)
    return User(**defaults)


# ── Tests ────────────────────────────────────────────────────────────

class TestGetCurrentUser:
    """Test the dependency directly (without FastAPI TestClient)."""

    @pytest.fixture(autouse=True)
    def _setup_deps(self, tmp_path):
        from src.auth.database import UserDB
        self.db = UserDB(tmp_path / "dep_test.db")
        init_auth_dependencies(self.db, SECRET)
        self.user = self.db.create_user("dep", "dep@t.com", "pw123456", Role.ADMINISTRATOR)

    @pytest.mark.asyncio
    async def test_jwt_auth(self):
        from fastapi.security import HTTPAuthorizationCredentials
        token = create_jwt({"sub": str(self.user.id), "role": self.user.role.value}, SECRET)
        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
        request = MagicMock()
        result = await get_current_user(request, token=creds, api_key=None)
        assert result.id == self.user.id

    @pytest.mark.asyncio
    async def test_api_key_auth(self):
        from src.auth.tokens import generate_api_key
        raw = generate_api_key()
        self.db.create_api_key(self.user.id, raw, label="test")
        request = MagicMock()
        result = await get_current_user(request, token=None, api_key=raw)
        assert result.id == self.user.id

    @pytest.mark.asyncio
    async def test_missing_credentials_raises(self):
        from fastapi import HTTPException
        request = MagicMock()
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(request, token=None, api_key=None)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_bad_jwt_raises(self):
        from fastapi import HTTPException
        from fastapi.security import HTTPAuthorizationCredentials
        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="bad.token.here")
        request = MagicMock()
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(request, token=creds, api_key=None)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_invalid_api_key_raises(self):
        from fastapi import HTTPException
        request = MagicMock()
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(request, token=None, api_key="invalid-key")
        assert exc_info.value.status_code == 401


class TestRequireRole:
    @pytest.fixture(autouse=True)
    def _setup_deps(self, tmp_path):
        from src.auth.database import UserDB
        self.db = UserDB(tmp_path / "role_test.db")
        init_auth_dependencies(self.db, SECRET)

    @pytest.mark.asyncio
    async def test_allowed_role_passes(self):
        checker = require_role(Role.ADMINISTRATOR, Role.OWNER)
        user = _make_user(role=Role.ADMINISTRATOR)
        result = await checker(user=user)
        assert result.role == Role.ADMINISTRATOR

    @pytest.mark.asyncio
    async def test_disallowed_role_raises_403(self):
        from fastapi import HTTPException
        checker = require_role(Role.OWNER)
        user = _make_user(role=Role.WATCHER)
        with pytest.raises(HTTPException) as exc_info:
            await checker(user=user)
        assert exc_info.value.status_code == 403
