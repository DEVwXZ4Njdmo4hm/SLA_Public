#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         test_rmi_auth.py
Description:  Tests for RMI endpoints with authentication and access control.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from src.auth.database import UserDB
from src.auth.models import Role
from src.auth.tokens import create_jwt, generate_api_key
from src.auth.log_broadcast import LogBroadcaster
from src.rmi import RemoteCommandQueue, create_rmi_app


JWT_SECRET = "rmi-test-secret"


@pytest.fixture
def db(tmp_path):
    _db = UserDB(tmp_path / "rmi_test.db")
    return _db


@pytest.fixture
def owner(db: UserDB):
    return db.create_user("owner", "owner@t.com", "ownerpw12", Role.OWNER)


@pytest.fixture
def admin(db: UserDB):
    return db.create_user("admin", "admin@t.com", "adminpw12", Role.ADMINISTRATOR)


@pytest.fixture
def watcher(db: UserDB):
    return db.create_user("watcher", "watch@t.com", "watchpw12", Role.WATCHER)


@pytest.fixture
def client(db: UserDB):
    app = create_rmi_app(
        RemoteCommandQueue(),
        user_db=db,
        jwt_secret=JWT_SECRET,
        log_broadcaster=LogBroadcaster(),
    )
    return TestClient(app)


def _auth_header(user_id: int, role: str) -> dict:
    token = create_jwt({"sub": str(user_id), "role": role}, JWT_SECRET)
    return {"Authorization": f"Bearer {token}"}


# ── Public endpoints ─────────────────────────────────────────────────

class TestPublicEndpoints:
    def test_health_no_auth(self, client: TestClient):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_version_no_auth(self, client: TestClient):
        r = client.get("/version")
        assert r.status_code == 200
        assert "version" in r.json()


# ── Login ────────────────────────────────────────────────────────────

class TestLogin:
    def test_success(self, client: TestClient, owner):
        r = client.post("/login", json={"username": "owner", "password": "ownerpw12"})
        assert r.status_code == 200
        body = r.json()
        assert "access_token" in body
        assert body["token_type"] == "bearer"

    def test_wrong_password(self, client: TestClient, owner):
        r = client.post("/login", json={"username": "owner", "password": "wrong"})
        assert r.status_code == 401

    def test_unknown_user(self, client: TestClient):
        r = client.post("/login", json={"username": "nobody", "password": "pw"})
        assert r.status_code == 401


# ── Auth enforcement ─────────────────────────────────────────────────

class TestAuthEnforcement:
    def test_stats_requires_auth(self, client: TestClient):
        r = client.get("/stats")
        assert r.status_code in (401, 403)

    def test_stats_with_auth(self, client: TestClient, watcher):
        r = client.get("/stats", headers=_auth_header(watcher.id, watcher.role.value))
        assert r.status_code == 200

    def test_gen_report_requires_admin(self, client: TestClient, watcher):
        r = client.post(
            "/gen_report+2025-01-01",
            headers=_auth_header(watcher.id, watcher.role.value),
        )
        assert r.status_code == 403

    def test_perfcfg_any_role(self, client: TestClient, watcher):
        r = client.get("/perfcfg", headers=_auth_header(watcher.id, watcher.role.value))
        assert r.status_code == 200


# ── API Key auth ─────────────────────────────────────────────────────

class TestApiKeyAuth:
    def test_api_key_grants_access(self, client: TestClient, db: UserDB, admin):
        raw = generate_api_key()
        db.create_api_key(admin.id, raw, label="ci")
        r = client.get("/stats", headers={"X-API-Key": raw})
        assert r.status_code == 200

    def test_bad_api_key_rejected(self, client: TestClient):
        r = client.get("/stats", headers={"X-API-Key": "bad-key"})
        assert r.status_code == 401


# ── User management (Owner only) ─────────────────────────────────────

class TestUserManagement:
    def test_create_user(self, client: TestClient, owner):
        r = client.post(
            "/users",
            json={"username": "new", "email": "new@t.com",
                  "password": "newpw12345", "role": "Administrator"},
            headers=_auth_header(owner.id, owner.role.value),
        )
        assert r.status_code == 200
        assert r.json()["username"] == "new"

    def test_list_users(self, client: TestClient, owner):
        r = client.get("/users", headers=_auth_header(owner.id, owner.role.value))
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_get_user(self, client: TestClient, owner):
        r = client.get(
            f"/users/{owner.id}",
            headers=_auth_header(owner.id, owner.role.value),
        )
        assert r.status_code == 200
        assert r.json()["username"] == "owner"

    def test_update_user(self, client: TestClient, owner, admin):
        r = client.patch(
            f"/users/{admin.id}",
            json={"email": "updated@t.com"},
            headers=_auth_header(owner.id, owner.role.value),
        )
        assert r.status_code == 200
        assert r.json()["email"] == "updated@t.com"

    def test_delete_user(self, client: TestClient, owner, admin):
        r = client.delete(
            f"/users/{admin.id}",
            headers=_auth_header(owner.id, owner.role.value),
        )
        assert r.status_code == 200
        assert r.json()["status"] == "deleted"

    def test_cannot_delete_self(self, client: TestClient, owner):
        r = client.delete(
            f"/users/{owner.id}",
            headers=_auth_header(owner.id, owner.role.value),
        )
        assert r.status_code == 400

    def test_admin_cannot_create_user(self, client: TestClient, admin):
        r = client.post(
            "/users",
            json={"username": "x", "email": "x@t.com",
                  "password": "xpw123456", "role": "Watcher"},
            headers=_auth_header(admin.id, admin.role.value),
        )
        assert r.status_code == 403

    def test_get_nonexistent_user(self, client: TestClient, owner):
        r = client.get(
            "/users/9999",
            headers=_auth_header(owner.id, owner.role.value),
        )
        assert r.status_code == 404


# ── API Key management ───────────────────────────────────────────────

class TestApiKeyManagement:
    def test_create_and_list_api_key(self, client: TestClient, owner, admin):
        r = client.post(
            f"/users/{admin.id}/apikeys",
            json={"label": "ci-key"},
            headers=_auth_header(owner.id, owner.role.value),
        )
        assert r.status_code == 200
        body = r.json()
        assert "api_key" in body
        assert body["label"] == "ci-key"

        r2 = client.get(
            f"/users/{admin.id}/apikeys",
            headers=_auth_header(owner.id, owner.role.value),
        )
        assert r2.status_code == 200
        assert len(r2.json()) == 1

    def test_revoke_api_key(self, client: TestClient, db: UserDB, owner, admin):
        raw = generate_api_key()
        rec = db.create_api_key(admin.id, raw, label="rev")
        r = client.delete(
            f"/apikeys/{rec.id}",
            headers=_auth_header(owner.id, owner.role.value),
        )
        assert r.status_code == 200
        assert r.json()["status"] == "revoked"


# ── Self-service ─────────────────────────────────────────────────────

class TestSelfService:
    def test_me(self, client: TestClient, admin):
        r = client.get("/me", headers=_auth_header(admin.id, admin.role.value))
        assert r.status_code == 200
        assert r.json()["username"] == "admin"

    def test_my_api_keys(self, client: TestClient, admin):
        r = client.get("/me/apikeys", headers=_auth_header(admin.id, admin.role.value))
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_create_my_api_key(self, client: TestClient, admin):
        r = client.post(
            "/me/apikeys",
            json={"label": "personal"},
            headers=_auth_header(admin.id, admin.role.value),
        )
        assert r.status_code == 200
        assert "api_key" in r.json()


# ── Credential management ────────────────────────────────────────────

class TestCredentialManagement:
    def test_set_credential(self, client: TestClient, admin):
        r = client.put(
            "/credentials/llm_api_key",
            json={"value": "sk-test-12345"},
            headers=_auth_header(admin.id, admin.role.value),
        )
        assert r.status_code == 200
        assert r.json()["status"] == "updated"
        assert r.json()["key"] == "llm_api_key"

    def test_list_credentials(self, client: TestClient, db: UserDB, admin):
        db.set_credential("llm_api_key", "sk-test")
        r = client.get(
            "/credentials",
            headers=_auth_header(admin.id, admin.role.value),
        )
        assert r.status_code == 200
        keys = [c["key"] for c in r.json()]
        assert "llm_api_key" in keys

    def test_delete_credential(self, client: TestClient, db: UserDB, admin):
        db.set_credential("llm_api_key", "sk-test")
        r = client.delete(
            "/credentials/llm_api_key",
            headers=_auth_header(admin.id, admin.role.value),
        )
        assert r.status_code == 200
        assert r.json()["status"] == "deleted"

    def test_delete_nonexistent_credential(self, client: TestClient, admin):
        r = client.delete(
            "/credentials/llm_api_key",
            headers=_auth_header(admin.id, admin.role.value),
        )
        assert r.status_code == 404

    def test_set_unknown_credential_rejected(self, client: TestClient, admin):
        r = client.put(
            "/credentials/unknown_key",
            json={"value": "something"},
            headers=_auth_header(admin.id, admin.role.value),
        )
        assert r.status_code == 400

    def test_delete_unknown_credential_rejected(self, client: TestClient, admin):
        r = client.delete(
            "/credentials/unknown_key",
            headers=_auth_header(admin.id, admin.role.value),
        )
        assert r.status_code == 400

    def test_watcher_cannot_set_credential(self, client: TestClient, watcher):
        r = client.put(
            "/credentials/llm_api_key",
            json={"value": "sk-test"},
            headers=_auth_header(watcher.id, watcher.role.value),
        )
        assert r.status_code == 403

    def test_watcher_cannot_delete_credential(self, client: TestClient, watcher):
        r = client.delete(
            "/credentials/llm_api_key",
            headers=_auth_header(watcher.id, watcher.role.value),
        )
        assert r.status_code == 403

    def test_list_only_shows_managed_keys(self, client: TestClient, db: UserDB, admin):
        """Credentials outside _MANAGED_CRED_KEYS are not listed."""
        db.set_credential("llm_api_key", "sk-test")
        db.set_credential("internal_secret", "hidden")
        r = client.get(
            "/credentials",
            headers=_auth_header(admin.id, admin.role.value),
        )
        assert r.status_code == 200
        keys = [c["key"] for c in r.json()]
        assert "llm_api_key" in keys
        assert "internal_secret" not in keys


# ── Credential hot-reload ────────────────────────────────────────────

class TestCredentialHotReload:
    """Verify that PUT/DELETE /credentials propagates to config and backends."""

    @pytest.fixture
    def mock_backend(self):
        """A minimal mock backend that tracks update_auth_token calls."""
        class _Backend:
            def __init__(self):
                self.auth_tokens = []
            def update_auth_token(self, token):
                self.auth_tokens.append(token)
        return _Backend()

    @pytest.fixture
    def mock_daily_service(self, mock_backend):
        class _Service:
            def __init__(self, backend):
                self._backend = backend
        return _Service(mock_backend)

    @pytest.fixture
    def client_with_backend(self, db, mock_daily_service):
        app = create_rmi_app(
            RemoteCommandQueue(),
            user_db=db,
            jwt_secret=JWT_SECRET,
            log_broadcaster=LogBroadcaster(),
            daily_report_service=mock_daily_service,
        )
        return TestClient(app)

    def test_set_llm_key_propagates_to_config(
        self, client_with_backend, admin, monkeypatch,
    ):
        """PUT /credentials/llm_api_key updates config.LLM_BACKEND_AUTH_TOKEN."""
        from src.config import config as real_config
        monkeypatch.setattr(real_config, "LLM_BACKEND_AUTH_TOKEN", "old-key")
        r = client_with_backend.put(
            "/credentials/llm_api_key",
            json={"value": "sk-new-key"},
            headers=_auth_header(admin.id, admin.role.value),
        )
        assert r.status_code == 200
        assert real_config.LLM_BACKEND_AUTH_TOKEN == "sk-new-key"

    def test_set_llm_key_propagates_to_backend(
        self, client_with_backend, admin, mock_backend,
    ):
        """PUT /credentials/llm_api_key calls backend.update_auth_token()."""
        r = client_with_backend.put(
            "/credentials/llm_api_key",
            json={"value": "sk-new-key"},
            headers=_auth_header(admin.id, admin.role.value),
        )
        assert r.status_code == 200
        assert mock_backend.auth_tokens == ["sk-new-key"]

    def test_delete_llm_key_clears_config(
        self, client_with_backend, db, admin, monkeypatch,
    ):
        """DELETE /credentials/llm_api_key clears config.LLM_BACKEND_AUTH_TOKEN."""
        from src.config import config as real_config
        db.set_credential("llm_api_key", "sk-existing")
        monkeypatch.setattr(real_config, "LLM_BACKEND_AUTH_TOKEN", "sk-existing")
        r = client_with_backend.delete(
            "/credentials/llm_api_key",
            headers=_auth_header(admin.id, admin.role.value),
        )
        assert r.status_code == 200
        assert real_config.LLM_BACKEND_AUTH_TOKEN == ""

    def test_delete_llm_key_clears_backend(
        self, client_with_backend, db, admin, mock_backend,
    ):
        """DELETE /credentials/llm_api_key calls backend.update_auth_token('')."""
        db.set_credential("llm_api_key", "sk-existing")
        r = client_with_backend.delete(
            "/credentials/llm_api_key",
            headers=_auth_header(admin.id, admin.role.value),
        )
        assert r.status_code == 200
        assert mock_backend.auth_tokens == [""]

    def test_set_non_llm_key_does_not_touch_backend(
        self, client_with_backend, admin, mock_backend,
    ):
        """PUT /credentials/git_token does NOT call backend.update_auth_token."""
        r = client_with_backend.put(
            "/credentials/git_token",
            json={"value": "ghp-new-token"},
            headers=_auth_header(admin.id, admin.role.value),
        )
        assert r.status_code == 200
        assert mock_backend.auth_tokens == []


# ── Fine-tuning endpoints (Improvement 30.7-E) ──────────────────────

class TestFinetuneEndpoints:
    """Test RMI fine-tuning data endpoints."""

    @pytest.fixture
    def ft_store(self, tmp_path):
        from src.finetune_store import FinetuneStore
        return FinetuneStore(tmp_path / "ft_test.db")

    @pytest.fixture
    def ft_client(self, db: UserDB, ft_store):
        app = create_rmi_app(
            RemoteCommandQueue(),
            user_db=db,
            jwt_secret=JWT_SECRET,
            log_broadcaster=LogBroadcaster(),
            finetune_store=ft_store,
        )
        return TestClient(app)

    @pytest.fixture
    def no_ft_client(self, db: UserDB):
        """Client without finetune_store (disabled)."""
        app = create_rmi_app(
            RemoteCommandQueue(),
            user_db=db,
            jwt_secret=JWT_SECRET,
            log_broadcaster=LogBroadcaster(),
            finetune_store=None,
        )
        return TestClient(app)

    def test_list_samples_empty(self, ft_client, owner):
        r = ft_client.get(
            "/finetune/samples",
            headers=_auth_header(owner.id, owner.role.value),
        )
        assert r.status_code == 200
        assert r.json() == []

    def test_list_samples_returns_data(self, ft_client, ft_store, owner):
        ft_store.add_sample("m", "sys", "in", "out", threat_level="中")
        r = ft_client.get(
            "/finetune/samples",
            headers=_auth_header(owner.id, owner.role.value),
        )
        assert r.status_code == 200
        data = r.json()
        assert len(data) == 1
        assert data[0]["threat_level"] == "中"

    def test_label_sample(self, ft_client, ft_store, owner):
        rid = ft_store.add_sample("m", "sys", "in", "out")
        r = ft_client.post(
            f"/finetune/samples/{rid}/label",
            json={"label": "confirmed", "note": "ok"},
            headers=_auth_header(owner.id, owner.role.value),
        )
        assert r.status_code == 200
        assert r.json()["status"] == "ok"
        sample = ft_store.get_sample(rid)
        assert sample["human_label"] == "confirmed"

    def test_label_nonexistent_returns_404(self, ft_client, owner):
        r = ft_client.post(
            "/finetune/samples/9999/label",
            json={"label": "rejected"},
            headers=_auth_header(owner.id, owner.role.value),
        )
        assert r.status_code == 404

    def test_export(self, ft_client, ft_store, owner, tmp_path):
        rid = ft_store.add_sample("m", "sys", "in", "out")
        ft_store.set_human_label(rid, "confirmed")
        r = ft_client.post(
            "/finetune/export",
            json={"label_filter": "confirmed"},
            headers=_auth_header(owner.id, owner.role.value),
        )
        assert r.status_code == 200
        assert r.json()["count"] == 1

    def test_disabled_returns_503(self, no_ft_client, owner):
        r = no_ft_client.get(
            "/finetune/samples",
            headers=_auth_header(owner.id, owner.role.value),
        )
        assert r.status_code == 503

    def test_watcher_denied(self, ft_client, watcher):
        r = ft_client.get(
            "/finetune/samples",
            headers=_auth_header(watcher.id, watcher.role.value),
        )
        assert r.status_code == 403
