#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         test_auth_database.py
Description:  Tests for user, API key, and credential database CRUD operations.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import pytest

from src.auth.database import UserDB
from src.auth.models import CredKey, Role
from src.auth.tokens import generate_api_key


@pytest.fixture
def db(tmp_path):
    """Provide a fresh in-tmpdir UserDB for each test."""
    return UserDB(tmp_path / "test_credentials.db")


# ── User CRUD ────────────────────────────────────────────────────────

class TestUserCRUD:
    def test_create_and_get(self, db: UserDB):
        user = db.create_user("alice", "alice@test.com", "password123", Role.ADMINISTRATOR)
        assert user.id > 0
        assert user.username == "alice"
        assert user.role == Role.ADMINISTRATOR
        fetched = db.get_user_by_id(user.id)
        assert fetched is not None
        assert fetched.username == "alice"

    def test_get_by_username(self, db: UserDB):
        db.create_user("bob", "bob@test.com", "pw123456", Role.WATCHER)
        assert db.get_user_by_username("bob") is not None
        assert db.get_user_by_username("nobody") is None

    def test_get_by_email(self, db: UserDB):
        db.create_user("carol", "carol@test.com", "pw123456", Role.WATCHER)
        assert db.get_user_by_email("carol@test.com") is not None
        assert db.get_user_by_email("nope@test.com") is None

    def test_duplicate_username_raises(self, db: UserDB):
        db.create_user("dup", "dup1@test.com", "pw123456", Role.WATCHER)
        with pytest.raises(Exception):
            db.create_user("dup", "dup2@test.com", "pw123456", Role.WATCHER)

    def test_duplicate_email_raises(self, db: UserDB):
        db.create_user("u1", "same@test.com", "pw123456", Role.WATCHER)
        with pytest.raises(Exception):
            db.create_user("u2", "same@test.com", "pw123456", Role.WATCHER)

    def test_list_users(self, db: UserDB):
        db.create_user("a", "a@t.com", "pw123456", Role.ADMINISTRATOR)
        db.create_user("b", "b@t.com", "pw123456", Role.WATCHER)
        users = db.list_users()
        assert len(users) == 2
        assert users[0].username == "a"

    def test_update_user(self, db: UserDB):
        user = db.create_user("old", "old@t.com", "pw123456", Role.WATCHER)
        updated = db.update_user(user.id, username="new", email="new@t.com")
        assert updated is not None
        assert updated.username == "new"
        assert updated.email == "new@t.com"

    def test_update_user_password(self, db: UserDB):
        user = db.create_user("pwtest", "pwtest@t.com", "oldpw123", Role.WATCHER)
        db.update_user(user.id, password="newpw456")
        assert db.authenticate("pwtest", "newpw456") is not None
        assert db.authenticate("pwtest", "oldpw123") is None

    def test_update_nonexistent_returns_none(self, db: UserDB):
        result = db.update_user(9999, username="x")
        assert result is None

    def test_update_no_changes_returns_user(self, db: UserDB):
        user = db.create_user("nochange", "nc@t.com", "pw123456", Role.WATCHER)
        result = db.update_user(user.id)
        assert result is not None
        assert result.username == "nochange"

    def test_delete_user(self, db: UserDB):
        user = db.create_user("gone", "gone@t.com", "pw123456", Role.WATCHER)
        assert db.delete_user(user.id) is True
        assert db.get_user_by_id(user.id) is None

    def test_delete_nonexistent_returns_false(self, db: UserDB):
        assert db.delete_user(9999) is False


# ── Authentication ───────────────────────────────────────────────────

class TestAuthenticate:
    def test_valid_credentials(self, db: UserDB):
        db.create_user("auth", "auth@t.com", "correct", Role.ADMINISTRATOR)
        assert db.authenticate("auth", "correct") is not None

    def test_wrong_password(self, db: UserDB):
        db.create_user("auth2", "auth2@t.com", "correct", Role.ADMINISTRATOR)
        assert db.authenticate("auth2", "wrong") is None

    def test_unknown_user(self, db: UserDB):
        assert db.authenticate("ghost", "pw") is None


# ── Owner constraint ─────────────────────────────────────────────────

class TestOwnerConstraint:
    def test_has_owner_false_initially(self, db: UserDB):
        assert db.has_owner() is False

    def test_has_owner_true_after_create(self, db: UserDB):
        db.create_user("owner", "owner@t.com", "pw123456", Role.OWNER)
        assert db.has_owner() is True

    def test_only_one_owner_allowed(self, db: UserDB):
        db.create_user("owner1", "o1@t.com", "pw123456", Role.OWNER)
        with pytest.raises(Exception):
            db.create_user("owner2", "o2@t.com", "pw123456", Role.OWNER)


# ── Email by roles ───────────────────────────────────────────────────

class TestGetEmailsByRoles:
    def test_returns_matching_emails(self, db: UserDB):
        db.create_user("own", "own@t.com", "pw123456", Role.OWNER)
        db.create_user("adm", "adm@t.com", "pw123456", Role.ADMINISTRATOR)
        db.create_user("wat", "wat@t.com", "pw123456", Role.WATCHER)

        emails = db.get_emails_by_roles([Role.OWNER, Role.ADMINISTRATOR])
        assert set(emails) == {"own@t.com", "adm@t.com"}

    def test_empty_roles_returns_empty(self, db: UserDB):
        assert db.get_emails_by_roles([]) == []


# ── API Keys ─────────────────────────────────────────────────────────

class TestAPIKeys:
    def test_create_and_verify(self, db: UserDB):
        user = db.create_user("apiuser", "api@t.com", "pw123456", Role.ADMINISTRATOR)
        raw = generate_api_key()
        rec = db.create_api_key(user.id, raw, label="test-key")
        assert rec.id > 0
        assert rec.label == "test-key"

        resolved = db.verify_api_key(raw)
        assert resolved is not None
        assert resolved.id == user.id

    def test_wrong_key_returns_none(self, db: UserDB):
        assert db.verify_api_key("bogus-key-value") is None

    def test_revoked_key_returns_none(self, db: UserDB):
        user = db.create_user("rk", "rk@t.com", "pw123456", Role.WATCHER)
        raw = generate_api_key()
        rec = db.create_api_key(user.id, raw, label="revoke-me")
        assert db.verify_api_key(raw) is not None

        assert db.revoke_api_key(rec.id) is True
        assert db.verify_api_key(raw) is None

    def test_list_api_keys(self, db: UserDB):
        user = db.create_user("lk", "lk@t.com", "pw123456", Role.WATCHER)
        db.create_api_key(user.id, generate_api_key(), label="k1")
        db.create_api_key(user.id, generate_api_key(), label="k2")
        keys = db.list_api_keys(user.id)
        assert len(keys) == 2
        labels = {k.label for k in keys}
        assert labels == {"k1", "k2"}

    def test_revoke_nonexistent_returns_false(self, db: UserDB):
        assert db.revoke_api_key(9999) is False

    def test_expired_key_returns_none(self, db: UserDB):
        user = db.create_user("ek", "ek@t.com", "pw123456", Role.WATCHER)
        raw = generate_api_key()
        db.create_api_key(user.id, raw, label="expired", expires_at="2000-01-01T00:00:00")
        assert db.verify_api_key(raw) is None

    def test_cascade_delete_user_removes_keys(self, db: UserDB):
        user = db.create_user("cascade", "c@t.com", "pw123456", Role.WATCHER)
        raw = generate_api_key()
        db.create_api_key(user.id, raw, label="c-key")
        db.delete_user(user.id)
        assert db.verify_api_key(raw) is None
        assert db.list_api_keys(user.id) == []

    def test_revoke_all_user_keys(self, db: UserDB):
        user = db.create_user("rak", "rak@t.com", "pw123456", Role.WATCHER)
        k1 = generate_api_key()
        k2 = generate_api_key()
        db.create_api_key(user.id, k1, label="k1")
        db.create_api_key(user.id, k2, label="k2")
        count = db.revoke_all_user_keys(user.id)
        assert count == 2
        assert db.verify_api_key(k1) is None
        assert db.verify_api_key(k2) is None

    def test_revoke_all_user_keys_skips_already_revoked(self, db: UserDB):
        user = db.create_user("rak2", "rak2@t.com", "pw123456", Role.WATCHER)
        k1 = generate_api_key()
        k2 = generate_api_key()
        rec = db.create_api_key(user.id, k1, label="k1")
        db.create_api_key(user.id, k2, label="k2")
        db.revoke_api_key(rec.id)
        count = db.revoke_all_user_keys(user.id)
        assert count == 1  # only k2 was still active

    def test_delete_all_user_keys(self, db: UserDB):
        user = db.create_user("dak", "dak@t.com", "pw123456", Role.WATCHER)
        db.create_api_key(user.id, generate_api_key(), label="k1")
        db.create_api_key(user.id, generate_api_key(), label="k2")
        count = db.delete_all_user_keys(user.id)
        assert count == 2
        assert db.list_api_keys(user.id) == []


# ── Close ────────────────────────────────────────────────────────────

class TestClose:
    def test_close_is_no_op(self, db: UserDB):
        db.close()  # should not raise


# ── Credentials ──────────────────────────────────────────────────────

class TestCredentials:
    def test_set_and_get_single(self, db: UserDB):
        db.set_credential(CredKey.ES_USER, "admin")
        assert db.get_credential(CredKey.ES_USER) == "admin"

    def test_get_missing_returns_none(self, db: UserDB):
        assert db.get_credential("nonexistent") is None

    def test_set_overwrites(self, db: UserDB):
        db.set_credential(CredKey.ES_PSWD, "old")
        db.set_credential(CredKey.ES_PSWD, "new")
        assert db.get_credential(CredKey.ES_PSWD) == "new"

    def test_set_credentials_bulk(self, db: UserDB):
        db.set_credentials({
            CredKey.ES_USER: "user1",
            CredKey.ES_PSWD: "pass1",
            CredKey.GIT_TOKEN: "tok1",
        })
        result = db.get_credentials([CredKey.ES_USER, CredKey.ES_PSWD, CredKey.GIT_TOKEN])
        assert result == {
            CredKey.ES_USER: "user1",
            CredKey.ES_PSWD: "pass1",
            CredKey.GIT_TOKEN: "tok1",
        }

    def test_get_credentials_partial_keys(self, db: UserDB):
        db.set_credential(CredKey.ES_USER, "u")
        result = db.get_credentials([CredKey.ES_USER, CredKey.JWT_SECRET])
        assert result == {CredKey.ES_USER: "u"}

    def test_get_all_credentials(self, db: UserDB):
        db.set_credentials({CredKey.ES_USER: "a", CredKey.ES_PSWD: "b"})
        assert db.get_all_credentials() == {CredKey.ES_USER: "a", CredKey.ES_PSWD: "b"}

    def test_delete_credential(self, db: UserDB):
        db.set_credential(CredKey.GIT_TOKEN, "tok")
        assert db.delete_credential(CredKey.GIT_TOKEN) is True
        assert db.get_credential(CredKey.GIT_TOKEN) is None

    def test_delete_nonexistent_returns_false(self, db: UserDB):
        assert db.delete_credential("nope") is False

    def test_set_credentials_empty_is_noop(self, db: UserDB):
        db.set_credentials({})  # should not raise

    def test_get_credentials_empty_keys(self, db: UserDB):
        assert db.get_credentials([]) == {}

    def test_credentials_table_created_on_init(self, db: UserDB):
        """The credentials table must exist even if no creds are written."""
        import sqlite3
        conn = sqlite3.connect(db._db_path)
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='credentials'"
        )
        assert cur.fetchone() is not None
        conn.close()
