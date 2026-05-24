#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         test_auth_bootstrap.py
Description:  Tests for user bootstrap and system user creation functionality.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

from src.auth.bootstrap import bootstrap_owner, bootstrap_agent, revoke_agent_session, AGENT_USERNAME_PREFIX, _active_agent_ids
from src.auth.database import UserDB
from src.auth.models import AgentIdentity, Role

import pytest


@pytest.fixture
def db(tmp_path):
    _active_agent_ids.clear()
    return UserDB(tmp_path / "boot_test.db")


class TestBootstrapOwner:
    def test_creates_owner_on_empty_db(self, db: UserDB):
        bootstrap_owner(db, "root", "rootpw123", "root@t.com")
        assert db.has_owner() is True
        user = db.get_user_by_username("root")
        assert user is not None
        assert user.role == Role.OWNER
        assert user.email == "root@t.com"

    def test_skips_if_owner_exists(self, db: UserDB):
        db.create_user("existing", "ex@t.com", "pw123456", Role.OWNER)
        # should not raise even though "root" is different
        bootstrap_owner(db, "root", "rootpw123", "root@t.com")
        users = db.list_users()
        assert len(users) == 1
        assert users[0].username == "existing"

    def test_skips_on_empty_credentials(self, db: UserDB):
        bootstrap_owner(db, "", "pw", "e@t.com")
        assert db.has_owner() is False
        bootstrap_owner(db, "u", "", "e@t.com")
        assert db.has_owner() is False
        bootstrap_owner(db, "u", "pw", "")
        assert db.has_owner() is False


class TestBootstrapAgent:
    def test_creates_agent_on_empty_db(self, db: UserDB):
        identity = bootstrap_agent(db)
        assert identity is not None
        assert isinstance(identity, AgentIdentity)
        assert identity.user.role == Role.AGENT
        assert identity.user.username.startswith(AGENT_USERNAME_PREFIX)
        assert identity.actor_role == "Agent"
        assert identity.api_key != ""

    def test_agent_exists_in_db_after_bootstrap(self, db: UserDB):
        bootstrap_agent(db)
        assert db.has_agent() is True
        agent = db.get_agent_user()
        assert agent is not None
        assert agent.role == Role.AGENT

    def test_purges_old_agent_on_rebootstrap(self, db: UserDB):
        """Simulated restart: purges previous Agent and creates a fresh one."""
        first = bootstrap_agent(db)
        # Simulate process restart — previous agent ID no longer tracked.
        _active_agent_ids.discard(first.user.id)
        second = bootstrap_agent(db)
        assert second is not None
        # New user row — old one was deleted
        assert second.user.id != first.user.id
        assert second.api_key != first.api_key
        # Old key no longer valid (user deleted → key deleted)
        assert db.verify_api_key(first.api_key) is None
        # Exactly one Agent user remains
        assert len([u for u in db.list_users() if u.role == Role.AGENT]) == 1

    def test_old_keys_purged_on_rebootstrap(self, db: UserDB):
        """All API keys of the previous Agent are hard-deleted on restart."""
        first = bootstrap_agent(db)
        old_user_id = first.user.id
        # Simulate process restart.
        _active_agent_ids.discard(old_user_id)
        second = bootstrap_agent(db)
        # No keys should remain for the old user
        assert db.list_api_keys(old_user_id) == []
        # Exactly one key for the new user
        assert len(db.list_api_keys(second.user.id)) == 1

    def test_each_handler_gets_own_agent_user(self, db: UserDB):
        """Each bootstrap creates a separate Agent user (1:1 handler-to-user)."""
        first = bootstrap_agent(db)
        second = bootstrap_agent(db)
        assert second is not None
        # Different user rows — each handler owns its own account
        assert second.user.id != first.user.id
        assert second.user.username != first.user.username
        # Different keys
        assert second.api_key != first.api_key
        # Both keys valid
        assert db.verify_api_key(first.api_key) is not None
        assert db.verify_api_key(second.api_key) is not None
        # Two Agent users exist
        assert len([u for u in db.list_users() if u.role == Role.AGENT]) == 2

    def test_close_one_handler_does_not_affect_other(self, db: UserDB):
        """Revoking one Agent session leaves the other intact."""
        first = bootstrap_agent(db)
        second = bootstrap_agent(db)
        revoke_agent_session(db, first)
        # second's key still valid
        assert db.verify_api_key(second.api_key) is not None
        assert db.get_user_by_id(second.user.id) is not None
        # first's key gone
        assert db.verify_api_key(first.api_key) is None
        assert db.get_user_by_id(first.user.id) is None

    def test_api_key_verifiable(self, db: UserDB):
        identity = bootstrap_agent(db)
        verified_user = db.verify_api_key(identity.api_key)
        assert verified_user is not None
        assert verified_user.id == identity.user.id
        assert verified_user.role == Role.AGENT

    def test_actor_id_is_string_user_id(self, db: UserDB):
        identity = bootstrap_agent(db)
        assert identity.actor_id == str(identity.user.id)

    def test_key_record_id_populated(self, db: UserDB):
        identity = bootstrap_agent(db)
        assert identity.key_record_id > 0

    def test_revoke_agent_session_deletes_user_and_keys(self, db: UserDB):
        """revoke_agent_session removes the Agent user and all its keys."""
        identity = bootstrap_agent(db)
        assert db.verify_api_key(identity.api_key) is not None
        revoke_agent_session(db, identity)
        # Key gone
        assert db.verify_api_key(identity.api_key) is None
        # User gone
        assert db.get_user_by_id(identity.user.id) is None
        assert db.has_agent() is False

    def test_agent_username_is_business_name(self, db: UserDB):
        """Agent username should reflect its business role, not a generic name."""
        assert AGENT_USERNAME_PREFIX == "suricata-analyzer-agent"
        identity = bootstrap_agent(db)
        assert identity.user.username.startswith("suricata-analyzer-agent-")
