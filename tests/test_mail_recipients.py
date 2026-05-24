#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         test_mail_recipients.py
Description:  Tests for multi-user recipient resolution based on roles.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import pytest
from unittest.mock import patch

from src.auth.database import UserDB
from src.auth.models import Role
from src.mailer.recipients import get_recipients_for_event, init_mail_recipients


@pytest.fixture
def db(tmp_path):
    _db = UserDB(tmp_path / "mail_test.db")
    _db.create_user("owner", "owner@co.com", "pw123456", Role.OWNER)
    _db.create_user("admin", "admin@co.com", "pw123456", Role.ADMINISTRATOR)
    _db.create_user("watch", "watch@co.com", "pw123456", Role.WATCHER)
    return _db


class TestGetRecipientsForEvent:
    def test_startup_shutdown_goes_to_owner_and_admin(self, db: UserDB):
        init_mail_recipients(db)
        result = get_recipients_for_event("startup_shutdown")
        assert set(result) == {"owner@co.com", "admin@co.com"}

    def test_daily_report_includes_watcher(self, db: UserDB):
        init_mail_recipients(db)
        result = get_recipients_for_event("daily_report")
        assert "watch@co.com" in result
        assert "owner@co.com" in result

    def test_unknown_event_returns_empty(self, db: UserDB):
        init_mail_recipients(db)
        result = get_recipients_for_event("nonexistent_event")
        # MAIL_PERMISSION_MAP has no entry → empty list (no fallback)
        assert result == []

    def test_no_db_returns_empty(self):
        """When init_mail_recipients was never called, return empty."""
        import src.mailer.recipients as mod
        old_db = mod._user_db
        try:
            mod._user_db = None
            result = get_recipients_for_event("startup_shutdown")
            assert result == []
        finally:
            mod._user_db = old_db
