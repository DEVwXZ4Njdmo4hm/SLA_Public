#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         test_mail_queue.py
Description:  Tests for email queue spool operations and retry logic.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations
import json
import os
import time
import pytest
from src.mailer.mail_queue import _SpooledMessage, MailQueue


# ── _SpooledMessage ────────────────────────────────────────────────────

class TestSpooledMessage:
    def test_to_dict_roundtrip(self, tmp_path):
        filepath = str(tmp_path / "test.json")
        msg = _SpooledMessage(
            file_path=filepath,
            subject="Test Subject",
            html_body="<p>Hello</p>",
            recipients=["a@b.com"],
            attachments=None,
            attempt=2,
            next_retry_at=1000.0,
            created_at=900.0,
        )
        d = msg.to_dict()
        assert d["subject"] == "Test Subject"
        assert d["attempt"] == 2
        assert d["recipients"] == ["a@b.com"]

    def test_save_and_from_file(self, tmp_path):
        filepath = str(tmp_path / "msg.json")
        msg = _SpooledMessage(
            file_path=filepath,
            subject="Saved",
            html_body="<b>body</b>",
            recipients=None,
            attachments=None,
            attempt=0,
            next_retry_at=time.time() + 60,
            created_at=time.time(),
        )
        msg.save()
        assert os.path.isfile(filepath)

        loaded = _SpooledMessage.from_file(filepath)
        assert loaded.subject == "Saved"
        assert loaded.html_body == "<b>body</b>"
        assert loaded.attempt == 0


# ── MailQueue ──────────────────────────────────────────────────────────

class TestMailQueue:
    def test_enqueue_creates_file(self, tmp_path):
        spool = str(tmp_path / "spool")
        q = MailQueue(spool_dir=spool)
        filepath = q.enqueue("Test", "<p>body</p>")
        assert os.path.isfile(filepath)
        assert filepath.endswith(".json")

    def test_pending_count(self, tmp_path):
        spool = str(tmp_path / "spool")
        q = MailQueue(spool_dir=spool)
        assert q.pending_count == 0
        q.enqueue("A", "body1")
        assert q.pending_count == 1
        q.enqueue("B", "body2")
        assert q.pending_count == 2

    def test_dead_letter_count_initially_zero(self, tmp_path):
        spool = str(tmp_path / "spool")
        q = MailQueue(spool_dir=spool)
        assert q.dead_letter_count == 0

    def test_calc_delay(self, tmp_path):
        spool = str(tmp_path / "spool")
        q = MailQueue(spool_dir=spool, base_delay=60, max_delay=3600)
        assert q._calc_delay(0) == 60
        assert q._calc_delay(1) == 120
        assert q._calc_delay(2) == 240
        assert q._calc_delay(10) == 3600  # capped

    def test_move_to_dead_letter(self, tmp_path):
        spool = str(tmp_path / "spool")
        q = MailQueue(spool_dir=spool)
        filepath = q.enqueue("Test", "body")
        assert os.path.isfile(filepath)

        q._move_to_dead_letter(filepath)
        assert not os.path.isfile(filepath)
        assert q.dead_letter_count == 1

    def test_start_stop(self, tmp_path):
        spool = str(tmp_path / "spool")
        q = MailQueue(spool_dir=spool, poll_interval=0.1)
        q.start()
        assert q.is_running
        q.stop(timeout=2)
        assert not q.is_running

    def test_enqueue_with_recipients(self, tmp_path):
        spool = str(tmp_path / "spool")
        q = MailQueue(spool_dir=spool)
        filepath = q.enqueue("Subj", "body", recipients=["x@y.com", "a@b.com"])
        msg = _SpooledMessage.from_file(filepath)
        assert msg.recipients == ["x@y.com", "a@b.com"]
