#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         test_rmi_helpers.py
Description:  Tests for RMI helper functions and response handling.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations
import pytest
from datetime import date
from tests.conftest import PerfConfig
from src.rmi import (
    _perf_config_to_dict,
    _parse_report_date,
    RemoteCommand,
    RemoteCommandQueue,
    apply_remote_command,
    apply_remote_commands,
)


# ── _perf_config_to_dict ──────────────────────────────────────────────

class TestPerfConfigToDict:
    def test_all_fields_present(self):
        cfg = PerfConfig(
            index=3,
            PERF_INDEX_MIN=100,
            PERF_INDEX_MAX=500,
            OLLAMA_MODEL="my-model",
            OLLAMA_NUM_PREDICT=256,
            OLLAMA_TEMPERATURE=0.3,
            OLLAMA_TOP_P=0.8,
            OLLAMA_TOP_K=30,
            LLM_CONCURRENCY=4,
            BATCH_SIZE=50,
            POLL_INTERVAL=10,
            OLLAMA_CONTEXT_LENGTH=8192,
        )
        d = _perf_config_to_dict(cfg)
        assert d["index"] == 3
        assert d["OLLAMA_MODEL"] == "my-model"
        assert d["OLLAMA_NUM_PREDICT"] == 256
        assert d["OLLAMA_TEMPERATURE"] == 0.3
        assert d["LLM_CONCURRENCY"] == 4
        assert d["BATCH_SIZE"] == 50
        assert d["POLL_INTERVAL"] == 10
        assert d["OLLAMA_CONTEXT_LENGTH"] == 8192


# ── _parse_report_date ─────────────────────────────────────────────────

class TestParseReportDate:
    def test_valid_date(self):
        d = _parse_report_date("2026-03-21")
        assert d == date(2026, 3, 21)

    def test_with_whitespace(self):
        d = _parse_report_date("  2026-01-01  ")
        assert d == date(2026, 1, 1)

    def test_invalid_format(self):
        with pytest.raises(ValueError, match="Invalid date format"):
            _parse_report_date("21-03-2026")

    def test_invalid_value(self):
        with pytest.raises(ValueError):
            _parse_report_date("2026-13-32")

    def test_empty_string(self):
        with pytest.raises(ValueError):
            _parse_report_date("")


# ── RemoteCommandQueue ─────────────────────────────────────────────────

class TestRemoteCommandQueue:
    def test_push_and_drain(self):
        q = RemoteCommandQueue()
        cmd = RemoteCommand(name="test", args={"key": "val"}, enqueued_at=1.0)
        q.push(cmd)
        assert q.size() == 1
        drained = q.drain()
        assert len(drained) == 1
        assert drained[0].name == "test"
        assert q.size() == 0

    def test_drain_empty(self):
        q = RemoteCommandQueue()
        assert q.drain() == []

    def test_multiple_commands(self):
        q = RemoteCommandQueue()
        for i in range(5):
            q.push(RemoteCommand(name=f"cmd{i}", args={}, enqueued_at=float(i)))
        assert q.size() == 5
        drained = q.drain()
        assert len(drained) == 5
        assert q.size() == 0


# ── apply_remote_command ───────────────────────────────────────────────

class TestApplyRemoteCommand:
    def test_unknown_command(self):
        cmd = RemoteCommand(name="unknown", args={}, enqueued_at=0.0)
        result = apply_remote_command(cmd)
        assert result["status"] == "error"
        assert result["reason"] == "unknown command"


# ── apply_remote_commands ──────────────────────────────────────────────

class TestApplyRemoteCommands:
    def test_processes_all(self):
        q = RemoteCommandQueue()
        q.push(RemoteCommand(name="a", args={}, enqueued_at=0.0))
        q.push(RemoteCommand(name="b", args={}, enqueued_at=0.0))
        results = apply_remote_commands(q)
        assert len(results) == 2
        assert q.size() == 0
