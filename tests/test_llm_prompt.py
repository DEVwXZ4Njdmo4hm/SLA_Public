#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         test_llm_prompt.py
Description:  Tests for prompt template loading and safe variable substitution.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations
import os
import pytest
from src.llm_prompt import (
    load_prompt_templates,
    _get_template,
    _SafeDict,
    get_shared_prompt,
    build_prompt,
    build_pipeline_messages,
    build_daily_report_prompt,
    build_segment_prompt,
    build_pair_prompt,
    build_final_report_prompt,
    build_escalation_prompt,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _load_templates():
    """Load the real prompt templates once for this module."""
    tpl_path = os.path.join(
        os.path.dirname(__file__), os.pardir, "llm_prompt.toml",
    )
    if os.path.isfile(tpl_path):
        load_prompt_templates(tpl_path)
    else:
        pytest.skip("llm_prompt.toml not found")


# ── _SafeDict ──────────────────────────────────────────────────────────

class TestSafeDict:
    def test_present_key(self):
        d = _SafeDict({"a": "hello"})
        assert d["a"] == "hello"

    def test_missing_key_returns_placeholder(self):
        d = _SafeDict({})
        assert d["missing"] == "{missing}"


# ── build_pipeline_messages (Improvement 30.7-A) ───────────────────────

class TestBuildPipelineMessages:
    """Verify build_pipeline_messages returns correct structure."""

    _ENTRY = {
        "event_type": "alert",
        "@timestamp": "2026-01-01T00:00:00Z",
        "src_ip": "10.0.0.1",
        "dest_ip": "10.0.0.2",
        "src_port": 12345,
        "dest_port": 80,
        "proto": "TCP",
        "alert": {"signature": "ET MALWARE", "severity": 1},
    }

    def test_build_pipeline_messages_structure(self):
        """Should return a 2-element list with correct roles."""
        msgs = build_pipeline_messages(self._ENTRY)
        assert isinstance(msgs, list)
        assert len(msgs) == 2
        assert msgs[0]["role"] == "system"
        assert msgs[1]["role"] == "user"
        assert isinstance(msgs[0]["content"], str)
        assert isinstance(msgs[1]["content"], str)
        assert len(msgs[0]["content"]) > 0
        assert len(msgs[1]["content"]) > 0

    def test_build_pipeline_messages_system_stable(self):
        """Different alerts should produce the same system message."""
        entry_a = {"event_type": "alert", "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2"}
        entry_b = {"event_type": "dns", "src_ip": "3.3.3.3", "dest_ip": "4.4.4.4"}
        msgs_a = build_pipeline_messages(entry_a)
        msgs_b = build_pipeline_messages(entry_b)
        assert msgs_a[0]["content"] == msgs_b[0]["content"]

    def test_build_pipeline_messages_user_contains_alert_data(self):
        """User message should contain alert-specific fields."""
        msgs = build_pipeline_messages(self._ENTRY)
        user = msgs[1]["content"]
        assert "10.0.0.1" in user
        assert "10.0.0.2" in user

    def test_build_pipeline_messages_with_memory(self):
        """Memory summaries should appear in the user message."""
        memories = ["[2026-01-01] dns NXDOMAIN evil.com"]
        msgs = build_pipeline_messages(self._ENTRY, memory_summaries=memories)
        user = msgs[1]["content"]
        assert "evil.com" in user
        assert "历史记忆" in user

    def test_build_pipeline_messages_no_memory(self):
        """Without memory, user message should still be valid."""
        msgs = build_pipeline_messages(self._ENTRY, memory_summaries=None)
        assert len(msgs[1]["content"]) > 0

    def test_system_and_user_dont_overlap(self):
        """System prompt should not contain alert data placeholders filled in."""
        msgs = build_pipeline_messages(self._ENTRY)
        system = msgs[0]["content"]
        user = msgs[1]["content"]
        # System should not contain the specific IP addresses from this alert
        assert "10.0.0.1" not in system
        assert "10.0.0.2" not in system
        # User should not contain the system role/instruction text
        assert "你是网络安全专家" not in user
        assert "# 网络环境" not in user

    def test_system_contains_static_rules(self):
        """Static rule tables and output format must be in system prompt."""
        msgs = build_pipeline_messages(self._ENTRY)
        system = msgs[0]["content"]
        user = msgs[1]["content"]
        # Rule tables must be in system (for KV cache effectiveness)
        assert "N0规则" in system
        assert "N1规则" in system
        assert "N2规则" in system
        assert "N3规则" in system
        assert "# 威胁等级" in system
        assert "# 输出要求" in system
        # Rule tables must NOT be in user
        assert "N0规则" not in user
        assert "# 输出要求" not in user


# ── _get_template ──────────────────────────────────────────────────────

class TestGetTemplate:
    def test_realtime(self):
        tpl = _get_template("realtime")
        assert isinstance(tpl, str)
        assert len(tpl) > 0

    def test_daily_report_segment(self):
        tpl = _get_template("daily_report", "segment")
        assert isinstance(tpl, str)

    def test_missing_key_raises(self):
        with pytest.raises(KeyError):
            _get_template("nonexistent")


# ── build_prompt ────────────────────────────────────────────────────────

class TestBuildPrompt:
    def test_basic_log_entry(self):
        entry = {
            "event_type": "alert",
            "@timestamp": "2026-01-01T00:00:00Z",
            "src_ip": "10.0.0.1",
            "dest_ip": "10.0.0.2",
            "src_port": 12345,
            "dest_port": 80,
            "proto": "TCP",
            "alert": {"signature": "ET MALWARE", "severity": 1},
        }
        result = build_prompt(entry)
        assert "10.0.0.1" in result
        assert "10.0.0.2" in result
        assert "alert" in result

    def test_with_memory(self):
        entry = {"event_type": "dns", "@timestamp": "2026-01-01T12:00:00Z"}
        memories = ["[2026-01-01T11:00:00Z] dns NXDOMAIN for evil.com"]
        result = build_prompt(entry, memory_summaries=memories)
        assert "历史记忆" in result
        assert "evil.com" in result

    def test_empty_memory(self):
        entry = {"event_type": "http"}
        result = build_prompt(entry, memory_summaries=[])
        # memory_block placeholder is replaced with empty string
        assert "该通信对的历史记忆" not in result

    def test_missing_fields_use_na(self):
        entry = {}
        result = build_prompt(entry)
        assert "N/A" in result


# ── build_daily_report_prompt ──────────────────────────────────────────

class TestBuildDailyReportPrompt:
    def test_with_high_threat_items(self):
        items = [
            {"threat_level": "高", "timestamp": "2026-01-01T01:00:00Z", "summary": "Attack detected"},
            {"threat_level": "低", "timestamp": "2026-01-01T02:00:00Z", "summary": "Normal traffic"},
        ]
        result = build_daily_report_prompt("2026-01-01", items)
        assert "Attack detected" in result
        assert "Normal traffic" not in result  # 低 is filtered out

    def test_no_high_items(self):
        items = [{"threat_level": "低", "summary": "Normal"}]
        result = build_daily_report_prompt("2026-01-01", items)
        assert "无高危/严重事件" in result

    def test_with_stats(self):
        stats = {
            "total_events": 1000,
            "event_type_breakdown": {"dns": 500, "http": 300},
            "threat_level_breakdown": {"高": 5, "低": 100},
        }
        result = build_daily_report_prompt("2026-01-01", [], daily_stats=stats)
        assert "1000" in result


# ── build_segment_prompt ───────────────────────────────────────────────

class TestBuildSegmentPrompt:
    def test_empty_events(self):
        assert build_segment_prompt("A", "B", []) == ""

    def test_basic_segment(self):
        events = [
            {"timestamp": "2026-01-01T10:00:00Z", "threat_level": "中", "summary": "DNS query"},
            {"timestamp": "2026-01-01T10:05:00Z", "threat_level": "低", "summary": "Normal"},
        ]
        result = build_segment_prompt("host-a", "host-b", events)
        assert "host-a" in result
        assert "host-b" in result
        assert "DNS query" in result
        assert "2" in result  # event_count

    def test_minimal_detail_level(self):
        """Minimal (default) detail level: [threat] timestamp | summary."""
        events = [
            {"timestamp": "2026-01-01T10:00:00Z", "threat_level": "高", "summary": "Suspicious DNS"},
        ]
        result = build_segment_prompt("A", "B", events, detail_level="minimal")
        assert "[高]" in result
        assert "Suspicious DNS" in result
        # Extended fields should NOT appear
        assert "alert:" not in result.lower()
        assert "hint:" not in result.lower()

    def test_extended_detail_level(self):
        """Extended detail level adds event_type, proto, alert, hint, etc."""
        events = [
            {
                "timestamp": "2026-01-01T10:00:00Z",
                "threat_level": "高",
                "summary": "Suspicious DNS",
                "event_type": "dns",
                "proto": "UDP",
                "src_port": "53214",
                "dest_port": "53",
                "alert_signature": "ET TROJAN DNS Query",
                "security_hint": "Check DNS tunnel",
                "tls_sni": "",
                "dns_rrname": "evil.example.com",
            },
        ]
        result = build_segment_prompt("A", "B", events, detail_level="extended")
        assert "dns" in result
        assert "UDP" in result
        assert "53214->53" in result
        assert "[alert: ET TROJAN DNS Query]" in result
        assert "[hint: Check DNS tunnel]" in result
        assert "[dns: evil.example.com]" in result

    def test_full_detail_level(self):
        """Full detail level serializes events as JSON."""
        events = [
            {
                "timestamp": "2026-01-01T10:00:00Z",
                "threat_level": "中",
                "summary": "Test",
                "_raw_source": '{"@timestamp": "2026-01-01T10:00:00Z", "event_type": "flow"}',
            },
        ]
        result = build_segment_prompt("A", "B", events, detail_level="full")
        assert "event_type" in result
        assert "flow" in result


# ── build_pair_prompt ─────────────────────────────────────────────────

class TestBuildPairPrompt:
    def test_empty(self):
        assert build_pair_prompt("A", "B", []) == ""

    def test_basic(self):
        segments = [
            {"time_range": "10:00 ~ 10:30", "analysis": "Normal traffic"},
            {"time_range": "11:00 ~ 11:30", "analysis": "Suspicious activity"},
        ]
        result = build_pair_prompt("host-a", "host-b", segments)
        assert "host-a" in result
        assert "Suspicious activity" in result
        assert "时间段 1" in result


# ── build_final_report_prompt ─────────────────────────────────────────

class TestBuildFinalReportPrompt:
    def test_basic(self):
        pairs = [
            {"pair": "A <-> B", "event_count": 10, "analysis": "Attack pattern"},
        ]
        stats = {"total_events": 100, "event_type_breakdown": {"dns": 50}}
        result = build_final_report_prompt("2026-01-01", pairs, daily_stats=stats)
        assert "A <-> B" in result
        assert "Attack pattern" in result

    def test_empty_pairs(self):
        result = build_final_report_prompt("2026-01-01", [])
        assert "无通信对分析数据" in result


# ── build_escalation_prompt ───────────────────────────────────────────

class TestBuildEscalationPrompt:
    def test_with_raw_fields(self):
        source = {
            "event_type": "alert",
            "@timestamp": "2026-04-01T10:00:00Z",
            "src_ip": "10.0.0.1",
            "dest_ip": "10.0.0.2",
            "src_hostname": "attacker.example.com",
            "dest_hostname": "victim.lan",
            "proto": "tcp",
            "alert": {"signature": "ET MALWARE Test", "severity": 1},
        }
        result = build_escalation_prompt(
            source=source,
            initial_analysis="初步威胁评估",
            memory_summaries=["previous event"],
            include_raw_fields=True,
        )
        assert "attacker.example.com" in result
        assert "初步威胁评估" in result
        assert "previous event" in result
        assert "ET MALWARE Test" in result

    def test_without_raw_fields(self):
        source = {
            "event_type": "dns",
            "src_ip": "10.0.0.1",
            "dest_ip": "10.0.0.2",
            "src_hostname": "a.lan",
            "dest_hostname": "b.lan",
        }
        result = build_escalation_prompt(
            source=source,
            initial_analysis="initial",
            include_raw_fields=False,
        )
        assert "a.lan" in result
        assert "b.lan" in result
        assert "无历史记录" in result

    def test_empty_memory(self):
        source = {"event_type": "http", "src_ip": "1.2.3.4", "dest_ip": "5.6.7.8"}
        result = build_escalation_prompt(
            source=source,
            initial_analysis="test analysis",
            memory_summaries=[],
            include_raw_fields=True,
        )
        assert "无历史记录" in result
        assert "test analysis" in result


# ── get_shared_prompt / shared_prompt injection ───────────────────────

class TestSharedPrompt:
    def test_shared_prompt_returns_string(self):
        """get_shared_prompt() should return a non-empty string when [shared] exists."""
        result = get_shared_prompt()
        assert isinstance(result, str)

    def test_shared_prompt_in_realtime(self):
        """Realtime template should contain resolved shared_prompt content."""
        shared = get_shared_prompt()
        if not shared:
            pytest.skip("shared_prompt is empty in test config")
        result = build_prompt({"event_type": "alert", "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2"})
        # shared_prompt placeholder must be resolved (not appear literally)
        assert "{shared_prompt}" not in result
        # A fragment from the shared content should appear
        assert "N0" in result or shared[:20] in result

    def test_shared_prompt_in_pipeline_system(self):
        """Pipeline system prompt should contain resolved shared_prompt."""
        shared = get_shared_prompt()
        if not shared:
            pytest.skip("shared_prompt is empty in test config")
        msgs = build_pipeline_messages({"event_type": "alert", "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2"})
        system = msgs[0]["content"]
        assert "{shared_prompt}" not in system
        assert "N0" in system or shared[:20] in system

    def test_shared_prompt_in_escalation(self):
        """Escalation prompt should contain resolved shared_prompt."""
        shared = get_shared_prompt()
        if not shared:
            pytest.skip("shared_prompt is empty in test config")
        source = {"event_type": "alert", "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2"}
        result = build_escalation_prompt(source=source, initial_analysis="test")
        assert "{shared_prompt}" not in result
        assert "N0" in result or shared[:20] in result

    def test_shared_prompt_in_daily_report_segment(self):
        """Segment prompt should contain resolved shared_prompt."""
        shared = get_shared_prompt()
        if not shared:
            pytest.skip("shared_prompt is empty in test config")
        events = [{"timestamp": "2026-01-01T10:00:00Z", "threat_level": "低", "summary": "Test"}]
        result = build_segment_prompt("A", "B", events)
        assert "{shared_prompt}" not in result
        assert "N0" in result or shared[:20] in result

    def test_shared_prompt_in_daily_report_pair(self):
        """Pair prompt should contain resolved shared_prompt."""
        shared = get_shared_prompt()
        if not shared:
            pytest.skip("shared_prompt is empty in test config")
        segments = [{"time_range": "10:00 ~ 10:30", "analysis": "Normal traffic"}]
        result = build_pair_prompt("A", "B", segments)
        assert "{shared_prompt}" not in result

    def test_shared_prompt_in_daily_report_final(self):
        """Final report prompt should contain resolved shared_prompt."""
        shared = get_shared_prompt()
        if not shared:
            pytest.skip("shared_prompt is empty in test config")
        pairs = [{"pair": "A <-> B", "event_count": 10, "analysis": "Test"}]
        result = build_final_report_prompt("2026-01-01", pairs)
        assert "{shared_prompt}" not in result

    def test_shared_prompt_in_daily_report_legacy(self):
        """Legacy daily report prompt should contain resolved shared_prompt."""
        shared = get_shared_prompt()
        if not shared:
            pytest.skip("shared_prompt is empty in test config")
        result = build_daily_report_prompt("2026-01-01", [])
        assert "{shared_prompt}" not in result
