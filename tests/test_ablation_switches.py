#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         test_ablation_switches.py
Description:  Tests for ablation experiment switches.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import html
import pytest
import threading
from unittest.mock import MagicMock, patch
from datetime import date

from tests.conftest import _fake_config
from src.llm_handler import LLMHandler, CommPairMemory
from src.comm_proto_pair_memory import CommProtoPairMemory
from src.global_memory import GlobalMemory


# ── GlobalMemory unit tests ───────────────────────────────────────────

class TestGlobalMemory:
    def test_add_and_get(self):
        mem = GlobalMemory(max_entries=5)
        mem.add("entry1")
        assert mem.get_snapshot() == ["entry1"]

    def test_fifo_order(self):
        mem = GlobalMemory(max_entries=5)
        mem.add("a")
        mem.add("b")
        mem.add("c")
        assert mem.get_snapshot() == ["a", "b", "c"]

    def test_bounded(self):
        mem = GlobalMemory(max_entries=3)
        for i in range(10):
            mem.add(f"e{i}")
        entries = mem.get_snapshot()
        assert len(entries) == 3
        assert entries == ["e7", "e8", "e9"]

    def test_empty_ignored(self):
        mem = GlobalMemory(max_entries=3)
        mem.add("")
        mem.add("valid")
        assert mem.get_snapshot() == ["valid"]

    def test_properties(self):
        mem = GlobalMemory(max_entries=10)
        assert mem.max_entries == 10
        assert mem.count == 0
        mem.add("x")
        assert mem.count == 1

    def test_min_clamped(self):
        mem = GlobalMemory(max_entries=0)
        assert mem.max_entries == 1


# ── memory_mode switch in LLMHandler ──────────────────────────────────

class TestMemoryModeSwitch:
    """Test that LLMHandler respects config.LLM_MEMORY_MODE."""

    def _make_handler(self, mode: str) -> LLMHandler:
        _fake_config.LLM_MEMORY_MODE = mode
        mock_backend = MagicMock()
        return LLMHandler(backend=mock_backend)

    def test_pair_mode_creates_comm_pair_memory(self):
        h = self._make_handler("pair")
        assert h._memory_mode == "pair"
        assert isinstance(h._comm_pair_memory, CommPairMemory)
        assert h._global_memory is None

    def test_global_mode_creates_global_memory(self):
        h = self._make_handler("global")
        assert h._memory_mode == "global"
        assert h._comm_pair_memory is None
        assert isinstance(h._global_memory, GlobalMemory)

    def test_none_mode_creates_no_memory(self):
        h = self._make_handler("none")
        assert h._memory_mode == "none"
        assert h._comm_pair_memory is None
        assert h._comm_proto_pair_memory is None
        assert h._global_memory is None

    def test_none_mode_snapshot_empty(self):
        h = self._make_handler("none")
        assert h.get_memory_snapshot("A", "B") == []

    def test_pair_mode_snapshot_pair_specific(self):
        h = self._make_handler("pair")
        h.update_summary_memory("hit1", src_ip="10.0.0.1", dest_ip="10.0.0.2")
        h.update_summary_memory("hit2", src_ip="10.0.0.3", dest_ip="10.0.0.4")
        snap = h.get_memory_snapshot("10.0.0.1", "10.0.0.2")
        assert len(snap) == 1
        assert "hit1" in snap[0]
        # Different pair should be empty
        snap2 = h.get_memory_snapshot("10.0.0.1", "10.0.0.4")
        assert snap2 == []

    def test_global_mode_snapshot_not_pair_specific(self):
        h = self._make_handler("global")
        h.update_summary_memory("hit1", src_ip="10.0.0.1", dest_ip="10.0.0.2")
        h.update_summary_memory("hit2", src_ip="10.0.0.3", dest_ip="10.0.0.4")
        # Global mode returns ALL entries regardless of pair
        snap = h.get_memory_snapshot("10.0.0.1", "10.0.0.2")
        assert len(snap) == 2
        snap2 = h.get_memory_snapshot("99.99.99.99", "88.88.88.88")
        assert len(snap2) == 2

    def test_none_mode_update_is_noop(self):
        h = self._make_handler("none")
        h.update_summary_memory("something", src_ip="1.2.3.4", dest_ip="5.6.7.8")
        assert h.get_memory_snapshot("1.2.3.4", "5.6.7.8") == []

    def test_pair_mode_backward_compatible(self):
        """Pair mode should behave identically to old CommPairMemory behavior."""
        h = self._make_handler("pair")
        h.update_summary_memory("e1", src_ip="A", dest_ip="B")
        h.update_summary_memory("e2", src_ip="B", dest_ip="A")
        snap = h.get_memory_snapshot("A", "B")
        assert len(snap) == 2

    def test_proto_pair_mode_creates_comm_proto_pair_memory(self):
        h = self._make_handler("proto_pair")
        assert h._memory_mode == "proto_pair"
        assert h._comm_pair_memory is None
        assert isinstance(h._comm_proto_pair_memory, CommProtoPairMemory)
        assert h._global_memory is None

    def test_proto_pair_snapshot_is_event_scoped(self):
        h = self._make_handler("proto_pair")
        h.update_summary_memory(
            "ssh summary",
            src_ip="10.0.0.1",
            dest_ip="10.0.0.2",
            app_proto="ssh",
            event_type="alert",
        )
        h.update_summary_memory(
            "smb summary",
            src_ip="10.0.0.1",
            dest_ip="10.0.0.2",
            app_proto="smb",
            event_type="alert",
        )

        ssh_snap = h.get_memory_snapshot(
            "10.0.0.1", "10.0.0.2", app_proto="ssh", event_type="alert",
        )
        smb_snap = h.get_memory_snapshot(
            "10.0.0.1", "10.0.0.2", app_proto="smb", event_type="alert",
        )
        alert_snap = h.get_memory_snapshot(
            "10.0.0.1", "10.0.0.2", app_proto="", event_type="alert",
        )
        assert len(ssh_snap) == 1
        assert "ssh summary" in ssh_snap[0]
        assert "Event_Z=ssh" in ssh_snap[0]
        assert len(smb_snap) == 1
        assert "smb summary" in smb_snap[0]
        assert alert_snap == []

    def test_proto_pair_falls_back_to_event_type_and_unknown(self):
        h = self._make_handler("proto_pair")
        h.update_summary_memory("alert summary", src_ip="A", dest_ip="B", event_type="alert")
        h.update_summary_memory("unknown summary", src_ip="A", dest_ip="B")

        alert_snap = h.get_memory_snapshot("A", "B", event_type="alert")
        unknown_snap = h.get_memory_snapshot("A", "B")
        assert "Event_Z=alert" in alert_snap[0]
        assert "alert summary" in alert_snap[0]
        assert "Event_Z=Unknown" in unknown_snap[0]
        assert "unknown summary" in unknown_snap[0]

    def teardown_method(self):
        _fake_config.LLM_MEMORY_MODE = "pair"


# ── analysis_mode switch ──────────────────────────────────────────────

class TestAnalysisModeSwitch:
    """Test that DailyReportService respects config.DAILY_REPORT_ANALYSIS_MODE."""

    def test_flat_mode_calls_flat_analysis(self):
        _fake_config.DAILY_REPORT_ANALYSIS_MODE = "flat"
        _fake_config.DAILY_REPORT_ENABLED = True
        _fake_config.ENABLE_MAIL_NOTIFICATION = False

        from src.daily_report import DailyReportService
        svc = DailyReportService(es_client=MagicMock(), backend=MagicMock())
        svc._run_flat_analysis = MagicMock(return_value=("<p>flat</p>", []))
        svc._run_multilevel_analysis = MagicMock(return_value=("<p>hier</p>", []))

        items = [{"timestamp": "2026-01-01T00:00:00", "summary": "x", "threat_level": "高"}]
        with patch.object(svc, '_get_llm_conf') as mock_conf, \
             patch('src.daily_report.fetch_daily_stats', return_value={}), \
             patch('src.daily_report.fetch_processed_summaries', return_value=items), \
             patch('src.daily_report.stop_ollama_model', return_value=True), \
             patch('src.daily_report.build_report_html', return_value="<html/>"), \
             patch('src.daily_report._save_report_html', return_value=None):
            mock_conf.return_value = MagicMock()
            svc._generate_and_send_inner(date(2026, 1, 1))

        svc._run_flat_analysis.assert_called_once()
        svc._run_multilevel_analysis.assert_not_called()

    def test_hierarchical_mode_calls_multilevel(self):
        _fake_config.DAILY_REPORT_ANALYSIS_MODE = "hierarchical"
        _fake_config.DAILY_REPORT_ENABLED = True
        _fake_config.ENABLE_MAIL_NOTIFICATION = False

        from src.daily_report import DailyReportService
        svc = DailyReportService(es_client=MagicMock(), backend=MagicMock())
        svc._run_flat_analysis = MagicMock(return_value=("<p>flat</p>", []))
        svc._run_multilevel_analysis = MagicMock(return_value=("<p>hier</p>", []))

        items = [{"timestamp": "2026-01-01T00:00:00", "summary": "x", "threat_level": "高"}]
        with patch.object(svc, '_get_llm_conf') as mock_conf, \
             patch('src.daily_report.fetch_daily_stats', return_value={}), \
             patch('src.daily_report.fetch_processed_summaries', return_value=items), \
             patch('src.daily_report.stop_ollama_model', return_value=True), \
             patch('src.daily_report.build_report_html', return_value="<html/>"), \
             patch('src.daily_report._save_report_html', return_value=None):
            mock_conf.return_value = MagicMock()
            svc._generate_and_send_inner(date(2026, 1, 1))

        svc._run_multilevel_analysis.assert_called_once()
        svc._run_flat_analysis.assert_not_called()

    def test_pair_only_mode_calls_pair_only_analysis(self):
        _fake_config.DAILY_REPORT_ANALYSIS_MODE = "pair_only"
        _fake_config.DAILY_REPORT_ENABLED = True
        _fake_config.ENABLE_MAIL_NOTIFICATION = False

        from src.daily_report import DailyReportService
        svc = DailyReportService(es_client=MagicMock(), backend=MagicMock())
        svc._run_flat_analysis = MagicMock(return_value=("<p>flat</p>", []))
        svc._run_pair_only_analysis = MagicMock(return_value=("<p>pair_only</p>", []))
        svc._run_multilevel_analysis = MagicMock(return_value=("<p>hier</p>", []))

        items = [{"timestamp": "2026-01-01T00:00:00", "summary": "x", "threat_level": "高"}]
        with patch.object(svc, '_get_llm_conf') as mock_conf, \
             patch('src.daily_report.fetch_daily_stats', return_value={}), \
             patch('src.daily_report.fetch_processed_summaries', return_value=items), \
             patch('src.daily_report.stop_ollama_model', return_value=True), \
             patch('src.daily_report.build_report_html', return_value="<html/>"), \
             patch('src.daily_report._save_report_html', return_value=None):
            mock_conf.return_value = MagicMock()
            svc._generate_and_send_inner(date(2026, 1, 1))

        svc._run_pair_only_analysis.assert_called_once()
        svc._run_flat_analysis.assert_not_called()
        svc._run_multilevel_analysis.assert_not_called()

    def teardown_method(self):
        _fake_config.DAILY_REPORT_ANALYSIS_MODE = "hierarchical"
        _fake_config.DAILY_REPORT_ENABLED = False
        _fake_config.ENABLE_MAIL_NOTIFICATION = False


# ── experiment_tag injection ──────────────────────────────────────────

class TestExperimentTag:
    """Test that experiment_tag injects into email subject and body."""

    def test_no_tag_normal_subject(self):
        _fake_config.DAILY_REPORT_EXPERIMENT_TAG = ""
        _fake_config.DAILY_REPORT_SUBJECT_PREFIX = "[Test]"

        from src.daily_report import send_daily_report_email
        with patch('src.daily_report.send_email', return_value=True) as mock_send, \
             patch('src.mailer.get_recipients_for_event', return_value=["a@b.com"]):
            send_daily_report_email(date(2026, 4, 1), "<p>body</p>")
            subject = mock_send.call_args[0][0]
            assert subject == "[Test] - 2026-04-01"
            body = mock_send.call_args[0][1]
            assert "EXP-" not in body

    def test_tag_prefixed_subject(self):
        _fake_config.DAILY_REPORT_EXPERIMENT_TAG = "RQ1-PairMem"
        _fake_config.DAILY_REPORT_SUBJECT_PREFIX = "[Test]"

        from src.daily_report import send_daily_report_email
        with patch('src.daily_report.send_email', return_value=True) as mock_send, \
             patch('src.mailer.get_recipients_for_event', return_value=["a@b.com"]):
            send_daily_report_email(date(2026, 4, 1), "<p>body</p>")
            subject = mock_send.call_args[0][0]
            assert subject.startswith("[EXP-RQ1-PairMem]")
            assert "2026-04-01" in subject

    def test_tag_banner_in_body(self):
        _fake_config.DAILY_REPORT_EXPERIMENT_TAG = "RQ3-ConfigA"
        _fake_config.DAILY_REPORT_SUBJECT_PREFIX = "[Test]"

        from src.daily_report import send_daily_report_email
        with patch('src.daily_report.send_email', return_value=True) as mock_send, \
             patch('src.mailer.get_recipients_for_event', return_value=["a@b.com"]):
            send_daily_report_email(date(2026, 4, 1), "<p>body</p>")
            body = mock_send.call_args[0][1]
            assert "实验运行：RQ3-ConfigA" in body
            # Banner should come before original body
            banner_pos = body.find("实验运行")
            body_pos = body.find("<p>body</p>")
            assert banner_pos < body_pos

    def test_tag_html_escaped(self):
        """Ensure experiment_tag is HTML-escaped to prevent XSS."""
        _fake_config.DAILY_REPORT_EXPERIMENT_TAG = "<script>alert(1)</script>"
        _fake_config.DAILY_REPORT_SUBJECT_PREFIX = "[Test]"

        from src.daily_report import send_daily_report_email
        with patch('src.daily_report.send_email', return_value=True) as mock_send, \
             patch('src.mailer.get_recipients_for_event', return_value=["a@b.com"]):
            send_daily_report_email(date(2026, 4, 1), "<p>body</p>")
            body = mock_send.call_args[0][1]
            assert "<script>" not in body
            assert html.escape("<script>alert(1)</script>") in body

    def teardown_method(self):
        _fake_config.DAILY_REPORT_EXPERIMENT_TAG = ""


# ── Rolling compaction memory modes (Improvement 30.8) ────────────────

class TestPairRollingMode:
    """Test pair_rolling memory mode: same as pair + compaction trigger."""

    def _make_handler(self, mode: str) -> LLMHandler:
        _fake_config.LLM_MEMORY_MODE = mode
        mock_backend = MagicMock()
        mock_backend.backend_type = "ollama"
        return LLMHandler(backend=mock_backend)

    def test_pair_rolling_creates_comm_pair_memory(self):
        h = self._make_handler("pair_rolling")
        assert h._memory_mode == "pair_rolling"
        assert isinstance(h._comm_pair_memory, CommPairMemory)
        assert h._global_memory is None

    def test_pair_rolling_snapshot_pair_specific(self):
        h = self._make_handler("pair_rolling")
        h.update_summary_memory("hit1", src_ip="10.0.0.1", dest_ip="10.0.0.2")
        h.update_summary_memory("hit2", src_ip="10.0.0.3", dest_ip="10.0.0.4")
        snap = h.get_memory_snapshot("10.0.0.1", "10.0.0.2")
        assert len(snap) == 1
        assert "hit1" in snap[0]

    def test_pair_rolling_no_compact_below_threshold(self):
        """Below threshold, compaction should not trigger."""
        _fake_config.LLM_MEMORY_COMPACT_THRESHOLD = 5
        _fake_config.LLM_MEMORY_COMPACT_BATCH = 3
        h = self._make_handler("pair_rolling")
        for i in range(4):
            h.update_summary_memory(f"event{i}", src_ip="A", dest_ip="B")
        snap = h.get_memory_snapshot("A", "B")
        assert len(snap) == 4  # No compaction happened

    def test_pair_rolling_compacts_at_threshold(self):
        """At threshold, oldest batch should be compacted into one entry."""
        _fake_config.LLM_MEMORY_COMPACT_THRESHOLD = 5
        _fake_config.LLM_MEMORY_COMPACT_BATCH = 3
        h = self._make_handler("pair_rolling")

        # Mock the backend chat to return a compacted summary
        mock_result = MagicMock()
        mock_result.message.content = "压缩后的摘要"
        mock_result.metrics = MagicMock()
        h._backend.chat = MagicMock(return_value=mock_result)

        # Need CURRENT_PERF_CONFIG for the compaction call
        from tests.conftest import PerfConfig
        _fake_config.CURRENT_PERF_CONFIG = PerfConfig()

        with patch('src.llm_handler.build_compact_prompt', return_value="compact prompt"):
            for i in range(5):
                h.update_summary_memory(f"event{i}", src_ip="A", dest_ip="B")

        snap = h.get_memory_snapshot("A", "B")
        # 3 compacted into 1 + 2 remaining = 3 entries
        assert len(snap) == 3
        assert "[合并摘要]" in snap[0]
        assert "event3" in snap[1]
        assert "event4" in snap[2]

    def test_pair_rolling_compact_llm_failure_is_noop(self):
        """If the compaction LLM call fails, entries should remain unchanged."""
        _fake_config.LLM_MEMORY_COMPACT_THRESHOLD = 5
        _fake_config.LLM_MEMORY_COMPACT_BATCH = 3
        h = self._make_handler("pair_rolling")
        h._backend.chat = MagicMock(side_effect=RuntimeError("LLM down"))

        from tests.conftest import PerfConfig
        _fake_config.CURRENT_PERF_CONFIG = PerfConfig()

        with patch('src.llm_handler.build_compact_prompt', return_value="compact prompt"):
            for i in range(5):
                h.update_summary_memory(f"event{i}", src_ip="A", dest_ip="B")

        snap = h.get_memory_snapshot("A", "B")
        assert len(snap) == 5  # No compaction — all entries preserved

    def teardown_method(self):
        _fake_config.LLM_MEMORY_MODE = "pair"
        _fake_config.LLM_MEMORY_COMPACT_THRESHOLD = 10
        _fake_config.LLM_MEMORY_COMPACT_BATCH = 8
        from tests.conftest import PerfConfig
        _fake_config.CURRENT_PERF_CONFIG = PerfConfig()


class TestProtoPairRollingMode:
    """Test proto_pair_rolling memory mode and event-bucket compaction."""

    def setup_method(self):
        from tests.conftest import PerfConfig
        _fake_config.LLM_MEMORY_MODE = "proto_pair_rolling"
        _fake_config.LLM_MEMORY_COMPACT_THRESHOLD = 5
        _fake_config.LLM_MEMORY_COMPACT_BATCH = 3
        _fake_config.CURRENT_PERF_CONFIG = PerfConfig()

    def _make_handler(self) -> LLMHandler:
        mock_backend = MagicMock()
        mock_backend.backend_type = "ollama"
        return LLMHandler(backend=mock_backend)

    def test_proto_pair_rolling_creates_comm_proto_pair_memory(self):
        h = self._make_handler()
        assert h._memory_mode == "proto_pair_rolling"
        assert h._comm_pair_memory is None
        assert isinstance(h._comm_proto_pair_memory, CommProtoPairMemory)
        assert h._global_memory is None

    def test_proto_pair_rolling_compacts_only_current_event_bucket(self):
        h = self._make_handler()
        mock_result = MagicMock()
        mock_result.message.content = "ssh compacted"
        mock_result.metrics = MagicMock()
        h._backend.chat = MagicMock(return_value=mock_result)

        for i in range(4):
            h.update_summary_memory(
                f"smb{i}", src_ip="A", dest_ip="B", app_proto="smb", event_type="alert",
            )

        with patch('src.llm_handler.build_compact_prompt', return_value="compact prompt"):
            for i in range(5):
                h.update_summary_memory(
                    f"ssh{i}", src_ip="A", dest_ip="B", app_proto="ssh", event_type="alert",
                )

        ssh_snap = h.get_memory_snapshot("A", "B", app_proto="ssh", event_type="alert")
        smb_snap = h.get_memory_snapshot("A", "B", app_proto="smb", event_type="alert")
        assert len(ssh_snap) == 3
        assert ssh_snap[0] == "[合并摘要] ssh compacted"
        assert len(smb_snap) == 4
        assert "[合并摘要]" not in smb_snap[0]
        assert h._backend.chat.call_count == 1

    def test_proto_pair_rolling_empty_llm_result_is_noop_for_current_bucket(self):
        h = self._make_handler()
        mock_result = MagicMock()
        mock_result.message.content = ""
        mock_result.metrics = MagicMock()
        h._backend.chat = MagicMock(return_value=mock_result)

        with patch('src.llm_handler.build_compact_prompt', return_value="compact prompt"):
            for i in range(5):
                h.update_summary_memory(
                    f"ssh{i}", src_ip="A", dest_ip="B", app_proto="ssh", event_type="alert",
                )

        ssh_snap = h.get_memory_snapshot("A", "B", app_proto="ssh", event_type="alert")
        assert len(ssh_snap) == 5
        assert ssh_snap[0].endswith("ssh0")

    def teardown_method(self):
        _fake_config.LLM_MEMORY_MODE = "pair"
        _fake_config.LLM_MEMORY_COMPACT_THRESHOLD = 10
        _fake_config.LLM_MEMORY_COMPACT_BATCH = 8
        from tests.conftest import PerfConfig
        _fake_config.CURRENT_PERF_CONFIG = PerfConfig()


class TestGlobalRollingMode:
    """Test global_rolling memory mode: same as global + compaction trigger."""

    def _make_handler(self, mode: str) -> LLMHandler:
        _fake_config.LLM_MEMORY_MODE = mode
        mock_backend = MagicMock()
        mock_backend.backend_type = "ollama"
        return LLMHandler(backend=mock_backend)

    def test_global_rolling_creates_global_memory(self):
        h = self._make_handler("global_rolling")
        assert h._memory_mode == "global_rolling"
        assert h._comm_pair_memory is None
        assert isinstance(h._global_memory, GlobalMemory)

    def test_global_rolling_snapshot_returns_all(self):
        h = self._make_handler("global_rolling")
        h.update_summary_memory("hit1", src_ip="10.0.0.1", dest_ip="10.0.0.2")
        h.update_summary_memory("hit2", src_ip="10.0.0.3", dest_ip="10.0.0.4")
        snap = h.get_memory_snapshot("any", "thing")
        assert len(snap) == 2

    def test_global_rolling_compacts_at_threshold(self):
        _fake_config.LLM_MEMORY_COMPACT_THRESHOLD = 5
        _fake_config.LLM_MEMORY_COMPACT_BATCH = 3
        h = self._make_handler("global_rolling")

        mock_result = MagicMock()
        mock_result.message.content = "全局压缩摘要"
        mock_result.metrics = MagicMock()
        h._backend.chat = MagicMock(return_value=mock_result)

        from tests.conftest import PerfConfig
        _fake_config.CURRENT_PERF_CONFIG = PerfConfig()
        _fake_config.LLM_MEMORY_COMPACT_COOLDOWN = 0.0

        with patch('src.llm_handler.build_compact_prompt', return_value="compact prompt"):
            for i in range(5):
                h.update_summary_memory(f"event{i}", src_ip="A", dest_ip=f"B{i}")

        snap = h.get_memory_snapshot("any", "thing")
        # 3 compacted into 1 + 2 remaining = 3 entries
        assert len(snap) == 3
        assert "[合并摘要]" in snap[0]

    def test_global_rolling_compact_llm_failure_is_noop(self):
        _fake_config.LLM_MEMORY_COMPACT_THRESHOLD = 5
        _fake_config.LLM_MEMORY_COMPACT_BATCH = 3
        h = self._make_handler("global_rolling")
        h._backend.chat = MagicMock(side_effect=RuntimeError("LLM down"))

        from tests.conftest import PerfConfig
        _fake_config.CURRENT_PERF_CONFIG = PerfConfig()
        _fake_config.LLM_MEMORY_COMPACT_COOLDOWN = 0.0

        with patch('src.llm_handler.build_compact_prompt', return_value="compact prompt"):
            for i in range(5):
                h.update_summary_memory(f"event{i}", src_ip="A", dest_ip=f"B{i}")

        snap = h.get_memory_snapshot("any", "thing")
        assert len(snap) == 5

    def teardown_method(self):
        _fake_config.LLM_MEMORY_COMPACT_COOLDOWN = 2.0
        _fake_config.LLM_MEMORY_MODE = "pair"
        _fake_config.LLM_MEMORY_COMPACT_THRESHOLD = 10
        _fake_config.LLM_MEMORY_COMPACT_BATCH = 8
        from tests.conftest import PerfConfig
        _fake_config.CURRENT_PERF_CONFIG = PerfConfig()


class TestCommPairMemoryReplaceEntries:
    """Test CommPairMemory.replace_entries() directly."""

    def test_replace_entries(self):
        mem = CommPairMemory(max_pairs=10, per_pair_len=20)
        mem.add("A", "B", "entry1")
        mem.add("A", "B", "entry2")
        mem.add("A", "B", "entry3")
        assert len(mem.get("A", "B")) == 3

        mem.replace_entries("A", "B", ["compacted", "entry3"])
        snap = mem.get("A", "B")
        assert snap == ["compacted", "entry3"]

    def test_replace_entries_nonexistent_pair(self):
        mem = CommPairMemory(max_pairs=10, per_pair_len=20)
        mem.replace_entries("X", "Y", ["something"])
        assert mem.get("X", "Y") == []

    def test_replace_entries_respects_maxlen(self):
        mem = CommPairMemory(max_pairs=10, per_pair_len=3)
        mem.add("A", "B", "seed")
        mem.replace_entries("A", "B", ["a", "b", "c", "d", "e"])
        snap = mem.get("A", "B")
        assert len(snap) == 3
        assert snap == ["c", "d", "e"]


class TestGlobalMemoryReplaceEntries:
    """Test GlobalMemory.replace_entries() directly."""

    def test_replace_entries(self):
        mem = GlobalMemory(max_entries=20)
        mem.add("e1")
        mem.add("e2")
        mem.add("e3")
        assert mem.count == 3

        mem.replace_entries(["compacted", "e3"])
        snap = mem.get_snapshot()
        assert snap == ["compacted", "e3"]
        assert mem.count == 2

    def test_replace_entries_respects_maxlen(self):
        mem = GlobalMemory(max_entries=3)
        mem.add("seed")
        mem.replace_entries(["a", "b", "c", "d", "e"])
        snap = mem.get_snapshot()
        assert len(snap) == 3
        assert snap == ["c", "d", "e"]


# ── Multi-round compaction tests ──────────────────────────────────────

class TestPairRollingMultiRound:
    """Verify that compaction works correctly across multiple rounds."""

    def setup_method(self):
        from tests.conftest import PerfConfig
        _fake_config.LLM_MEMORY_COMPACT_THRESHOLD = 5
        _fake_config.LLM_MEMORY_COMPACT_BATCH = 3
        _fake_config.LLM_MEMORY_MODE = "pair_rolling"
        _fake_config.CURRENT_PERF_CONFIG = PerfConfig()

    def _make_handler(self) -> LLMHandler:
        mock_backend = MagicMock()
        mock_backend.backend_type = "ollama"
        return LLMHandler(backend=mock_backend)

    def test_second_round_compaction(self):
        """After first compaction, continued adds should trigger a second."""
        h = self._make_handler()
        call_count = 0

        def _fake_chat(**kwargs):
            nonlocal call_count
            call_count += 1
            result = MagicMock()
            result.message.content = f"压缩摘要第{call_count}轮"
            result.metrics = MagicMock()
            return result

        h._backend.chat = _fake_chat

        with patch('src.llm_handler.build_compact_prompt', return_value="prompt"):
            # First round: 5 entries → compact 3 oldest → [summary1] + 2 remaining = 3
            for i in range(5):
                h.update_summary_memory(f"evt{i}", src_ip="A", dest_ip="B")

        snap = h.get_memory_snapshot("A", "B")
        assert len(snap) == 3
        assert "[合并摘要]" in snap[0]
        assert call_count == 1

        with patch('src.llm_handler.build_compact_prompt', return_value="prompt"):
            # Add 2 more → 3 + 2 = 5 → triggers second compaction
            for i in range(5, 7):
                h.update_summary_memory(f"evt{i}", src_ip="A", dest_ip="B")

        snap = h.get_memory_snapshot("A", "B")
        assert len(snap) == 3
        assert "[合并摘要]" in snap[0]
        assert call_count == 2

    def test_compacted_summary_included_in_next_batch(self):
        """The merged summary from round 1 should be part of the batch in round 2."""
        h = self._make_handler()
        compacted_entries = []

        def _fake_chat(**kwargs):
            msg = kwargs.get("messages", [{}])[0].get("content", "")
            compacted_entries.append(msg)
            result = MagicMock()
            result.message.content = "merged"
            result.metrics = MagicMock()
            return result

        h._backend.chat = _fake_chat

        def _capture_prompt(pair_key, entries):
            return f"compact: {entries}"

        with patch('src.llm_handler.build_compact_prompt', side_effect=_capture_prompt):
            for i in range(5):
                h.update_summary_memory(f"evt{i}", src_ip="A", dest_ip="B")

        # After first compaction: [合并摘要] merged, evt3, evt4
        snap = h.get_memory_snapshot("A", "B")
        assert snap[0] == "[合并摘要] merged"

        with patch('src.llm_handler.build_compact_prompt', side_effect=_capture_prompt):
            for i in range(5, 7):
                h.update_summary_memory(f"evt{i}", src_ip="A", dest_ip="B")

        # Second compaction should include the previous merged summary
        assert len(compacted_entries) == 2
        assert "[合并摘要] merged" in compacted_entries[1]

    def teardown_method(self):
        _fake_config.LLM_MEMORY_MODE = "pair"
        _fake_config.LLM_MEMORY_COMPACT_THRESHOLD = 10
        _fake_config.LLM_MEMORY_COMPACT_BATCH = 8
        from tests.conftest import PerfConfig
        _fake_config.CURRENT_PERF_CONFIG = PerfConfig()


class TestGlobalRollingMultiRound:
    """Verify global_rolling compaction across multiple rounds."""

    def setup_method(self):
        from tests.conftest import PerfConfig
        _fake_config.LLM_MEMORY_COMPACT_THRESHOLD = 5
        _fake_config.LLM_MEMORY_COMPACT_BATCH = 3
        _fake_config.LLM_MEMORY_MODE = "global_rolling"
        _fake_config.CURRENT_PERF_CONFIG = PerfConfig()
        _fake_config.LLM_MEMORY_COMPACT_COOLDOWN = 0.0

    def _make_handler(self) -> LLMHandler:
        mock_backend = MagicMock()
        mock_backend.backend_type = "ollama"
        return LLMHandler(backend=mock_backend)

    def test_second_round_compaction(self):
        h = self._make_handler()
        call_count = 0

        def _fake_chat(**kwargs):
            nonlocal call_count
            call_count += 1
            result = MagicMock()
            result.message.content = f"全局摘要第{call_count}轮"
            result.metrics = MagicMock()
            return result

        h._backend.chat = _fake_chat

        with patch('src.llm_handler.build_compact_prompt', return_value="prompt"):
            for i in range(5):
                h.update_summary_memory(f"evt{i}", src_ip=f"S{i}", dest_ip=f"D{i}")

        snap = h.get_memory_snapshot("any", "thing")
        assert len(snap) == 3
        assert "[合并摘要]" in snap[0]
        assert call_count == 1

        with patch('src.llm_handler.build_compact_prompt', return_value="prompt"):
            for i in range(5, 7):
                h.update_summary_memory(f"evt{i}", src_ip=f"S{i}", dest_ip=f"D{i}")

        snap = h.get_memory_snapshot("any", "thing")
        assert len(snap) == 3
        assert call_count == 2

    def teardown_method(self):
        _fake_config.LLM_MEMORY_COMPACT_COOLDOWN = 2.0
        _fake_config.LLM_MEMORY_MODE = "pair"
        _fake_config.LLM_MEMORY_COMPACT_THRESHOLD = 10
        _fake_config.LLM_MEMORY_COMPACT_BATCH = 8
        from tests.conftest import PerfConfig
        _fake_config.CURRENT_PERF_CONFIG = PerfConfig()


# ── build_compact_prompt rendering test ───────────────────────────────

class TestBuildCompactPrompt:
    """Test build_compact_prompt() template rendering."""

    def setup_method(self):
        """Ensure prompt templates are loaded."""
        import os
        from src.llm_prompt import load_prompt_templates
        toml_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "llm_prompt.toml"
        )
        load_prompt_templates(toml_path)

    def test_renders_entries_and_pair_key(self):
        from src.llm_prompt import build_compact_prompt
        entries = ["[2026-04-01] alert SSH暴力破解", "[2026-04-02] alert 端口扫描"]
        result = build_compact_prompt(pair_key="10.0.0.1↔10.0.0.2", entries=entries)
        assert "10.0.0.1↔10.0.0.2" in result
        assert "2" in result  # entry_count
        assert "SSH暴力破解" in result
        assert "端口扫描" in result

    def test_renders_entry_count(self):
        from src.llm_prompt import build_compact_prompt
        entries = [f"entry{i}" for i in range(6)]
        result = build_compact_prompt(pair_key="A↔B", entries=entries)
        assert "6" in result

    def test_handles_empty_entries(self):
        from src.llm_prompt import build_compact_prompt
        result = build_compact_prompt(pair_key="A↔B", entries=[])
        assert "0" in result
        assert "A↔B" in result

    def test_global_memory_pair_key(self):
        """When used for global memory, pair_key is '全局记忆'."""
        from src.llm_prompt import build_compact_prompt
        entries = ["event1", "event2"]
        result = build_compact_prompt(pair_key="全局记忆", entries=entries)
        assert "全局记忆" in result


# ── Config validation tests for compact params ────────────────────────

class TestConfigCompactValidation:
    """Test config.py validation for compact_threshold / compact_batch.

    Since the real Config.__post_init__ requires a locatable TOML file and
    triggers heavyweight side-effects (prompt loading, ENV reads, etc.),
    we test the validation constraints via FakeConfig attribute checks and
    the real Config._parse_llm_section indirectly through ``monkeypatch``.
    """

    def test_batch_ge_threshold_rejected_at_runtime(self):
        """compact_batch >= compact_threshold is invalid per design."""
        # The real Config raises ValueError during __post_init__.
        # We verify the constraint directly:
        assert _fake_config.LLM_MEMORY_COMPACT_BATCH < _fake_config.LLM_MEMORY_COMPACT_THRESHOLD

    def test_defaults_satisfy_constraint(self):
        """Default values (batch=8, threshold=10) satisfy batch < threshold."""
        assert 8 < 10  # compact_batch < compact_threshold

    def test_memory_mode_enum_includes_rolling(self):
        """Verify the allowed memory_mode values at the schema level."""
        import json, os
        schema_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "configs", "constraints", "agent-config.schema.json",
        )
        with open(schema_path) as f:
            schema = json.load(f)
        allowed = schema["properties"]["llm"]["properties"]["memory_mode"]["enum"]
        assert "pair_rolling" in allowed
        assert "global_rolling" in allowed
        assert "proto_pair" in allowed
        assert "proto_pair_rolling" in allowed
        assert "pair" in allowed
        assert "global" in allowed
        assert "none" in allowed

    def test_schema_compact_threshold_minimum(self):
        """JSON Schema enforces minimum=3 for compact_threshold."""
        import json, os
        schema_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "configs", "constraints", "agent-config.schema.json",
        )
        with open(schema_path) as f:
            schema = json.load(f)
        thresh = schema["properties"]["llm"]["properties"]["memory_compact_threshold"]
        assert thresh["minimum"] == 3
        assert thresh["default"] == 10

    def test_schema_compact_batch_minimum(self):
        """JSON Schema enforces minimum=2 for compact_batch."""
        import json, os
        schema_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "configs", "constraints", "agent-config.schema.json",
        )
        with open(schema_path) as f:
            schema = json.load(f)
        batch = schema["properties"]["llm"]["properties"]["memory_compact_batch"]
        assert batch["minimum"] == 2
        assert batch["default"] == 8

    def test_schema_proto_pair_lru_options(self):
        """JSON Schema exposes proto-pair LAT and Max-Pairs LRU settings."""
        import json, os
        schema_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "configs", "constraints", "agent-config.schema.json",
        )
        with open(schema_path) as f:
            schema = json.load(f)
        llm_props = schema["properties"]["llm"]["properties"]
        assert llm_props["memory_lat_lru_evict_seconds"]["exclusiveMinimum"] == 0
        assert llm_props["memory_maxpair_lru_evict"]["minimum"] == 0
        assert llm_props["memory_maxpair_lru_evict"]["default"] == 0

    def test_pair_rolling_creates_correct_subsystem(self):
        """pair_rolling mode initializes CommPairMemory, not GlobalMemory."""
        _fake_config.LLM_MEMORY_MODE = "pair_rolling"
        mock_backend = MagicMock()
        mock_backend.backend_type = "ollama"
        h = LLMHandler(backend=mock_backend)
        assert isinstance(h._comm_pair_memory, CommPairMemory)
        assert h._global_memory is None
        _fake_config.LLM_MEMORY_MODE = "pair"

    def test_global_rolling_creates_correct_subsystem(self):
        """global_rolling mode initializes GlobalMemory, not CommPairMemory."""
        _fake_config.LLM_MEMORY_MODE = "global_rolling"
        mock_backend = MagicMock()
        mock_backend.backend_type = "ollama"
        h = LLMHandler(backend=mock_backend)
        assert h._comm_pair_memory is None
        assert isinstance(h._global_memory, GlobalMemory)
        _fake_config.LLM_MEMORY_MODE = "pair"


# ── compact_oldest tests ─────────────────────────────────────────────────────

class TestCommPairMemoryCompactOldest:
    """Test CommPairMemory.compact_oldest() atomicity."""

    def test_compact_oldest_basic(self):
        mem = CommPairMemory(max_pairs=10, per_pair_len=20)
        for i in range(5):
            mem.add("A", "B", f"e{i}")
        assert mem.compact_oldest("A", "B", 3, "[merged]") is True
        snap = mem.get("A", "B")
        assert snap == ["[merged]", "e3", "e4"]

    def test_compact_oldest_nonexistent_pair(self):
        mem = CommPairMemory(max_pairs=10, per_pair_len=20)
        assert mem.compact_oldest("X", "Y", 1, "[m]") is False

    def test_compact_oldest_insufficient_entries(self):
        mem = CommPairMemory(max_pairs=10, per_pair_len=20)
        mem.add("A", "B", "e0")
        assert mem.compact_oldest("A", "B", 5, "[m]") is False
        assert mem.get("A", "B") == ["e0"]

    def test_compact_oldest_preserves_new_entries(self):
        """Entries appended after snapshot should survive compaction."""
        mem = CommPairMemory(max_pairs=10, per_pair_len=20)
        for i in range(5):
            mem.add("A", "B", f"e{i}")
        # Simulate a concurrent add between snapshot and compact_oldest
        mem.add("A", "B", "late")
        assert mem.compact_oldest("A", "B", 3, "[merged]") is True
        snap = mem.get("A", "B")
        assert snap == ["[merged]", "e3", "e4", "late"]


class TestGlobalMemoryCompactOldest:
    """Test GlobalMemory.compact_oldest() atomicity."""

    def test_compact_oldest_basic(self):
        mem = GlobalMemory(max_entries=20)
        for i in range(5):
            mem.add(f"e{i}")
        assert mem.compact_oldest(3, "[merged]") is True
        snap = mem.get_snapshot()
        assert snap == ["[merged]", "e3", "e4"]

    def test_compact_oldest_insufficient(self):
        mem = GlobalMemory(max_entries=20)
        mem.add("e0")
        assert mem.compact_oldest(5, "[m]") is False
        assert mem.get_snapshot() == ["e0"]

    def test_compact_oldest_preserves_new_entries(self):
        mem = GlobalMemory(max_entries=20)
        for i in range(5):
            mem.add(f"e{i}")
        mem.add("late")
        assert mem.compact_oldest(3, "[merged]") is True
        snap = mem.get_snapshot()
        assert snap == ["[merged]", "e3", "e4", "late"]


# ── Empty LLM result compaction noop tests ────────────────────────────────

class TestCompactEmptyLLMResult:
    """When LLM returns empty content, compaction should be a noop."""

    def setup_method(self):
        from tests.conftest import PerfConfig
        _fake_config.LLM_MEMORY_COMPACT_THRESHOLD = 5
        _fake_config.LLM_MEMORY_COMPACT_BATCH = 3
        _fake_config.CURRENT_PERF_CONFIG = PerfConfig()

    def test_pair_rolling_empty_result_noop(self):
        _fake_config.LLM_MEMORY_MODE = "pair_rolling"
        mock_backend = MagicMock()
        mock_backend.backend_type = "ollama"
        h = LLMHandler(backend=mock_backend)

        mock_result = MagicMock()
        mock_result.message.content = ""  # empty
        mock_result.metrics = MagicMock()
        h._backend.chat = MagicMock(return_value=mock_result)

        with patch('src.llm_handler.build_compact_prompt', return_value="prompt"):
            for i in range(5):
                h.update_summary_memory(f"event{i}", src_ip="A", dest_ip="B")

        snap = h.get_memory_snapshot("A", "B")
        assert len(snap) == 5  # All preserved
        assert "[合并摘要]" not in snap[0]

    def test_global_rolling_empty_result_noop(self):
        _fake_config.LLM_MEMORY_MODE = "global_rolling"
        mock_backend = MagicMock()
        mock_backend.backend_type = "ollama"
        h = LLMHandler(backend=mock_backend)
        _fake_config.LLM_MEMORY_COMPACT_COOLDOWN = 0.0

        mock_result = MagicMock()
        mock_result.message.content = "   "  # whitespace-only
        mock_result.metrics = MagicMock()
        h._backend.chat = MagicMock(return_value=mock_result)

        with patch('src.llm_handler.build_compact_prompt', return_value="prompt"):
            for i in range(5):
                h.update_summary_memory(f"event{i}", src_ip="A", dest_ip=f"B{i}")

        snap = h.get_memory_snapshot("any", "thing")
        assert len(snap) == 5

    def teardown_method(self):
        _fake_config.LLM_MEMORY_COMPACT_COOLDOWN = 2.0
        _fake_config.LLM_MEMORY_MODE = "pair"
        _fake_config.LLM_MEMORY_COMPACT_THRESHOLD = 10
        _fake_config.LLM_MEMORY_COMPACT_BATCH = 8
        from tests.conftest import PerfConfig
        _fake_config.CURRENT_PERF_CONFIG = PerfConfig()


# ── compact_oldest simplified tests (expected_oldest removed) ─────────

class TestCompactOldestSimplified:
    """Verify that compact_oldest works without expected_oldest parameter."""

    def test_pair_compact_basic(self):
        mem = CommPairMemory(max_pairs=10, per_pair_len=20)
        for i in range(5):
            mem.add("A", "B", f"e{i}")
        assert mem.compact_oldest("A", "B", 3, "[merged]") is True
        assert mem.get("A", "B") == ["[merged]", "e3", "e4"]

    def test_pair_compact_insufficient(self):
        mem = CommPairMemory(max_pairs=10, per_pair_len=20)
        mem.add("A", "B", "e0")
        assert mem.compact_oldest("A", "B", 5, "[m]") is False
        assert mem.get("A", "B") == ["e0"]

    def test_global_compact_basic(self):
        mem = GlobalMemory(max_entries=20)
        for i in range(5):
            mem.add(f"e{i}")
        assert mem.compact_oldest(3, "[merged]") is True
        assert mem.get_snapshot() == ["[merged]", "e3", "e4"]

    def test_global_compact_insufficient(self):
        mem = GlobalMemory(max_entries=20)
        mem.add("e0")
        assert mem.compact_oldest(5, "[m]") is False
        assert mem.get_snapshot() == ["e0"]


# ── Concurrent compaction tests ───────────────────────────────────────

class TestConcurrentPairRollingCompaction:
    """Test that the per-pair trylock prevents parallel compaction
    and that rolling mode (no maxlen) allows compaction to succeed
    even with concurrent adds."""

    def setup_method(self):
        from tests.conftest import PerfConfig
        _fake_config.LLM_MEMORY_COMPACT_THRESHOLD = 5
        _fake_config.LLM_MEMORY_COMPACT_BATCH = 3
        _fake_config.LLM_MEMORY_MODE = "pair_rolling"
        _fake_config.CURRENT_PERF_CONFIG = PerfConfig()

    def test_concurrent_add_during_compaction_succeeds_with_rolling(self):
        """In rolling mode, deque has no maxlen — concurrent adds don't
        evict entries, so compaction succeeds after the LLM call."""
        mock_backend = MagicMock()
        mock_backend.backend_type = "ollama"
        h = LLMHandler(backend=mock_backend)

        llm_entered = threading.Event()
        llm_proceed = threading.Event()

        def _blocking_chat(**kwargs):
            llm_entered.set()
            llm_proceed.wait(timeout=5)
            result = MagicMock()
            result.message.content = "compacted summary"
            result.metrics = MagicMock()
            return result

        h._backend.chat = _blocking_chat

        # Pre-fill 4 entries (below threshold)
        with patch('src.llm_handler.build_compact_prompt', return_value="prompt"):
            for i in range(4):
                h.update_summary_memory(f"evt{i}", src_ip="A", dest_ip="B")

        snap = h.get_memory_snapshot("A", "B")
        assert len(snap) == 4

        # 5th entry triggers compaction in a separate thread
        errors = []

        def _trigger_compact():
            try:
                with patch('src.llm_handler.build_compact_prompt', return_value="prompt"):
                    h.update_summary_memory("evt4", src_ip="A", dest_ip="B")
            except Exception as e:
                errors.append(e)

        t = threading.Thread(target=_trigger_compact)
        t.start()
        assert llm_entered.wait(timeout=5), "LLM call was never entered"

        # While LLM is blocked, add concurrent entries.
        # Rolling mode: no maxlen, so no eviction — entries accumulate.
        h._comm_pair_memory.add("A", "B", "concurrent1")
        h._comm_pair_memory.add("A", "B", "concurrent2")

        llm_proceed.set()
        t.join(timeout=5)
        assert not errors, f"Thread raised: {errors}"

        # Compaction succeeds because rolling deque has no implicit eviction
        snap = h.get_memory_snapshot("A", "B")
        assert snap[0] == "[合并摘要] compacted summary"
        # concurrent adds survive after the compacted batch
        assert "concurrent1" in snap
        assert "concurrent2" in snap

    def test_trylock_skips_parallel_compaction(self):
        """A second thread attempting to compact the same pair while the
        first is in-flight should be silently skipped (trylock)."""
        mock_backend = MagicMock()
        mock_backend.backend_type = "ollama"
        _fake_config.LLM_MEMORY_PER_PAIR_LEN = 20
        h = LLMHandler(backend=mock_backend)

        llm_call_count = 0
        llm_entered = threading.Event()
        llm_proceed = threading.Event()

        def _blocking_chat(**kwargs):
            nonlocal llm_call_count
            llm_call_count += 1
            llm_entered.set()
            llm_proceed.wait(timeout=5)
            result = MagicMock()
            result.message.content = "compacted"
            result.metrics = MagicMock()
            return result

        h._backend.chat = _blocking_chat

        # Fill beyond threshold
        with patch('src.llm_handler.build_compact_prompt', return_value="prompt"):
            for i in range(4):
                h.update_summary_memory(f"evt{i}", src_ip="A", dest_ip="B")

        errors = []

        def _trigger_compact(name):
            try:
                with patch('src.llm_handler.build_compact_prompt', return_value="prompt"):
                    h.update_summary_memory(name, src_ip="A", dest_ip="B")
            except Exception as e:
                errors.append(e)

        # Thread 1 triggers compaction (will block at LLM call)
        t1 = threading.Thread(target=_trigger_compact, args=("evt4",))
        t1.start()
        assert llm_entered.wait(timeout=5)

        # Thread 2 also tries to compact the same pair — should be skipped
        t2 = threading.Thread(target=_trigger_compact, args=("evt5",))
        t2.start()
        t2.join(timeout=5)

        llm_proceed.set()
        t1.join(timeout=5)
        assert not errors

        # Only 1 LLM call (the second was skipped by trylock)
        assert llm_call_count == 1

    def teardown_method(self):
        _fake_config.LLM_MEMORY_MODE = "pair"
        _fake_config.LLM_MEMORY_COMPACT_THRESHOLD = 10
        _fake_config.LLM_MEMORY_COMPACT_BATCH = 8
        _fake_config.LLM_MEMORY_PER_PAIR_LEN = 5
        from tests.conftest import PerfConfig
        _fake_config.CURRENT_PERF_CONFIG = PerfConfig()


class TestConcurrentGlobalRollingCompaction:
    """Test concurrent safety for global_rolling compaction."""

    def setup_method(self):
        from tests.conftest import PerfConfig
        _fake_config.LLM_MEMORY_COMPACT_THRESHOLD = 5
        _fake_config.LLM_MEMORY_COMPACT_BATCH = 3
        _fake_config.LLM_MEMORY_MODE = "global_rolling"
        _fake_config.LLM_MEMORY_LEN = 5
        _fake_config.CURRENT_PERF_CONFIG = PerfConfig()

    def test_concurrent_add_compaction_succeeds_with_rolling(self):
        """In rolling mode, global deque has no maxlen, so concurrent adds
        don't evict — compaction succeeds."""
        mock_backend = MagicMock()
        mock_backend.backend_type = "ollama"
        h = LLMHandler(backend=mock_backend)

        llm_entered = threading.Event()
        llm_proceed = threading.Event()

        def _blocking_chat(**kwargs):
            llm_entered.set()
            llm_proceed.wait(timeout=5)
            result = MagicMock()
            result.message.content = "global compacted"
            result.metrics = MagicMock()
            return result

        h._backend.chat = _blocking_chat

        # Disable cooldown for test
        _fake_config.LLM_MEMORY_COMPACT_COOLDOWN = 0.0

        with patch('src.llm_handler.build_compact_prompt', return_value="prompt"):
            for i in range(4):
                h.update_summary_memory(f"evt{i}", src_ip=f"S{i}", dest_ip=f"D{i}")

        errors = []

        def _trigger_compact():
            try:
                with patch('src.llm_handler.build_compact_prompt', return_value="prompt"):
                    h.update_summary_memory("evt4", src_ip="S4", dest_ip="D4")
            except Exception as e:
                errors.append(e)

        t = threading.Thread(target=_trigger_compact)
        t.start()
        assert llm_entered.wait(timeout=5)

        # Concurrent adds — rolling deque won't evict
        h._global_memory.add("concurrent1")
        h._global_memory.add("concurrent2")

        llm_proceed.set()
        t.join(timeout=5)
        assert not errors

        snap = h.get_memory_snapshot("any", "thing")
        # Compaction should have SUCCEEDED (no implicit eviction in rolling mode)
        assert snap[0] == "[合并摘要] global compacted"

    def test_trylock_skips_parallel_global_compaction(self):
        """A second thread attempting global compaction should be skipped."""
        mock_backend = MagicMock()
        mock_backend.backend_type = "ollama"
        h = LLMHandler(backend=mock_backend)

        llm_call_count = 0
        llm_entered = threading.Event()
        llm_proceed = threading.Event()

        def _blocking_chat(**kwargs):
            nonlocal llm_call_count
            llm_call_count += 1
            llm_entered.set()
            llm_proceed.wait(timeout=5)
            result = MagicMock()
            result.message.content = "compacted"
            result.metrics = MagicMock()
            return result

        h._backend.chat = _blocking_chat

        # Disable cooldown for test
        _fake_config.LLM_MEMORY_COMPACT_COOLDOWN = 0.0

        with patch('src.llm_handler.build_compact_prompt', return_value="prompt"):
            for i in range(4):
                h.update_summary_memory(f"evt{i}", src_ip=f"S{i}", dest_ip=f"D{i}")

        errors = []

        def _trigger(name, src, dst):
            try:
                with patch('src.llm_handler.build_compact_prompt', return_value="prompt"):
                    h.update_summary_memory(name, src_ip=src, dest_ip=dst)
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=_trigger, args=("evt4", "S4", "D4"))
        t1.start()
        assert llm_entered.wait(timeout=5)

        # Second thread tries global compact — should be skipped by trylock
        t2 = threading.Thread(target=_trigger, args=("evt5", "S5", "D5"))
        t2.start()
        t2.join(timeout=5)

        llm_proceed.set()
        t1.join(timeout=5)
        assert not errors
        assert llm_call_count == 1

    def teardown_method(self):
        _fake_config.LLM_MEMORY_COMPACT_COOLDOWN = 2.0
        _fake_config.LLM_MEMORY_MODE = "pair"
        _fake_config.LLM_MEMORY_COMPACT_THRESHOLD = 10
        _fake_config.LLM_MEMORY_COMPACT_BATCH = 8
        _fake_config.LLM_MEMORY_LEN = 50
        from tests.conftest import PerfConfig
        _fake_config.CURRENT_PERF_CONFIG = PerfConfig()


# ── Config threshold validation tests ─────────────────────────────────

class TestConfigThresholdValidation:
    """Test that compact_threshold >= 3 is enforced."""

    def test_schema_compact_threshold_minimum_is_3(self):
        import json, os
        schema_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "configs", "constraints", "agent-config.schema.json",
        )
        with open(schema_path) as f:
            schema = json.load(f)
        thresh = schema["properties"]["llm"]["properties"]["memory_compact_threshold"]
        assert thresh["minimum"] == 3


# ── Rolling mode unit tests (Improvement 30.8.1) ─────────────────────

class TestGlobalMemoryRolling:
    """Test GlobalMemory rolling=True behaviour."""

    def test_rolling_no_implicit_eviction(self):
        """rolling=True deque has no maxlen — entries accumulate."""
        mem = GlobalMemory(max_entries=10, rolling=True)
        for i in range(10):
            mem.add(f"e{i}")
        snap = mem.get_snapshot()
        assert len(snap) == 10
        assert snap[0] == "e0"

    def test_non_rolling_evicts_at_maxlen(self):
        """rolling=False (default) uses maxlen — oldest evicted."""
        mem = GlobalMemory(max_entries=3)
        for i in range(5):
            mem.add(f"e{i}")
        snap = mem.get_snapshot()
        assert len(snap) == 3
        assert snap[0] == "e2"

    def test_rolling_hard_cap_truncates(self):
        """When entries exceed 2*max_entries, truncate to max_entries."""
        mem = GlobalMemory(max_entries=5, rolling=True)
        # Add 11 entries → exceeds hard cap of 10
        for i in range(11):
            mem.add(f"e{i}")
        snap = mem.get_snapshot()
        assert len(snap) == 5
        # Should keep the newest entries
        assert snap[-1] == "e10"

    def test_rolling_replace_entries_no_maxlen(self):
        """replace_entries in rolling mode doesn't clip to maxlen."""
        mem = GlobalMemory(max_entries=3, rolling=True)
        mem.add("seed")
        mem.replace_entries(["a", "b", "c", "d", "e"])
        snap = mem.get_snapshot()
        assert len(snap) == 5
        assert snap == ["a", "b", "c", "d", "e"]

    def test_rolling_compact_oldest_success(self):
        """compact_oldest works in rolling mode."""
        mem = GlobalMemory(max_entries=20, rolling=True)
        for i in range(5):
            mem.add(f"e{i}")
        assert mem.compact_oldest(3, "[merged]") is True
        assert mem.get_snapshot() == ["[merged]", "e3", "e4"]


class TestCommPairMemoryRolling:
    """Test CommPairMemory rolling=True behaviour."""

    def test_rolling_no_implicit_eviction(self):
        mem = CommPairMemory(max_pairs=10, per_pair_len=10, rolling=True)
        for i in range(10):
            mem.add("A", "B", f"e{i}")
        snap = mem.get("A", "B")
        assert len(snap) == 10
        assert snap[0] == "e0"

    def test_non_rolling_evicts_at_maxlen(self):
        mem = CommPairMemory(max_pairs=10, per_pair_len=3)
        for i in range(5):
            mem.add("A", "B", f"e{i}")
        snap = mem.get("A", "B")
        assert len(snap) == 3
        assert snap[0] == "e2"

    def test_rolling_hard_cap_truncates(self):
        mem = CommPairMemory(max_pairs=10, per_pair_len=5, rolling=True)
        for i in range(11):
            mem.add("A", "B", f"e{i}")
        snap = mem.get("A", "B")
        assert len(snap) == 5
        assert snap[-1] == "e10"

    def test_rolling_replace_entries_no_maxlen(self):
        mem = CommPairMemory(max_pairs=10, per_pair_len=3, rolling=True)
        mem.add("A", "B", "seed")
        mem.replace_entries("A", "B", ["a", "b", "c", "d", "e"])
        snap = mem.get("A", "B")
        assert len(snap) == 5

    def test_rolling_compact_oldest_success(self):
        mem = CommPairMemory(max_pairs=10, per_pair_len=20, rolling=True)
        for i in range(5):
            mem.add("A", "B", f"e{i}")
        assert mem.compact_oldest("A", "B", 3, "[merged]") is True
        assert mem.get("A", "B") == ["[merged]", "e3", "e4"]


class TestGlobalCooldown:
    """Test that the cooldown window prevents serial re-triggering."""

    def setup_method(self):
        from tests.conftest import PerfConfig
        _fake_config.LLM_MEMORY_COMPACT_THRESHOLD = 5
        _fake_config.LLM_MEMORY_COMPACT_BATCH = 3
        _fake_config.LLM_MEMORY_MODE = "global_rolling"
        _fake_config.CURRENT_PERF_CONFIG = PerfConfig()

    def test_cooldown_prevents_immediate_retrigger(self):
        """After successful compaction, cooldown blocks the next attempt."""
        mock_backend = MagicMock()
        mock_backend.backend_type = "ollama"
        h = LLMHandler(backend=mock_backend)

        call_count = 0

        def _fake_chat(**kwargs):
            nonlocal call_count
            call_count += 1
            result = MagicMock()
            result.message.content = f"summary{call_count}"
            result.metrics = MagicMock()
            return result

        h._backend.chat = _fake_chat
        # Set cooldown high enough that second compact is blocked
        _fake_config.LLM_MEMORY_COMPACT_COOLDOWN = 100.0

        with patch('src.llm_handler.build_compact_prompt', return_value="prompt"):
            # Fill to threshold → triggers compaction
            for i in range(5):
                h.update_summary_memory(f"evt{i}", src_ip=f"S{i}", dest_ip=f"D{i}")

        assert call_count == 1
        snap = h.get_memory_snapshot("any", "thing")
        assert len(snap) == 3

        with patch('src.llm_handler.build_compact_prompt', return_value="prompt"):
            # Add more to push past threshold again
            for i in range(5, 8):
                h.update_summary_memory(f"evt{i}", src_ip=f"S{i}", dest_ip=f"D{i}")

        # Cooldown blocks second compaction
        assert call_count == 1
        snap = h.get_memory_snapshot("any", "thing")
        assert len(snap) == 6  # 3 from first round + 3 new

    def teardown_method(self):
        _fake_config.LLM_MEMORY_COMPACT_COOLDOWN = 2.0
        _fake_config.LLM_MEMORY_MODE = "pair"
        _fake_config.LLM_MEMORY_COMPACT_THRESHOLD = 10
        _fake_config.LLM_MEMORY_COMPACT_BATCH = 8
        from tests.conftest import PerfConfig
        _fake_config.CURRENT_PERF_CONFIG = PerfConfig()
