#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         test_processor.py
Description:  Tests for log processor batch handling and LLM integration.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations
from unittest.mock import MagicMock, patch, PropertyMock, ANY
import pytest


class TestLogProcessorBuildUpdate:
    """Test _build_update with mocked LLMHandler and ESClient."""

    def _make_processor(self):
        with patch("src.processor.ESClient"):
            from src.processor import LogProcessor
            proc = LogProcessor()
            proc.es_client = MagicMock()
            proc.llm_handler = MagicMock()
            return proc

    def test_successful_build(self):
        proc = self._make_processor()
        proc.llm_handler.generate_advice.return_value = "some advice"
        proc.llm_handler.parse_json_sections.return_value = {
            "summary": "Test summary",
            "threat_level": "低",
        }

        log = {
            "_index": "suricata-eve-2026.01.01",
            "_id": "doc123",
            "_source": {
                "@timestamp": "2026-01-01T00:00:00Z",
                "event_type": "dns",
                "src_ip": "10.0.0.1",
                "dest_ip": "10.0.0.2",
                "src_hostname": "",
                "dest_hostname": "",
            },
        }

        result = proc._build_update(log, 1700000000000)
        assert result is not None
        assert result["_id"] == "doc123"
        assert result["ai_advice"] == "some advice"
        assert result["ai_fields"]["summary"] == "Test summary"
        proc.llm_handler.update_summary_memory.assert_called_once()

    def test_pipeline_memory_update_passes_app_proto(self):
        proc = self._make_processor()
        proc.llm_handler.generate_advice.return_value = "some advice"
        proc.llm_handler.parse_json_sections.return_value = {
            "summary": "HTTP alert summary",
            "threat_level": "中",
        }

        log = {
            "_index": "suricata-eve-2026.01.01",
            "_id": "doc-http",
            "_source": {
                "@timestamp": "2026-01-01T00:00:00Z",
                "event_type": "alert",
                "app_proto": "http",
                "src_ip": "10.0.0.1",
                "dest_ip": "10.0.0.2",
            },
        }

        proc._build_update_pipeline(log, 1700000000000)

        kwargs = proc.llm_handler.update_summary_memory.call_args.kwargs
        assert kwargs["event_type"] == "alert"
        assert kwargs["app_proto"] == "http"

    def test_empty_advice_returns_none(self):
        proc = self._make_processor()
        proc.llm_handler.generate_advice.return_value = ""

        log = {
            "_index": "test", "_id": "1",
            "_source": {"event_type": "dns"},
        }
        result = proc._build_update(log, 0)
        assert result is None

    def test_no_summary_skips_memory(self):
        proc = self._make_processor()
        proc.llm_handler.generate_advice.return_value = "advice"
        proc.llm_handler.parse_json_sections.return_value = {}

        log = {"_index": "test", "_id": "2", "_source": {}}
        proc._build_update(log, 0)
        proc.llm_handler.update_summary_memory.assert_not_called()


class TestLogProcessorGetStats:
    def _make_processor(self):
        with patch("src.processor.ESClient"):
            from src.processor import LogProcessor
            proc = LogProcessor()
            proc.es_client = MagicMock()
            proc.llm_handler = MagicMock()
            return proc

    def test_initial_stats(self):
        proc = self._make_processor()
        stats = proc.get_stats()
        assert stats["processed"] == 0
        assert stats["failed"] == 0
        assert stats["last_run"] is None

    def test_stats_returns_copy(self):
        proc = self._make_processor()
        s1 = proc.get_stats()
        s1["processed"] = 999
        s2 = proc.get_stats()
        assert s2["processed"] == 0  # original unchanged


class TestLogProcessorProcessBatch:
    def _make_processor(self):
        with patch("src.processor.ESClient"):
            from src.processor import LogProcessor
            proc = LogProcessor()
            proc.es_client = MagicMock()
            proc.llm_handler = MagicMock()
            return proc

    def test_no_docs(self):
        proc = self._make_processor()
        proc.es_client.get_unprocessed_docs.return_value = iter([])
        proc.es_client.count_unprocessed_docs.return_value = 0

        result = proc.process_batch("test-index")
        assert result["processed"] == 0
        assert result["fetched"] == 0

    def test_with_docs(self):
        proc = self._make_processor()
        docs = [
            {"_index": "i", "_id": "1", "_source": {"event_type": "dns"}},
            {"_index": "i", "_id": "2", "_source": {"event_type": "http"}},
        ]
        proc.es_client.get_unprocessed_docs.return_value = iter(docs)
        proc.es_client.count_unprocessed_docs.return_value = 2
        proc.llm_handler.generate_advice.return_value = "advice"
        proc.llm_handler.parse_json_sections.return_value = {"summary": "s"}
        proc.llm_handler.drain_batch_metrics.return_value = []
        proc.es_client.bulk_update_ai_advice.return_value = {"success": 2, "failed": 0}

        result = proc.process_batch("test-index")
        assert result["fetched"] == 2
        assert result["processed"] == 2


class TestMaybeCreateIssue:
    """Test _maybe_create_issue includes event ID, index, and alert rule."""

    def _make_processor(self):
        with patch("src.processor.ESClient"):
            from src.processor import LogProcessor
            proc = LogProcessor()
            proc.es_client = MagicMock()
            proc.llm_handler = MagicMock()
            return proc

    @patch("src.processor._issue_dedup")
    @patch("src.processor.config")
    def test_issue_body_contains_event_id_and_index(self, mock_cfg, mock_dedup):
        proc = self._make_processor()
        mock_cfg.GIT_ENABLED = True
        mock_cfg.GIT_AUTO_ISSUE = True
        mock_cfg.GIT_ISSUE_THREAT_THRESHOLD = "高"
        mock_dedup.check_and_add.return_value = True
        executor = MagicMock()
        executor.execute.return_value = MagicMock(status=MagicMock(value="success"))
        proc._executor = executor
        proc.llm_handler.agent_identity = None

        log = {
            "_id": "abc123xyz",
            "_index": "suricata-eve-2026.03.28",
            "_source": {
                "@timestamp": "2026-03-28T10:00:00Z",
                "event_type": "alert",
                "src_ip": "10.0.0.1",
                "dest_ip": "10.0.0.2",
                "alert": {
                    "signature": "ET MALWARE Trojan CnC",
                    "signature_id": 2024897,
                    "severity": 1,
                },
            },
        }
        parsed = {"threat_level": "高", "summary": "Detected trojan activity"}

        proc._maybe_create_issue(log, parsed)

        executor.execute.assert_called_once()
        req = executor.execute.call_args[0][0]
        body = req.params["body"]
        assert "abc123xyz" in body, "Issue body must contain event ID"
        assert "suricata-eve-2026.03.28" in body, "Issue body must contain index name"
        assert "ET MALWARE Trojan CnC" in body, "Issue body must contain alert signature"
        assert "2024897" in body, "Issue body must contain SID"

    @patch("src.processor._issue_dedup")
    @patch("src.processor.config")
    def test_issue_body_without_alert_info(self, mock_cfg, mock_dedup):
        """Non-alert events should still include event ID but no rule info."""
        proc = self._make_processor()
        mock_cfg.GIT_ENABLED = True
        mock_cfg.GIT_AUTO_ISSUE = True
        mock_cfg.GIT_ISSUE_THREAT_THRESHOLD = "高"
        mock_dedup.check_and_add.return_value = True
        executor = MagicMock()
        executor.execute.return_value = MagicMock(status=MagicMock(value="success"))
        proc._executor = executor
        proc.llm_handler.agent_identity = None

        log = {
            "_id": "flow999",
            "_index": "suricata-eve-2026.03.28",
            "_source": {
                "@timestamp": "2026-03-28T11:00:00Z",
                "event_type": "flow",
                "src_ip": "192.168.1.1",
                "dest_ip": "8.8.8.8",
            },
        }
        parsed = {"threat_level": "严重", "summary": "Suspicious outbound flow"}

        proc._maybe_create_issue(log, parsed)

        req = executor.execute.call_args[0][0]
        body = req.params["body"]
        assert "flow999" in body, "Issue body must contain event ID"
        assert "告警规则" not in body, "No alert rule for non-alert events"

    @patch("src.processor._issue_dedup")
    @patch("src.processor.config")
    def test_alert_field_not_dict_handled(self, mock_cfg, mock_dedup):
        """When alert field is a string instead of dict, no crash."""
        proc = self._make_processor()
        mock_cfg.GIT_ENABLED = True
        mock_cfg.GIT_AUTO_ISSUE = True
        mock_cfg.GIT_ISSUE_THREAT_THRESHOLD = "高"
        mock_dedup.check_and_add.return_value = True
        executor = MagicMock()
        executor.execute.return_value = MagicMock(status=MagicMock(value="success"))
        proc._executor = executor
        proc.llm_handler.agent_identity = None

        log = {
            "_id": "doc123",
            "_index": "idx",
            "_source": {
                "@timestamp": "2026-03-28T12:00:00Z",
                "event_type": "alert",
                "src_ip": "10.0.0.1",
                "dest_ip": "10.0.0.2",
                "alert": "malformed-string-not-dict",
            },
        }
        parsed = {"threat_level": "高", "summary": "Malformed alert"}

        proc._maybe_create_issue(log, parsed)
        executor.execute.assert_called_once()
        body = executor.execute.call_args[0][0].params["body"]
        assert "告警规则" not in body

    @patch("src.processor.config")
    def test_skipped_when_git_disabled(self, mock_cfg):
        """No issue created when GIT_ENABLED is False."""
        proc = self._make_processor()
        mock_cfg.GIT_ENABLED = False
        mock_cfg.GIT_AUTO_ISSUE = True
        executor = MagicMock()
        proc._executor = executor

        proc._maybe_create_issue(
            {"_source": {}},
            {"threat_level": "严重", "summary": "test"},
        )
        executor.execute.assert_not_called()

    @patch("src.processor.config")
    def test_skipped_when_auto_issue_disabled(self, mock_cfg):
        """No issue created when GIT_AUTO_ISSUE is False."""
        proc = self._make_processor()
        mock_cfg.GIT_ENABLED = True
        mock_cfg.GIT_AUTO_ISSUE = False
        executor = MagicMock()
        proc._executor = executor

        proc._maybe_create_issue(
            {"_source": {}},
            {"threat_level": "严重", "summary": "test"},
        )
        executor.execute.assert_not_called()

    @patch("src.processor.config")
    def test_skipped_when_executor_none(self, mock_cfg):
        """No issue created when executor is None."""
        proc = self._make_processor()
        mock_cfg.GIT_ENABLED = True
        mock_cfg.GIT_AUTO_ISSUE = True
        proc._executor = None

        # Should not raise
        proc._maybe_create_issue(
            {"_source": {}},
            {"threat_level": "严重", "summary": "test"},
        )

    @patch("src.processor._issue_dedup")
    @patch("src.processor.config")
    def test_skipped_when_below_threshold(self, mock_cfg, mock_dedup):
        """No issue created when threat level is below threshold."""
        proc = self._make_processor()
        mock_cfg.GIT_ENABLED = True
        mock_cfg.GIT_AUTO_ISSUE = True
        mock_cfg.GIT_ISSUE_THREAT_THRESHOLD = "严重"
        executor = MagicMock()
        proc._executor = executor

        proc._maybe_create_issue(
            {"_source": {}},
            {"threat_level": "高", "summary": "Not critical enough"},
        )
        executor.execute.assert_not_called()
        mock_dedup.check_and_add.assert_not_called()

    @patch("src.processor._issue_dedup")
    @patch("src.processor.config")
    def test_skipped_when_summary_empty(self, mock_cfg, mock_dedup):
        """No issue created when parsed summary is empty."""
        proc = self._make_processor()
        mock_cfg.GIT_ENABLED = True
        mock_cfg.GIT_AUTO_ISSUE = True
        mock_cfg.GIT_ISSUE_THREAT_THRESHOLD = "高"
        executor = MagicMock()
        proc._executor = executor

        proc._maybe_create_issue(
            {"_source": {}},
            {"threat_level": "高", "summary": ""},
        )
        executor.execute.assert_not_called()

    @patch("src.processor._issue_dedup")
    @patch("src.processor.config")
    def test_skipped_when_dedup_rejects(self, mock_cfg, mock_dedup):
        """No issue created when dedup cache rejects the key."""
        proc = self._make_processor()
        mock_cfg.GIT_ENABLED = True
        mock_cfg.GIT_AUTO_ISSUE = True
        mock_cfg.GIT_ISSUE_THREAT_THRESHOLD = "高"
        mock_dedup.check_and_add.return_value = False
        executor = MagicMock()
        proc._executor = executor

        proc._maybe_create_issue(
            {"_source": {}},
            {"threat_level": "严重", "summary": "Duplicate event"},
        )
        executor.execute.assert_not_called()

    @patch("src.processor._issue_dedup")
    @patch("src.processor.config")
    def test_execute_exception_handled(self, mock_cfg, mock_dedup):
        """Exception in executor.execute does not crash."""
        proc = self._make_processor()
        mock_cfg.GIT_ENABLED = True
        mock_cfg.GIT_AUTO_ISSUE = True
        mock_cfg.GIT_ISSUE_THREAT_THRESHOLD = "高"
        mock_dedup.check_and_add.return_value = True
        executor = MagicMock()
        executor.execute.side_effect = RuntimeError("network failure")
        proc._executor = executor
        proc.llm_handler.agent_identity = None

        log = {
            "_id": "err1",
            "_index": "idx",
            "_source": {
                "@timestamp": "2026-03-28T12:00:00Z",
                "event_type": "alert",
                "src_ip": "10.0.0.1",
                "dest_ip": "10.0.0.2",
            },
        }
        # Should not raise
        proc._maybe_create_issue(log, {"threat_level": "高", "summary": "Test"})

    @patch("src.processor._issue_dedup")
    @patch("src.processor.config")
    def test_agent_identity_forwarded(self, mock_cfg, mock_dedup):
        """When agent identity is set, ActionRequest carries its credentials."""
        proc = self._make_processor()
        mock_cfg.GIT_ENABLED = True
        mock_cfg.GIT_AUTO_ISSUE = True
        mock_cfg.GIT_ISSUE_THREAT_THRESHOLD = "高"
        mock_dedup.check_and_add.return_value = True
        executor = MagicMock()
        executor.execute.return_value = MagicMock(status=MagicMock(value="success"))
        proc._executor = executor

        # Simulate a real agent identity via llm_handler
        identity = MagicMock()
        identity.actor_role = "Agent"
        identity.actor_id = "agent-42"
        identity.api_key = "key-xyz"
        proc.llm_handler.agent_identity = identity

        log = {
            "_id": "id1",
            "_index": "idx",
            "_source": {
                "@timestamp": "2026-03-28T12:00:00Z",
                "event_type": "alert",
                "src_ip": "10.0.0.1",
                "dest_ip": "10.0.0.2",
            },
        }
        proc._maybe_create_issue(log, {"threat_level": "严重", "summary": "Critical event"})

        req = executor.execute.call_args[0][0]
        assert req.actor_role == "Agent"
        assert req.actor_id == "agent-42"
        assert req.api_key == "key-xyz"

    @patch("src.processor._issue_dedup")
    @patch("src.processor.config")
    def test_issue_title_contains_comm_pair_and_event_type(self, mock_cfg, mock_dedup):
        """Issue title includes source → dest and event_type."""
        proc = self._make_processor()
        mock_cfg.GIT_ENABLED = True
        mock_cfg.GIT_AUTO_ISSUE = True
        mock_cfg.GIT_ISSUE_THREAT_THRESHOLD = "高"
        mock_dedup.check_and_add.return_value = True
        executor = MagicMock()
        executor.execute.return_value = MagicMock(status=MagicMock(value="success"))
        proc._executor = executor
        proc.llm_handler.agent_identity = None

        log = {
            "_id": "t1",
            "_index": "idx",
            "_source": {
                "@timestamp": "2026-03-28T12:00:00Z",
                "event_type": "tls",
                "src_hostname": "workstation.local",
                "dest_hostname": "evil.com",
            },
        }
        proc._maybe_create_issue(log, {"threat_level": "高", "summary": "Bad TLS"})

        req = executor.execute.call_args[0][0]
        title = req.params["title"]
        assert "workstation.local" in title
        assert "evil.com" in title
        assert "tls" in title
        assert "[高]" in title

    @patch("src.processor._issue_dedup")
    @patch("src.processor.config")
    def test_issue_labels_contain_threat_level(self, mock_cfg, mock_dedup):
        """Issue labels include auto-alert and the threat level."""
        proc = self._make_processor()
        mock_cfg.GIT_ENABLED = True
        mock_cfg.GIT_AUTO_ISSUE = True
        mock_cfg.GIT_ISSUE_THREAT_THRESHOLD = "高"
        mock_dedup.check_and_add.return_value = True
        executor = MagicMock()
        executor.execute.return_value = MagicMock(status=MagicMock(value="success"))
        proc._executor = executor
        proc.llm_handler.agent_identity = None

        log = {
            "_id": "lbl1",
            "_index": "idx",
            "_source": {
                "@timestamp": "2026-03-28T12:00:00Z",
                "event_type": "alert",
                "src_ip": "10.0.0.1",
                "dest_ip": "10.0.0.2",
            },
        }
        proc._maybe_create_issue(log, {"threat_level": "严重", "summary": "Critical event"})

        req = executor.execute.call_args[0][0]
        labels = req.params["labels"]
        assert "auto-alert" in labels
        assert "严重" in labels

    @patch("src.processor._issue_dedup")
    @patch("src.processor.config")
    def test_issue_prefers_hostname_over_ip(self, mock_cfg, mock_dedup):
        """Issue body uses hostname when available, falls back to IP."""
        proc = self._make_processor()
        mock_cfg.GIT_ENABLED = True
        mock_cfg.GIT_AUTO_ISSUE = True
        mock_cfg.GIT_ISSUE_THREAT_THRESHOLD = "高"
        mock_dedup.check_and_add.return_value = True
        executor = MagicMock()
        executor.execute.return_value = MagicMock(status=MagicMock(value="success"))
        proc._executor = executor
        proc.llm_handler.agent_identity = None

        log = {
            "_id": "hn1",
            "_index": "idx",
            "_source": {
                "@timestamp": "2026-03-28T12:00:00Z",
                "event_type": "dns",
                "src_ip": "192.168.1.100",
                "dest_ip": "8.8.8.8",
                "src_hostname": "workstation.local",
                "dest_hostname": "",
            },
        }
        proc._maybe_create_issue(log, {"threat_level": "高", "summary": "DNS exfil"})

        req = executor.execute.call_args[0][0]
        body = req.params["body"]
        title = req.params["title"]
        assert "workstation.local" in title
        assert "8.8.8.8" in title
        assert "workstation.local" in body

    @patch("src.processor._issue_dedup")
    @patch("src.processor.config")
    def test_issue_body_includes_security_hint_and_recommendation(self, mock_cfg, mock_dedup):
        """Issue body includes optional security_hint and recommendation fields."""
        proc = self._make_processor()
        mock_cfg.GIT_ENABLED = True
        mock_cfg.GIT_AUTO_ISSUE = True
        mock_cfg.GIT_ISSUE_THREAT_THRESHOLD = "高"
        mock_dedup.check_and_add.return_value = True
        executor = MagicMock()
        executor.execute.return_value = MagicMock(status=MagicMock(value="success"))
        proc._executor = executor
        proc.llm_handler.agent_identity = None

        log = {
            "_id": "hint1",
            "_index": "idx",
            "_source": {
                "@timestamp": "2026-03-28T12:00:00Z",
                "event_type": "alert",
                "src_ip": "10.0.0.1",
                "dest_ip": "10.0.0.2",
            },
        }
        parsed = {
            "threat_level": "高",
            "summary": "Trojan activity detected",
            "security_hint": "Block outbound traffic to C2 server",
            "recommendation": "Isolate affected host immediately",
        }
        proc._maybe_create_issue(log, parsed)

        req = executor.execute.call_args[0][0]
        body = req.params["body"]
        assert "Block outbound traffic to C2 server" in body
        assert "Isolate affected host immediately" in body
        assert "安全提示" in body
        assert "建议措施" in body


class TestProcessBatchDailyReportPause:
    """process_batch returns immediately while a daily report is running."""

    def _make_processor(self):
        with patch("src.processor.ESClient"):
            from src.processor import LogProcessor
            proc = LogProcessor()
            proc.es_client = MagicMock()
            proc.llm_handler = MagicMock()
            return proc

    def test_skips_when_daily_report_active(self):
        from src.config import config
        proc = self._make_processor()
        config.set_daily_report_active()
        try:
            result = proc.process_batch("test-index")
            assert result["processed"] == 0
            assert result["fetched"] == 0
            proc.es_client.get_unprocessed_docs.assert_not_called()
        finally:
            config.clear_daily_report_active()

    def test_runs_when_daily_report_inactive(self):
        from src.config import config
        proc = self._make_processor()
        assert not config.daily_report_active

        proc.es_client.get_unprocessed_docs.return_value = iter([])
        proc.es_client.count_unprocessed_docs.return_value = 0
        result = proc.process_batch("test-index")
        assert result["processed"] == 0
        proc.es_client.get_unprocessed_docs.assert_called_once()


class TestMaybeEscalate:
    """Test _maybe_escalate escalation processing."""

    def _make_processor(self):
        with patch("src.processor.ESClient"):
            from src.processor import LogProcessor
            proc = LogProcessor()
            proc.es_client = MagicMock()
            proc.llm_handler = MagicMock()
            return proc

    def _sample_log(self):
        return {
            "_index": "suricata-eve-2026.04.01",
            "_id": "esc001",
            "_source": {
                "@timestamp": "2026-04-01T10:00:00Z",
                "event_type": "alert",
                "src_ip": "10.0.0.1",
                "dest_ip": "10.0.0.2",
                "src_hostname": "attacker.example.com",
                "dest_hostname": "victim.lan",
                "proto": "tcp",
                "alert": {"signature": "ET MALWARE Test", "severity": 1},
            },
        }

    @patch("src.processor.config")
    def test_disabled_returns_none(self, mock_cfg):
        proc = self._make_processor()
        mock_cfg.ESCALATION_ENABLED = False
        result = proc._maybe_escalate(
            self._sample_log(), {"threat_level": "高"}, "initial advice"
        )
        assert result is None

    @patch("src.processor.config")
    def test_no_model_returns_none(self, mock_cfg):
        proc = self._make_processor()
        mock_cfg.ESCALATION_ENABLED = True
        mock_cfg.ESCALATION_MODEL = ""
        result = proc._maybe_escalate(
            self._sample_log(), {"threat_level": "高"}, "initial advice"
        )
        assert result is None

    @patch("src.processor.config")
    def test_below_threshold_returns_none(self, mock_cfg):
        proc = self._make_processor()
        mock_cfg.ESCALATION_ENABLED = True
        mock_cfg.ESCALATION_MODEL = "gpt-4.1-mini"
        mock_cfg.ESCALATION_THREAT_THRESHOLD = "高"
        result = proc._maybe_escalate(
            self._sample_log(), {"threat_level": "低"}, "initial advice"
        )
        assert result is None

    @patch("src.processor.config")
    def test_missing_profile_returns_none(self, mock_cfg):
        proc = self._make_processor()
        mock_cfg.ESCALATION_ENABLED = True
        mock_cfg.ESCALATION_MODEL = "nonexistent-model"
        mock_cfg.ESCALATION_THREAT_THRESHOLD = "中"
        mock_cfg.MODEL_PROFILES = {}
        mock_cfg.ESCALATION_INCLUDE_RAW_FIELDS = True
        proc.llm_handler.get_memory_snapshot.return_value = []
        with patch("src.llm_prompt.build_escalation_prompt", return_value="escalation prompt"):
            result = proc._maybe_escalate(
                self._sample_log(), {"threat_level": "高"}, "initial advice"
            )
        assert result is None

    @patch("src.processor.config")
    def test_successful_escalation(self, mock_cfg):
        proc = self._make_processor()
        mock_cfg.ESCALATION_ENABLED = True
        mock_cfg.ESCALATION_MODEL = "gpt-4.1-mini"
        mock_cfg.ESCALATION_THREAT_THRESHOLD = "中"
        mock_cfg.ESCALATION_MAX_TOKENS = 4096
        mock_cfg.ESCALATION_CONTEXT_LENGTH = 65536
        mock_cfg.ESCALATION_TEMPERATURE = 0.2
        mock_cfg.ESCALATION_TOP_P = 0.9
        mock_cfg.ESCALATION_TOP_K = 40
        mock_cfg.ESCALATION_INCLUDE_RAW_FIELDS = True
        mock_cfg.MODEL_PROFILES = {"gpt-4.1-mini": MagicMock()}

        proc.llm_handler.get_memory_snapshot.return_value = ["previous event"]

        mock_backend = MagicMock()
        mock_result = MagicMock()
        mock_result.text = '{"summary": "深度分析", "threat_level": "严重", "security_hint": "hint", "recommendation": "rec"}'
        mock_result.metrics = MagicMock()
        mock_backend.generate.return_value = mock_result
        proc.llm_handler.get_backend_for_model.return_value = mock_backend
        proc.llm_handler.parse_json_sections.return_value = {
            "summary": "深度分析",
            "threat_level": "严重",
            "security_hint": "hint",
            "recommendation": "rec",
        }

        with patch("src.llm_prompt.build_escalation_prompt", return_value="escalation prompt"):
            result = proc._maybe_escalate(
                self._sample_log(), {"threat_level": "高"}, "initial advice"
            )
        assert result is not None
        assert result["escalated"] is True
        assert result["escalated_from"] == "高"
        assert result["escalated_model"] == "gpt-4.1-mini"
        assert result["threat_level"] == "严重"
        assert result["_escalation_advice"] is not None

        mock_backend.generate.assert_called_once()
        proc.llm_handler.record_metrics.assert_called_once_with(mock_result.metrics)
        proc.llm_handler.get_memory_snapshot.assert_called_once_with(
            "attacker.example.com",
            "victim.lan",
            app_proto="",
            event_type="alert",
        )

    @patch("src.processor.config")
    def test_llm_failure_returns_none(self, mock_cfg):
        proc = self._make_processor()
        mock_cfg.ESCALATION_ENABLED = True
        mock_cfg.ESCALATION_MODEL = "gpt-4.1-mini"
        mock_cfg.ESCALATION_THREAT_THRESHOLD = "中"
        mock_cfg.ESCALATION_INCLUDE_RAW_FIELDS = True
        mock_cfg.MODEL_PROFILES = {"gpt-4.1-mini": MagicMock()}

        proc.llm_handler.get_memory_snapshot.return_value = []
        mock_backend = MagicMock()
        mock_backend.generate.side_effect = RuntimeError("API error")
        proc.llm_handler.get_backend_for_model.return_value = mock_backend

        with patch("src.llm_prompt.build_escalation_prompt", return_value="escalation prompt"):
            result = proc._maybe_escalate(
                self._sample_log(), {"threat_level": "高"}, "initial advice"
            )
        assert result is None

    @patch("src.processor.config")
    def test_empty_response_returns_none(self, mock_cfg):
        proc = self._make_processor()
        mock_cfg.ESCALATION_ENABLED = True
        mock_cfg.ESCALATION_MODEL = "gpt-4.1-mini"
        mock_cfg.ESCALATION_THREAT_THRESHOLD = "中"
        mock_cfg.ESCALATION_MAX_TOKENS = 4096
        mock_cfg.ESCALATION_CONTEXT_LENGTH = 65536
        mock_cfg.ESCALATION_TEMPERATURE = 0.2
        mock_cfg.ESCALATION_TOP_P = 0.9
        mock_cfg.ESCALATION_TOP_K = 40
        mock_cfg.ESCALATION_INCLUDE_RAW_FIELDS = True
        mock_cfg.MODEL_PROFILES = {"gpt-4.1-mini": MagicMock()}

        proc.llm_handler.get_memory_snapshot.return_value = []
        mock_backend = MagicMock()
        mock_result = MagicMock()
        mock_result.text = "<think>reasoning only</think>"
        mock_result.metrics = MagicMock()
        mock_backend.generate.return_value = mock_result
        proc.llm_handler.get_backend_for_model.return_value = mock_backend

        with patch("src.llm_prompt.build_escalation_prompt", return_value="escalation prompt"):
            result = proc._maybe_escalate(
                self._sample_log(), {"threat_level": "高"}, "initial advice"
            )
        assert result is None


class TestPipelineEscalationIntegration:
    """Test that _build_update_pipeline integrates with escalation."""

    def _make_processor(self):
        with patch("src.processor.ESClient"):
            from src.processor import LogProcessor
            proc = LogProcessor()
            proc.es_client = MagicMock()
            proc.llm_handler = MagicMock()
            return proc

    def test_escalation_replaces_parsed(self):
        proc = self._make_processor()
        proc.llm_handler.generate_advice.return_value = "initial advice"
        proc.llm_handler.parse_json_sections.side_effect = [
            {"summary": "初步分析", "threat_level": "高"},
            {"summary": "深度分析", "threat_level": "严重", "security_hint": "h", "recommendation": "r"},
        ]

        mock_backend = MagicMock()
        mock_result = MagicMock()
        mock_result.text = '{"summary": "深度分析"}'
        mock_result.metrics = MagicMock()
        mock_backend.generate.return_value = mock_result
        proc.llm_handler.get_backend_for_model.return_value = mock_backend
        proc.llm_handler.get_memory_snapshot.return_value = []

        with patch("src.processor.config") as mock_cfg, \
             patch("src.llm_prompt.build_escalation_prompt", return_value="escalation prompt"):
            mock_cfg.ESCALATION_ENABLED = True
            mock_cfg.ESCALATION_MODEL = "gpt-4.1-mini"
            mock_cfg.ESCALATION_THREAT_THRESHOLD = "中"
            mock_cfg.ESCALATION_MAX_TOKENS = 4096
            mock_cfg.ESCALATION_CONTEXT_LENGTH = 65536
            mock_cfg.ESCALATION_TEMPERATURE = 0.2
            mock_cfg.ESCALATION_TOP_P = 0.9
            mock_cfg.ESCALATION_TOP_K = 40
            mock_cfg.ESCALATION_INCLUDE_RAW_FIELDS = True
            mock_cfg.MODEL_PROFILES = {"gpt-4.1-mini": MagicMock()}
            mock_cfg.GIT_ENABLED = False
            mock_cfg.CURRENT_PERF_CONFIG = None

            log = {
                "_index": "test-idx",
                "_id": "doc1",
                "_source": {
                    "event_type": "alert",
                    "src_ip": "10.0.0.1",
                    "dest_ip": "10.0.0.2",
                    "src_hostname": "a.lan",
                    "dest_hostname": "b.lan",
                },
            }
            result = proc._build_update_pipeline(log, 1700000000000)

        assert result is not None
        assert result["ai_fields"]["escalated"] is True
        assert result["ai_fields"]["threat_level"] == "严重"
        # ai_advice should be replaced with escalation model output
        assert result["ai_advice"] != "initial advice"


class TestAgentModeEscalationIntegration:
    """Test that _build_update_agent integrates with escalation."""

    def _make_processor(self):
        with patch("src.processor.ESClient"):
            from src.processor import LogProcessor
            proc = LogProcessor()
            proc.es_client = MagicMock()
            proc.llm_handler = MagicMock()
            proc._orchestrator = MagicMock()
            return proc

    def _sample_log(self):
        return {
            "_index": "suricata-eve-2026.04.01",
            "_id": "agent-esc001",
            "_source": {
                "@timestamp": "2026-04-01T12:00:00Z",
                "event_type": "alert",
                "src_ip": "10.0.0.1",
                "dest_ip": "10.0.0.2",
                "src_hostname": "attacker.example.com",
                "dest_hostname": "victim.lan",
                "proto": "tcp",
                "alert": {"signature": "ET MALWARE Agent Test", "severity": 1},
            },
        }

    def test_agent_mode_escalation(self):
        proc = self._make_processor()

        # Orchestrator returns initial analysis
        orch_result = MagicMock()
        orch_result.final_answer = '{"summary": "初步分析", "threat_level": "高"}'
        orch_result.tool_calls_made = []
        orch_result.terminated_by = "max_turns"
        proc._orchestrator.run.return_value = orch_result

        # parse_json_sections: first call for initial, second for escalated
        proc.llm_handler.parse_json_sections.side_effect = [
            {"summary": "初步分析", "threat_level": "高"},
            {"summary": "深度分析", "threat_level": "严重", "security_hint": "h", "recommendation": "r"},
        ]
        proc.llm_handler.supports_tool_use = True
        proc.llm_handler.get_memory_snapshot.return_value = []

        mock_backend = MagicMock()
        mock_result = MagicMock()
        mock_result.text = '{"summary": "深度分析", "threat_level": "严重"}'
        mock_result.metrics = MagicMock()
        mock_backend.generate.return_value = mock_result
        proc.llm_handler.get_backend_for_model.return_value = mock_backend

        with patch("src.processor.config") as mock_cfg, \
             patch("src.llm_prompt.build_escalation_prompt", return_value="escalation prompt"), \
             patch("src.llm_prompt.build_agent_system_prompt", return_value="system"), \
             patch("src.llm_prompt.build_agent_user_message", return_value="user msg"), \
             patch("src.tool_schema.capabilities_to_tools", return_value=[]):
            mock_cfg.ESCALATION_ENABLED = True
            mock_cfg.ESCALATION_MODEL = "gpt-4.1-mini"
            mock_cfg.ESCALATION_THREAT_THRESHOLD = "中"
            mock_cfg.ESCALATION_MAX_TOKENS = 4096
            mock_cfg.ESCALATION_CONTEXT_LENGTH = 65536
            mock_cfg.ESCALATION_TEMPERATURE = 0.2
            mock_cfg.ESCALATION_TOP_P = 0.9
            mock_cfg.ESCALATION_TOP_K = 40
            mock_cfg.ESCALATION_INCLUDE_RAW_FIELDS = True
            mock_cfg.MODEL_PROFILES = {"gpt-4.1-mini": MagicMock()}
            mock_cfg.GIT_ENABLED = False

            result = proc._build_update_agent(self._sample_log(), 1700000000000)

        assert result is not None
        assert result["ai_fields"]["escalated"] is True
        assert result["ai_fields"]["escalated_from"] == "高"
        assert result["ai_fields"]["threat_level"] == "严重"
        # ai_advice should be replaced with escalation output
        assert "深度分析" in result["ai_advice"]

    def test_agent_mode_memory_snapshot_passes_app_proto(self):
        proc = self._make_processor()

        orch_result = MagicMock()
        orch_result.final_answer = '{"summary": "分析", "threat_level": "中"}'
        orch_result.tool_calls_made = []
        orch_result.terminated_by = "max_turns"
        proc._orchestrator.run.return_value = orch_result

        proc.llm_handler.parse_json_sections.return_value = {
            "summary": "分析", "threat_level": "中",
        }
        proc.llm_handler.supports_tool_use = True
        proc.llm_handler.get_memory_snapshot.return_value = []

        log = self._sample_log()
        log["_source"]["app_proto"] = "http"

        with patch("src.processor.config") as mock_cfg, \
             patch("src.llm_prompt.build_agent_system_prompt", return_value="system"), \
             patch("src.llm_prompt.build_agent_user_message", return_value="user msg"), \
             patch("src.tool_schema.capabilities_to_tools", return_value=[]):
            mock_cfg.ESCALATION_ENABLED = False
            mock_cfg.GIT_ENABLED = False

            proc._build_update_agent(log, 1700000000000)

        proc.llm_handler.get_memory_snapshot.assert_called_with(
            "attacker.example.com",
            "victim.lan",
            app_proto="http",
            event_type="alert",
        )
        kwargs = proc.llm_handler.update_summary_memory.call_args.kwargs
        assert kwargs["app_proto"] == "http"
        assert kwargs["event_type"] == "alert"

    def test_agent_mode_no_escalation_when_below_threshold(self):
        proc = self._make_processor()

        orch_result = MagicMock()
        orch_result.final_answer = '{"summary": "普通分析", "threat_level": "低"}'
        orch_result.tool_calls_made = []
        orch_result.terminated_by = "max_turns"
        proc._orchestrator.run.return_value = orch_result

        proc.llm_handler.parse_json_sections.return_value = {
            "summary": "普通分析", "threat_level": "低",
        }
        proc.llm_handler.supports_tool_use = True
        proc.llm_handler.get_memory_snapshot.return_value = []

        with patch("src.processor.config") as mock_cfg, \
             patch("src.llm_prompt.build_agent_system_prompt", return_value="system"), \
             patch("src.llm_prompt.build_agent_user_message", return_value="user msg"), \
             patch("src.tool_schema.capabilities_to_tools", return_value=[]):
            mock_cfg.ESCALATION_ENABLED = True
            mock_cfg.ESCALATION_MODEL = "gpt-4.1-mini"
            mock_cfg.ESCALATION_THREAT_THRESHOLD = "高"
            mock_cfg.ESCALATION_INCLUDE_RAW_FIELDS = True
            mock_cfg.MODEL_PROFILES = {"gpt-4.1-mini": MagicMock()}
            mock_cfg.GIT_ENABLED = False

            result = proc._build_update_agent(self._sample_log(), 1700000000000)

        assert result is not None
        assert "escalated" not in result["ai_fields"]

    def test_agent_mode_escalation_disabled(self):
        proc = self._make_processor()

        orch_result = MagicMock()
        orch_result.final_answer = '{"summary": "分析", "threat_level": "严重"}'
        orch_result.tool_calls_made = []
        orch_result.terminated_by = "max_turns"
        proc._orchestrator.run.return_value = orch_result

        proc.llm_handler.parse_json_sections.return_value = {
            "summary": "分析", "threat_level": "严重",
        }
        proc.llm_handler.supports_tool_use = True
        proc.llm_handler.get_memory_snapshot.return_value = []

        with patch("src.processor.config") as mock_cfg, \
             patch("src.llm_prompt.build_agent_system_prompt", return_value="system"), \
             patch("src.llm_prompt.build_agent_user_message", return_value="user msg"), \
             patch("src.tool_schema.capabilities_to_tools", return_value=[]):
            mock_cfg.ESCALATION_ENABLED = False
            mock_cfg.GIT_ENABLED = False

            result = proc._build_update_agent(self._sample_log(), 1700000000000)

        assert result is not None
        assert "escalated" not in result["ai_fields"]
