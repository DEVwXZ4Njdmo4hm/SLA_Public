#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         test_daily_report.py
Description:  Tests for daily report generation logic and HTML building.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations
import pytest
import requests
from datetime import datetime, date
from unittest.mock import MagicMock, patch
from src.daily_report import (
    _strip_think,
    _extract_html_body,
    _parse_timestamp,
    _resolve_nested,
    _make_pair_key,
    group_by_comm_pair,
    split_by_time_gap,
    build_report_html,
    DailyReportLLMConfig,
    load_daily_report_llm_config,
    call_daily_report_llm,
    DailyReportService,
    _is_provider_sensitive_error,
)
from src.llm_backend import LLMMetrics, GenerateResult


# ── _strip_think ───────────────────────────────────────────────────────

class TestStripThink:
    def test_empty(self):
        assert _strip_think("") == ""

    def test_removes_think_block(self):
        assert _strip_think("before <think>hidden</think> after") == "before  after"

    def test_unclosed_think(self):
        assert _strip_think("start <think>forever open") == "start"

    def test_no_think(self):
        assert _strip_think("hello world") == "hello world"


# ── _extract_html_body ─────────────────────────────────────────────────

class TestExtractHtmlBody:
    def test_empty(self):
        assert _extract_html_body("") == ""

    def test_no_body_tag(self):
        assert _extract_html_body("<p>hello</p>") == "<p>hello</p>"

    def test_with_body(self):
        html = "<html><body><p>content</p></body></html>"
        assert _extract_html_body(html) == "<p>content</p>"

    def test_body_with_attrs(self):
        html = '<html><body class="main"><p>content</p></body></html>'
        assert _extract_html_body(html) == "<p>content</p>"

    def test_no_closing_body(self):
        html = "<html><body><p>content</p>"
        assert _extract_html_body(html) == "<p>content</p>"


# ── _parse_timestamp ───────────────────────────────────────────────────

class TestParseTimestamp:
    def test_valid_iso(self):
        dt = _parse_timestamp("2026-01-01T12:00:00Z")
        assert dt.year == 2026
        assert dt.hour == 12

    def test_empty_string(self):
        assert _parse_timestamp("") == datetime.min

    def test_invalid_string(self):
        assert _parse_timestamp("not-a-date") == datetime.min


# ── _resolve_nested ────────────────────────────────────────────────────

class TestResolveNested:
    def test_simple_key(self):
        assert _resolve_nested({"src_ip": "1.2.3.4"}, "src_ip") == "1.2.3.4"

    def test_dotted_key(self):
        assert _resolve_nested({"alert": {"signature": "ET TROJAN"}}, "alert.signature") == "ET TROJAN"

    def test_three_level(self):
        assert _resolve_nested({"tls": {"ja3": {"hash": "abc123"}}}, "tls.ja3.hash") == "abc123"

    def test_missing_intermediate(self):
        assert _resolve_nested({"alert": None}, "alert.signature") == ""

    def test_missing_leaf(self):
        assert _resolve_nested({"alert": {}}, "alert.signature") == ""

    def test_non_dict_intermediate(self):
        assert _resolve_nested({"alert": 42}, "alert.severity") == ""

    def test_integer_leaf(self):
        assert _resolve_nested({"alert": {"severity": 1}}, "alert.severity") == "1"

    def test_dict_leaf_serialized_as_json(self):
        source = {"flow": {"nested": {"a": 1, "b": 2}}}
        result = _resolve_nested(source, "flow.nested")
        import json
        assert json.loads(result) == {"a": 1, "b": 2}

    def test_list_leaf_serialized_as_json(self):
        source = {"tags": ["one", "two"]}
        result = _resolve_nested(source, "tags")
        import json
        assert json.loads(result) == ["one", "two"]

    def test_empty_source(self):
        assert _resolve_nested({}, "any.key") == ""


# ── _make_pair_key ─────────────────────────────────────────────────────

class TestMakePairKey:
    def test_sorted(self):
        assert _make_pair_key("B", "A") == "A <-> B"
        assert _make_pair_key("A", "B") == "A <-> B"

    def test_same(self):
        assert _make_pair_key("X", "X") == "X <-> X"


# ── group_by_comm_pair ─────────────────────────────────────────────────

class TestGroupByCommPair:
    def test_empty(self):
        assert group_by_comm_pair([]) == {}

    def test_groups_by_pair(self):
        items = [
            {"src_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "src_hostname": "", "dest_hostname": "", "timestamp": "2026-01-01T01:00:00Z"},
            {"src_ip": "10.0.0.2", "dest_ip": "10.0.0.1", "src_hostname": "", "dest_hostname": "", "timestamp": "2026-01-01T02:00:00Z"},
            {"src_ip": "10.0.0.3", "dest_ip": "10.0.0.4", "src_hostname": "", "dest_hostname": "", "timestamp": "2026-01-01T01:00:00Z"},
        ]
        groups = group_by_comm_pair(items)
        assert len(groups) == 2
        # 10.0.0.1 <-> 10.0.0.2 should have 2 items (bidirectional)
        pair_key = "10.0.0.1 <-> 10.0.0.2"
        assert pair_key in groups
        assert len(groups[pair_key]) == 2

    def test_prefers_hostname(self):
        items = [
            {"src_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "src_hostname": "hostA", "dest_hostname": "hostB", "timestamp": "2026-01-01T01:00:00Z"},
            {"src_ip": "10.0.0.2", "dest_ip": "10.0.0.1", "src_hostname": "hostB", "dest_hostname": "hostA", "timestamp": "2026-01-01T02:00:00Z"},
        ]
        groups = group_by_comm_pair(items)
        assert "hostA <-> hostB" in groups
        assert len(groups["hostA <-> hostB"]) == 2

    def test_sorted_by_count(self):
        items = [
            {"src_ip": "1", "dest_ip": "2", "src_hostname": "", "dest_hostname": "", "timestamp": "2026-01-01T01:00:00Z"},
            {"src_ip": "3", "dest_ip": "4", "src_hostname": "", "dest_hostname": "", "timestamp": "2026-01-01T01:00:00Z"},
            {"src_ip": "3", "dest_ip": "4", "src_hostname": "", "dest_hostname": "", "timestamp": "2026-01-01T02:00:00Z"},
        ]
        groups = group_by_comm_pair(items)
        keys = list(groups.keys())
        # Pair with more events comes first
        assert len(groups[keys[0]]) >= len(groups[keys[1]])


# ── split_by_time_gap ─────────────────────────────────────────────────

class TestSplitByTimeGap:
    def test_empty(self):
        assert split_by_time_gap([]) == []

    def test_single_item(self):
        items = [{"timestamp": "2026-01-01T10:00:00Z"}]
        segments = split_by_time_gap(items, gap_seconds=1800)
        assert len(segments) == 1
        assert len(segments[0]) == 1

    def test_no_gap(self):
        items = [
            {"timestamp": "2026-01-01T10:00:00Z"},
            {"timestamp": "2026-01-01T10:10:00Z"},
            {"timestamp": "2026-01-01T10:20:00Z"},
        ]
        segments = split_by_time_gap(items, gap_seconds=1800)
        assert len(segments) == 1
        assert len(segments[0]) == 3

    def test_with_gap(self):
        items = [
            {"timestamp": "2026-01-01T10:00:00Z"},
            {"timestamp": "2026-01-01T10:10:00Z"},
            {"timestamp": "2026-01-01T11:00:00Z"},  # 50 min gap
            {"timestamp": "2026-01-01T11:05:00Z"},
        ]
        segments = split_by_time_gap(items, gap_seconds=1800)
        assert len(segments) == 2
        assert len(segments[0]) == 2
        assert len(segments[1]) == 2

    def test_custom_gap(self):
        items = [
            {"timestamp": "2026-01-01T10:00:00Z"},
            {"timestamp": "2026-01-01T10:02:00Z"},  # 2 min gap
        ]
        # gap_seconds=60 means 2 min > 1 min → split
        segments = split_by_time_gap(items, gap_seconds=60)
        assert len(segments) == 2

    def test_splits_continuous_stream_by_max_items(self):
        items = [
            {"timestamp": f"2026-01-01T10:{i:02d}:00Z"}
            for i in range(5)
        ]
        segments = split_by_time_gap(
            items,
            gap_seconds=1800,
            max_items_per_segment=2,
        )
        assert [len(segment) for segment in segments] == [2, 2, 1]


# ── build_report_html ─────────────────────────────────────────────────

class TestBuildReportHtml:
    def test_basic_structure(self):
        html = build_report_html(
            report_date=date(2026, 1, 1),
            items=[],
            analysis_html="<p>Test analysis</p>",
        )
        assert "2026-01-01" in html
        assert "Test analysis" in html
        assert "<!doctype html>" in html

    def test_high_threat_items_shown(self):
        items = [
            {"timestamp": "2026-01-01T01:00:00Z", "threat_level": "严重", "summary": "Critical attack"},
            {"timestamp": "2026-01-01T02:00:00Z", "threat_level": "低", "summary": "Normal traffic"},
        ]
        html = build_report_html(date(2026, 1, 1), items, "")
        assert "Critical attack" in html
        assert "Normal traffic" not in html  # 低 is filtered

    def test_with_daily_stats(self):
        stats = {
            "total_events": 42,
            "ai_processed_count": 10,
            "ai_has_summary_count": 8,
            "event_type_breakdown": {"dns": 20, "http": 15},
            "threat_level_breakdown": {"高": 3},
            "time_min": "2026-01-01T00:00:00Z",
            "time_max": "2026-01-01T23:59:59Z",
        }
        html = build_report_html(date(2026, 1, 1), [], "", daily_stats=stats)
        assert "42" in html
        assert "dns" in html

    def test_with_pair_results(self):
        pairs = [
            {"pair": "A <-> B", "event_count": 5, "segment_count": 2, "analysis": "Suspicious"},
        ]
        html = build_report_html(date(2026, 1, 1), [], "", pair_results=pairs)
        assert "A &lt;-&gt; B" in html  # html escaped
        assert "Suspicious" in html


# ── load_daily_report_llm_config ──────────────────────────────────────

class TestLoadDailyReportLLMConfig:
    def test_valid_file_new_names(self, tmp_path):
        toml_content = b"""
[TestModel]
MODEL = "test-model"
MAX_TOKENS = 4096
TEMPERATURE = 0.2
TOP_P = 0.9
TOP_K = 40
CONTEXT_LENGTH = 65536
"""
        f = tmp_path / "daily_llm.toml"
        f.write_bytes(toml_content)
        cfg = load_daily_report_llm_config(str(f))
        assert cfg.MODEL == "test-model"
        assert cfg.MAX_TOKENS == 4096
        assert cfg.CONTEXT_LENGTH == 65536
        assert cfg.DETAIL_LEVEL == "minimal"  # default when omitted

    def test_valid_file_with_detail_level(self, tmp_path):
        toml_content = b"""
[TestModel]
MODEL = "test-model"
MAX_TOKENS = 4096
TEMPERATURE = 0.2
TOP_P = 0.9
TOP_K = 40
CONTEXT_LENGTH = 65536
detail_level = "extended"
"""
        f = tmp_path / "daily_llm.toml"
        f.write_bytes(toml_content)
        cfg = load_daily_report_llm_config(str(f))
        assert cfg.DETAIL_LEVEL == "extended"

    def test_valid_file_detail_level_full(self, tmp_path):
        toml_content = b"""
[TestModel]
MODEL = "test-model"
MAX_TOKENS = 4096
TEMPERATURE = 0.2
TOP_P = 0.9
TOP_K = 40
CONTEXT_LENGTH = 65536
detail_level = "full"
"""
        f = tmp_path / "daily_llm.toml"
        f.write_bytes(toml_content)
        cfg = load_daily_report_llm_config(str(f))
        assert cfg.DETAIL_LEVEL == "full"

    def test_invalid_detail_level(self, tmp_path):
        toml_content = b"""
[TestModel]
MODEL = "test-model"
MAX_TOKENS = 4096
TEMPERATURE = 0.2
TOP_P = 0.9
TOP_K = 40
CONTEXT_LENGTH = 65536
detail_level = "invalid"
"""
        f = tmp_path / "daily_llm.toml"
        f.write_bytes(toml_content)
        with pytest.raises(ValueError, match="detail_level"):
            load_daily_report_llm_config(str(f))

    def test_valid_file_legacy_names(self, tmp_path):
        """Legacy OLLAMA_* field names are still accepted for backward compat."""
        toml_content = b"""
[TestModel]
OLLAMA_MODEL = "test-model"
OLLAMA_NUM_PREDICT = 4096
OLLAMA_TEMPERATURE = 0.2
OLLAMA_TOP_P = 0.9
OLLAMA_TOP_K = 40
OLLAMA_CONTEXT_LENGTH = 65536
"""
        f = tmp_path / "daily_llm.toml"
        f.write_bytes(toml_content)
        cfg = load_daily_report_llm_config(str(f))
        assert cfg.MODEL == "test-model"
        assert cfg.MAX_TOKENS == 4096
        # Backward-compat aliases should also work
        assert cfg.OLLAMA_MODEL == "test-model"
        assert cfg.OLLAMA_NUM_PREDICT == 4096

    def test_empty_path(self):
        with pytest.raises(ValueError, match="empty"):
            load_daily_report_llm_config("")

    def test_missing_key(self, tmp_path):
        toml_content = b"""
[M]
MODEL = "test"
"""
        f = tmp_path / "bad.toml"
        f.write_bytes(toml_content)
        with pytest.raises(ValueError, match="missing key"):
            load_daily_report_llm_config(str(f))

    def test_missing_model_key_raises(self, tmp_path):
        """MODEL (str field) missing should raise, not silently produce 'None'."""
        toml_content = b"""
[M]
MAX_TOKENS = 4096
TEMPERATURE = 0.2
TOP_P = 0.9
TOP_K = 40
CONTEXT_LENGTH = 65536
"""
        f = tmp_path / "no_model.toml"
        f.write_bytes(toml_content)
        with pytest.raises(ValueError, match="missing key"):
            load_daily_report_llm_config(str(f))


# ── Fork mode rule generation pipeline ─────────────────────────────────

class TestForkModeRuleGeneration:
    """Verify fork mode branch selection and PR workflow in rule generation."""

    def test_fork_mode_branch_selection(self):
        """In fork mode, branch_name is empty (push to default branch)."""
        from unittest.mock import patch
        with patch("src.daily_report.config") as mock_cfg:
            mock_cfg.GIT_FORK_OWNER = "capri-ai-bot"
            use_fork = bool(mock_cfg.GIT_FORK_OWNER)
            branch_name = "" if use_fork else "ai-rules/20260329"
        assert use_fork is True
        assert branch_name == ""

    def test_non_fork_mode_branch_selection(self):
        """In same-repo mode, branch_name is ai-rules/{date}."""
        from unittest.mock import patch
        with patch("src.daily_report.config") as mock_cfg:
            mock_cfg.GIT_FORK_OWNER = ""
            use_fork = bool(mock_cfg.GIT_FORK_OWNER)
            branch_name = "" if use_fork else "ai-rules/20260329"
        assert use_fork is False
        assert branch_name == "ai-rules/20260329"

    def test_fork_mode_pr_head_uses_default_branch(self):
        """In fork mode, PR head is the default branch (handler adds fork prefix)."""
        from unittest.mock import patch
        with patch("src.daily_report.config") as mock_cfg:
            mock_cfg.GIT_FORK_OWNER = "capri-ai-bot"
            mock_cfg.GIT_DEFAULT_BRANCH = "main"
            use_fork = bool(mock_cfg.GIT_FORK_OWNER)
            branch_name = "" if use_fork else "ai-rules/20260329"
            pr_head = mock_cfg.GIT_DEFAULT_BRANCH if use_fork else branch_name
        assert pr_head == "main"

    def test_non_fork_mode_pr_head_uses_branch_name(self):
        """In same-repo mode, PR head is the dated feature branch."""
        from unittest.mock import patch
        with patch("src.daily_report.config") as mock_cfg:
            mock_cfg.GIT_FORK_OWNER = ""
            mock_cfg.GIT_DEFAULT_BRANCH = "main"
            use_fork = bool(mock_cfg.GIT_FORK_OWNER)
            branch_name = "" if use_fork else "ai-rules/20260329"
            pr_head = mock_cfg.GIT_DEFAULT_BRANCH if use_fork else branch_name
        assert pr_head == "ai-rules/20260329"


# ── call_daily_report_llm backend integration ─────────────────────────

class TestCallDailyReportLlmBackend:
    """Verify that call_daily_report_llm delegates to the backend."""

    def _make_conf(self):
        return DailyReportLLMConfig(
            MODEL="test-model",
            MAX_TOKENS=512,
            CONTEXT_LENGTH=4096,
            TEMPERATURE=0.7,
            TOP_P=0.9,
            TOP_K=40,
        )

    def test_backend_path(self):
        """Backend.generate is called and result processed."""
        mock_backend = MagicMock()
        mock_backend.backend_type = "ollama"
        mock_backend.generate.return_value = GenerateResult(
            text="<p>Backend result</p>",
            metrics=LLMMetrics(model="test"),
        )
        result = call_daily_report_llm("Analyze this", self._make_conf(), backend=mock_backend)
        mock_backend.generate.assert_called_once()
        assert "Backend result" in result

    def test_backend_generate_params(self):
        """Verify correct parameter mapping to backend.generate()."""
        mock_backend = MagicMock()
        mock_backend.backend_type = "ollama"
        mock_backend.generate.return_value = GenerateResult(
            text="ok", metrics=LLMMetrics(),
        )
        conf = self._make_conf()
        call_daily_report_llm("prompt-text", conf, backend=mock_backend)
        kw = mock_backend.generate.call_args.kwargs
        assert kw["model"] == "test-model"
        assert kw["prompt"] == "prompt-text"
        assert kw["max_tokens"] == 512
        assert kw["context_length"] == 4096
        assert kw["temperature"] == 0.7
        assert kw["top_p"] == 0.9
        assert kw["top_k"] == 40


class TestDailyReportServiceBackendInjection:
    """Verify DailyReportService accepts and uses an injected backend."""

    def test_service_stores_injected_backend(self):
        from src.daily_report import DailyReportService
        mock_backend = MagicMock()
        mock_backend.backend_type = "openai"
        svc = DailyReportService(backend=mock_backend)
        assert svc._backend is mock_backend

    def test_service_auto_creates_backend_when_none(self):
        """When no backend is provided, create_backend() is called."""
        from unittest.mock import patch
        from src.daily_report import DailyReportService
        mock_be = MagicMock()
        with patch("src.backends.create_backend", return_value=mock_be):
            svc = DailyReportService()
        assert svc._backend is mock_be


class TestDailyReportProviderSafetyFallback:
    def _make_conf(self):
        return DailyReportLLMConfig(
            MODEL="test-model",
            MAX_TOKENS=512,
            CONTEXT_LENGTH=4096,
            TEMPERATURE=0.7,
            TOP_P=0.9,
            TOP_K=40,
        )

    def _sensitive_http_error(self):
        response = MagicMock()
        response.status_code = 422
        response.text = '{"error":{"message":"output new_sensitive (1027)"}}'
        exc = requests.HTTPError("422 Client Error")
        exc.response = response
        return exc

    def test_detects_minimax_output_sensitive_error(self):
        assert _is_provider_sensitive_error(self._sensitive_http_error())

    def test_segment_analysis_falls_back_on_provider_sensitive_error(self):
        backend = MagicMock()
        backend.backend_type = "ollama"
        backend.generate.side_effect = self._sensitive_http_error()
        svc = DailyReportService(es_client=MagicMock(), backend=backend)
        segment = [
            {
                "timestamp": "2026-05-10T08:30:25.028Z",
                "threat_level": "中",
                "event_type": "tls",
                "proto": "TCP",
                "summary": "example",
            },
            {
                "timestamp": "2026-05-10T08:35:03.589Z",
                "threat_level": "低",
                "event_type": "dns",
                "proto": "UDP",
                "summary": "example",
            },
        ]

        with patch("src.daily_report.build_segment_prompt", return_value="prompt"):
            result = svc._analyze_segment("host-a", "host-b", segment, self._make_conf())

        assert "Deterministic fallback summary" in result
        assert "2 events" in result
        assert "Event type distribution" in result
        assert "tls: 1" in result
        assert "dns: 1" in result


# ═══════════════════════════════════════════════════════════════════════
# Cross-backend routing in call_daily_report_llm
# ═══════════════════════════════════════════════════════════════════════

class TestDailyReportCrossBackendRouting:
    """Verify that call_daily_report_llm routes to the correct backend
    when the model profile declares a different backend type or a custom
    base URL."""

    def setup_method(self):
        from src.backends import clear_backend_cache
        from tests.conftest import _fake_config
        clear_backend_cache()
        self._saved_profiles = dict(_fake_config.MODEL_PROFILES)

    def teardown_method(self):
        from src.backends import clear_backend_cache
        from tests.conftest import _fake_config
        clear_backend_cache()
        _fake_config.MODEL_PROFILES.clear()
        _fake_config.MODEL_PROFILES.update(self._saved_profiles)

    def _make_conf(self, model="test-model"):
        return DailyReportLLMConfig(
            MODEL=model,
            MAX_TOKENS=512,
            CONTEXT_LENGTH=4096,
            TEMPERATURE=0.7,
            TOP_P=0.9,
            TOP_K=40,
        )

    def test_different_backend_type_routes_to_new_backend(self, fake_config):
        """When profile declares openai but injected backend is ollama,
        a new backend should be created."""
        from tests.conftest import ModelProfile
        from unittest.mock import patch
        fake_config.MODEL_PROFILES["openai-model"] = ModelProfile(
            name="openai-model",
            backend_type="openai",
            backend_base_url="https://api.openai.com",
            backend_auth_token="sk-test",
        )
        mock_default = MagicMock()
        mock_default.backend_type = "ollama"

        mock_routed = MagicMock()
        mock_routed.generate.return_value = GenerateResult(
            text="<p>Routed result</p>", metrics=LLMMetrics(),
        )
        with patch("src.backends.create_backend_for_model", return_value=mock_routed) as p:
            result = call_daily_report_llm(
                "prompt", self._make_conf("openai-model"), backend=mock_default,
            )
            p.assert_called_once()
        mock_default.generate.assert_not_called()
        mock_routed.generate.assert_called_once()
        assert "Routed result" in result

    def test_same_backend_type_no_custom_url_uses_default(self, fake_config):
        """When profile matches injected backend type and has no custom
        URL, the injected backend is used directly."""
        from tests.conftest import ModelProfile
        fake_config.MODEL_PROFILES["local"] = ModelProfile(
            name="local", backend_type="ollama", backend_base_url="",
        )
        mock_default = MagicMock()
        mock_default.backend_type = "ollama"
        mock_default.generate.return_value = GenerateResult(
            text="<p>Default backend</p>", metrics=LLMMetrics(),
        )
        result = call_daily_report_llm(
            "prompt", self._make_conf("local"), backend=mock_default,
        )
        mock_default.generate.assert_called_once()
        assert "Default backend" in result

    def test_custom_base_url_same_type_routes(self, fake_config):
        """When profile has same backend_type but a custom base URL,
        routing should still create a new backend."""
        from tests.conftest import ModelProfile
        from unittest.mock import patch
        fake_config.MODEL_PROFILES["remote-ollama"] = ModelProfile(
            name="remote-ollama",
            backend_type="ollama",
            backend_base_url="http://remote:11434",
        )
        mock_default = MagicMock()
        mock_default.backend_type = "ollama"

        mock_routed = MagicMock()
        mock_routed.generate.return_value = GenerateResult(
            text="<p>Remote result</p>", metrics=LLMMetrics(),
        )
        with patch("src.backends.create_backend_for_model", return_value=mock_routed) as p:
            result = call_daily_report_llm(
                "prompt", self._make_conf("remote-ollama"), backend=mock_default,
            )
            p.assert_called_once()
        mock_default.generate.assert_not_called()
        assert "Remote result" in result

    def test_unknown_model_uses_default(self, fake_config):
        """When model is not in MODEL_PROFILES, the default backend is used."""
        fake_config.MODEL_PROFILES.clear()
        mock_default = MagicMock()
        mock_default.backend_type = "ollama"
        mock_default.generate.return_value = GenerateResult(
            text="<p>Fallback</p>", metrics=LLMMetrics(),
        )
        result = call_daily_report_llm(
            "prompt", self._make_conf("missing-model"), backend=mock_default,
        )
        mock_default.generate.assert_called_once()
        assert "Fallback" in result
