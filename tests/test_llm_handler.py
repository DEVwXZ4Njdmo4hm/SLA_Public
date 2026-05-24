#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         test_llm_handler.py
Description:  Tests for LLM metrics calculating and text processing utilities.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations
import pytest
from unittest.mock import MagicMock
from src.llm_handler import OllamaMetrics, LLMHandler, CommPairMemory
from src.llm_backend import LLMMetrics, GenerateResult, ChatResult, ChatMessage


# ── OllamaMetrics ──────────────────────────────────────────────────────

class TestOllamaMetrics:
    def test_eval_tokens_per_sec(self):
        m = OllamaMetrics(eval_count=100, eval_duration_ns=int(2e9))
        assert m.eval_tokens_per_sec == pytest.approx(50.0)

    def test_eval_tokens_per_sec_zero_duration(self):
        m = OllamaMetrics(eval_count=100, eval_duration_ns=0)
        assert m.eval_tokens_per_sec == 0.0

    def test_prompt_tokens_per_sec(self):
        m = OllamaMetrics(prompt_eval_count=200, prompt_eval_duration_ns=int(1e9))
        assert m.prompt_tokens_per_sec == pytest.approx(200.0)

    def test_prompt_tokens_per_sec_zero_duration(self):
        m = OllamaMetrics(prompt_eval_count=100, prompt_eval_duration_ns=0)
        assert m.prompt_tokens_per_sec == 0.0

    def test_total_tokens(self):
        m = OllamaMetrics(prompt_eval_count=50, eval_count=100)
        assert m.total_tokens == 150

    def test_default_values(self):
        m = OllamaMetrics()
        assert m.model == ""
        assert m.eval_count == 0
        assert m.total_tokens == 0


# ── LLMHandler._strip_think ────────────────────────────────────────────

class TestStripThink:
    strip = staticmethod(LLMHandler._strip_think)

    def test_empty(self):
        assert self.strip("") == ""
        assert self.strip(None) == ""

    def test_no_think_tags(self):
        assert self.strip("hello world") == "hello world"

    def test_complete_think_block(self):
        text = "before <think>internal reasoning</think> after"
        assert self.strip(text) == "before  after"

    def test_unclosed_think_tag(self):
        text = "before <think>internal reasoning that never closes"
        assert self.strip(text) == "before"

    def test_orphan_close_tag(self):
        text = "some text </think> more text"
        assert self.strip(text) == "some text  more text"

    def test_multiline_think(self):
        text = "start\n<think>\nline1\nline2\n</think>\nend"
        assert self.strip(text) == "start\n\nend"

    def test_case_insensitive(self):
        text = "<THINK>hidden</THINK>visible"
        assert self.strip(text) == "visible"

    def test_think_with_attributes(self):
        text = '<think type="reasoning">hidden</think>visible'
        assert self.strip(text) == "visible"

    def test_think_only_content_yields_empty(self):
        text = "<think>This is all thinking with no actual output</think>"
        assert self.strip(text) == ""

    def test_think_only_unclosed_yields_empty(self):
        text = "<think>Only thinking content that never closes"
        assert self.strip(text) == ""


# ── LLMHandler.parse_json_sections ─────────────────────────────────────

class TestParseJsonSections:
    parse = staticmethod(LLMHandler.parse_json_sections)

    def test_empty(self):
        assert self.parse("") == {}
        assert self.parse(None) == {}

    def test_valid_english_keys(self):
        text = '{"summary": "Test", "threat_level": "高", "security_hint": "None", "recommendation": "OK"}'
        result = self.parse(text)
        assert result["summary"] == "Test"
        assert result["threat_level"] == "高"
        assert result["security_hint"] == "None"
        assert result["recommendation"] == "OK"

    def test_valid_chinese_keys(self):
        text = '{"日志简报": "测试", "威胁评分": "低", "安全提示": "无", "建议措施": "继续观察"}'
        result = self.parse(text)
        assert result["summary"] == "测试"
        assert result["threat_level"] == "低"

    def test_json_with_prefix(self):
        text = '回答：{"summary": "Test", "threat_level": "中"}'
        result = self.parse(text)
        assert result["summary"] == "Test"

    def test_json_with_markdown_fence(self):
        text = '```json\n{"summary": "Test"}\n```'
        result = self.parse(text)
        assert result["summary"] == "Test"

    def test_json_embedded_in_text(self):
        text = 'Here is my analysis: {"summary": "Attack detected", "threat_level": "严重"} end.'
        result = self.parse(text)
        assert result["summary"] == "Attack detected"

    def test_invalid_json(self):
        assert self.parse("not json at all") == {}

    def test_non_dict_json(self):
        assert self.parse("[1, 2, 3]") == {}

    def test_empty_values_skipped(self):
        text = '{"summary": "", "threat_level": "低"}'
        result = self.parse(text)
        assert "summary" not in result
        assert result["threat_level"] == "低"


# ── CommPairMemory._make_pair_key ──────────────────────────────────────

class TestMakePairKey:
    make = staticmethod(CommPairMemory._make_pair_key)

    def test_sorted_order(self):
        assert self.make("B", "A") == "A <-> B"
        assert self.make("A", "B") == "A <-> B"

    def test_same_idents(self):
        assert self.make("X", "X") == "X <-> X"

    def test_strips_whitespace(self):
        assert self.make("  A  ", "  B  ") == "A <-> B"

    def test_ip_addresses(self):
        assert self.make("10.0.0.2", "10.0.0.1") == "10.0.0.1 <-> 10.0.0.2"

    def test_hostnames(self):
        assert self.make("server.com", "client.com") == "client.com <-> server.com"


# ── LLMHandler Agent identity lifecycle ─────────────────────────────────

class TestLLMHandlerIdentityLifecycle:
    """Verify that LLMHandler bootstraps/revokes its own Agent identity."""

    def test_no_identity_without_user_db(self):
        handler = LLMHandler(user_db=None)
        assert handler.agent_identity is None
        handler.close()  # should be harmless

    def test_identity_bootstrapped_with_user_db(self, tmp_path):
        from src.auth.database import UserDB
        db = UserDB(tmp_path / "handler_id.db")
        handler = LLMHandler(user_db=db)
        assert handler.agent_identity is not None
        assert handler.agent_identity.actor_role == "Agent"
        assert handler.agent_identity.api_key != ""
        assert handler.agent_identity.key_record_id > 0
        handler.close()

    def test_close_revokes_api_key(self, tmp_path):
        from src.auth.database import UserDB
        db = UserDB(tmp_path / "handler_revoke.db")
        handler = LLMHandler(user_db=db)
        raw_key = handler.agent_identity.api_key
        assert db.verify_api_key(raw_key) is not None
        handler.close()
        assert db.verify_api_key(raw_key) is None
        assert handler.agent_identity is None

    def test_multiple_handlers_have_separate_identities(self, tmp_path):
        from src.auth.database import UserDB
        db = UserDB(tmp_path / "handler_multi.db")
        h1 = LLMHandler(user_db=db)
        h2 = LLMHandler(user_db=db)
        assert h1.agent_identity.api_key != h2.agent_identity.api_key
        # Each handler owns its own Agent user
        assert h1.agent_identity.user.id != h2.agent_identity.user.id
        # Close h1 — h2's identity should remain intact
        h1.close()
        assert db.verify_api_key(h2.agent_identity.api_key) is not None
        assert db.get_user_by_id(h2.agent_identity.user.id) is not None
        h2.close()


# ── LLMMetrics (backend-agnostic) ──────────────────────────────────────

class TestLLMMetrics:
    def test_completion_tokens_per_sec_with_native_duration(self):
        m = LLMMetrics(completion_tokens=100, completion_duration_sec=2.0)
        assert m.completion_tokens_per_sec == pytest.approx(50.0)

    def test_completion_tokens_per_sec_wallclock_fallback(self):
        m = LLMMetrics(completion_tokens=100, total_duration_sec=4.0)
        assert m.completion_tokens_per_sec == pytest.approx(25.0)

    def test_completion_tokens_per_sec_zero_duration(self):
        m = LLMMetrics(completion_tokens=100)
        assert m.completion_tokens_per_sec == 0.0

    def test_prompt_tokens_per_sec_with_native_duration(self):
        m = LLMMetrics(prompt_tokens=200, prompt_eval_duration_sec=1.0)
        assert m.prompt_tokens_per_sec == pytest.approx(200.0)

    def test_prompt_tokens_per_sec_wallclock_fallback(self):
        m = LLMMetrics(prompt_tokens=100, total_duration_sec=5.0)
        assert m.prompt_tokens_per_sec == pytest.approx(20.0)

    def test_total_tokens(self):
        m = LLMMetrics(prompt_tokens=50, completion_tokens=100)
        assert m.total_tokens == 150

    def test_default_values(self):
        m = LLMMetrics()
        assert m.model == ""
        assert m.completion_tokens == 0
        assert m.total_tokens == 0
        assert m.completion_tokens_per_sec == 0.0
        assert m.prompt_tokens_per_sec == 0.0


# ── LLMHandler backend injection ───────────────────────────────────────

class TestLLMHandlerBackendInjection:
    """Verify that LLMHandler correctly accepts and uses an injected backend."""

    def test_injected_backend_stored(self):
        mock_backend = MagicMock()
        mock_backend.backend_type = "openai"
        handler = LLMHandler(backend=mock_backend)
        assert handler.backend is mock_backend
        assert handler.backend.backend_type == "openai"

    def test_auto_creates_backend_when_none(self):
        """When no backend is provided, create_backend() is called."""
        from unittest.mock import patch
        mock_be = MagicMock()
        with patch("src.backends.create_backend", return_value=mock_be):
            handler = LLMHandler()
        assert handler.backend is mock_be

    def test_backend_property_exposed(self):
        mock_backend = MagicMock()
        handler = LLMHandler(backend=mock_backend)
        assert handler.backend is mock_backend


class TestLLMHandlerCallLlmViaBackend:
    """Verify _call_llm delegates to backend.chat() (Improvement 30.7-A)."""

    _MOCK_MESSAGES = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "user data"},
    ]

    def _make_handler(self):
        mock_backend = MagicMock()
        mock_backend.backend_type = "ollama"
        handler = LLMHandler(backend=mock_backend)
        return handler, mock_backend

    @pytest.fixture(autouse=True)
    def _patch_build_pipeline_messages(self):
        with pytest.importorskip("unittest.mock").patch(
            "src.llm_handler.build_pipeline_messages",
            return_value=self._MOCK_MESSAGES,
        ):
            yield

    def test_call_llm_uses_chat_api(self):
        """Pipeline mode should call backend.chat() instead of generate()."""
        handler, mock_backend = self._make_handler()
        mock_backend.chat.return_value = ChatResult(
            message=ChatMessage(role="assistant", content='{"summary": "Test", "threat_level": "低"}'),
            metrics=LLMMetrics(model="test", completion_tokens=50),
        )
        log_entry = {
            "event_type": "alert",
            "timestamp": "2026-01-01T00:00:00Z",
            "src_ip": "10.0.0.1",
            "dest_ip": "10.0.0.2",
            "src_hostname": "",
            "dest_hostname": "",
            "raw": '{"alert": {"signature": "test"}}',
        }
        result = handler._call_llm(log_entry)
        mock_backend.chat.assert_called_once()
        mock_backend.generate.assert_not_called()
        assert isinstance(result, str)

    def test_keep_alive_passed(self):
        """keep_alive config value should be forwarded to backend.chat()."""
        handler, mock_backend = self._make_handler()
        mock_backend.chat.return_value = ChatResult(
            message=ChatMessage(role="assistant", content='{"summary": "ok"}'),
            metrics=LLMMetrics(model="test"),
        )
        log_entry = {
            "event_type": "alert", "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2",
            "src_hostname": "", "dest_hostname": "",
        }
        handler._call_llm(log_entry)
        call_kwargs = mock_backend.chat.call_args
        assert call_kwargs.kwargs.get("keep_alive") == "5m"

    def test_call_llm_records_metrics(self):
        handler, mock_backend = self._make_handler()
        metrics = LLMMetrics(model="test", completion_tokens=42)
        mock_backend.chat.return_value = ChatResult(
            message=ChatMessage(role="assistant", content='{"summary": "ok"}'),
            metrics=metrics,
        )
        log_entry = {
            "event_type": "dns",
            "timestamp": "2026-01-01T00:00:00Z",
            "src_ip": "1.1.1.1",
            "dest_ip": "2.2.2.2",
            "src_hostname": "",
            "dest_hostname": "",
            "raw": '{"dns": {"query": "test"}}',
        }
        handler._call_llm(log_entry)
        drained = handler.drain_batch_metrics()
        assert len(drained) == 1
        assert drained[0].completion_tokens == 42

    def test_call_llm_strips_think_blocks(self):
        handler, mock_backend = self._make_handler()
        mock_backend.chat.return_value = ChatResult(
            message=ChatMessage(role="assistant", content='<think>reasoning</think>{"summary": "Clean result"}'),
            metrics=LLMMetrics(),
        )
        log_entry = {
            "event_type": "http",
            "timestamp": "2026-01-01T00:00:00Z",
            "src_ip": "10.0.0.1",
            "dest_ip": "10.0.0.2",
            "src_hostname": "",
            "dest_hostname": "",
            "raw": '{"http": {"url": "/test"}}',
        }
        result = handler._call_llm(log_entry)
        assert "<think>" not in result
        assert "Clean result" in result


class TestLLMHandlerFinetuneIntegration:
    """Verify finetune data collection in _call_llm (Improvement 30.7-D)."""

    _MOCK_MESSAGES = [
        {"role": "system", "content": "sys prompt"},
        {"role": "user", "content": "user data"},
    ]

    @pytest.fixture(autouse=True)
    def _patch_build_pipeline_messages(self):
        with pytest.importorskip("unittest.mock").patch(
            "src.llm_handler.build_pipeline_messages",
            return_value=self._MOCK_MESSAGES,
        ):
            yield

    def _make_log_entry(self):
        return {
            "event_type": "alert",
            "src_ip": "10.0.0.1", "dest_ip": "10.0.0.2",
            "src_hostname": "", "dest_hostname": "",
        }

    def test_finetune_sample_written(self, tmp_path):
        """When finetune is enabled, a sample should be written after _call_llm."""
        from tests.conftest import _fake_config
        from src.finetune_store import FinetuneStore

        db_path = tmp_path / "ft.db"
        store = FinetuneStore(db_path)
        _fake_config.FINETUNE_COLLECT_ENABLED = True
        _fake_config.FINETUNE_DB_PATH = str(db_path)

        mock_backend = MagicMock()
        mock_backend.backend_type = "ollama"
        mock_backend.chat.return_value = ChatResult(
            message=ChatMessage(role="assistant", content='{"summary":"ok","threat_level":"低"}'),
            metrics=LLMMetrics(model="test"),
        )
        handler = LLMHandler(backend=mock_backend)
        # Inject the store directly (constructor may fail due to conftest path)
        handler._finetune_store = store

        handler._call_llm(self._make_log_entry())

        samples = store.query_samples()
        assert len(samples) == 1
        assert samples[0]["system_prompt"] == "sys prompt"
        assert samples[0]["user_input"] == "user data"
        assert samples[0]["threat_level"] == "低"

        _fake_config.FINETUNE_COLLECT_ENABLED = False

    def test_finetune_disabled_no_write(self):
        """When finetune is disabled, no store should be created."""
        mock_backend = MagicMock()
        mock_backend.backend_type = "ollama"
        mock_backend.chat.return_value = ChatResult(
            message=ChatMessage(role="assistant", content='{"summary":"ok"}'),
            metrics=LLMMetrics(model="test"),
        )
        handler = LLMHandler(backend=mock_backend)
        assert handler.finetune_store is None

    def test_finetune_write_failure_does_not_break_call(self, tmp_path):
        """Finetune write failure should not affect _call_llm result."""
        mock_backend = MagicMock()
        mock_backend.backend_type = "ollama"
        mock_backend.chat.return_value = ChatResult(
            message=ChatMessage(role="assistant", content='{"summary":"ok"}'),
            metrics=LLMMetrics(model="test"),
        )
        handler = LLMHandler(backend=mock_backend)
        # Set a broken store that raises on add_sample
        broken_store = MagicMock()
        broken_store.add_sample.side_effect = RuntimeError("DB error")
        handler._finetune_store = broken_store

        result = handler._call_llm(self._make_log_entry())
        assert result == '{"summary":"ok"}'


class TestLLMHandlerCallLlmChatViaBackend:
    """Verify call_llm_chat delegates to backend.chat()."""

    def _make_handler(self):
        mock_backend = MagicMock()
        mock_backend.backend_type = "ollama"
        handler = LLMHandler(backend=mock_backend)
        return handler, mock_backend

    def test_chat_delegates_to_backend(self):
        handler, mock_backend = self._make_handler()
        mock_backend.chat.return_value = ChatResult(
            message=ChatMessage(role="assistant", content="Hello!"),
            metrics=LLMMetrics(model="test", completion_tokens=10),
        )
        messages = [{"role": "user", "content": "Hi"}]
        result = handler.call_llm_chat(messages)
        mock_backend.chat.assert_called_once()
        assert result["role"] == "assistant"
        assert result["content"] == "Hello!"

    def test_chat_with_tool_calls(self):
        handler, mock_backend = self._make_handler()
        tool_calls = [{"function": {"name": "test_fn", "arguments": "{}"}}]
        mock_backend.chat.return_value = ChatResult(
            message=ChatMessage(role="assistant", content="", tool_calls=tool_calls),
            metrics=LLMMetrics(model="test"),
        )
        result = handler.call_llm_chat([{"role": "user", "content": "Do it"}])
        assert result["tool_calls"] == tool_calls

    def test_chat_without_tool_calls_omits_key(self):
        handler, mock_backend = self._make_handler()
        mock_backend.chat.return_value = ChatResult(
            message=ChatMessage(role="assistant", content="answer"),
            metrics=LLMMetrics(),
        )
        result = handler.call_llm_chat([{"role": "user", "content": "Hi"}])
        assert "tool_calls" not in result

    def test_chat_records_metrics(self):
        handler, mock_backend = self._make_handler()
        mock_backend.chat.return_value = ChatResult(
            message=ChatMessage(role="assistant", content="ok"),
            metrics=LLMMetrics(model="test", completion_tokens=25),
        )
        handler.call_llm_chat([{"role": "user", "content": "Hi"}])
        drained = handler.drain_batch_metrics()
        assert len(drained) == 1
        assert drained[0].completion_tokens == 25

    def test_chat_attaches_metrics_to_message(self):
        handler, mock_backend = self._make_handler()
        metrics = LLMMetrics(model="test", completion_tokens=30)
        mock_backend.chat.return_value = ChatResult(
            message=ChatMessage(role="assistant", content="ok"),
            metrics=metrics,
        )
        result = handler.call_llm_chat([{"role": "user", "content": "Hi"}])
        assert result["_metrics"] is metrics

    def test_chat_strips_think_in_content(self):
        handler, mock_backend = self._make_handler()
        mock_backend.chat.return_value = ChatResult(
            message=ChatMessage(role="assistant", content="<think>x</think>Real answer"),
            metrics=LLMMetrics(),
        )
        result = handler.call_llm_chat([{"role": "user", "content": "Hi"}])
        assert "<think>" not in result["content"]
        assert "Real answer" in result["content"]


class TestLLMHandlerSupportsToolUseViaBackend:
    """Verify supports_tool_use delegates to backend.detect_tool_support()."""

    def test_profile_override_true(self):
        from tests.conftest import ModelProfile
        mock_backend = MagicMock()
        handler = LLMHandler(backend=mock_backend)
        handler._backend.detect_tool_support.return_value = False
        # Override via ModelProfile
        from tests.conftest import _fake_config
        _fake_config.MODEL_PROFILES["test-model"] = ModelProfile(supports_tool_use=True)
        assert handler.supports_tool_use is True

    def test_profile_override_false(self):
        from tests.conftest import ModelProfile
        mock_backend = MagicMock()
        handler = LLMHandler(backend=mock_backend)
        from tests.conftest import _fake_config
        _fake_config.MODEL_PROFILES["test-model"] = ModelProfile(supports_tool_use=False)
        assert handler.supports_tool_use is False

    def test_delegates_to_backend_when_profile_is_none(self):
        from tests.conftest import ModelProfile
        mock_backend = MagicMock()
        mock_backend.backend_type = "ollama"
        mock_backend.detect_tool_support.return_value = True
        handler = LLMHandler(backend=mock_backend)
        from tests.conftest import _fake_config
        _fake_config.MODEL_PROFILES["test-model"] = ModelProfile(supports_tool_use=None)
        assert handler.supports_tool_use is True
        mock_backend.detect_tool_support.assert_called_once()

    def test_returns_false_when_detection_returns_none(self):
        from tests.conftest import ModelProfile
        mock_backend = MagicMock()
        mock_backend.backend_type = "ollama"
        mock_backend.detect_tool_support.return_value = None
        handler = LLMHandler(backend=mock_backend)
        from tests.conftest import _fake_config
        _fake_config.MODEL_PROFILES["test-model"] = ModelProfile(supports_tool_use=None)
        assert handler.supports_tool_use is False

    def test_routes_to_correct_backend_for_detection(self):
        """When profile declares a different backend, detect_tool_support
        should be called on the routed backend, not the default one."""
        from tests.conftest import ModelProfile, _fake_config
        from unittest.mock import patch
        mock_default = MagicMock()
        mock_default.backend_type = "ollama"
        mock_default.detect_tool_support.return_value = False

        mock_routed = MagicMock()
        mock_routed.detect_tool_support.return_value = True

        saved = _fake_config.MODEL_PROFILES.get("test-model")
        _fake_config.MODEL_PROFILES["test-model"] = ModelProfile(
            supports_tool_use=None,
            backend_type="openai",
            backend_base_url="https://api.openai.com",
            backend_auth_token="sk-test",
        )
        try:
            handler = LLMHandler(backend=mock_default)
            with patch("src.backends.create_backend_for_model", return_value=mock_routed):
                result = handler.supports_tool_use
            assert result is True
            mock_routed.detect_tool_support.assert_called_once()
            mock_default.detect_tool_support.assert_not_called()
        finally:
            if saved is not None:
                _fake_config.MODEL_PROFILES["test-model"] = saved
            else:
                _fake_config.MODEL_PROFILES.pop("test-model", None)


class TestStopOllamaModelViaBackend:
    """Verify stop_ollama_model delegates to backend when provided."""

    def test_delegates_to_backend_stop_model(self):
        from src.llm_handler import stop_ollama_model
        mock_backend = MagicMock()
        mock_backend.stop_model.return_value = True
        assert stop_ollama_model("test-model", backend=mock_backend) is True
        mock_backend.stop_model.assert_called_once_with("test-model")

    def test_backend_stop_returns_false(self):
        from src.llm_handler import stop_ollama_model
        mock_backend = MagicMock()
        mock_backend.stop_model.return_value = False
        assert stop_ollama_model("test-model", backend=mock_backend) is False

    def test_empty_model_returns_false(self):
        from src.llm_handler import stop_ollama_model
        mock_backend = MagicMock()
        assert stop_ollama_model("", backend=mock_backend) is False
        mock_backend.stop_model.assert_not_called()


# ═══════════════════════════════════════════════════════════════════════
# get_backend_for_model — per-model backend routing in LLMHandler
# ═══════════════════════════════════════════════════════════════════════

class TestGetBackendForModel:
    """Verify ``LLMHandler.get_backend_for_model`` routing logic."""

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

    def test_unknown_model_returns_default(self, fake_config):
        from src.llm_handler import LLMHandler
        mock_backend = MagicMock()
        mock_backend.backend_type = "ollama"
        handler = LLMHandler(backend=mock_backend)
        result = handler.get_backend_for_model("nonexistent-model")
        assert result is mock_backend

    def test_same_backend_type_returns_default(self, fake_config):
        from src.llm_handler import LLMHandler
        from tests.conftest import ModelProfile
        mock_backend = MagicMock()
        mock_backend.backend_type = "ollama"
        fake_config.MODEL_PROFILES["local"] = ModelProfile(
            name="local", backend_type="ollama", backend_base_url="",
        )
        handler = LLMHandler(backend=mock_backend)
        result = handler.get_backend_for_model("local")
        assert result is mock_backend

    def test_different_backend_type_routes(self, fake_config):
        from src.llm_handler import LLMHandler
        from tests.conftest import ModelProfile
        mock_backend = MagicMock()
        mock_backend.backend_type = "ollama"
        fake_config.MODEL_PROFILES["gpt-4.1-mini"] = ModelProfile(
            name="gpt-4.1-mini",
            backend_type="openai",
            backend_base_url="https://api.openai.com",
            backend_auth_token="sk-test",
        )
        handler = LLMHandler(backend=mock_backend)
        result = handler.get_backend_for_model("gpt-4.1-mini")
        assert result is not mock_backend
        assert result.backend_type == "openai"

    def test_custom_base_url_routes(self, fake_config):
        from src.llm_handler import LLMHandler
        from tests.conftest import ModelProfile
        mock_backend = MagicMock()
        mock_backend.backend_type = "ollama"
        fake_config.MODEL_PROFILES["remote-ollama"] = ModelProfile(
            name="remote-ollama",
            backend_type="ollama",
            backend_base_url="http://remote:11434",
        )
        handler = LLMHandler(backend=mock_backend)
        result = handler.get_backend_for_model("remote-ollama")
        assert result is not mock_backend
        assert result.backend_type == "ollama"
