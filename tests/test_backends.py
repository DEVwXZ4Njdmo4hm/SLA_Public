#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         test_backends.py
Description:  Unit tests for LLM backend implementations and factory wiring.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import json
import logging
from unittest.mock import patch, MagicMock

import pytest
import requests

from src.llm_backend import (
    LLMBackend,
    LLMMetrics,
    GenerateResult,
    ChatResult,
    ChatMessage,
)
from src.backends.ollama import OllamaBackend, _template_mentions_tools
from src.backends.openai_compat import OpenAICompatBackend


# ═══════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════

def _mock_response(json_data, status_code=200):
    """Return a ``MagicMock`` that mimics ``requests.Response``."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data
    resp.raise_for_status.return_value = None
    return resp


def _mock_http_error_response(status_code=500):
    resp = MagicMock()
    resp.status_code = status_code
    resp.ok = False
    resp.text = ""
    resp.raise_for_status.side_effect = requests.HTTPError(
        response=resp,
    )
    return resp


# ═══════════════════════════════════════════════════════════════════════
# OllamaBackend
# ═══════════════════════════════════════════════════════════════════════

class TestOllamaBackendProtocol:
    def test_conforms_to_protocol(self):
        backend = OllamaBackend("http://localhost:11434")
        assert isinstance(backend, LLMBackend)

    def test_backend_type(self):
        assert OllamaBackend("http://localhost:11434").backend_type == "ollama"


class TestOllamaBackendInit:
    def test_strips_trailing_slash(self):
        b = OllamaBackend("http://localhost:11434/")
        assert b._base_url == "http://localhost:11434"

    def test_no_auth_header_by_default(self):
        b = OllamaBackend("http://localhost:11434")
        assert "Authorization" not in b._headers

    def test_auth_token_sets_bearer(self):
        b = OllamaBackend("http://localhost:11434", auth_token="tok123")
        assert b._headers["Authorization"] == "Bearer tok123"


class TestOllamaGenerate:
    OLLAMA_RESPONSE = {
        "model": "llama3",
        "response": "  Test output  ",
        "prompt_eval_count": 50,
        "eval_count": 100,
        "prompt_eval_duration": 500_000_000,   # 0.5 s
        "eval_duration": 2_000_000_000,        # 2.0 s
        "total_duration": 3_000_000_000,
    }

    @patch("src.backends.ollama.requests.post")
    def test_basic_generate(self, mock_post):
        mock_post.return_value = _mock_response(self.OLLAMA_RESPONSE)
        b = OllamaBackend("http://localhost:11434", timeout=60)
        result = b.generate("llama3", "Hello")

        assert isinstance(result, GenerateResult)
        assert result.text == "Test output"
        assert result.metrics.model == "llama3"
        assert result.metrics.prompt_tokens == 50
        assert result.metrics.completion_tokens == 100
        assert result.metrics.prompt_eval_duration_sec == pytest.approx(0.5)
        assert result.metrics.completion_duration_sec == pytest.approx(2.0)
        assert result.metrics.total_duration_sec > 0

        # Verify payload structure
        call_args = mock_post.call_args
        payload = call_args.kwargs.get("json") or call_args[1].get("json")
        assert payload["model"] == "llama3"
        assert payload["stream"] is False
        assert payload["options"]["num_predict"] == 512  # default

    @patch("src.backends.ollama.requests.post")
    def test_generate_with_stop_sequences(self, mock_post):
        mock_post.return_value = _mock_response(self.OLLAMA_RESPONSE)
        b = OllamaBackend("http://localhost:11434")
        b.generate("llama3", "Hello", stop=["STOP1", "STOP2"])

        payload = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1].get("json")
        assert payload["options"]["stop"] == ["STOP1", "STOP2"]

    @patch("src.backends.ollama.requests.post")
    def test_generate_no_stop_omits_key(self, mock_post):
        mock_post.return_value = _mock_response(self.OLLAMA_RESPONSE)
        b = OllamaBackend("http://localhost:11434")
        b.generate("llama3", "Hello")

        payload = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1].get("json")
        assert "stop" not in payload["options"]

    @patch("src.backends.ollama.requests.post")
    def test_generate_parameters_pass_through(self, mock_post):
        mock_post.return_value = _mock_response(self.OLLAMA_RESPONSE)
        b = OllamaBackend("http://localhost:11434")
        b.generate(
            "llama3", "Hello",
            max_tokens=1024, context_length=4096,
            temperature=0.1, top_p=0.5, top_k=10, think=True,
        )

        payload = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1].get("json")
        assert payload["think"] is True
        assert payload["options"]["num_predict"] == 1024
        assert payload["options"]["num_ctx"] == 4096
        assert payload["options"]["temperature"] == 0.1
        assert payload["options"]["top_p"] == 0.5
        assert payload["options"]["top_k"] == 10

    @patch("src.backends.ollama.requests.post")
    def test_generate_http_error_propagates(self, mock_post):
        mock_post.return_value = _mock_http_error_response(500)
        b = OllamaBackend("http://localhost:11434")
        with pytest.raises(requests.HTTPError):
            b.generate("llama3", "Hello")

    @patch("src.backends.ollama.requests.post")
    def test_generate_missing_fields_default_to_zero(self, mock_post):
        mock_post.return_value = _mock_response({"model": "m", "response": "ok"})
        b = OllamaBackend("http://localhost:11434")
        result = b.generate("m", "Hi")
        assert result.metrics.prompt_tokens == 0
        assert result.metrics.completion_tokens == 0
        assert result.metrics.prompt_eval_duration_sec == 0.0
        assert result.metrics.completion_duration_sec == 0.0

    @patch("src.backends.ollama.requests.post")
    def test_generate_auth_header_sent(self, mock_post):
        mock_post.return_value = _mock_response({"response": "ok"})
        b = OllamaBackend("http://localhost:11434", auth_token="secret")
        b.generate("m", "Hi")
        headers = mock_post.call_args.kwargs.get("headers") or mock_post.call_args[1].get("headers")
        assert headers["Authorization"] == "Bearer secret"


class TestOllamaChat:
    CHAT_RESPONSE = {
        "model": "llama3",
        "message": {
            "role": "assistant",
            "content": "I can help with that.",
            "tool_calls": None,
        },
        "prompt_eval_count": 30,
        "eval_count": 60,
        "prompt_eval_duration": 300_000_000,
        "eval_duration": 1_000_000_000,
    }

    @patch("src.backends.ollama.requests.post")
    def test_basic_chat(self, mock_post):
        mock_post.return_value = _mock_response(self.CHAT_RESPONSE)
        b = OllamaBackend("http://localhost:11434")
        result = b.chat("llama3", [{"role": "user", "content": "Hi"}])

        assert isinstance(result, ChatResult)
        assert result.message.role == "assistant"
        assert result.message.content == "I can help with that."
        assert result.message.tool_calls is None
        assert result.metrics.prompt_tokens == 30
        assert result.metrics.completion_tokens == 60

    @patch("src.backends.ollama.requests.post")
    def test_chat_with_tools(self, mock_post):
        resp = dict(self.CHAT_RESPONSE)
        resp["message"] = {
            "role": "assistant",
            "content": "",
            "tool_calls": [{"function": {"name": "test_fn", "arguments": "{}"}}],
        }
        mock_post.return_value = _mock_response(resp)
        b = OllamaBackend("http://localhost:11434")
        tools = [{"type": "function", "function": {"name": "test_fn"}}]
        result = b.chat("llama3", [{"role": "user", "content": "Do it"}], tools=tools)

        assert result.message.tool_calls is not None
        assert len(result.message.tool_calls) == 1

        payload = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1].get("json")
        assert payload["tools"] == tools

    @patch("src.backends.ollama.requests.post")
    def test_chat_no_tools_omits_key(self, mock_post):
        mock_post.return_value = _mock_response(self.CHAT_RESPONSE)
        b = OllamaBackend("http://localhost:11434")
        b.chat("llama3", [{"role": "user", "content": "Hi"}])

        payload = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1].get("json")
        assert "tools" not in payload


class TestOllamaStopModel:
    @patch("src.backends.ollama.requests.post")
    def test_stop_via_api_stop(self, mock_post):
        mock_post.return_value = _mock_response({})
        b = OllamaBackend("http://localhost:11434")
        assert b.stop_model("llama3") is True
        assert "/api/stop" in mock_post.call_args_list[0].args[0]

    def test_stop_empty_model(self):
        b = OllamaBackend("http://localhost:11434")
        assert b.stop_model("") is False

    @patch("src.backends.ollama.requests.post")
    def test_stop_fallback_to_keepalive(self, mock_post):
        # First call (api/stop) returns 404, second (keep_alive=0) succeeds
        resp_404 = _mock_response({}, status_code=404)
        resp_404.status_code = 404
        resp_ok = _mock_response({})
        mock_post.side_effect = [resp_404, resp_ok]

        b = OllamaBackend("http://localhost:11434")
        assert b.stop_model("llama3") is True
        assert mock_post.call_count == 2

    @patch("src.backends.ollama.requests.post")
    def test_stop_both_fail(self, mock_post):
        mock_post.side_effect = requests.ConnectionError("down")
        b = OllamaBackend("http://localhost:11434")
        assert b.stop_model("llama3") is False


class TestOllamaDetectToolSupport:
    @patch("src.backends.ollama.requests.post")
    def test_capabilities_list(self, mock_post):
        mock_post.return_value = _mock_response({"capabilities": ["tools", "vision"]})
        b = OllamaBackend("http://localhost:11434")
        assert b.detect_tool_support("llama3") is True

    @patch("src.backends.ollama.requests.post")
    def test_chat_template_tools(self, mock_post):
        mock_post.return_value = _mock_response({
            "model_info": {"tokenizer.chat_template": "Some template with <tool_call> markers"},
        })
        b = OllamaBackend("http://localhost:11434")
        assert b.detect_tool_support("llama3") is True

    @patch("src.backends.ollama.requests.post")
    def test_template_field_tools(self, mock_post):
        mock_post.return_value = _mock_response({
            "template": "... tools ... something",
        })
        b = OllamaBackend("http://localhost:11434")
        assert b.detect_tool_support("llama3") is True

    @patch("src.backends.ollama.requests.post")
    def test_no_tool_support(self, mock_post):
        mock_post.return_value = _mock_response({"template": "plain template"})
        b = OllamaBackend("http://localhost:11434")
        assert b.detect_tool_support("llama3") is False

    @patch("src.backends.ollama.requests.post")
    def test_request_fails_returns_none(self, mock_post):
        mock_post.side_effect = requests.ConnectionError("down")
        b = OllamaBackend("http://localhost:11434")
        assert b.detect_tool_support("llama3") is None

    def test_empty_model_returns_none(self):
        b = OllamaBackend("http://localhost:11434")
        assert b.detect_tool_support("") is None


class TestTemplateHeuristic:
    def test_empty(self):
        assert _template_mentions_tools("") is False

    def test_tools_keyword(self):
        assert _template_mentions_tools("Use tools to answer") is True

    def test_tool_call_keyword(self):
        assert _template_mentions_tools("call tool_call func") is True

    def test_no_match(self):
        assert _template_mentions_tools("This is a plain template") is False


# ═══════════════════════════════════════════════════════════════════════
# OpenAICompatBackend
# ═══════════════════════════════════════════════════════════════════════

class TestOpenAICompatProtocol:
    def test_conforms_to_protocol(self):
        backend = OpenAICompatBackend("http://localhost:8000")
        assert isinstance(backend, LLMBackend)

    def test_backend_type(self):
        assert OpenAICompatBackend("http://localhost:8000").backend_type == "openai"


class TestOpenAICompatInit:
    def test_strips_trailing_slash(self):
        b = OpenAICompatBackend("http://localhost:8000/")
        assert b._base_url == "http://localhost:8000"

    def test_no_auth_header_when_no_key(self):
        b = OpenAICompatBackend("http://localhost:8000")
        assert "Authorization" not in b._headers

    def test_api_key_sets_bearer(self):
        b = OpenAICompatBackend("http://localhost:8000", api_key="sk-test")
        assert b._headers["Authorization"] == "Bearer sk-test"

    def test_content_type_always_set(self):
        b = OpenAICompatBackend("http://localhost:8000")
        assert b._headers["Content-Type"] == "application/json"

    def test_extra_headers_merged(self):
        b = OpenAICompatBackend("http://localhost:8000", extra_headers={"X-Custom": "val"})
        assert b._headers["X-Custom"] == "val"

    def test_remote_endpoint_logs_warning(self, caplog):
        with caplog.at_level(logging.WARNING):
            OpenAICompatBackend("https://api.openai.com")
        assert "remote endpoint" in caplog.text.lower()

    def test_local_endpoint_no_warning(self, caplog):
        with caplog.at_level(logging.WARNING):
            OpenAICompatBackend("http://localhost:8000")
        assert "remote endpoint" not in caplog.text.lower()


class TestOpenAIIsLocal:
    @pytest.mark.parametrize("url,expected", [
        ("http://localhost:8000", True),
        ("http://127.0.0.1:8000", True),
        ("http://host.containers.internal:8000", True),
        ("http://host.docker.internal:8000", True),
        ("https://api.openai.com", False),
        ("https://vllm.example.com:8000", False),
    ])
    def test_is_local(self, url, expected):
        assert OpenAICompatBackend._is_local(url) is expected


class TestOpenAIGenerate:
    OPENAI_RESPONSE = {
        "choices": [{
            "message": {"role": "assistant", "content": "  Test output  "},
        }],
        "usage": {"prompt_tokens": 20, "completion_tokens": 80, "total_tokens": 100},
    }

    @patch("src.backends.openai_compat.requests.post")
    def test_basic_generate(self, mock_post):
        mock_post.return_value = _mock_response(self.OPENAI_RESPONSE)
        b = OpenAICompatBackend("http://localhost:8000")
        result = b.generate("gpt-4", "Hello")

        assert isinstance(result, GenerateResult)
        assert result.text == "Test output"
        assert result.metrics.model == "gpt-4"
        assert result.metrics.prompt_tokens == 20
        assert result.metrics.completion_tokens == 80
        assert result.metrics.total_duration_sec > 0
        # OpenAI backend does not populate per-phase durations
        assert result.metrics.prompt_eval_duration_sec == 0.0
        assert result.metrics.completion_duration_sec == 0.0

    @patch("src.backends.openai_compat.requests.post")
    def test_generate_wraps_prompt_as_user_message(self, mock_post):
        mock_post.return_value = _mock_response(self.OPENAI_RESPONSE)
        b = OpenAICompatBackend("http://localhost:8000")
        b.generate("gpt-4", "My prompt text")

        payload = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1].get("json")
        assert payload["messages"] == [{"role": "user", "content": "My prompt text"}]
        assert "/v1/chat/completions" in mock_post.call_args.args[0]

    @patch("src.backends.openai_compat.requests.post")
    def test_generate_with_stop(self, mock_post):
        mock_post.return_value = _mock_response(self.OPENAI_RESPONSE)
        b = OpenAICompatBackend("http://localhost:8000")
        b.generate("gpt-4", "Hello", stop=["END"])

        payload = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1].get("json")
        assert payload["stop"] == ["END"]

    @patch("src.backends.openai_compat.requests.post")
    def test_generate_parameters(self, mock_post):
        mock_post.return_value = _mock_response(self.OPENAI_RESPONSE)
        b = OpenAICompatBackend("http://localhost:8000")
        b.generate("gpt-4", "Hello", max_tokens=2048, temperature=0.3, top_p=0.8)

        payload = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1].get("json")
        assert payload["max_tokens"] == 2048
        assert payload["temperature"] == 0.3
        assert payload["top_p"] == 0.8

    @patch("src.backends.openai_compat.requests.post")
    def test_generate_http_error_propagates(self, mock_post):
        mock_post.return_value = _mock_http_error_response(500)
        b = OpenAICompatBackend("http://localhost:8000")
        with pytest.raises(requests.HTTPError):
            b.generate("gpt-4", "Hello")

    @patch("src.backends.openai_compat.requests.post")
    def test_generate_sensitive_http_error_warns_without_error_log(self, mock_post, caplog):
        resp = _mock_http_error_response(422)
        resp.text = '{"error":{"message":"output new_sensitive (1027)"}}'
        mock_post.return_value = resp
        b = OpenAICompatBackend("http://localhost:8000")

        with caplog.at_level(logging.WARNING):
            with pytest.raises(requests.HTTPError):
                b.generate("gpt-4", "Hello")

        assert "content-safety" in caplog.text
        assert not [record for record in caplog.records if record.levelno >= logging.ERROR]

    @patch("src.backends.openai_compat.requests.post")
    def test_generate_empty_choices(self, mock_post):
        mock_post.return_value = _mock_response({"choices": [], "usage": {}})
        b = OpenAICompatBackend("http://localhost:8000")
        result = b.generate("gpt-4", "Hello")
        assert result.text == ""
        assert result.metrics.prompt_tokens == 0

    @patch("src.backends.openai_compat.requests.post")
    def test_generate_missing_usage(self, mock_post):
        mock_post.return_value = _mock_response({
            "choices": [{"message": {"content": "ok"}}],
        })
        b = OpenAICompatBackend("http://localhost:8000")
        result = b.generate("gpt-4", "Hello")
        assert result.text == "ok"
        assert result.metrics.prompt_tokens == 0
        assert result.metrics.completion_tokens == 0

    @patch("src.backends.openai_compat.requests.post")
    def test_generate_auth_header_sent(self, mock_post):
        mock_post.return_value = _mock_response(self.OPENAI_RESPONSE)
        b = OpenAICompatBackend("http://localhost:8000", api_key="sk-key")
        b.generate("gpt-4", "Hello")
        headers = mock_post.call_args.kwargs.get("headers") or mock_post.call_args[1].get("headers")
        assert headers["Authorization"] == "Bearer sk-key"


class TestOpenAIChat:
    CHAT_RESPONSE = {
        "choices": [{
            "message": {
                "role": "assistant",
                "content": "I can help.",
                "tool_calls": None,
            },
        }],
        "usage": {"prompt_tokens": 10, "completion_tokens": 40},
    }

    @patch("src.backends.openai_compat.requests.post")
    def test_basic_chat(self, mock_post):
        mock_post.return_value = _mock_response(self.CHAT_RESPONSE)
        b = OpenAICompatBackend("http://localhost:8000")
        result = b.chat("gpt-4", [{"role": "user", "content": "Hi"}])

        assert isinstance(result, ChatResult)
        assert result.message.role == "assistant"
        assert result.message.content == "I can help."
        assert result.message.tool_calls is None
        assert result.metrics.prompt_tokens == 10
        assert result.metrics.completion_tokens == 40

    @patch("src.backends.openai_compat.requests.post")
    def test_chat_with_tools(self, mock_post):
        resp = {
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [{"id": "c1", "function": {"name": "fn", "arguments": "{}"}}],
                },
            }],
            "usage": {"prompt_tokens": 10, "completion_tokens": 20},
        }
        mock_post.return_value = _mock_response(resp)
        b = OpenAICompatBackend("http://localhost:8000")
        tools = [{"type": "function", "function": {"name": "fn"}}]
        result = b.chat("gpt-4", [{"role": "user", "content": "Do it"}], tools=tools)

        assert result.message.tool_calls is not None
        payload = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1].get("json")
        assert payload["tools"] == tools

    @patch("src.backends.openai_compat.requests.post")
    def test_chat_no_tools_omits_key(self, mock_post):
        mock_post.return_value = _mock_response(self.CHAT_RESPONSE)
        b = OpenAICompatBackend("http://localhost:8000")
        b.chat("gpt-4", [{"role": "user", "content": "Hi"}])

        payload = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1].get("json")
        assert "tools" not in payload

    @patch("src.backends.openai_compat.requests.post")
    def test_chat_null_content_becomes_empty_string(self, mock_post):
        resp = {
            "choices": [{"message": {"role": "assistant", "content": None}}],
            "usage": {},
        }
        mock_post.return_value = _mock_response(resp)
        b = OpenAICompatBackend("http://localhost:8000")
        result = b.chat("gpt-4", [{"role": "user", "content": "Hi"}])
        assert result.message.content == ""


class TestOpenAIStopAndDetect:
    def test_stop_model_always_false(self):
        b = OpenAICompatBackend("http://localhost:8000")
        assert b.stop_model("gpt-4") is False

    def test_detect_tool_support_always_true(self):
        b = OpenAICompatBackend("http://localhost:8000")
        assert b.detect_tool_support("gpt-4") is True


# ═══════════════════════════════════════════════════════════════════════
# Backend factory
# ═══════════════════════════════════════════════════════════════════════

class TestCreateBackend:
    def setup_method(self):
        """Snapshot mutable config fields so they can be restored."""
        from tests.conftest import _fake_config
        self._cfg = _fake_config
        self._orig_type = self._cfg.LLM_BACKEND_TYPE
        self._orig_url = self._cfg.LLM_BACKEND_BASE_URL

    def teardown_method(self):
        """Restore config to avoid polluting subsequent tests."""
        self._cfg.LLM_BACKEND_TYPE = self._orig_type
        self._cfg.LLM_BACKEND_BASE_URL = self._orig_url

    def test_creates_ollama_by_default(self, fake_config):
        from src.backends import create_backend
        backend = create_backend()
        assert backend.backend_type == "ollama"

    def test_creates_openai(self, fake_config):
        fake_config.LLM_BACKEND_TYPE = "openai"
        fake_config.LLM_BACKEND_BASE_URL = "http://localhost:8000"
        from src.backends import create_backend
        backend = create_backend()
        assert backend.backend_type == "openai"

    def test_unknown_type_raises(self, fake_config):
        fake_config.LLM_BACKEND_TYPE = "unknown"
        from src.backends import create_backend
        with pytest.raises(ValueError, match="Unknown LLM backend type"):
            create_backend()


# ═══════════════════════════════════════════════════════════════════════
# call_daily_report_llm with backend injection
# ═══════════════════════════════════════════════════════════════════════

class TestCallDailyReportLlmBackend:
    """Verify that ``call_daily_report_llm`` properly delegates to the
    injected backend and processes the result."""

    def _make_llm_conf(self):
        from src.daily_report import DailyReportLLMConfig
        return DailyReportLLMConfig(
            MODEL="test-model",
            MAX_TOKENS=512,
            CONTEXT_LENGTH=4096,
            TEMPERATURE=0.7,
            TOP_P=0.9,
            TOP_K=40,
        )

    def test_empty_prompt_returns_empty(self):
        from src.daily_report import call_daily_report_llm
        result = call_daily_report_llm("", self._make_llm_conf(), backend=MagicMock())
        assert result == ""

    def test_delegates_to_backend_generate(self):
        from src.daily_report import call_daily_report_llm
        mock_backend = MagicMock()
        mock_backend.backend_type = "ollama"
        mock_backend.generate.return_value = GenerateResult(
            text="<p>Report content</p>",
            metrics=LLMMetrics(model="test"),
        )

        conf = self._make_llm_conf()
        result = call_daily_report_llm("Analyze this", conf, backend=mock_backend)

        mock_backend.generate.assert_called_once()
        call_kwargs = mock_backend.generate.call_args
        assert call_kwargs.kwargs["model"] == "test-model"
        assert call_kwargs.kwargs["prompt"] == "Analyze this"
        assert call_kwargs.kwargs["max_tokens"] == 512
        assert "Report content" in result

    def test_strips_think_and_code_fences(self):
        from src.daily_report import call_daily_report_llm
        mock_backend = MagicMock()
        mock_backend.backend_type = "ollama"
        mock_backend.generate.return_value = GenerateResult(
            text="<think>reasoning</think>```html\n<p>Clean</p>\n```",
            metrics=LLMMetrics(model="test"),
        )
        result = call_daily_report_llm("prompt", self._make_llm_conf(), backend=mock_backend)
        assert "<think>" not in result
        assert "```" not in result
        assert "Clean" in result

    def test_extracts_html_body(self):
        from src.daily_report import call_daily_report_llm
        mock_backend = MagicMock()
        mock_backend.backend_type = "ollama"
        html = "<html><body><p>Inside body</p></body></html>"
        mock_backend.generate.return_value = GenerateResult(
            text=html,
            metrics=LLMMetrics(model="test"),
        )
        result = call_daily_report_llm("prompt", self._make_llm_conf(), backend=mock_backend)
        assert "<html>" not in result
        assert "Inside body" in result


# ═══════════════════════════════════════════════════════════════════════
# vLLM Prometheus metrics
# ═══════════════════════════════════════════════════════════════════════

class TestVLLMMetricsParsing:
    """Test parsing of vLLM Prometheus /metrics text output."""

    def test_parse_full_metrics(self):
        from src.backends.openai_compat import _parse_vllm_metrics
        text = (
            "# HELP vllm:num_requests_running Number of running requests\n"
            "# TYPE vllm:num_requests_running gauge\n"
            "vllm:num_requests_running 3.0\n"
            "# HELP vllm:avg_generation_throughput_toks_per_s Average throughput\n"
            "# TYPE vllm:avg_generation_throughput_toks_per_s gauge\n"
            "vllm:avg_generation_throughput_toks_per_s 42.5\n"
            "# HELP vllm:gpu_cache_usage_perc GPU cache usage\n"
            "# TYPE vllm:gpu_cache_usage_perc gauge\n"
            "vllm:gpu_cache_usage_perc 0.75\n"
        )
        m = _parse_vllm_metrics(text)
        assert m.num_requests_running == pytest.approx(3.0)
        assert m.avg_generation_throughput_toks_per_s == pytest.approx(42.5)
        assert m.gpu_cache_usage_perc == pytest.approx(0.75)

    def test_parse_partial_metrics(self):
        from src.backends.openai_compat import _parse_vllm_metrics
        text = "vllm:num_requests_running 1.0\n"
        m = _parse_vllm_metrics(text)
        assert m.num_requests_running == pytest.approx(1.0)
        assert m.avg_generation_throughput_toks_per_s is None
        assert m.gpu_cache_usage_perc is None

    def test_parse_empty_text(self):
        from src.backends.openai_compat import _parse_vllm_metrics
        m = _parse_vllm_metrics("")
        assert m.num_requests_running is None
        assert m.avg_generation_throughput_toks_per_s is None
        assert m.gpu_cache_usage_perc is None

    def test_parse_metrics_with_labels(self):
        from src.backends.openai_compat import _parse_vllm_metrics
        text = 'vllm:num_requests_running{model_name="llama"} 5.0\n'
        m = _parse_vllm_metrics(text)
        assert m.num_requests_running == pytest.approx(5.0)


class TestVLLMMetricsScraping:
    def test_scrape_disabled_returns_none(self):
        b = OpenAICompatBackend("http://localhost:8000")
        assert b.vllm_metrics is None
        assert b.scrape_vllm_metrics() is None

    @patch("src.backends.openai_compat.requests.get")
    def test_scrape_success(self, mock_get):
        text = (
            "vllm:num_requests_running 2.0\n"
            "vllm:avg_generation_throughput_toks_per_s 30.0\n"
            "vllm:gpu_cache_usage_perc 0.5\n"
        )
        resp = MagicMock()
        resp.text = text
        resp.raise_for_status.return_value = None
        mock_get.return_value = resp

        b = OpenAICompatBackend(
            "http://localhost:8000",
            vllm_prometheus_url="http://localhost:8000/metrics",
        )
        result = b.scrape_vllm_metrics()
        assert result is not None
        assert result.num_requests_running == pytest.approx(2.0)
        assert result.avg_generation_throughput_toks_per_s == pytest.approx(30.0)
        assert result.gpu_cache_usage_perc == pytest.approx(0.5)
        # Cached
        assert b.vllm_metrics is result

    @patch("src.backends.openai_compat.requests.get")
    def test_scrape_failure_returns_none(self, mock_get):
        mock_get.side_effect = requests.ConnectionError("down")
        b = OpenAICompatBackend(
            "http://localhost:8000",
            vllm_prometheus_url="http://localhost:8000/metrics",
        )
        result = b.scrape_vllm_metrics()
        assert result is None


class TestOpenAICompatVLLMInit:
    def test_no_prometheus_url_by_default(self):
        b = OpenAICompatBackend("http://localhost:8000")
        assert b._vllm_prometheus_url == ""

    def test_prometheus_url_stored(self):
        b = OpenAICompatBackend(
            "http://localhost:8000",
            vllm_prometheus_url="http://localhost:8000/metrics/",
        )
        assert b._vllm_prometheus_url == "http://localhost:8000/metrics"


# ═══════════════════════════════════════════════════════════════════════
# DailyReportLLMConfig backward compatibility
# ═══════════════════════════════════════════════════════════════════════

class TestDailyReportLLMConfigCompat:
    """Verify that DailyReportLLMConfig supports both new and legacy names."""

    def test_new_field_names(self):
        from src.daily_report import DailyReportLLMConfig
        cfg = DailyReportLLMConfig(
            MODEL="m", MAX_TOKENS=512, TEMPERATURE=0.5,
            TOP_P=0.9, TOP_K=40, CONTEXT_LENGTH=8192,
        )
        assert cfg.MODEL == "m"
        assert cfg.MAX_TOKENS == 512
        assert cfg.CONTEXT_LENGTH == 8192

    def test_legacy_alias_properties(self):
        from src.daily_report import DailyReportLLMConfig
        cfg = DailyReportLLMConfig(
            MODEL="m", MAX_TOKENS=512, TEMPERATURE=0.5,
            TOP_P=0.9, TOP_K=40, CONTEXT_LENGTH=8192,
        )
        assert cfg.OLLAMA_MODEL == "m"
        assert cfg.OLLAMA_NUM_PREDICT == 512
        assert cfg.OLLAMA_TEMPERATURE == 0.5
        assert cfg.OLLAMA_TOP_P == 0.9
        assert cfg.OLLAMA_TOP_K == 40
        assert cfg.OLLAMA_CONTEXT_LENGTH == 8192


# ═══════════════════════════════════════════════════════════════════════
# Backend update_auth_token
# ═══════════════════════════════════════════════════════════════════════

class TestOllamaUpdateAuthToken:
    """OllamaBackend.update_auth_token hot-reload behaviour."""

    def test_set_token_adds_header(self):
        b = OllamaBackend("http://localhost:11434")
        assert "Authorization" not in b._headers
        b.update_auth_token("new-key")
        assert b._headers["Authorization"] == "Bearer new-key"

    def test_clear_token_removes_header(self):
        b = OllamaBackend("http://localhost:11434", auth_token="old-key")
        assert "Authorization" in b._headers
        b.update_auth_token("")
        assert "Authorization" not in b._headers

    def test_replace_token(self):
        b = OllamaBackend("http://localhost:11434", auth_token="old-key")
        b.update_auth_token("new-key")
        assert b._headers["Authorization"] == "Bearer new-key"


class TestOpenAICompatUpdateAuthToken:
    """OpenAICompatBackend.update_auth_token hot-reload behaviour."""

    def test_set_token_adds_header(self):
        b = OpenAICompatBackend("http://localhost:8000", api_key="")
        assert "Authorization" not in b._headers
        b.update_auth_token("sk-new")
        assert b._headers["Authorization"] == "Bearer sk-new"
        assert b._api_key == "sk-new"

    def test_clear_token_removes_header(self):
        b = OpenAICompatBackend("http://localhost:8000", api_key="sk-old")
        assert "Authorization" in b._headers
        b.update_auth_token("")
        assert "Authorization" not in b._headers
        assert b._api_key == ""

    def test_replace_token(self):
        b = OpenAICompatBackend("http://localhost:8000", api_key="sk-old")
        b.update_auth_token("sk-new")
        assert b._headers["Authorization"] == "Bearer sk-new"
        assert b._api_key == "sk-new"


# ═══════════════════════════════════════════════════════════════════════
# create_backend_for_model — per-model backend routing + cache
# ═══════════════════════════════════════════════════════════════════════

class TestCreateBackendForModel:
    """Verify that ``create_backend_for_model`` routes and caches correctly."""

    def setup_method(self):
        from src.backends import clear_backend_cache
        clear_backend_cache()

    def teardown_method(self):
        from src.backends import clear_backend_cache
        clear_backend_cache()

    def test_ollama_profile_creates_ollama_backend(self, fake_config):
        from tests.conftest import ModelProfile
        from src.backends import create_backend_for_model
        profile = ModelProfile(
            name="local-model",
            backend_type="ollama",
            backend_base_url="http://custom:11434",
        )
        backend = create_backend_for_model(profile)
        assert backend.backend_type == "ollama"
        assert backend._base_url == "http://custom:11434"

    def test_openai_profile_creates_openai_backend(self, fake_config):
        from tests.conftest import ModelProfile
        from src.backends import create_backend_for_model
        profile = ModelProfile(
            name="gpt-4.1-mini",
            backend_type="openai",
            backend_base_url="https://api.openai.com",
            backend_auth_token="sk-test",
        )
        backend = create_backend_for_model(profile)
        assert backend.backend_type == "openai"
        assert backend._base_url == "https://api.openai.com"

    def test_caches_same_triple(self, fake_config):
        from tests.conftest import ModelProfile
        from src.backends import create_backend_for_model
        p1 = ModelProfile(name="m1", backend_type="ollama", backend_base_url="http://h:11434")
        p2 = ModelProfile(name="m2", backend_type="ollama", backend_base_url="http://h:11434")
        b1 = create_backend_for_model(p1)
        b2 = create_backend_for_model(p2)
        assert b1 is b2

    def test_different_url_creates_separate_backends(self, fake_config):
        from tests.conftest import ModelProfile
        from src.backends import create_backend_for_model
        p1 = ModelProfile(name="m1", backend_type="ollama", backend_base_url="http://h1:11434")
        p2 = ModelProfile(name="m2", backend_type="ollama", backend_base_url="http://h2:11434")
        b1 = create_backend_for_model(p1)
        b2 = create_backend_for_model(p2)
        assert b1 is not b2

    def test_unknown_backend_type_raises(self, fake_config):
        from tests.conftest import ModelProfile
        from src.backends import create_backend_for_model
        profile = ModelProfile(name="bad", backend_type="unknown")
        with pytest.raises(ValueError, match="Unknown backend type"):
            create_backend_for_model(profile)

    def test_empty_base_url_uses_global(self, fake_config):
        from tests.conftest import ModelProfile
        from src.backends import create_backend_for_model
        profile = ModelProfile(
            name="local",
            backend_type="ollama",
            backend_base_url="",
        )
        backend = create_backend_for_model(profile)
        assert backend.backend_type == "ollama"
        assert backend._base_url == fake_config.OLLAMA_BASE_URL

    def test_empty_auth_token_uses_global(self, fake_config):
        from tests.conftest import ModelProfile
        from src.backends import create_backend_for_model
        fake_config.LLM_BACKEND_AUTH_TOKEN = "global-token"
        profile = ModelProfile(
            name="openai-model",
            backend_type="openai",
            backend_base_url="https://api.example.com",
            backend_auth_token="",
        )
        backend = create_backend_for_model(profile)
        assert backend._api_key == "global-token"
        fake_config.LLM_BACKEND_AUTH_TOKEN = ""


# ═══════════════════════════════════════════════════════════════════════
# TokenBucketRateLimiter  (Improvement 30.6)
# ═══════════════════════════════════════════════════════════════════════

import time
import threading


class TestTokenBucketRateLimiter:
    """Unit tests for the token-bucket rate limiter."""

    def setup_method(self):
        from src.backends.rate_limiter import TokenBucketRateLimiter
        self.RateLimiter = TokenBucketRateLimiter

    def test_disabled_when_zero_capacity(self):
        rl = self.RateLimiter(capacity=0, period=60.0)
        assert not rl.enabled
        assert rl.acquire(timeout=0) is True

    def test_disabled_when_zero_period(self):
        rl = self.RateLimiter(capacity=100, period=0)
        assert not rl.enabled

    def test_acquire_consumes_tokens(self):
        rl = self.RateLimiter(capacity=3, period=60.0)
        assert rl.acquire(timeout=0) is True
        assert rl.acquire(timeout=0) is True
        assert rl.acquire(timeout=0) is True
        # Bucket empty
        assert rl.acquire(timeout=0) is False

    def test_tokens_refill_over_time(self):
        rl = self.RateLimiter(capacity=10, period=1.0)  # 10 tokens/sec
        for _ in range(10):
            rl.acquire(timeout=0)
        assert rl.acquire(timeout=0) is False
        time.sleep(0.15)
        assert rl.acquire(timeout=0) is True

    def test_acquire_blocks_until_available(self):
        rl = self.RateLimiter(capacity=1, period=0.5)  # 2 tokens/sec
        rl.acquire(timeout=0)  # consume the only token
        t0 = time.monotonic()
        assert rl.acquire(timeout=2.0) is True
        elapsed = time.monotonic() - t0
        assert 0.2 < elapsed < 1.0

    def test_acquire_timeout_returns_false(self):
        rl = self.RateLimiter(capacity=1, period=10.0)  # very slow refill
        rl.acquire(timeout=0)  # consume
        assert rl.acquire(timeout=0.1) is False

    def test_try_acquire(self):
        rl = self.RateLimiter(capacity=1, period=60.0)
        assert rl.try_acquire() is True
        assert rl.try_acquire() is False

    def test_thread_safety(self):
        rl = self.RateLimiter(capacity=50, period=60.0)
        results = []

        def worker():
            acquired = rl.acquire(timeout=0)
            results.append(acquired)

        threads = [threading.Thread(target=worker) for _ in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert sum(1 for r in results if r) == 50
        assert sum(1 for r in results if not r) == 50

    def test_reconfigure_updates_in_place(self):
        rl = self.RateLimiter(capacity=100, period=60.0)
        original_id = id(rl)
        for _ in range(100):
            rl.acquire(timeout=0)
        assert rl.acquire(timeout=0) is False

        # Reconfigure to smaller capacity
        rl.reconfigure(capacity=5, period=60.0)
        assert rl.capacity == 5.0
        assert id(rl) == original_id  # same object
        # Tokens clamped to new capacity; bucket should have <=5 tokens
        acquired = sum(1 for _ in range(10) if rl.acquire(timeout=0))
        assert acquired <= 5

    def test_reconfigure_to_disabled(self):
        rl = self.RateLimiter(capacity=10, period=60.0)
        assert rl.enabled
        rl.reconfigure(capacity=0, period=60.0)
        assert not rl.enabled
        # Disabled limiter should always succeed
        assert rl.acquire(timeout=0) is True


# ═══════════════════════════════════════════════════════════════════════
# Backend rate limiter integration  (Improvement 30.6)
# ═══════════════════════════════════════════════════════════════════════

class TestBackendRateLimiterIntegration:
    """Verify backend factory injects rate limiters correctly."""

    def setup_method(self):
        from src.backends import clear_backend_cache
        clear_backend_cache()

    def teardown_method(self):
        from src.backends import clear_backend_cache
        clear_backend_cache()

    def test_openai_backend_receives_limiter(self, fake_config):
        from tests.conftest import ModelProfile
        from src.backends import create_backend_for_model
        profile = ModelProfile(
            name="gpt-4.1-mini",
            backend_type="openai",
            backend_base_url="https://api.example.com",
            backend_auth_token="test-key",
            max_requests_per_minute=100,
        )
        backend = create_backend_for_model(profile)
        assert backend._rate_limiter is not None
        assert backend._rate_limiter.capacity == 100.0

    def test_ollama_backend_no_limiter_by_default(self, fake_config):
        from tests.conftest import ModelProfile
        from src.backends import create_backend_for_model
        profile = ModelProfile(
            name="local-model",
            backend_type="ollama",
            backend_base_url="http://localhost:11434",
            max_requests_per_minute=0,
        )
        backend = create_backend_for_model(profile)
        assert backend._rate_limiter is None

    def test_shared_limiter_takes_strictest(self, fake_config):
        from tests.conftest import ModelProfile
        from src.backends import create_backend_for_model
        profile_a = ModelProfile(
            name="model-a",
            backend_type="openai",
            backend_base_url="https://api.example.com",
            backend_auth_token="key",
            max_requests_per_minute=500,
        )
        profile_b = ModelProfile(
            name="model-b",
            backend_type="openai",
            backend_base_url="https://api.example.com",
            backend_auth_token="key",
            max_requests_per_minute=200,
        )
        backend_a = create_backend_for_model(profile_a)
        limiter_after_a = backend_a._rate_limiter
        assert limiter_after_a.capacity == 500.0

        backend_b = create_backend_for_model(profile_b)
        # Same cache_key, limiter should be updated to stricter 200
        assert backend_b._rate_limiter.capacity == 200.0
        # Same backend instance
        assert backend_a is backend_b
        # Same limiter object (reconfigured in-place, not replaced)
        assert backend_a._rate_limiter is limiter_after_a

    def test_ollama_backend_receives_limiter_when_rpm_set(self, fake_config):
        from tests.conftest import ModelProfile
        from src.backends import create_backend_for_model
        profile = ModelProfile(
            name="remote-ollama",
            backend_type="ollama",
            backend_base_url="http://remote:11434",
            max_requests_per_minute=60,
        )
        backend = create_backend_for_model(profile)
        assert backend._rate_limiter is not None
        assert backend._rate_limiter.capacity == 60.0


# ═══════════════════════════════════════════════════════════════════════
# OpenAI 429 retry  (Improvement 30.6)
# ═══════════════════════════════════════════════════════════════════════

class TestOpenAI429Retry:
    """Verify OpenAI backend retries on HTTP 429."""

    def test_retry_on_429_then_success(self):
        call_count = 0

        def mock_post(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            resp = MagicMock()
            if call_count <= 2:
                resp.status_code = 429
                resp.headers = {"Retry-After": "0.01"}
                resp.raise_for_status.side_effect = requests.HTTPError(response=resp)
                return resp
            # 3rd call succeeds
            resp.status_code = 200
            resp.json.return_value = {
                "choices": [{"message": {"role": "assistant", "content": "ok"}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            }
            resp.raise_for_status.return_value = None
            return resp

        with patch("src.backends.openai_compat.requests.post", side_effect=mock_post):
            backend = OpenAICompatBackend(
                base_url="https://api.example.com", api_key="test",
            )
            result = backend.generate(model="test", prompt="hello")
        assert call_count == 3
        assert result.text == "ok"

    def test_max_retries_exceeded(self):
        def mock_post(*args, **kwargs):
            resp = MagicMock()
            resp.status_code = 429
            resp.headers = {}
            resp.raise_for_status.side_effect = requests.HTTPError(response=resp)
            return resp

        with patch("src.backends.openai_compat.requests.post", side_effect=mock_post):
            backend = OpenAICompatBackend(
                base_url="https://api.example.com", api_key="test",
            )
            # Override delays to make test fast
            backend._INITIAL_RETRY_DELAY = 0.001
            backend._MAX_RETRY_DELAY = 0.001
            with pytest.raises(requests.HTTPError):
                backend.generate(model="test", prompt="hello")

    def test_chat_retry_on_429(self):
        call_count = 0

        def mock_post(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            resp = MagicMock()
            if call_count <= 1:
                resp.status_code = 429
                resp.headers = {"Retry-After": "0.01"}
                resp.raise_for_status.side_effect = requests.HTTPError(response=resp)
                return resp
            resp.status_code = 200
            resp.json.return_value = {
                "choices": [{"message": {"role": "assistant", "content": "reply"}}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
            }
            resp.raise_for_status.return_value = None
            return resp

        with patch("src.backends.openai_compat.requests.post", side_effect=mock_post):
            backend = OpenAICompatBackend(
                base_url="https://api.example.com", api_key="test",
            )
            result = backend.chat(
                model="test",
                messages=[{"role": "user", "content": "hi"}],
            )
        assert call_count == 2
        assert result.message.content == "reply"


# ═══════════════════════════════════════════════════════════════════════
# Ollama 429 retry  (Improvement 30.6)
# ═══════════════════════════════════════════════════════════════════════

class TestOllama429Retry:
    """Verify Ollama backend retries on HTTP 429."""

    def test_retry_on_429_then_success(self):
        call_count = 0

        def mock_post(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            resp = MagicMock()
            if call_count <= 2:
                resp.status_code = 429
                resp.headers = {"Retry-After": "0.01"}
                resp.raise_for_status.side_effect = requests.HTTPError(response=resp)
                return resp
            # 3rd call succeeds
            resp.status_code = 200
            resp.json.return_value = {
                "model": "test",
                "response": "ok",
                "prompt_eval_count": 10,
                "eval_count": 5,
                "prompt_eval_duration": 100000000,
                "eval_duration": 200000000,
            }
            resp.raise_for_status.return_value = None
            return resp

        with patch("src.backends.ollama.requests.post", side_effect=mock_post):
            backend = OllamaBackend(base_url="http://remote:11434")
            result = backend.generate(model="test", prompt="hello")
        assert call_count == 3
        assert result.text == "ok"

    def test_max_retries_exceeded(self):
        def mock_post(*args, **kwargs):
            resp = MagicMock()
            resp.status_code = 429
            resp.headers = {}
            resp.raise_for_status.side_effect = requests.HTTPError(response=resp)
            return resp

        with patch("src.backends.ollama.requests.post", side_effect=mock_post):
            backend = OllamaBackend(base_url="http://remote:11434")
            backend._INITIAL_RETRY_DELAY = 0.001
            backend._MAX_RETRY_DELAY = 0.001
            with pytest.raises(requests.HTTPError):
                backend.generate(model="test", prompt="hello")

    def test_chat_retry_on_429(self):
        call_count = 0

        def mock_post(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            resp = MagicMock()
            if call_count <= 1:
                resp.status_code = 429
                resp.headers = {"Retry-After": "0.01"}
                resp.raise_for_status.side_effect = requests.HTTPError(response=resp)
                return resp
            resp.status_code = 200
            resp.json.return_value = {
                "model": "test",
                "message": {"role": "assistant", "content": "reply"},
                "prompt_eval_count": 5,
                "eval_count": 3,
                "prompt_eval_duration": 100000000,
                "eval_duration": 200000000,
            }
            resp.raise_for_status.return_value = None
            return resp

        with patch("src.backends.ollama.requests.post", side_effect=mock_post):
            backend = OllamaBackend(base_url="http://remote:11434")
            result = backend.chat(
                model="test",
                messages=[{"role": "user", "content": "hi"}],
            )
        assert call_count == 2
        assert result.message.content == "reply"
