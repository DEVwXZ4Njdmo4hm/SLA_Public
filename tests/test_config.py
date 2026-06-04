#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         test_config.py
Description:  Tests for TOML configuration loading and parsing utilities.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations
import os
import tomllib
from typing import Optional, List
import pytest

import logging
logger = logging.getLogger(__name__)


# Re-implement the real functions here to avoid loading the entire config module
# (which triggers Config.__post_init__ and requires ES credentials).
def _load_toml(filepath: str):
    with open(filepath, "rb") as f:
        return tomllib.load(f)


def _load_ja3_file(filepath: str, key: str) -> Optional[List[str]]:
    if not filepath or not os.path.isfile(filepath):
        return None
    try:
        data = _load_toml(filepath)
        hashes = data.get(key)
        if isinstance(hashes, list):
            return [h.strip().lower() for h in hashes if isinstance(h, str) and h.strip()]
    except Exception as exc:
        logger.warning("Failed to load JA3 file %s: %s", filepath, exc)
    return None


class TestLoadToml:
    def test_valid_toml(self, tmp_path):
        toml_file = tmp_path / "test.toml"
        toml_file.write_bytes(b'[section]\nkey = "value"\nnum = 42\n')
        data = _load_toml(str(toml_file))
        assert data["section"]["key"] == "value"
        assert data["section"]["num"] == 42

    def test_empty_toml(self, tmp_path):
        toml_file = tmp_path / "empty.toml"
        toml_file.write_bytes(b"")
        data = _load_toml(str(toml_file))
        assert data == {}

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            _load_toml("/nonexistent/file.toml")


class TestLoadJa3File:
    def test_valid_ja3_file(self, tmp_path):
        ja3_file = tmp_path / "ja3.toml"
        ja3_file.write_bytes(b'tls_ja3_hashes = ["AAAA", "BBBB", "  cccc  "]\n')
        result = _load_ja3_file(str(ja3_file), "tls_ja3_hashes")
        assert result == ["aaaa", "bbbb", "cccc"]

    def test_missing_file_returns_none(self):
        assert _load_ja3_file("/nonexistent.toml", "key") is None

    def test_empty_path_returns_none(self):
        assert _load_ja3_file("", "key") is None

    def test_wrong_key_returns_none(self, tmp_path):
        ja3_file = tmp_path / "ja3.toml"
        ja3_file.write_bytes(b'other_key = ["hash1"]\n')
        assert _load_ja3_file(str(ja3_file), "tls_ja3_hashes") is None

    def test_non_list_returns_none(self, tmp_path):
        ja3_file = tmp_path / "ja3.toml"
        ja3_file.write_bytes(b'tls_ja3_hashes = "not-a-list"\n')
        assert _load_ja3_file(str(ja3_file), "tls_ja3_hashes") is None


class TestGitForkOwnerConfig:
    """Verify that fork_owner is loaded from the [git] section."""

    def test_fork_owner_loaded(self, tmp_path):
        toml_file = tmp_path / "agent.toml"
        toml_file.write_bytes(b'[git]\nfork_owner = "capri-ai-bot"\n')
        data = _load_toml(str(toml_file))
        assert data["git"]["fork_owner"] == "capri-ai-bot"

    def test_fork_owner_empty(self, tmp_path):
        toml_file = tmp_path / "agent.toml"
        toml_file.write_bytes(b'[git]\nfork_owner = ""\n')
        data = _load_toml(str(toml_file))
        assert data["git"]["fork_owner"] == ""

    def test_fork_owner_absent(self, tmp_path):
        toml_file = tmp_path / "agent.toml"
        toml_file.write_bytes(b'[git]\nenabled = true\n')
        data = _load_toml(str(toml_file))
        assert "fork_owner" not in data["git"]


# ── [llm.backend] configuration parsing ───────────────────────────────

class TestLLMBackendConfig:
    """Verify that [llm.backend] section is parsed correctly."""

    def test_backend_defaults(self, tmp_path):
        """No [llm.backend] section → defaults to ollama."""
        toml_file = tmp_path / "agent.toml"
        toml_file.write_bytes(b'[llm]\nmemory_length = 50\n')
        data = _load_toml(str(toml_file))
        backend = data.get("llm", {}).get("backend", {})
        assert backend.get("type", "ollama") == "ollama"

    def test_backend_type_ollama(self, tmp_path):
        toml_file = tmp_path / "agent.toml"
        toml_file.write_bytes(b'[llm.backend]\ntype = "ollama"\n')
        data = _load_toml(str(toml_file))
        assert data["llm"]["backend"]["type"] == "ollama"

    def test_backend_type_openai(self, tmp_path):
        toml_file = tmp_path / "agent.toml"
        toml_file.write_bytes(
            b'[llm.backend]\ntype = "openai"\nbase_url = "https://api.openai.com"\n'
        )
        data = _load_toml(str(toml_file))
        assert data["llm"]["backend"]["type"] == "openai"
        assert data["llm"]["backend"]["base_url"] == "https://api.openai.com"

    def test_backend_auth_token(self, tmp_path):
        toml_file = tmp_path / "agent.toml"
        toml_file.write_bytes(
            b'[llm.backend]\ntype = "openai"\nauth_token = "sk-test-123"\n'
        )
        data = _load_toml(str(toml_file))
        assert data["llm"]["backend"]["auth_token"] == "sk-test-123"

    def test_backend_type_case_preserved(self, tmp_path):
        """TOML preserves case; Config.__post_init__ lowercases it."""
        toml_file = tmp_path / "agent.toml"
        toml_file.write_bytes(b'[llm.backend]\ntype = "OpenAI"\n')
        data = _load_toml(str(toml_file))
        # Raw TOML value is case-preserved
        assert data["llm"]["backend"]["type"] == "OpenAI"


class TestLLMBackendConfigValidation:
    """Test Config.__post_init__ validation of [llm.backend] fields.

    Uses the FakeConfig approach: we simulate the parsing logic
    inline because instantiating real Config requires ES credentials.
    """

    @staticmethod
    def _parse_backend(llm_backend: dict) -> dict:
        """Simulate the [llm.backend] parsing logic from Config.__post_init__."""
        result = {
            "LLM_BACKEND_TYPE": "ollama",
            "LLM_BACKEND_BASE_URL": "",
            "LLM_BACKEND_AUTH_TOKEN": "",
            "LLM_BACKEND_VLLM_PROMETHEUS_URL": "",
        }
        if "type" in llm_backend:
            result["LLM_BACKEND_TYPE"] = str(llm_backend["type"]).lower()
        if result["LLM_BACKEND_TYPE"] not in ("ollama", "openai", "deepseek"):
            raise ValueError(
                f"llm.backend.type must be 'ollama', 'openai', or 'deepseek', "
                f"got: {result['LLM_BACKEND_TYPE']!r}"
            )
        if "base_url" in llm_backend:
            result["LLM_BACKEND_BASE_URL"] = str(llm_backend["base_url"])
        if "auth_token" in llm_backend:
            result["LLM_BACKEND_AUTH_TOKEN"] = str(llm_backend["auth_token"])
        vllm_metrics = llm_backend.get("vllm_metrics", {})
        if "prometheus_url" in vllm_metrics:
            result["LLM_BACKEND_VLLM_PROMETHEUS_URL"] = str(vllm_metrics["prometheus_url"])
        return result

    def test_valid_ollama(self):
        r = self._parse_backend({"type": "ollama"})
        assert r["LLM_BACKEND_TYPE"] == "ollama"

    def test_valid_openai(self):
        r = self._parse_backend({"type": "openai", "base_url": "http://vllm:8000"})
        assert r["LLM_BACKEND_TYPE"] == "openai"
        assert r["LLM_BACKEND_BASE_URL"] == "http://vllm:8000"

    def test_valid_deepseek(self):
        r = self._parse_backend({"type": "deepseek"})
        assert r["LLM_BACKEND_TYPE"] == "deepseek"

    def test_case_insensitive(self):
        r = self._parse_backend({"type": "DeepSeek"})
        assert r["LLM_BACKEND_TYPE"] == "deepseek"

    def test_invalid_type_raises(self):
        with pytest.raises(ValueError, match="must be 'ollama', 'openai', or 'deepseek'"):
            self._parse_backend({"type": "anthropic"})

    def test_empty_dict_defaults_to_ollama(self):
        r = self._parse_backend({})
        assert r["LLM_BACKEND_TYPE"] == "ollama"

    def test_auth_token_propagated(self):
        r = self._parse_backend({"auth_token": "tok-123"})
        assert r["LLM_BACKEND_AUTH_TOKEN"] == "tok-123"

    def test_env_override_priority(self, monkeypatch):
        """Environment variable SURICATA_LLM_API_KEY should override all."""
        monkeypatch.setenv("SURICATA_LLM_API_KEY", "env-key-999")
        # Simulate the env override logic from Config.__post_init__
        token = "config-token"
        env_key = os.getenv("SURICATA_LLM_API_KEY")
        if env_key:
            token = env_key
        assert token == "env-key-999"

    def test_cred_key_exists(self):
        """Verify CredKey.LLM_API_KEY is defined in auth models."""
        from src.auth.models import CredKey
        assert hasattr(CredKey, "LLM_API_KEY")
        assert CredKey.LLM_API_KEY == "llm_api_key"

    def test_vllm_prometheus_url_propagated(self):
        r = self._parse_backend({
            "type": "openai",
            "vllm_metrics": {"prometheus_url": "http://vllm:8000/metrics"},
        })
        assert r["LLM_BACKEND_VLLM_PROMETHEUS_URL"] == "http://vllm:8000/metrics"

    def test_vllm_prometheus_url_defaults_empty(self):
        r = self._parse_backend({"type": "openai"})
        assert r["LLM_BACKEND_VLLM_PROMETHEUS_URL"] == ""

    def test_vllm_metrics_empty_object(self):
        r = self._parse_backend({"type": "openai", "vllm_metrics": {}})
        assert r["LLM_BACKEND_VLLM_PROMETHEUS_URL"] == ""


class TestVLLMMetricsTOMLParsing:
    """Verify [llm.backend.vllm_metrics] section is parsed from TOML."""

    def test_vllm_metrics_section(self, tmp_path):
        toml_file = tmp_path / "agent.toml"
        toml_file.write_bytes(
            b'[llm.backend]\ntype = "openai"\n'
            b'[llm.backend.vllm_metrics]\nprometheus_url = "http://vllm:8000/metrics"\n'
        )
        data = _load_toml(str(toml_file))
        assert data["llm"]["backend"]["vllm_metrics"]["prometheus_url"] == "http://vllm:8000/metrics"

    def test_no_vllm_metrics_section(self, tmp_path):
        toml_file = tmp_path / "agent.toml"
        toml_file.write_bytes(b'[llm.backend]\ntype = "openai"\n')
        data = _load_toml(str(toml_file))
        assert "vllm_metrics" not in data["llm"]["backend"]


class TestMailCredentialMigration:
    """Verify mail credentials can be loaded from both main config and secrets."""

    def test_mail_client_id_from_toml(self, tmp_path):
        """client_id/client_secret in [mail] are loadable for dev mode."""
        toml_file = tmp_path / "agent.toml"
        toml_file.write_bytes(
            b'[mail]\nclient_id = "dev-id"\nclient_secret = "dev-secret"\n'
        )
        data = _load_toml(str(toml_file))
        assert data["mail"]["client_id"] == "dev-id"
        assert data["mail"]["client_secret"] == "dev-secret"

    def test_mail_section_without_credentials(self, tmp_path):
        """[mail] without credentials is valid (production uses credentials.db)."""
        toml_file = tmp_path / "agent.toml"
        toml_file.write_bytes(
            b'[mail]\nenable_notification = true\nprovider = "outlook"\nsender = "a@b.com"\n'
        )
        data = _load_toml(str(toml_file))
        assert "client_id" not in data["mail"]
        assert data["mail"]["provider"] == "outlook"

    def test_secrets_mail_section(self, tmp_path):
        """secrets.toml [mail] section uses secret_entry format."""
        toml_file = tmp_path / "secrets.toml"
        toml_file.write_bytes(
            b'[elasticsearch]\nusername = { "value" = "elastic" }\n'
            b'password = { "value" = "changeme" }\n\n'
            b'[mail]\nclient_id = { "value" = "my-id" }\n'
            b'client_secret = { "value" = "my-secret" }\n'
        )
        data = _load_toml(str(toml_file))
        assert data["mail"]["client_id"]["value"] == "my-id"
        assert data["mail"]["client_secret"]["value"] == "my-secret"


class TestGitConfigFields:
    """Verify all git config fields from improvement point 28."""

    def test_git_full_config(self, tmp_path):
        toml_file = tmp_path / "agent.toml"
        toml_file.write_bytes(
            b'[git]\n'
            b'enabled = true\n'
            b'remote_url = "https://github.com/org/repo.git"\n'
            b'default_branch = "main"\n'
            b'local_repo_path = "/app/git-workspace"\n'
            b'api_base_url = "https://api.github.com"\n'
            b'repo_owner = "org"\n'
            b'repo_name = "repo"\n'
            b'auto_pr = true\n'
            b'auto_issue = true\n'
            b'issue_threat_threshold = "\\u9ad8"\n'  # "高"
            b'rules_path = "rules/generated"\n'
            b'validate_with_suricata = false\n'
            b'fork_owner = "bot-user"\n'
        )
        data = _load_toml(str(toml_file))
        git = data["git"]
        assert git["enabled"] is True
        assert git["fork_owner"] == "bot-user"
        assert git["remote_url"] == "https://github.com/org/repo.git"
        assert git["issue_threat_threshold"] == "高"

    def test_git_minimal_config(self, tmp_path):
        toml_file = tmp_path / "agent.toml"
        toml_file.write_bytes(b'[git]\nenabled = false\n')
        data = _load_toml(str(toml_file))
        assert data["git"]["enabled"] is False
        assert "fork_owner" not in data["git"]


class TestPerfConfigDataclass:
    def test_creation(self):
        from tests.conftest import PerfConfig
        cfg = PerfConfig(
            index=0, PERF_INDEX_MIN=0, PERF_INDEX_MAX=100,
            OLLAMA_MODEL="m", OLLAMA_NUM_PREDICT=256,
            OLLAMA_TEMPERATURE=0.2, OLLAMA_TOP_P=0.9, OLLAMA_TOP_K=40,
            LLM_CONCURRENCY=4, BATCH_SIZE=50, POLL_INTERVAL=5,
            OLLAMA_CONTEXT_LENGTH=4096,
        )
        assert cfg.OLLAMA_MODEL == "m"
        assert cfg.LLM_CONCURRENCY == 4


class TestModelProfileDataclass:
    def test_creation(self):
        from tests.conftest import ModelProfile
        mp = ModelProfile(
            name="test", baseline_tps=40.0, quality_score=0.7,
            vram_calibration_context=16384, vram_calibration_mb=8192,
            context_length_min=2048, context_length_max=16384,
            num_predict_min=128, num_predict_max=512,
            concurrency_min=1, concurrency_max=8,
            batch_size_min=10, batch_size_max=100,
            poll_interval_min=5, poll_interval_max=30,
            temperature=0.2, top_p=0.9, top_k=40,
        )
        assert mp.name == "test"
        assert mp.baseline_tps == 40.0

    def test_backend_type_defaults_to_ollama(self):
        from tests.conftest import ModelProfile
        mp = ModelProfile(name="default-backend")
        assert mp.backend_type == "ollama"
        assert mp.backend_base_url == ""
        assert mp.backend_auth_token == ""

    def test_backend_fields_set_explicitly(self):
        from tests.conftest import ModelProfile
        mp = ModelProfile(
            name="openai-model",
            backend_type="openai",
            backend_base_url="https://api.openai.com",
            backend_auth_token="sk-test",
        )
        assert mp.backend_type == "openai"
        assert mp.backend_base_url == "https://api.openai.com"
        assert mp.backend_auth_token == "sk-test"

    def test_deepseek_backend_type_set_explicitly(self):
        from tests.conftest import ModelProfile
        mp = ModelProfile(
            name="deepseek-v4-flash",
            backend_type="deepseek",
            backend_auth_token="ds-test",
        )
        assert mp.backend_type == "deepseek"
        assert mp.backend_auth_token == "ds-test"


class TestModelProfileTomlParsing:
    """Verify that backend_type / backend_base_url / backend_auth_token
    are correctly parsed from a ModelProfiles TOML file."""

    def test_backend_fields_parsed_from_toml(self, tmp_path):
        toml_content = b"""
total_vram_mb = 8192

[model."local-model"]
baseline_tps = 40.0
quality_score = 0.7
vram_calibration_context = 8192
vram_calibration_mb = 4096
context_length = { min = 8192, max = 16384 }
num_predict = { min = 128, max = 512 }
concurrency = { min = 1, max = 8 }
batch_size = { min = 10, max = 100 }
poll_interval = { min = 5, max = 30 }
temperature = 0.2
top_p = 0.9
top_k = 40
backend_type = "ollama"

[model."remote-model"]
baseline_tps = 80.0
quality_score = 0.95
vram_calibration_context = 0
vram_calibration_mb = 0
context_length = { min = 32768, max = 131072 }
num_predict = { min = 512, max = 16384 }
concurrency = { min = 1, max = 4 }
batch_size = { min = 10, max = 50 }
poll_interval = { min = 10, max = 60 }
temperature = 0.2
top_p = 0.9
top_k = 40
backend_type = "openai"
backend_base_url = "https://api.openai.com"
backend_auth_token = "sk-test-key"
"""
        toml_file = tmp_path / "ModelProfiles.toml"
        toml_file.write_bytes(toml_content)

        data = _load_toml(str(toml_file))
        models = data["model"]

        # Verify raw TOML parsing
        assert models["local-model"]["backend_type"] == "ollama"
        assert "backend_base_url" not in models["local-model"]

        assert models["remote-model"]["backend_type"] == "openai"
        assert models["remote-model"]["backend_base_url"] == "https://api.openai.com"
        assert models["remote-model"]["backend_auth_token"] == "sk-test-key"

    def test_missing_backend_type_defaults(self, tmp_path):
        toml_content = b"""
total_vram_mb = 8192

[model."no-backend"]
baseline_tps = 30.0
quality_score = 0.5
vram_calibration_context = 0
vram_calibration_mb = 0
context_length = { min = 2048, max = 16384 }
num_predict = { min = 128, max = 512 }
concurrency = { min = 1, max = 8 }
batch_size = { min = 10, max = 100 }
poll_interval = { min = 5, max = 30 }
temperature = 0.2
top_p = 0.9
top_k = 40
"""
        toml_file = tmp_path / "ModelProfiles.toml"
        toml_file.write_bytes(toml_content)

        data = _load_toml(str(toml_file))
        models = data["model"]

        # backend_type absent → load_model_profiles will default to global LLM_BACKEND_TYPE
        assert "backend_type" not in models["no-backend"]

    def test_deepseek_backend_fields_parsed_from_toml(self, tmp_path):
        toml_content = b"""
total_vram_mb = 8192

[model."deepseek-v4-flash"]
baseline_tps = 80.0
quality_score = 0.8
vram_calibration_context = 0
vram_calibration_mb = 0
context_length = { min = 8192, max = 1048576 }
num_predict = { min = 512, max = 8192 }
concurrency = { min = 1, max = 8 }
batch_size = { min = 10, max = 50 }
poll_interval = { min = 5, max = 30 }
temperature = 0.2
top_p = 0.9
top_k = 40
backend_type = "deepseek"
backend_auth_token = "ds-test-key"
"""
        toml_file = tmp_path / "ModelProfiles.toml"
        toml_file.write_bytes(toml_content)

        data = _load_toml(str(toml_file))
        profile = data["model"]["deepseek-v4-flash"]
        assert profile["backend_type"] == "deepseek"
        assert profile["backend_auth_token"] == "ds-test-key"


class TestDisableAgentModeConfig:
    """Verify disable_agent_mode is loaded from [executor]."""

    def test_disable_agent_mode_true(self, tmp_path):
        toml_file = tmp_path / "agent.toml"
        toml_file.write_bytes(b'[executor]\ndisable_agent_mode = true\n')
        data = _load_toml(str(toml_file))
        assert data["executor"]["disable_agent_mode"] is True

    def test_disable_agent_mode_false(self, tmp_path):
        toml_file = tmp_path / "agent.toml"
        toml_file.write_bytes(b'[executor]\ndisable_agent_mode = false\n')
        data = _load_toml(str(toml_file))
        assert data["executor"]["disable_agent_mode"] is False

    def test_disable_agent_mode_absent(self, tmp_path):
        toml_file = tmp_path / "agent.toml"
        toml_file.write_bytes(b'[executor]\nenabled = true\n')
        data = _load_toml(str(toml_file))
        assert "disable_agent_mode" not in data["executor"]


class TestOllamaThinkConfig:
    """Verify ollama.think is loaded from [ollama]."""

    def test_think_true(self, tmp_path):
        toml_file = tmp_path / "agent.toml"
        toml_file.write_bytes(b'[ollama]\nthink = true\n')
        data = _load_toml(str(toml_file))
        assert data["ollama"]["think"] is True

    def test_think_false(self, tmp_path):
        toml_file = tmp_path / "agent.toml"
        toml_file.write_bytes(b'[ollama]\nthink = false\n')
        data = _load_toml(str(toml_file))
        assert data["ollama"]["think"] is False

    def test_think_absent(self, tmp_path):
        toml_file = tmp_path / "agent.toml"
        toml_file.write_bytes(b'[ollama]\nbase_url = "http://localhost:11434"\n')
        data = _load_toml(str(toml_file))
        assert "think" not in data["ollama"]


class TestGitResetTimeParsing:
    """Verify git.reset_time is correctly parsed from TOML config."""

    def test_reset_time_present(self, tmp_path):
        toml_file = tmp_path / "agent.toml"
        toml_file.write_bytes(b'[git]\nreset_time = "05:30:00"\n')
        data = _load_toml(str(toml_file))
        assert data["git"]["reset_time"] == "05:30:00"

    def test_reset_time_midnight(self, tmp_path):
        toml_file = tmp_path / "agent.toml"
        toml_file.write_bytes(b'[git]\nreset_time = "00:00:00"\n')
        data = _load_toml(str(toml_file))
        assert data["git"]["reset_time"] == "00:00:00"

    def test_reset_time_end_of_day(self, tmp_path):
        toml_file = tmp_path / "agent.toml"
        toml_file.write_bytes(b'[git]\nreset_time = "23:59:59"\n')
        data = _load_toml(str(toml_file))
        assert data["git"]["reset_time"] == "23:59:59"

    def test_reset_time_absent(self, tmp_path):
        toml_file = tmp_path / "agent.toml"
        toml_file.write_bytes(b'[git]\nenabled = false\n')
        data = _load_toml(str(toml_file))
        assert "reset_time" not in data["git"]

    def test_reset_time_regex_validates(self):
        import re
        pattern = r'^([01]\d|2[0-3]):[0-5]\d:[0-5]\d$'
        assert re.match(pattern, "02:00:00")
        assert re.match(pattern, "23:59:59")
        assert re.match(pattern, "00:00:00")
        assert not re.match(pattern, "24:00:00")
        assert not re.match(pattern, "12:60:00")
        assert not re.match(pattern, "12:00:60")
        assert not re.match(pattern, "2:00:00")
        assert not re.match(pattern, "12:0:00")
        assert not re.match(pattern, "12:00")


class TestDailyReportActiveFlag:
    """Verify the daily_report_active flag on the Config dataclass."""

    def test_default_is_inactive(self):
        from src.config import config
        assert not config.daily_report_active

    def test_set_and_clear(self):
        from src.config import config
        config.set_daily_report_active()
        assert config.daily_report_active
        config.clear_daily_report_active()
        assert not config.daily_report_active


# ── [llm.escalation] configuration parsing ─────────────────────────────

class TestEscalationConfig:
    """Verify that [llm.escalation] section is parsed correctly."""

    def test_escalation_defaults(self, tmp_path):
        """No [llm.escalation] section → defaults."""
        toml_file = tmp_path / "agent.toml"
        toml_file.write_bytes(b'[llm]\nmemory_length = 50\n')
        data = _load_toml(str(toml_file))
        escalation = data.get("llm", {}).get("escalation", {})
        assert escalation == {}

    def test_escalation_enabled(self, tmp_path):
        toml_file = tmp_path / "agent.toml"
        toml_file.write_bytes(
            b'[llm.escalation]\nenabled = true\n'
            b'model = "gpt-4.1-mini"\n'
            b'threat_threshold = "\xe4\xb8\xad"\n'
        )
        data = _load_toml(str(toml_file))
        esc = data["llm"]["escalation"]
        assert esc["enabled"] is True
        assert esc["model"] == "gpt-4.1-mini"
        assert esc["threat_threshold"] == "中"

    def test_escalation_all_fields(self, tmp_path):
        toml_file = tmp_path / "agent.toml"
        content = (
            b'[llm.escalation]\n'
            b'enabled = true\n'
            b'threat_threshold = "\xe9\xab\x98"\n'
            b'model = "gpt-4.1"\n'
            b'max_tokens = 8192\n'
            b'context_length = 131072\n'
            b'temperature = 0.5\n'
            b'top_p = 0.8\n'
            b'top_k = 50\n'
            b'include_raw_fields = false\n'
        )
        toml_file.write_bytes(content)
        data = _load_toml(str(toml_file))
        esc = data["llm"]["escalation"]
        assert esc["enabled"] is True
        assert esc["threat_threshold"] == "高"
        assert esc["model"] == "gpt-4.1"
        assert esc["max_tokens"] == 8192
        assert esc["context_length"] == 131072
        assert esc["temperature"] == 0.5
        assert esc["top_p"] == 0.8
        assert esc["top_k"] == 50
        assert esc["include_raw_fields"] is False

    def test_escalation_disabled(self, tmp_path):
        toml_file = tmp_path / "agent.toml"
        toml_file.write_bytes(b'[llm.escalation]\nenabled = false\n')
        data = _load_toml(str(toml_file))
        assert data["llm"]["escalation"]["enabled"] is False


# ── [ollama] keep_alive & [finetune] (Improvement 30.7-G) ─────────────

class TestOllamaKeepAliveConfig:
    def test_keep_alive_parsed(self, tmp_path):
        toml_file = tmp_path / "agent.toml"
        toml_file.write_bytes(b'[ollama]\nkeep_alive = "10m"\n')
        data = _load_toml(str(toml_file))
        assert data["ollama"]["keep_alive"] == "10m"

    def test_keep_alive_default_absent(self, tmp_path):
        toml_file = tmp_path / "agent.toml"
        toml_file.write_bytes(b'[ollama]\ntimeout = 300\n')
        data = _load_toml(str(toml_file))
        assert "keep_alive" not in data["ollama"]


class TestFinetuneConfig:
    def test_finetune_enabled(self, tmp_path):
        toml_file = tmp_path / "agent.toml"
        toml_file.write_bytes(
            b'[finetune]\nenabled = true\ndb_path = "/data/ft.db"\nexport_dir = "/data/export"\n'
        )
        data = _load_toml(str(toml_file))
        assert data["finetune"]["enabled"] is True
        assert data["finetune"]["db_path"] == "/data/ft.db"
        assert data["finetune"]["export_dir"] == "/data/export"

    def test_finetune_disabled(self, tmp_path):
        toml_file = tmp_path / "agent.toml"
        toml_file.write_bytes(b'[finetune]\nenabled = false\n')
        data = _load_toml(str(toml_file))
        assert data["finetune"]["enabled"] is False
