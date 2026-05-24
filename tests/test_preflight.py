#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         test_preflight.py
Description:  Tests for pre-flight configuration validation and schema extraction.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from deploy.preflight import (
    _extract_deploy_dirs,
    _extract_deploy_files,
    _validate_agent_memory_cross_constraints,
)


# ═══════════════════════════════════════════════════════════════════════
# _extract_deploy_dirs
# ═══════════════════════════════════════════════════════════════════════

class TestExtractDeployDirs:
    def test_basic_extraction(self):
        schema = {
            "properties": {
                "capabilities_dir": {
                    "type": "string",
                    "x-deploy-dir": True,
                    "x-deploy-dir-schema": "cap.schema.json",
                },
            },
        }
        config = {"capabilities_dir": "configs/capabilities"}
        result = _extract_deploy_dirs(schema, config)
        assert result == [("configs/capabilities", "cap.schema.json")]

    def test_no_companion_schema(self):
        schema = {
            "properties": {
                "some_dir": {
                    "type": "string",
                    "x-deploy-dir": True,
                },
            },
        }
        config = {"some_dir": "data/stuff"}
        result = _extract_deploy_dirs(schema, config)
        assert result == [("data/stuff", None)]

    def test_missing_key_in_config(self):
        schema = {
            "properties": {
                "capabilities_dir": {
                    "type": "string",
                    "x-deploy-dir": True,
                },
            },
        }
        config = {}
        result = _extract_deploy_dirs(schema, config)
        assert result == []

    def test_empty_value_skipped(self):
        schema = {
            "properties": {
                "d": {"type": "string", "x-deploy-dir": True},
            },
        }
        config = {"d": "   "}
        assert _extract_deploy_dirs(schema, config) == []

    def test_nested_object(self):
        schema = {
            "properties": {
                "executor": {
                    "type": "object",
                    "properties": {
                        "caps_dir": {
                            "type": "string",
                            "x-deploy-dir": True,
                            "x-deploy-dir-schema": "schema.json",
                        },
                    },
                },
            },
        }
        config = {"executor": {"caps_dir": "configs/caps"}}
        result = _extract_deploy_dirs(schema, config)
        assert result == [("configs/caps", "schema.json")]

    def test_multiple_dirs(self):
        schema = {
            "properties": {
                "dir_a": {"type": "string", "x-deploy-dir": True},
                "dir_b": {
                    "type": "string",
                    "x-deploy-dir": True,
                    "x-deploy-dir-schema": "b.schema.json",
                },
            },
        }
        config = {"dir_a": "path/a", "dir_b": "path/b"}
        result = _extract_deploy_dirs(schema, config)
        assert len(result) == 2
        assert ("path/a", None) in result
        assert ("path/b", "b.schema.json") in result


# ═══════════════════════════════════════════════════════════════════════
# Capability declaration schema validation (integration-style)
# ═══════════════════════════════════════════════════════════════════════

class TestCapabilityDeclarationSchema:
    """Validate that the capability-declaration schema correctly accepts
    and rejects TOML-like structures."""

    @pytest.fixture
    def schema(self) -> dict:
        schema_path = (
            Path(__file__).resolve().parent.parent
            / "configs" / "constraints" / "capability-declaration.schema.json"
        )
        return json.loads(schema_path.read_text(encoding="utf-8"))

    @pytest.fixture
    def jsonschema(self):
        js = pytest.importorskip("jsonschema")
        return js

    def test_valid_minimal(self, schema, jsonschema):
        data = {
            "capability": {
                "ping": {
                    "handler": "ping_handler",
                },
            },
        }
        jsonschema.validate(instance=data, schema=schema)

    def test_valid_full(self, schema, jsonschema):
        data = {
            "capability": {
                "rule_suggest": {
                    "description": "Suggest a rule",
                    "handler": "rule_handler",
                    "allowed_roles": ["Agent", "Owner"],
                    "enabled": True,
                    "params": {
                        "text": {
                            "type": "string",
                            "required": True,
                            "pattern": "^alert .+",
                        },
                        "priority": {
                            "type": "integer",
                            "required": False,
                            "min": 1,
                            "max": 10,
                        },
                    },
                    "rate_limit": {
                        "max_calls": 30,
                        "window_seconds": 3600,
                    },
                    "paths": {
                        "read": {"dirs": ["/app/rules"]},
                        "write": {"dirs": ["/app/rules"]},
                    },
                },
            },
        }
        jsonschema.validate(instance=data, schema=schema)

    def test_missing_capability_section(self, schema, jsonschema):
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance={}, schema=schema)

    def test_empty_capability_section(self, schema, jsonschema):
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance={"capability": {}}, schema=schema)

    def test_missing_handler(self, schema, jsonschema):
        data = {
            "capability": {
                "bad": {"description": "No handler"},
            },
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=schema)

    def test_empty_handler(self, schema, jsonschema):
        data = {
            "capability": {
                "bad": {"handler": ""},
            },
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=schema)

    def test_invalid_role(self, schema, jsonschema):
        data = {
            "capability": {
                "bad": {
                    "handler": "h",
                    "allowed_roles": ["Agent", "SuperAdmin"],
                },
            },
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=schema)

    def test_invalid_param_type(self, schema, jsonschema):
        data = {
            "capability": {
                "bad": {
                    "handler": "h",
                    "params": {
                        "x": {"type": "bytes"},
                    },
                },
            },
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=schema)

    def test_unknown_param_field(self, schema, jsonschema):
        data = {
            "capability": {
                "bad": {
                    "handler": "h",
                    "params": {
                        "x": {"type": "string", "unknown_field": True},
                    },
                },
            },
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=schema)

    def test_unknown_capability_field(self, schema, jsonschema):
        data = {
            "capability": {
                "bad": {
                    "handler": "h",
                    "unknown_top_field": True,
                },
            },
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=schema)

    def test_negative_rate_limit_window(self, schema, jsonschema):
        data = {
            "capability": {
                "bad": {
                    "handler": "h",
                    "rate_limit": {"max_calls": 5, "window_seconds": 0},
                },
            },
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=schema)

    def test_existing_examples_toml_passes(self, schema, jsonschema):
        """Validate that the shipped capability TOML files pass the schema."""
        import tomllib
        caps_dir = (
            Path(__file__).resolve().parent.parent
            / "configs" / "capabilities"
        )
        toml_files = [f for f in caps_dir.glob("*.toml") if f.name != "examples.toml"]
        assert toml_files, "No capability TOML files found besides examples.toml"
        for toml_path in toml_files:
            with open(toml_path, "rb") as fh:
                data = tomllib.load(fh)
            jsonschema.validate(instance=data, schema=schema)


# ═══════════════════════════════════════════════════════════════════════
# Agent-config schema validation (integration-style)
# ═══════════════════════════════════════════════════════════════════════

class TestAgentConfigSchemaValidation:
    """Validate the shipped config template against agent-config.schema.json."""

    @pytest.fixture
    def schema(self) -> dict:
        schema_path = (
            Path(__file__).resolve().parent.parent
            / "configs" / "constraints" / "agent-config.schema.json"
        )
        return json.loads(schema_path.read_text(encoding="utf-8"))

    @pytest.fixture
    def jsonschema(self):
        js = pytest.importorskip("jsonschema")
        return js

    def test_config_template_passes(self, schema, jsonschema):
        """The shipped config_templates/suricata-llm-agent.toml must validate."""
        import tomllib
        template_path = (
            Path(__file__).resolve().parent.parent
            / "config_templates" / "suricata-llm-agent.toml"
        )
        with open(template_path, "rb") as fh:
            data = tomllib.load(fh)
        jsonschema.validate(instance=data, schema=schema)

    def test_git_fork_owner_string(self, schema, jsonschema):
        """fork_owner must be a string."""
        data = {"elasticsearch": {"host": "http://es:9200", "index_pattern": "x"},
                "processing": {"batch_size": 1, "poll_interval": 1, "max_retries": 0, "retry_interval": 1},
                "filter": {},
                "llm": {},
                "ollama": {"base_url": "http://localhost:11434", "timeout": 300},
                "perf": {"model_profiles_file": "m.toml", "auto_select": True},
                "logging": {"output_to_elasticsearch": False},
                "git": {"fork_owner": 123}}
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=schema)

    def test_git_unknown_property_rejected(self, schema, jsonschema):
        """additionalProperties: false on [git] rejects unknown keys."""
        data = {"elasticsearch": {"host": "http://es:9200", "index_pattern": "x"},
                "processing": {"batch_size": 1, "poll_interval": 1, "max_retries": 0, "retry_interval": 1},
                "filter": {},
                "llm": {},
                "ollama": {"base_url": "http://localhost:11434", "timeout": 300},
                "perf": {"model_profiles_file": "m.toml", "auto_select": True},
                "logging": {"output_to_elasticsearch": False},
                "git": {"unknown_key": "nope"}}
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=schema)

    def test_proto_pair_memory_options_validate(self, schema, jsonschema):
        data = self._minimal_data(llm={
            "memory_mode": "proto_pair",
            "memory_max_pairs": 10,
            "memory_per_pair_length": 5,
            "memory_lat_lru_evict_seconds": 3600.0,
            "memory_maxpair_lru_evict": 2,
        })
        jsonschema.validate(instance=data, schema=schema)

    # -- mail credential migration -----------------------------------------

    def _minimal_data(self, **overrides) -> dict:
        """Return a minimal valid config dict, with optional section overrides."""
        base = {
            "elasticsearch": {"host": "http://es:9200", "index_pattern": "x"},
            "processing": {"batch_size": 1, "poll_interval": 1,
                           "max_retries": 0, "retry_interval": 1},
            "filter": {},
            "llm": {},
            "ollama": {"base_url": "http://localhost:11434", "timeout": 300},
            "perf": {"model_profiles_file": "m.toml", "auto_select": True},
            "logging": {"output_to_elasticsearch": False},
        }
        base.update(overrides)
        return base

    def test_mail_client_id_rejected(self, schema, jsonschema):
        """client_id has been migrated to secrets.toml; schema must reject it."""
        data = self._minimal_data(
            mail={"provider": "outlook", "client_id": "some-id"})
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=schema)

    def test_mail_client_secret_rejected(self, schema, jsonschema):
        """client_secret has been migrated to secrets.toml; schema must reject it."""
        data = self._minimal_data(
            mail={"provider": "outlook", "client_secret": "some-secret"})
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=schema)

    # -- git.remote_url anyOf validation -----------------------------------

    def test_git_remote_url_empty_accepted(self, schema, jsonschema):
        """An empty remote_url is the valid default in the template."""
        data = self._minimal_data(git={"remote_url": ""})
        jsonschema.validate(instance=data, schema=schema)

    def test_git_remote_url_valid_https(self, schema, jsonschema):
        """A proper HTTPS URL must pass."""
        data = self._minimal_data(
            git={"remote_url": "https://github.com/org/repo.git"})
        jsonschema.validate(instance=data, schema=schema)

    def test_git_remote_url_invalid_string_rejected(self, schema, jsonschema):
        """A non-empty, non-URL string must be rejected."""
        data = self._minimal_data(git={"remote_url": "not-a-url"})
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=schema)

    def test_top_level_unknown_section_rejected(self, schema, jsonschema):
        """Unknown top-level sections are rejected by additionalProperties: false."""
        data = self._minimal_data(unknown_section={"key": "value"})
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=schema)

    def test_git_issue_threat_threshold_enum(self, schema, jsonschema):
        """issue_threat_threshold only allows recognised threat levels."""
        data = self._minimal_data(
            git={"issue_threat_threshold": "超严重"})
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=schema)

    def test_git_fork_owner_empty_accepted(self, schema, jsonschema):
        """An empty fork_owner (same-repo mode) is valid."""
        data = self._minimal_data(git={"fork_owner": ""})
        jsonschema.validate(instance=data, schema=schema)

    def test_git_fork_owner_with_value_accepted(self, schema, jsonschema):
        """A non-empty fork_owner (fork mode) is valid."""
        data = self._minimal_data(git={"fork_owner": "capri-ai-bot"})
        jsonschema.validate(instance=data, schema=schema)

    def test_git_fork_owner_invalid_format_rejected(self, schema, jsonschema):
        """fork_owner with invalid GitHub username format is rejected."""
        for bad_name in ["-leading-dash", "trailing-dash-", "--double"]:
            data = self._minimal_data(git={"fork_owner": bad_name})
            with pytest.raises(jsonschema.ValidationError):
                jsonschema.validate(instance=data, schema=schema)

    def test_executor_disable_agent_mode_accepted(self, schema, jsonschema):
        """disable_agent_mode boolean in [executor] is valid."""
        data = self._minimal_data()
        data["executor"] = {"disable_agent_mode": True}
        jsonschema.validate(instance=data, schema=schema)

    def test_executor_disable_agent_mode_non_bool_rejected(self, schema, jsonschema):
        """disable_agent_mode must be a boolean."""
        data = self._minimal_data()
        data["executor"] = {"disable_agent_mode": "yes"}
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=schema)

    def test_ollama_think_accepted(self, schema, jsonschema):
        """think boolean in [ollama] is valid."""
        data = self._minimal_data()
        data["ollama"]["think"] = True
        jsonschema.validate(instance=data, schema=schema)

    def test_ollama_think_non_bool_rejected(self, schema, jsonschema):
        """think must be a boolean."""
        data = self._minimal_data()
        data["ollama"]["think"] = "yes"
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=schema)

    def test_backend_vllm_metrics_accepted(self, schema, jsonschema):
        """[llm.backend.vllm_metrics] with prometheus_url passes."""
        data = self._minimal_data()
        data["llm"]["backend"] = {
            "type": "openai",
            "vllm_metrics": {"prometheus_url": "http://vllm:8000/metrics"},
        }
        jsonschema.validate(instance=data, schema=schema)

    def test_backend_vllm_metrics_invalid_url_rejected(self, schema, jsonschema):
        """prometheus_url must match the URL pattern."""
        data = self._minimal_data()
        data["llm"]["backend"] = {
            "type": "openai",
            "vllm_metrics": {"prometheus_url": "not-a-url"},
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=schema)

    def test_backend_vllm_metrics_unknown_property_rejected(self, schema, jsonschema):
        """Unknown properties in [llm.backend.vllm_metrics] are rejected."""
        data = self._minimal_data()
        data["llm"]["backend"] = {
            "type": "openai",
            "vllm_metrics": {
                "prometheus_url": "http://vllm:8000/metrics",
                "extra": "bad",
            },
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=schema)


class TestAgentMemoryCrossConstraints:
    def test_non_proto_mode_allows_legacy_small_max_pairs(self):
        _validate_agent_memory_cross_constraints({
            "llm": {"memory_mode": "pair", "memory_max_pairs": 1},
        })

    def test_proto_pair_rejects_small_max_pairs(self):
        with pytest.raises(SystemExit):
            _validate_agent_memory_cross_constraints({
                "llm": {"memory_mode": "proto_pair", "memory_max_pairs": 2},
            })

    def test_proto_pair_rejects_bad_explicit_evict_count(self):
        with pytest.raises(SystemExit):
            _validate_agent_memory_cross_constraints({
                "llm": {
                    "memory_mode": "proto_pair_rolling",
                    "memory_max_pairs": 5,
                    "memory_maxpair_lru_evict": 5,
                },
            })

    def test_proto_pair_allows_auto_evict_count(self):
        _validate_agent_memory_cross_constraints({
            "llm": {
                "memory_mode": "proto_pair",
                "memory_max_pairs": 5,
                "memory_maxpair_lru_evict": 0,
                "memory_lat_lru_evict_seconds": 30,
            },
        })


# ═══════════════════════════════════════════════════════════════════════
# Secrets schema validation
# ═══════════════════════════════════════════════════════════════════════

class TestSecretsSchemaValidation:
    """Validate secrets.toml against secrets.schema.json."""

    @pytest.fixture
    def schema(self) -> dict:
        schema_path = (
            Path(__file__).resolve().parent.parent
            / "configs" / "constraints" / "secrets.schema.json"
        )
        return json.loads(schema_path.read_text(encoding="utf-8"))

    @pytest.fixture
    def jsonschema(self):
        js = pytest.importorskip("jsonschema")
        return js

    def _minimal_secrets(self, **overrides) -> dict:
        base = {
            "elasticsearch": {
                "username": {"value": "elastic"},
                "password": {"value": "changeme"},
            },
        }
        base.update(overrides)
        return base

    def test_secrets_template_passes(self, schema, jsonschema):
        """The shipped config_templates/secrets.toml must validate."""
        import tomllib
        template_path = (
            Path(__file__).resolve().parent.parent
            / "config_templates" / "secrets.toml"
        )
        with open(template_path, "rb") as fh:
            data = tomllib.load(fh)
        jsonschema.validate(instance=data, schema=schema)

    def test_minimal_valid(self, schema, jsonschema):
        """Minimal config with only required elasticsearch section."""
        data = self._minimal_secrets()
        jsonschema.validate(instance=data, schema=schema)

    def test_mail_section_valid(self, schema, jsonschema):
        """Mail section with client_id and client_secret passes."""
        data = self._minimal_secrets(
            mail={
                "client_id": {"value": "test-client-id"},
                "client_secret": {"value": "test-secret"},
            })
        jsonschema.validate(instance=data, schema=schema)

    def test_mail_unknown_property_rejected(self, schema, jsonschema):
        """Unknown properties in [mail] are rejected."""
        data = self._minimal_secrets(
            mail={
                "client_id": {"value": "test"},
                "unknown_field": {"value": "bad"},
            })
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=schema)

    def test_git_section_valid(self, schema, jsonschema):
        """Git section with token passes."""
        data = self._minimal_secrets(
            git={"token": {"value": "ghp_xxxx"}})
        jsonschema.validate(instance=data, schema=schema)

    def test_git_unknown_property_rejected(self, schema, jsonschema):
        """Unknown properties in [git] are rejected."""
        data = self._minimal_secrets(
            git={"token": {"value": "ghp_xxxx"}, "extra": {"value": "bad"}})
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=schema)

    def test_top_level_unknown_section_rejected(self, schema, jsonschema):
        """Unknown top-level sections are rejected."""
        data = self._minimal_secrets(unknown={"key": "value"})
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=schema)

    def test_elasticsearch_unknown_property_rejected(self, schema, jsonschema):
        """Unknown properties in [elasticsearch] are rejected."""
        data = {
            "elasticsearch": {
                "username": {"value": "elastic"},
                "password": {"value": "changeme"},
                "extra_field": {"value": "bad"},
            },
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=schema)

    def test_auth_owner_valid(self, schema, jsonschema):
        """Auth section with owner sub-section passes."""
        data = self._minimal_secrets(
            auth={
                "jwt_secret": {"value": "my-jwt-secret"},
                "owner": {
                    "username": "admin",
                    "password": "12345678",
                    "email": "admin@example.com",
                },
            })
        jsonschema.validate(instance=data, schema=schema)

    def test_auth_owner_short_password_rejected(self, schema, jsonschema):
        """Owner password must be at least 8 characters."""
        data = self._minimal_secrets(
            auth={
                "owner": {
                    "username": "admin",
                    "password": "short",
                    "email": "admin@example.com",
                },
            })
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=schema)

    def test_secret_entry_requires_value(self, schema, jsonschema):
        """Secret entries must have a 'value' field."""
        data = {
            "elasticsearch": {
                "username": {},
                "password": {"value": "changeme"},
            },
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=schema)

    def test_secret_entry_value_nonempty(self, schema, jsonschema):
        """Secret entry value must be non-empty."""
        data = {
            "elasticsearch": {
                "username": {"value": ""},
                "password": {"value": "changeme"},
            },
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=schema)

    def test_llm_section_valid(self, schema, jsonschema):
        """LLM section with api_key passes."""
        data = self._minimal_secrets(
            llm={"api_key": {"value": "sk-test-key"}})
        jsonschema.validate(instance=data, schema=schema)

    def test_llm_unknown_property_rejected(self, schema, jsonschema):
        """Unknown properties in [llm] are rejected."""
        data = self._minimal_secrets(
            llm={"api_key": {"value": "sk-test"}, "extra": {"value": "bad"}})
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=data, schema=schema)


# ═══════════════════════════════════════════════════════════════════════
# Deploy credential provisioning logic
# ═══════════════════════════════════════════════════════════════════════

class TestDeployLLMCredentialProvisioning:
    """Verify the LLM API key extraction logic used by deploy._provision_auth_db.

    These tests exercise the same credential-mapping algorithm without
    invoking the full _provision_auth_db (which requires sudo / host dirs).
    """

    @staticmethod
    def _extract_llm_key(secrets: dict, agent_conf: dict) -> str:
        """Replicate the LLM key extraction from deploy/main.py."""
        from src.auth.models import CredKey
        creds: dict = {}
        llm_sec = secrets.get("llm", {})
        llm_api_entry = llm_sec.get("api_key", {})
        if isinstance(llm_api_entry, dict) and llm_api_entry.get("value"):
            creds[CredKey.LLM_API_KEY] = str(llm_api_entry["value"])
        elif not creds.get(CredKey.LLM_API_KEY):
            backend_conf = agent_conf.get("llm", {}).get("backend", {})
            if backend_conf.get("auth_token"):
                creds[CredKey.LLM_API_KEY] = str(backend_conf["auth_token"])
        return creds.get(CredKey.LLM_API_KEY, "")

    def test_from_secrets_toml(self):
        """LLM API key from secrets.toml [llm].api_key takes priority."""
        result = self._extract_llm_key(
            secrets={"llm": {"api_key": {"value": "sk-from-secrets"}}},
            agent_conf={"llm": {"backend": {"auth_token": "sk-from-config"}}},
        )
        assert result == "sk-from-secrets"

    def test_fallback_to_agent_config(self):
        """Falls back to agent config auth_token when secrets.toml has no [llm]."""
        result = self._extract_llm_key(
            secrets={},
            agent_conf={"llm": {"backend": {"auth_token": "sk-from-config"}}},
        )
        assert result == "sk-from-config"

    def test_no_key_available(self):
        """Returns empty string when neither source provides a key."""
        result = self._extract_llm_key(secrets={}, agent_conf={})
        assert result == ""

    def test_empty_secrets_value_triggers_fallback(self):
        """An empty value in secrets.toml falls back to agent config."""
        result = self._extract_llm_key(
            secrets={"llm": {"api_key": {"value": ""}}},
            agent_conf={"llm": {"backend": {"auth_token": "sk-fallback"}}},
        )
        assert result == "sk-fallback"

    def test_secrets_value_not_dict_triggers_fallback(self):
        """A non-dict api_key entry falls back to agent config."""
        result = self._extract_llm_key(
            secrets={"llm": {"api_key": "bare-string"}},
            agent_conf={"llm": {"backend": {"auth_token": "sk-fallback"}}},
        )
        assert result == "sk-fallback"
