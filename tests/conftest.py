#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         conftest.py
Description:  Shared pytest fixtures and lightweight config stubs for testing.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import sys
import types
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock
import threading

import pytest


# ---------------------------------------------------------------------------
# Lightweight Config stub that does NOT trigger file I/O.
# Tests import `src.*` modules which do `from .config import config`.
# We intercept the module before any production code is loaded.
# ---------------------------------------------------------------------------

@dataclass
class PerfConfig:
    index: int = 0
    PERF_INDEX_MIN: int = 0
    PERF_INDEX_MAX: int = 999
    OLLAMA_MODEL: str = "test-model"
    OLLAMA_NUM_PREDICT: int = 256
    OLLAMA_TEMPERATURE: float = 0.2
    OLLAMA_TOP_P: float = 0.9
    OLLAMA_TOP_K: int = 40
    LLM_CONCURRENCY: int = 1
    BATCH_SIZE: int = 10
    POLL_INTERVAL: int = 5
    OLLAMA_CONTEXT_LENGTH: int = 4096


@dataclass
class ModelProfile:
    name: str = "test-model"
    baseline_tps: float = 40.0
    quality_score: float = 0.7
    vram_calibration_context: int = 16384
    vram_calibration_mb: int = 8192
    context_length_min: int = 2048
    context_length_max: int = 16384
    num_predict_min: int = 128
    num_predict_max: int = 512
    concurrency_min: int = 1
    concurrency_max: int = 8
    batch_size_min: int = 10
    batch_size_max: int = 100
    poll_interval_min: int = 5
    poll_interval_max: int = 30
    temperature: float = 0.2
    top_p: float = 0.9
    top_k: int = 40
    supports_tool_use: Optional[bool] = None
    backend_type: str = "ollama"
    backend_base_url: str = ""
    backend_auth_token: str = ""
    total_params_b: float = 0.0
    active_params_b: float = 0.0
    bytes_per_param: float = 0.0
    cost_per_1k_prompt: float = 0.0
    cost_per_1k_completion: float = 0.0
    max_requests_per_minute: int = 0


@dataclass
class FakeConfig:
    """Minimal Config stand-in for unit tests — no file I/O."""
    SOFTWARE_NAME: str = "test-agent"
    SOFTWARE_NAME_SUFFIX: str = "(Test)"
    SOFTWARE_VERSION: str = "0.0.1"
    SOFTWARE_AUTHOR: str = "test"
    SOFTWARE_LICENSE: str = "MIT"

    ES_HOST: str = "http://localhost:9200"
    ES_USER: str = "test"
    ES_PSWD: str = "test"
    ES_INDEX_PATTERN: str = "suricata-eve-*"

    BATCH_SIZE: int = 10
    POLL_INTERVAL: int = 5
    MAX_RETRIES: int = 3
    RETRY_INTERVAL: int = 5
    EMPTY_RUNS_BEFORE_INDEX_REFRESH: int = 50

    SUPPORTED_EVENT_TYPES: List[str] = field(default_factory=lambda: ["alert", "dns", "http", "tls"])
    SUPPORTED_L7_PROTOCOLS: List[str] = field(default_factory=lambda: ["dns", "http", "tls"])
    SUPPORTED_L4_PROTOCOLS: List[str] = field(default_factory=lambda: ["tcp", "udp"])
    SUPPORTED_L3_PROTOCOLS: List[str] = field(default_factory=lambda: ["ipv4", "ipv6"])
    ALLOWED_EVENT_TYPE: List[str] = field(default_factory=lambda: ["alert", "dns", "http", "tls"])
    ALLOWED_L7_PROTOCOL: List[str] = field(default_factory=lambda: ["dns", "http", "tls"])
    ALLOWED_L4_PROTOCOL: List[str] = field(default_factory=list)
    ALLOWED_L3_PROTOCOL: List[str] = field(default_factory=list)
    AI_AGENT_MINIMAL_ALERT_SEVERITY: int = 2
    AI_AGENT_DNS_RCODES: List[str] = field(default_factory=lambda: ["NXDOMAIN", "SERVFAIL"])
    AI_AGENT_DNS_RRTYPES: List[str] = field(default_factory=lambda: ["ANY", "TXT"])
    AI_AGENT_HTTP_STATUS_MIN: Optional[int] = 400
    AI_AGENT_HTTP_METHODS: List[str] = field(default_factory=lambda: ["PUT", "DELETE"])
    AI_AGENT_TLS_VERSIONS: List[str] = field(default_factory=lambda: ["SSLv3", "TLSv1"])
    AI_AGENT_TLS_REQUIRE_SNI: bool = True
    AI_AGENT_TLS_JA3_HASHES: List[str] = field(default_factory=lambda: ["aaa", "bbb"])
    AI_AGENT_TLS_JA3S_HASHES: List[str] = field(default_factory=lambda: ["ccc"])

    LLM_PROMPT_FILE: str = "llm_prompt.toml"
    LLM_MEMORY_LEN: int = 50
    LLM_MEMORY_MAX_PAIRS: int = 10
    LLM_MEMORY_PER_PAIR_LEN: int = 5
    LLM_MEMORY_MODE: str = "pair"
    LLM_MEMORY_LAT_LRU_EVICT_SECONDS: float = 3600.0
    LLM_MEMORY_MAXPAIR_LRU_EVICT: int = 2
    LLM_MEMORY_COMPACT_THRESHOLD: int = 10
    LLM_MEMORY_COMPACT_BATCH: int = 8
    LLM_MEMORY_COMPACT_COOLDOWN: float = 2.0

    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_TIMEOUT: int = 60
    OLLAMA_THINK: bool = False
    OLLAMA_KEEP_ALIVE: str = "5m"

    FINETUNE_COLLECT_ENABLED: bool = False
    FINETUNE_DB_PATH: str = ""
    FINETUNE_EXPORT_DIR: str = ""

    LLM_BACKEND_TYPE: str = "ollama"
    LLM_BACKEND_BASE_URL: str = ""
    LLM_BACKEND_AUTH_TOKEN: str = ""
    LLM_BACKEND_VLLM_PROMETHEUS_URL: str = ""

    ESCALATION_ENABLED: bool = False
    ESCALATION_THREAT_THRESHOLD: str = "中"
    ESCALATION_MODEL: str = ""
    ESCALATION_MAX_TOKENS: int = 4096
    ESCALATION_CONTEXT_LENGTH: int = 65536
    ESCALATION_TEMPERATURE: float = 0.2
    ESCALATION_TOP_P: float = 0.9
    ESCALATION_TOP_K: int = 40
    ESCALATION_INCLUDE_RAW_FIELDS: bool = True

    AUTO_PERF_SELECT: bool = True
    ANALYSIS_VALUE_INDEX: float = 0.5
    PERF_PREDICT_ALPHA: float = 0.6
    PERF_PREDICT_WINDOW: int = 5
    PERF_PREDICT_WINDOW_WEIGHT: float = 0.5
    PERF_STATS_ALPHA: float = 0.5
    PERF_INDEX_CURRENT: Optional[int] = None
    ADAPTIVE_DETAILS: Dict[str, float] = field(default_factory=dict)

    MODEL_PROFILES_FILE: str = ""
    MODEL_PROFILES: Dict[str, Any] = field(default_factory=dict)
    TOTAL_VRAM_MB: int = 65536

    RMI_ENABLED: bool = False
    RMI_HOST: str = "127.0.0.1"
    RMI_PORT: int = 18765

    DAILY_REPORT_ENABLED: bool = False
    DAILY_REPORT_LLM_CONFIG_FILE: str = ""
    DAILY_REPORT_FETCH_SIZE: int = 100
    DAILY_REPORT_OUTPUT_DIR: str = ""
    DAILY_REPORT_SESSION_GAP: int = 1800
    DAILY_REPORT_SUBJECT_PREFIX: str = "Test Daily Report"
    DAILY_REPORT_ANALYSIS_MODE: str = "hierarchical"
    DAILY_REPORT_EXPERIMENT_TAG: str = ""

    ENABLE_MAIL_NOTIFICATION: bool = False
    MAIL_PROVIDER: str = "outlook"
    SUPPORTED_MAIL_PROVIDERS: List[str] = field(default_factory=list)
    MAIL_CLIENT_ID: str = ""
    MAIL_CLIENT_SECRET: str = ""
    MAIL_OAUTH2_TOKEN_CACHE: str = ""
    MAIL_SENDER: str = "test@test.com"

    AUTH_DB_PATH: str = ""
    AUTH_JWT_SECRET: str = "test-jwt-secret"
    AUTH_JWT_EXPIRE_SECONDS: int = 86400

    EXECUTOR_ENABLED: bool = False
    EXECUTOR_CAPABILITIES_DIR: str = ""
    EXECUTOR_AUDIT_DB_PATH: str = ""
    EXECUTOR_SANDBOX_ROOT: str = ""
    EXECUTOR_DRY_RUN: bool = True

    GIT_ENABLED: bool = False
    GIT_TOKEN: str = ""
    GIT_REMOTE_URL: str = ""
    GIT_DEFAULT_BRANCH: str = "main"
    GIT_LOCAL_REPO_PATH: str = "/tmp/test-git-repo"
    GIT_API_BASE_URL: str = "https://api.github.com"
    GIT_REPO_OWNER: str = "test-owner"
    GIT_REPO_NAME: str = "test-repo"
    GIT_AUTO_PR: bool = False
    GIT_AUTO_ISSUE: bool = False
    GIT_ISSUE_THREAT_THRESHOLD: str = "严重"
    GIT_RULES_PATH: str = "rules/ai"
    GIT_VALIDATE_WITH_SURICATA: bool = False
    GIT_FORK_OWNER: str = ""
    GIT_RESET_TIME: str = "02:00:00"

    LOG_OUTPUT_ES: bool = False
    LOG_ES_HOST: str = ""
    LOG_ES_USER: str = ""
    LOG_ES_PSWD: str = ""
    LOG_INDEX_PREFIX: str = "test-log-"
    LOG_INDEX_PATTERN: str = "test-log-*"
    LOG_TEMPLATE_NAME: str = "test-log"
    LOG_FIELD_LIMIT: int = 65536
    LOG_FLUSH_INTERVAL: float = 1.0
    LOG_BATCH_SIZE: int = 200
    STATS_INDEX_PREFIX: str = "test-stats-"
    STATS_INDEX_PATTERN: str = "test-stats-*"
    STATS_TEMPLATE_NAME: str = "test-stats"

    GPU_FP16_TFLOPS: float = 0.0
    GPU_MEM_BANDWIDTH_GBPS: float = 0.0
    GPU_SATURATION_THRESHOLD: float = 0.9
    COST_AWARE_SELECT: bool = False
    COST_BUDGET_PER_HOUR: float = 0.0
    COST_WEIGHT: float = 0.5
    COST_SATURATION_THRESHOLD: float = 0.9

    _CURRENT_PERF_CONFIG: Optional[PerfConfig] = field(default=None, repr=False)
    _perf_config_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _daily_report_active: threading.Event = field(default_factory=lambda: threading.Event(), repr=False)

    @property
    def CURRENT_PERF_CONFIG(self) -> Optional[PerfConfig]:
        with self._perf_config_lock:
            return self._CURRENT_PERF_CONFIG

    @CURRENT_PERF_CONFIG.setter
    def CURRENT_PERF_CONFIG(self, value: Optional[PerfConfig]) -> None:
        with self._perf_config_lock:
            self._CURRENT_PERF_CONFIG = value

    @property
    def daily_report_active(self) -> bool:
        return self._daily_report_active.is_set()

    def set_daily_report_active(self) -> None:
        self._daily_report_active.set()

    def clear_daily_report_active(self) -> None:
        self._daily_report_active.clear()

    def __post_init__(self):
        # Skip all file I/O — set up a default PerfConfig and ModelProfile
        profile = ModelProfile()
        self.MODEL_PROFILES = {profile.name: profile}
        self.CURRENT_PERF_CONFIG = PerfConfig()

    @staticmethod
    def get_today_index() -> str:
        from datetime import datetime
        return f"suricata-eve-{datetime.now().strftime('%Y.%m.%d')}"


def _install_fake_third_party():
    """Pre-install mock modules for third-party packages that may be
    incompatible with the current Python version or unavailable."""
    # Only mock if the real import would fail
    _mods_to_mock = [
        "elasticsearch", "elasticsearch.helpers",
        "elastic_transport",
    ]
    for name in _mods_to_mock:
        if name not in sys.modules:
            try:
                __import__(name)
            except Exception:
                sys.modules[name] = MagicMock()


def _install_fake_config():
    """Install the fake config module before any src.* imports."""
    fake_cfg = FakeConfig()

    # Create a fake module that provides the same public interface
    mod = types.ModuleType("src.config")
    mod.config = fake_cfg
    mod.Config = FakeConfig
    mod.PerfConfig = PerfConfig
    mod.ModelProfile = ModelProfile
    mod._load_toml = lambda fp: {}
    mod._load_ja3_file = lambda fp, key: None
    mod._locate_conf_file = lambda: "/dev/null"
    sys.modules["src.config"] = mod
    return fake_cfg


# Install BEFORE any src.* module can import the real Config
_install_fake_third_party()
_fake_config = _install_fake_config()


@pytest.fixture
def fake_config():
    """Return the global FakeConfig instance (already installed in sys.modules)."""
    return _fake_config


@pytest.fixture
def mock_perf_config():
    return PerfConfig()


@pytest.fixture
def mock_model_profile():
    return ModelProfile()
