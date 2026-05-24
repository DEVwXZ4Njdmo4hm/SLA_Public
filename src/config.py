#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         config.py
Description:  Configuration loader and manager for TOML-based application settings.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

import os
import sys
import logging
import threading
import tomllib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from .versioning import (
    SOFTWARE_AUTHOR,
    SOFTWARE_LICENSE,
    SOFTWARE_NAME,
    SOFTWARE_NAME_SUFFIX,
    SOFTWARE_VERSION,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default conf file search order:
#   1. CLI argument  --config <path>
#   2. Environment variable  SURICATA_LLM_AGENT_CONF
#   3. ./suricata-llm-agent.toml   (relative to project root / CWD)
#   4. /app/suricata-llm-agent.toml  (container default)
# ---------------------------------------------------------------------------
_CONF_SEARCH_PATHS = [
    os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)), "suricata-llm-agent.toml"),
    "/app/suricata-llm-agent.toml",
]


def _locate_conf_file() -> str:
    """Return the absolute path to the configuration file."""
    # 1. --config CLI argument (parsed early, before argparse)
    for i, arg in enumerate(sys.argv):
        if arg == "--config" and i + 1 < len(sys.argv):
            cli_path = sys.argv[i + 1]
            if not os.path.isfile(cli_path):
                raise FileNotFoundError(f"Config file specified by --config not found: {cli_path}")
            return os.path.abspath(cli_path)

    # 2. Environment variable
    env_path = os.getenv("SURICATA_LLM_AGENT_CONF")
    if env_path:
        if not os.path.isfile(env_path):
            raise FileNotFoundError(f"Config file specified by SURICATA_LLM_AGENT_CONF not found: {env_path}")
        return os.path.abspath(env_path)

    for candidate in _CONF_SEARCH_PATHS:
        if os.path.isfile(candidate):
            return candidate

    raise FileNotFoundError(
        "Cannot find suricata-llm-agent.toml. "
        "Set SURICATA_LLM_AGENT_CONF or place the file alongside the project root."
    )


def _load_toml(filepath: str) -> Dict[str, Any]:
    """Read a TOML conf file and return a dict."""
    with open(filepath, "rb") as f:
        return tomllib.load(f)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _load_ja3_file(filepath: str, key: str) -> Optional[List[str]]:
    """Load a JA3/JA3S hash list from an external TOML file.

    Returns the list of hashes on success, or None if the file is missing
    / unreadable (in which case the built-in defaults will be kept).
    """
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


@dataclass
class PerfConfig:
    index: int
    PERF_INDEX_MIN: int
    PERF_INDEX_MAX: int
    OLLAMA_MODEL: str
    OLLAMA_NUM_PREDICT: int
    OLLAMA_TEMPERATURE: float
    OLLAMA_TOP_P: float
    OLLAMA_TOP_K: int
    LLM_CONCURRENCY: int
    BATCH_SIZE: int
    POLL_INTERVAL: int
    OLLAMA_CONTEXT_LENGTH: int


@dataclass
class ModelProfile:
    """Baseline performance profile for an LLM model.

    Used by the adaptive performance engine to estimate capacity and
    compute optimal parameters at runtime.  Each profile may declare its
    own ``backend_type`` so that different models can use different
    backends (e.g. local Ollama *and* remote OpenAI) simultaneously.
    """
    name: str
    baseline_tps: float
    quality_score: float
    vram_calibration_context: int
    vram_calibration_mb: int
    context_length_min: int
    context_length_max: int
    num_predict_min: int
    num_predict_max: int
    concurrency_min: int
    concurrency_max: int
    batch_size_min: int
    batch_size_max: int
    poll_interval_min: int
    poll_interval_max: int
    temperature: float
    top_p: float
    top_k: int
    supports_tool_use: Optional[bool] = None  # None = auto-detect at runtime
    backend_type: str = "ollama"               # "ollama" | "openai"
    backend_base_url: str = ""                 # empty = use global config
    backend_auth_token: str = ""               # empty = use global LLM_BACKEND_AUTH_TOKEN

    # --- Improvement 30: GPU performance quantification ---
    total_params_b: float = 0.0       # Total params (billions)
    active_params_b: float = 0.0      # Active params per inference (billions); dense = total
    bytes_per_param: float = 0.0      # Avg bytes per param after quantization

    # --- Improvement 30.5: Cost-aware scheduling ---
    cost_per_1k_prompt: float = 0.0       # $/1K prompt tokens (0 = free/local)
    cost_per_1k_completion: float = 0.0   # $/1K completion tokens (0 = free/local)

    # --- Improvement 30.6: Rate limiting ---
    max_requests_per_minute: int = 0      # RPM limit (0 = unlimited)


@dataclass
class Config:
    # Product (sourced from versioning.py)
    SOFTWARE_NAME: str = SOFTWARE_NAME
    SOFTWARE_NAME_SUFFIX: str = SOFTWARE_NAME_SUFFIX
    SOFTWARE_VERSION: str = SOFTWARE_VERSION
    SOFTWARE_AUTHOR: str = SOFTWARE_AUTHOR
    SOFTWARE_LICENSE: str = SOFTWARE_LICENSE

    # ElasticSearch Configuration
    ES_HOST: str = "http://elasticsearch:9200"
    ES_USER: str = ""
    ES_PSWD: str = ""
    ES_INDEX_PATTERN: str = "suricata-eve-*"

    # Processing Configuration
    BATCH_SIZE: int = 50
    POLL_INTERVAL: int = 5
    MAX_RETRIES: int = 3
    RETRY_INTERVAL: int = 10
    EMPTY_RUNS_BEFORE_INDEX_REFRESH: int = 50

    # Filtering Configuration
    SUPPORTED_EVENT_TYPES: List[str] = field(default_factory=lambda: [
        "alert", "dns", "http", "tls", "ssh", "smtp", "ftp", "smb",
        "rdp", "dhcp", "ntp", "mqtt", "sip", "modbus", "fileinfo", "flow",
    ])
    SUPPORTED_L7_PROTOCOLS: List[str] = field(default_factory=lambda: [
        "dns", "mdns", "http", "https", "ftp", "smtp", "ssh", "tls",
        "smb", "rdp", "dhcp", "ntp", "mqtt", "sip", "modbus",
    ])
    SUPPORTED_L4_PROTOCOLS: List[str] = field(default_factory=lambda: [
        "tcp", "udp", "icmp", "icmpv6", "sctp",
    ])
    SUPPORTED_L3_PROTOCOLS: List[str] = field(default_factory=lambda: [
        "ipv4", "ipv6", "arp",
    ])
    ALLOWED_EVENT_TYPE: List[str] = field(default_factory=list)
    ALLOWED_L7_PROTOCOL: List[str] = field(default_factory=list)
    ALLOWED_L4_PROTOCOL: List[str] = field(default_factory=list)
    ALLOWED_L3_PROTOCOL: List[str] = field(default_factory=list)
    AI_AGENT_MINIMAL_ALERT_SEVERITY: int = 2
    AI_AGENT_DNS_RCODES: List[str] = field(default_factory=lambda: [
        "NXDOMAIN", "SERVFAIL", "REFUSED",
    ])
    AI_AGENT_DNS_RRTYPES: List[str] = field(default_factory=lambda: [
        "ANY", "TXT",
    ])
    AI_AGENT_HTTP_STATUS_MIN: Optional[int] = 400
    AI_AGENT_HTTP_METHODS: List[str] = field(default_factory=lambda: [
        "PUT", "DELETE", "TRACE", "CONNECT", "PATCH", "PROPFIND",
    ])
    AI_AGENT_TLS_VERSIONS: List[str] = field(default_factory=lambda: [
        "SSLv3", "TLSv1", "TLSv1.1",
    ])
    AI_AGENT_TLS_REQUIRE_SNI: bool = True
    AI_AGENT_TLS_JA3_HASHES: List[str] = field(default_factory=list)
    AI_AGENT_TLS_JA3S_HASHES: List[str] = field(default_factory=list)

    # LLM Configuration
    LLM_PROMPT_FILE: str = "llm_prompt.toml"
    LLM_MEMORY_LEN: int = 50
    LLM_MEMORY_MAX_PAIRS: int = 50
    LLM_MEMORY_PER_PAIR_LEN: int = 20
    LLM_MEMORY_MODE: str = "pair"
    LLM_MEMORY_LAT_LRU_EVICT_SECONDS: float = 3600.0
    LLM_MEMORY_MAXPAIR_LRU_EVICT: int = 0
    LLM_MEMORY_COMPACT_THRESHOLD: int = 10
    LLM_MEMORY_COMPACT_BATCH: int = 8
    LLM_MEMORY_COMPACT_COOLDOWN: float = 2.0

    # Daily Report Configurations
    DAILY_REPORT_ENABLED: bool = False
    DAILY_REPORT_LLM_CONFIG_FILE: str = "daily_report_llm_conf.toml"
    DAILY_REPORT_FETCH_SIZE: int = 10000
    DAILY_REPORT_OUTPUT_DIR: str = ""
    DAILY_REPORT_SESSION_GAP: int = 1800
    DAILY_REPORT_MAX_SEGMENT_EVENTS: int = 200
    DAILY_REPORT_SUBJECT_PREFIX: str = "[Suricata AI 每日流量日报]"
    DAILY_REPORT_ANALYSIS_MODE: str = "hierarchical"  # "hierarchical" | "pair_only" | "flat"
    DAILY_REPORT_EXPERIMENT_TAG: str = ""

    # Mailer Configuration
    ENABLE_MAIL_NOTIFICATION: bool = False
    MAIL_PROVIDER: str = "outlook"
    SUPPORTED_MAIL_PROVIDERS: List[str] = field(default_factory=list)
    MAIL_CLIENT_ID: str = ""
    MAIL_CLIENT_SECRET: str = ""
    MAIL_OAUTH2_TOKEN_CACHE: str = ""
    MAIL_SENDER: str = "capri_ai_report@outlook.com"

    # Perf Decision Configuration
    AUTO_PERF_SELECT: bool = True
    ANALYSIS_VALUE_INDEX: float = 0.5
    PERF_PREDICT_ALPHA: float = 0.6
    PERF_PREDICT_WINDOW: int = 5
    PERF_PREDICT_WINDOW_WEIGHT: float = 0.5
    PERF_STATS_ALPHA: float = 0.5
    PERF_INDEX_CURRENT: Optional[int] = None
    ADAPTIVE_DETAILS: Dict[str, float] = field(default_factory=dict)

    # Model Performance Profiles
    MODEL_PROFILES_FILE: str = "ModelProfiles.toml"
    MODEL_PROFILES: Dict[str, 'ModelProfile'] = field(default_factory=dict)
    TOTAL_VRAM_MB: int = 0

    # RMI Configuration
    RMI_ENABLED: bool = True
    RMI_HOST: str = "0.0.0.0"
    RMI_PORT: int = 8765

    # Auth Configuration
    AUTH_DB_PATH: str = ""
    AUTH_JWT_SECRET: str = ""
    AUTH_JWT_EXPIRE_SECONDS: int = 86400

    # Executor Configuration
    EXECUTOR_ENABLED: bool = False
    EXECUTOR_CAPABILITIES_DIR: str = "configs/capabilities"
    EXECUTOR_AUDIT_DB_PATH: str = ""
    EXECUTOR_SANDBOX_ROOT: str = ""
    EXECUTOR_DRY_RUN: bool = True
    EXECUTOR_DISABLE_AGENT_MODE: bool = False

    # Git Integration Configuration
    GIT_ENABLED: bool = False
    GIT_TOKEN: str = ""
    GIT_REMOTE_URL: str = ""
    GIT_DEFAULT_BRANCH: str = "main"
    GIT_LOCAL_REPO_PATH: str = "/app/git-workspace"
    GIT_API_BASE_URL: str = "https://api.github.com"
    GIT_REPO_OWNER: str = ""
    GIT_REPO_NAME: str = ""
    GIT_AUTO_PR: bool = True
    GIT_AUTO_ISSUE: bool = True
    GIT_ISSUE_THREAT_THRESHOLD: str = "高"
    GIT_RULES_PATH: str = "rules/generated"
    GIT_VALIDATE_WITH_SURICATA: bool = False
    GIT_FORK_OWNER: str = ""
    GIT_RESET_TIME: str = "02:00:00"

    # Logging Configuration
    LOG_OUTPUT_ES: bool = False
    LOG_ES_HOST: str = ""
    LOG_ES_USER: str = ""
    LOG_ES_PSWD: str = ""
    LOG_INDEX_PREFIX: str = "suricata-ai-agent-"
    LOG_INDEX_PATTERN: str = "suricata-ai-agent-*"
    LOG_TEMPLATE_NAME: str = "suricata-ai-agent-logs"
    LOG_FIELD_LIMIT: int = 65536
    LOG_FLUSH_INTERVAL: float = 1.0
    LOG_BATCH_SIZE: int = 200
    STATS_INDEX_PREFIX: str = "suricata-ai-agent-stats-"
    STATS_INDEX_PATTERN: str = "suricata-ai-agent-stats-*"
    STATS_TEMPLATE_NAME: str = "suricata-ai-agent-stats"

    # LLM Backend Configuration
    LLM_BACKEND_TYPE: str = "ollama"       # "ollama" | "openai"
    LLM_BACKEND_BASE_URL: str = ""          # only used when type = "openai"
    LLM_BACKEND_AUTH_TOKEN: str = ""        # Bearer token / API key
    LLM_BACKEND_VLLM_PROMETHEUS_URL: str = ""  # optional vLLM /metrics endpoint

    # Escalation Configuration
    ESCALATION_ENABLED: bool = False
    ESCALATION_THREAT_THRESHOLD: str = "中"
    ESCALATION_MODEL: str = ""
    ESCALATION_MAX_TOKENS: int = 4096
    ESCALATION_CONTEXT_LENGTH: int = 65536
    ESCALATION_TEMPERATURE: float = 0.2
    ESCALATION_TOP_P: float = 0.9
    ESCALATION_TOP_K: int = 40
    ESCALATION_INCLUDE_RAW_FIELDS: bool = True

    # --- Improvement 30: GPU hardware metrics ---
    GPU_FP16_TFLOPS: float = 0.0
    GPU_MEM_BANDWIDTH_GBPS: float = 0.0
    GPU_SATURATION_THRESHOLD: float = 0.9

    # --- Improvement 30.5: Cost-aware scheduling ---
    COST_AWARE_SELECT: bool = False
    COST_BUDGET_PER_HOUR: float = 0.0
    COST_WEIGHT: float = 0.5
    COST_SATURATION_THRESHOLD: float = 0.9

    # OLLAMA Configuration
    OLLAMA_BASE_URL: str = "http://host.containers.internal:11434"
    OLLAMA_TIMEOUT: int = 300
    OLLAMA_THINK: bool = False
    OLLAMA_KEEP_ALIVE: str = "5m"

    # Fine-tuning data collection (Improvement 30.7)
    FINETUNE_COLLECT_ENABLED: bool = False
    FINETUNE_DB_PATH: str = "./finetune_data.db"
    FINETUNE_EXPORT_DIR: str = "./finetune_export"

    # Daily-report pause flag (thread-safe via threading.Event)
    _daily_report_active: threading.Event = field(default_factory=lambda: threading.Event(), repr=False)

    # Perf configuration
    _CURRENT_PERF_CONFIG: Optional[PerfConfig] = field(default=None, repr=False)
    _perf_config_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

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
        """True while a daily report generation is in progress."""
        return self._daily_report_active.is_set()

    def set_daily_report_active(self) -> None:
        """Signal that daily report generation has started."""
        self._daily_report_active.set()

    def clear_daily_report_active(self) -> None:
        """Signal that daily report generation has finished."""
        self._daily_report_active.clear()

    # ------------------------------------------------------------------
    # Initialization: read from conf file
    # ------------------------------------------------------------------
    def __post_init__(self):
        conf_path = _locate_conf_file()
        cfg = _load_toml(conf_path)
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))

        # --- [elasticsearch] -------------------------------------------
        es = cfg.get("elasticsearch", {})
        if "host" in es:
            self.ES_HOST = str(es["host"])
        if es.get("user"):
            self.ES_USER = str(es["user"])
        if es.get("password"):
            self.ES_PSWD = str(es["password"])
        if "index_pattern" in es:
            self.ES_INDEX_PATTERN = str(es["index_pattern"])

        # --- [processing] ---------------------------------------------
        proc = cfg.get("processing", {})
        if "batch_size" in proc:
            self.BATCH_SIZE = int(proc["batch_size"])
        if "poll_interval" in proc:
            self.POLL_INTERVAL = int(proc["poll_interval"])
        if "max_retries" in proc:
            self.MAX_RETRIES = int(proc["max_retries"])
        if "retry_interval" in proc:
            self.RETRY_INTERVAL = int(proc["retry_interval"])
        if "empty_runs_before_index_refresh" in proc:
            self.EMPTY_RUNS_BEFORE_INDEX_REFRESH = int(proc["empty_runs_before_index_refresh"])

        # --- [filter] -------------------------------------------------
        flt = cfg.get("filter", {})
        allowed_event_configured = "allowed_event_types" in flt
        if allowed_event_configured:
            self.ALLOWED_EVENT_TYPE = [s.lower() for s in flt["allowed_event_types"]]

        allowed_l7_configured = "allowed_l7_protocols" in flt
        if allowed_l7_configured:
            self.ALLOWED_L7_PROTOCOL = [s.lower() for s in flt["allowed_l7_protocols"]]

        allowed_l4_configured = "allowed_l4_protocols" in flt
        if allowed_l4_configured:
            self.ALLOWED_L4_PROTOCOL = [s.lower() for s in flt["allowed_l4_protocols"]]

        allowed_l3_configured = "allowed_l3_protocols" in flt
        if allowed_l3_configured:
            self.ALLOWED_L3_PROTOCOL = [s.lower() for s in flt["allowed_l3_protocols"]]

        if "minimal_alert_severity" in flt:
            self.AI_AGENT_MINIMAL_ALERT_SEVERITY = int(flt["minimal_alert_severity"])

        if "dns_rcodes" in flt:
            self.AI_AGENT_DNS_RCODES = [s.upper() for s in flt["dns_rcodes"]]
        if "dns_rrtypes" in flt:
            self.AI_AGENT_DNS_RRTYPES = [s.upper() for s in flt["dns_rrtypes"]]

        if "http_status_min" in flt:
            v = flt["http_status_min"]
            self.AI_AGENT_HTTP_STATUS_MIN = int(v) if v is not None else None
        if "http_methods" in flt:
            self.AI_AGENT_HTTP_METHODS = [s.upper() for s in flt["http_methods"]]
        if "tls_versions" in flt:
            self.AI_AGENT_TLS_VERSIONS = list(flt["tls_versions"])
        if "tls_require_sni" in flt:
            self.AI_AGENT_TLS_REQUIRE_SNI = bool(flt["tls_require_sni"])

        # JA3/JA3S: load from external TOML files (default to project-provided lists)
        ja3_file = flt.get("ja3_hashes_file", "suspicious_ja3.toml")
        if ja3_file:
            if not os.path.isabs(ja3_file):
                ja3_file = os.path.join(base_dir, ja3_file)
            loaded = _load_ja3_file(ja3_file, "tls_ja3_hashes")
            if loaded is not None:
                self.AI_AGENT_TLS_JA3_HASHES = loaded

        ja3s_file = flt.get("ja3s_hashes_file", "suspicious_ja3s.toml")
        if ja3s_file:
            if not os.path.isabs(ja3s_file):
                ja3s_file = os.path.join(base_dir, ja3s_file)
            loaded = _load_ja3_file(ja3s_file, "tls_ja3s_hashes")
            if loaded is not None:
                self.AI_AGENT_TLS_JA3S_HASHES = loaded

        # Fallback: if allowed lists were not explicitly configured, copy from supported
        if not self.ALLOWED_EVENT_TYPE and not allowed_event_configured:
            self.ALLOWED_EVENT_TYPE = list(self.SUPPORTED_EVENT_TYPES)
        if not self.ALLOWED_L7_PROTOCOL and not allowed_l7_configured:
            self.ALLOWED_L7_PROTOCOL = list(self.SUPPORTED_L7_PROTOCOLS)
        if not self.ALLOWED_L4_PROTOCOL and not allowed_l4_configured:
            self.ALLOWED_L4_PROTOCOL = []
        if not self.ALLOWED_L3_PROTOCOL and not allowed_l3_configured:
            self.ALLOWED_L3_PROTOCOL = []

        # Restrict allowed to supported
        self.ALLOWED_EVENT_TYPE = [
            t for t in self.ALLOWED_EVENT_TYPE if t in self.SUPPORTED_EVENT_TYPES
        ]
        self.ALLOWED_L7_PROTOCOL = [
            p for p in self.ALLOWED_L7_PROTOCOL if p in self.SUPPORTED_L7_PROTOCOLS
        ]
        self.ALLOWED_L4_PROTOCOL = [
            p for p in self.ALLOWED_L4_PROTOCOL if p in self.SUPPORTED_L4_PROTOCOLS
        ]
        self.ALLOWED_L3_PROTOCOL = [
            p for p in self.ALLOWED_L3_PROTOCOL if p in self.SUPPORTED_L3_PROTOCOLS
        ]

        # --- [llm] ----------------------------------------------------
        llm = cfg.get("llm", {})
        if "prompt_file" in llm:
            self.LLM_PROMPT_FILE = str(llm["prompt_file"])
        if "memory_length" in llm:
            self.LLM_MEMORY_LEN = int(llm["memory_length"])
        if self.LLM_MEMORY_LEN < 0:
            raise ValueError("llm.memory_length must be >= 0.")
        if "memory_max_pairs" in llm:
            self.LLM_MEMORY_MAX_PAIRS = int(llm["memory_max_pairs"])
        if self.LLM_MEMORY_MAX_PAIRS < 1:
            raise ValueError("llm.memory_max_pairs must be >= 1.")
        if "memory_per_pair_length" in llm:
            self.LLM_MEMORY_PER_PAIR_LEN = int(llm["memory_per_pair_length"])
        if self.LLM_MEMORY_PER_PAIR_LEN < 1:
            raise ValueError("llm.memory_per_pair_length must be >= 1.")
        if "memory_mode" in llm:
            self.LLM_MEMORY_MODE = str(llm["memory_mode"]).lower()
        memory_modes = (
            "pair", "global", "none", "pair_rolling", "global_rolling",
            "proto_pair", "proto_pair_rolling",
        )
        if self.LLM_MEMORY_MODE not in memory_modes:
            raise ValueError(
                f"llm.memory_mode must be 'pair', 'global', 'none', "
                f"'pair_rolling', 'global_rolling', 'proto_pair', "
                f"or 'proto_pair_rolling', "
                f"got: {self.LLM_MEMORY_MODE!r}"
            )
        if "memory_lat_lru_evict_seconds" in llm:
            self.LLM_MEMORY_LAT_LRU_EVICT_SECONDS = float(
                llm["memory_lat_lru_evict_seconds"]
            )
        if self.LLM_MEMORY_LAT_LRU_EVICT_SECONDS <= 0:
            raise ValueError("llm.memory_lat_lru_evict_seconds must be > 0.")
        if "memory_maxpair_lru_evict" in llm:
            self.LLM_MEMORY_MAXPAIR_LRU_EVICT = int(llm["memory_maxpair_lru_evict"])
        if self.LLM_MEMORY_MAXPAIR_LRU_EVICT < 0:
            raise ValueError("llm.memory_maxpair_lru_evict must be >= 0.")
        if self.LLM_MEMORY_MODE in ("proto_pair", "proto_pair_rolling"):
            if self.LLM_MEMORY_MAX_PAIRS < 3:
                raise ValueError(
                    "proto_pair memory modes require llm.memory_max_pairs >= 3."
                )
            if self.LLM_MEMORY_MAXPAIR_LRU_EVICT == 0:
                self.LLM_MEMORY_MAXPAIR_LRU_EVICT = min(5, self.LLM_MEMORY_MAX_PAIRS - 1)
            if not (2 <= self.LLM_MEMORY_MAXPAIR_LRU_EVICT < self.LLM_MEMORY_MAX_PAIRS):
                raise ValueError(
                    "proto_pair memory modes require "
                    "2 <= llm.memory_maxpair_lru_evict < llm.memory_max_pairs, "
                    "or 0 for automatic selection."
                )
        if "memory_compact_threshold" in llm:
            self.LLM_MEMORY_COMPACT_THRESHOLD = int(llm["memory_compact_threshold"])
        if "memory_compact_batch" in llm:
            self.LLM_MEMORY_COMPACT_BATCH = int(llm["memory_compact_batch"])
        if self.LLM_MEMORY_COMPACT_THRESHOLD < 3:
            raise ValueError(
                "llm.memory_compact_threshold must be >= 3."
            )
        if self.LLM_MEMORY_COMPACT_BATCH < 2:
            raise ValueError(
                "llm.memory_compact_batch must be >= 2."
            )
        if self.LLM_MEMORY_COMPACT_BATCH >= self.LLM_MEMORY_COMPACT_THRESHOLD:
            raise ValueError(
                "llm.memory_compact_batch must be < llm.memory_compact_threshold."
            )
        if "memory_compact_cooldown" in llm:
            self.LLM_MEMORY_COMPACT_COOLDOWN = float(llm["memory_compact_cooldown"])
        if self.LLM_MEMORY_COMPACT_COOLDOWN < 0:
            raise ValueError(
                "llm.memory_compact_cooldown must be >= 0."
            )

        # --- [llm.backend] -------------------------------------------
        llm_backend = llm.get("backend", {})
        if "type" in llm_backend:
            self.LLM_BACKEND_TYPE = str(llm_backend["type"]).lower()
        if self.LLM_BACKEND_TYPE not in ("ollama", "openai"):
            raise ValueError(
                f"llm.backend.type must be 'ollama' or 'openai', "
                f"got: {self.LLM_BACKEND_TYPE!r}"
            )
        if "base_url" in llm_backend:
            self.LLM_BACKEND_BASE_URL = str(llm_backend["base_url"])
        if "auth_token" in llm_backend:
            self.LLM_BACKEND_AUTH_TOKEN = str(llm_backend["auth_token"])

        # [llm.backend.vllm_metrics]
        vllm_metrics = llm_backend.get("vllm_metrics", {})
        if "prometheus_url" in vllm_metrics:
            self.LLM_BACKEND_VLLM_PROMETHEUS_URL = str(vllm_metrics["prometheus_url"])

        # [llm.escalation]
        escalation = llm.get("escalation", {})
        if "enabled" in escalation:
            self.ESCALATION_ENABLED = bool(escalation["enabled"])
        if "threat_threshold" in escalation:
            self.ESCALATION_THREAT_THRESHOLD = str(escalation["threat_threshold"])
        if "model" in escalation:
            self.ESCALATION_MODEL = str(escalation["model"])
        if "max_tokens" in escalation:
            self.ESCALATION_MAX_TOKENS = int(escalation["max_tokens"])
        if "context_length" in escalation:
            self.ESCALATION_CONTEXT_LENGTH = int(escalation["context_length"])
        if "temperature" in escalation:
            self.ESCALATION_TEMPERATURE = float(escalation["temperature"])
        if "top_p" in escalation:
            self.ESCALATION_TOP_P = float(escalation["top_p"])
        if "top_k" in escalation:
            self.ESCALATION_TOP_K = int(escalation["top_k"])
        if "include_raw_fields" in escalation:
            self.ESCALATION_INCLUDE_RAW_FIELDS = bool(escalation["include_raw_fields"])

        # --- [ollama] -------------------------------------------------
        ollama = cfg.get("ollama", {})
        if "base_url" in ollama:
            self.OLLAMA_BASE_URL = str(ollama["base_url"])
        if "timeout" in ollama:
            self.OLLAMA_TIMEOUT = int(ollama["timeout"])
        if "think" in ollama:
            self.OLLAMA_THINK = bool(ollama["think"])
        if "keep_alive" in ollama:
            self.OLLAMA_KEEP_ALIVE = str(ollama["keep_alive"])

        # --- [finetune] -----------------------------------------------
        finetune = cfg.get("finetune", {})
        if "enabled" in finetune:
            self.FINETUNE_COLLECT_ENABLED = bool(finetune["enabled"])
        if "db_path" in finetune:
            self.FINETUNE_DB_PATH = str(finetune["db_path"])
        if "export_dir" in finetune:
            self.FINETUNE_EXPORT_DIR = str(finetune["export_dir"])

        # --- [perf] ---------------------------------------------------
        perf = cfg.get("perf", {})
        if "model_profiles_file" in perf:
            self.MODEL_PROFILES_FILE = str(perf["model_profiles_file"])
        if "auto_select" in perf:
            self.AUTO_PERF_SELECT = bool(perf["auto_select"])

        # [perf.indexes]
        perf_idx = perf.get("indexes", {})
        if "analysis_value" in perf_idx:
            self.ANALYSIS_VALUE_INDEX = float(perf_idx["analysis_value"])

        # [perf.predict]
        perf_pred = perf.get("predict", {})
        if "alpha" in perf_pred:
            self.PERF_PREDICT_ALPHA = float(perf_pred["alpha"])
        if "window" in perf_pred:
            self.PERF_PREDICT_WINDOW = int(perf_pred["window"])
        if "window_weight" in perf_pred:
            self.PERF_PREDICT_WINDOW_WEIGHT = float(perf_pred["window_weight"])

        # [perf.stats]
        perf_stats = perf.get("stats", {})
        if "alpha" in perf_stats:
            self.PERF_STATS_ALPHA = float(perf_stats["alpha"])

        # Validate perf ranges
        if not (0.0 <= self.ANALYSIS_VALUE_INDEX <= 1.0):
            raise ValueError("perf.analysis_value_index must be between 0 and 1.")
        if not (0.0 <= self.PERF_PREDICT_ALPHA <= 1.0):
            raise ValueError("perf.predict_alpha must be between 0 and 1.")
        if self.PERF_PREDICT_WINDOW < 1:
            raise ValueError("perf.predict_window must be >= 1.")
        if not (0.0 <= self.PERF_PREDICT_WINDOW_WEIGHT <= 1.0):
            raise ValueError("perf.predict_window_weight must be between 0 and 1.")
        if not (0.0 <= self.PERF_STATS_ALPHA <= 1.0):
            raise ValueError("perf.stats_alpha must be between 0 and 1.")

        # [perf] — GPU hardware metrics (Improvement 30)
        # Now read from top-level [gpu] section (was flat keys under [perf]).
        gpu_sec = cfg.get("gpu", {})
        if "fp16_tflops" in gpu_sec:
            self.GPU_FP16_TFLOPS = float(gpu_sec["fp16_tflops"])
        if "mem_bandwidth_gbps" in gpu_sec:
            self.GPU_MEM_BANDWIDTH_GBPS = float(gpu_sec["mem_bandwidth_gbps"])
        if "saturation_threshold" in gpu_sec:
            self.GPU_SATURATION_THRESHOLD = float(gpu_sec["saturation_threshold"])
        if "total_vram_mb" in gpu_sec:
            self.TOTAL_VRAM_MB = int(gpu_sec["total_vram_mb"])

        if self.GPU_FP16_TFLOPS < 0:
            raise ValueError("gpu.fp16_tflops must be >= 0.")
        if self.GPU_MEM_BANDWIDTH_GBPS < 0:
            raise ValueError("gpu.mem_bandwidth_gbps must be >= 0.")
        if not (0.0 < self.GPU_SATURATION_THRESHOLD <= 1.0):
            raise ValueError("gpu.saturation_threshold must be in (0, 1].")

        # [cost] — Cost-aware scheduling (Improvement 30.5)
        # Now read from top-level [cost] section (was flat keys under [perf]).
        cost_sec = cfg.get("cost", {})
        if "aware_select" in cost_sec:
            self.COST_AWARE_SELECT = bool(cost_sec["aware_select"])
        if "budget_per_hour" in cost_sec:
            self.COST_BUDGET_PER_HOUR = float(cost_sec["budget_per_hour"])
        if "weight" in cost_sec:
            self.COST_WEIGHT = float(cost_sec["weight"])
        if "saturation_threshold" in cost_sec:
            self.COST_SATURATION_THRESHOLD = float(cost_sec["saturation_threshold"])

        if self.COST_BUDGET_PER_HOUR < 0:
            raise ValueError("cost.budget_per_hour must be >= 0.")
        if not (0.0 <= self.COST_WEIGHT <= 1.0):
            raise ValueError("cost.weight must be between 0 and 1.")
        if not (0.0 < self.COST_SATURATION_THRESHOLD <= 1.0):
            raise ValueError("cost.saturation_threshold must be in (0, 1].")

        # --- [rmi] ----------------------------------------------------
        rmi = cfg.get("rmi", {})
        if "enabled" in rmi:
            self.RMI_ENABLED = bool(rmi["enabled"])
        if "host" in rmi:
            self.RMI_HOST = str(rmi["host"])
        if "port" in rmi:
            self.RMI_PORT = int(rmi["port"])
            if not (1 <= self.RMI_PORT <= 65535):
                raise ValueError("rmi.port must be between 1 and 65535.")

        # --- [auth] ---------------------------------------------------
        auth = cfg.get("auth", {})
        if "db_path" in auth:
            self.AUTH_DB_PATH = str(auth["db_path"])
        if "jwt_secret" in auth:
            self.AUTH_JWT_SECRET = str(auth["jwt_secret"])
        if "jwt_expire_seconds" in auth:
            self.AUTH_JWT_EXPIRE_SECONDS = int(auth["jwt_expire_seconds"])

        # --- [executor] -----------------------------------------------
        executor = cfg.get("executor", {})
        if "enabled" in executor:
            self.EXECUTOR_ENABLED = bool(executor["enabled"])
        if "capabilities_dir" in executor:
            self.EXECUTOR_CAPABILITIES_DIR = str(executor["capabilities_dir"])
        if "audit_db_path" in executor:
            self.EXECUTOR_AUDIT_DB_PATH = str(executor["audit_db_path"])
        if "sandbox_root" in executor:
            self.EXECUTOR_SANDBOX_ROOT = str(executor["sandbox_root"])
        if "dry_run" in executor:
            self.EXECUTOR_DRY_RUN = bool(executor["dry_run"])
        if "disable_agent_mode" in executor:
            self.EXECUTOR_DISABLE_AGENT_MODE = bool(executor["disable_agent_mode"])

        # --- [git] ----------------------------------------------------
        git = cfg.get("git", {})
        if "enabled" in git:
            self.GIT_ENABLED = bool(git["enabled"])
        if "token" in git:
            self.GIT_TOKEN = str(git["token"])
        if "remote_url" in git:
            self.GIT_REMOTE_URL = str(git["remote_url"])
        if "default_branch" in git:
            self.GIT_DEFAULT_BRANCH = str(git["default_branch"])
        if "local_repo_path" in git:
            self.GIT_LOCAL_REPO_PATH = str(git["local_repo_path"])
        if "api_base_url" in git:
            self.GIT_API_BASE_URL = str(git["api_base_url"])
        if "repo_owner" in git:
            self.GIT_REPO_OWNER = str(git["repo_owner"])
        if "repo_name" in git:
            self.GIT_REPO_NAME = str(git["repo_name"])
        if "auto_pr" in git:
            self.GIT_AUTO_PR = bool(git["auto_pr"])
        if "auto_issue" in git:
            self.GIT_AUTO_ISSUE = bool(git["auto_issue"])
        if "issue_threat_threshold" in git:
            self.GIT_ISSUE_THREAT_THRESHOLD = str(git["issue_threat_threshold"])
        if "rules_path" in git:
            self.GIT_RULES_PATH = str(git["rules_path"])
        if "validate_with_suricata" in git:
            self.GIT_VALIDATE_WITH_SURICATA = bool(git["validate_with_suricata"])
        if "fork_owner" in git:
            self.GIT_FORK_OWNER = str(git["fork_owner"])
        if "reset_time" in git:
            import re
            val = str(git["reset_time"]).strip()
            if not re.fullmatch(r'[0-2]\d:[0-5]\d:[0-5]\d', val):
                raise ValueError(
                    f"git.reset_time must be in HH:MM:SS format (00:00:00–23:59:59), got: {val!r}"
                )
            h = int(val[:2])
            if h > 23:
                raise ValueError(
                    f"git.reset_time hour must be 00–23, got: {val!r}"
                )
            self.GIT_RESET_TIME = val

        # --- [logging] ------------------------------------------------
        log = cfg.get("logging", {})
        if "output_to_elasticsearch" in log:
            self.LOG_OUTPUT_ES = bool(log["output_to_elasticsearch"])
        if log.get("log_es_host"):
            self.LOG_ES_HOST = str(log["log_es_host"])
        if log.get("log_es_user"):
            self.LOG_ES_USER = str(log["log_es_user"])
        if log.get("log_es_password"):
            self.LOG_ES_PSWD = str(log["log_es_password"])
        if "log_index_prefix" in log:
            self.LOG_INDEX_PREFIX = str(log["log_index_prefix"])
        if "log_index_pattern" in log:
            self.LOG_INDEX_PATTERN = str(log["log_index_pattern"])
        if "log_template_name" in log:
            self.LOG_TEMPLATE_NAME = str(log["log_template_name"])
        if "log_field_limit" in log:
            self.LOG_FIELD_LIMIT = int(log["log_field_limit"])
        if "log_flush_interval" in log:
            self.LOG_FLUSH_INTERVAL = float(log["log_flush_interval"])
            if self.LOG_FLUSH_INTERVAL <= 0:
                raise ValueError("logging.log_flush_interval must be > 0.")
        if "log_batch_size" in log:
            self.LOG_BATCH_SIZE = int(log["log_batch_size"])
            if self.LOG_BATCH_SIZE <= 0:
                raise ValueError("logging.log_batch_size must be > 0.")
        if "stats_index_prefix" in log:
            self.STATS_INDEX_PREFIX = str(log["stats_index_prefix"])
        if "stats_index_pattern" in log:
            self.STATS_INDEX_PATTERN = str(log["stats_index_pattern"])
        if "stats_template_name" in log:
            self.STATS_TEMPLATE_NAME = str(log["stats_template_name"])

        # Fallback: reuse main ES credentials for logging if not set
        if not self.LOG_ES_HOST:
            self.LOG_ES_HOST = self.ES_HOST
        if not self.LOG_ES_USER:
            self.LOG_ES_USER = self.ES_USER
        if not self.LOG_ES_PSWD:
            self.LOG_ES_PSWD = self.ES_PSWD

        # --- [daily_report] -------------------------------------------
        dr = cfg.get("daily_report", {})
        if "enabled" in dr:
            self.DAILY_REPORT_ENABLED = bool(dr["enabled"])
        if "llm_config_file" in dr:
            self.DAILY_REPORT_LLM_CONFIG_FILE = str(dr["llm_config_file"])
        if "fetch_size" in dr:
            self.DAILY_REPORT_FETCH_SIZE = int(dr["fetch_size"])
            if self.DAILY_REPORT_FETCH_SIZE <= 0:
                raise ValueError("daily_report.fetch_size must be > 0.")
        if "session_gap" in dr:
            self.DAILY_REPORT_SESSION_GAP = int(dr["session_gap"])
            if self.DAILY_REPORT_SESSION_GAP <= 0:
                raise ValueError("daily_report.session_gap must be > 0.")
        if "max_segment_events" in dr:
            self.DAILY_REPORT_MAX_SEGMENT_EVENTS = int(dr["max_segment_events"])
            if self.DAILY_REPORT_MAX_SEGMENT_EVENTS <= 0:
                raise ValueError("daily_report.max_segment_events must be > 0.")
        if "output_dir" in dr:
            self.DAILY_REPORT_OUTPUT_DIR = str(dr["output_dir"])
        if "subject_prefix" in dr:
            self.DAILY_REPORT_SUBJECT_PREFIX = str(dr["subject_prefix"])
        if "analysis_mode" in dr:
            self.DAILY_REPORT_ANALYSIS_MODE = str(dr["analysis_mode"]).lower()
        if self.DAILY_REPORT_ANALYSIS_MODE not in ("hierarchical", "pair_only", "flat"):
            raise ValueError(
                f"daily_report.analysis_mode must be 'hierarchical', 'pair_only' or 'flat', "
                f"got: {self.DAILY_REPORT_ANALYSIS_MODE!r}"
            )
        if "experiment_tag" in dr:
            self.DAILY_REPORT_EXPERIMENT_TAG = str(dr["experiment_tag"])

        # --- [mail] ---------------------------------------------------
        mail = cfg.get("mail", {})
        if "enable_notification" in mail:
            self.ENABLE_MAIL_NOTIFICATION = bool(mail["enable_notification"])
        if "provider" in mail:
            self.MAIL_PROVIDER = str(mail["provider"]).lower()
        if "client_id" in mail:
            self.MAIL_CLIENT_ID = str(mail["client_id"])
        if "client_secret" in mail:
            self.MAIL_CLIENT_SECRET = str(mail["client_secret"])
        if "sender" in mail:
            self.MAIL_SENDER = str(mail["sender"])

        # --- Resolve relative paths to absolute -----------------------
        if not os.path.isabs(self.MODEL_PROFILES_FILE):
            self.MODEL_PROFILES_FILE = os.path.join(base_dir, self.MODEL_PROFILES_FILE)
        if not os.path.isabs(self.LLM_PROMPT_FILE):
            self.LLM_PROMPT_FILE = os.path.join(base_dir, self.LLM_PROMPT_FILE)
        if not os.path.isabs(self.DAILY_REPORT_LLM_CONFIG_FILE):
            self.DAILY_REPORT_LLM_CONFIG_FILE = os.path.join(base_dir, self.DAILY_REPORT_LLM_CONFIG_FILE)
        if self.DAILY_REPORT_OUTPUT_DIR and not os.path.isabs(self.DAILY_REPORT_OUTPUT_DIR):
            self.DAILY_REPORT_OUTPUT_DIR = os.path.join(base_dir, self.DAILY_REPORT_OUTPUT_DIR)
        if self.AUTH_DB_PATH and not os.path.isabs(self.AUTH_DB_PATH):
            self.AUTH_DB_PATH = os.path.join(base_dir, self.AUTH_DB_PATH)
        if self.EXECUTOR_CAPABILITIES_DIR and not os.path.isabs(self.EXECUTOR_CAPABILITIES_DIR):
            self.EXECUTOR_CAPABILITIES_DIR = os.path.join(base_dir, self.EXECUTOR_CAPABILITIES_DIR)
        if self.EXECUTOR_AUDIT_DB_PATH and not os.path.isabs(self.EXECUTOR_AUDIT_DB_PATH):
            self.EXECUTOR_AUDIT_DB_PATH = os.path.join(base_dir, self.EXECUTOR_AUDIT_DB_PATH)

        # --- Load credentials from credentials.db --------------------
        # When AUTH_DB_PATH is set and the database file exists,
        # service credentials stored in the ``credentials`` table
        # override any values read from the TOML configuration file.
        # This is the *single source of truth* for secrets at runtime.
        if self.AUTH_DB_PATH and os.path.isfile(self.AUTH_DB_PATH):
            from .auth.database import UserDB
            from .auth.models import CredKey
            _cred_db = UserDB(self.AUTH_DB_PATH)
            _creds = _cred_db.get_all_credentials()
            _cred_db.close()

            if CredKey.ES_USER in _creds:
                self.ES_USER = _creds[CredKey.ES_USER]
            if CredKey.ES_PSWD in _creds:
                self.ES_PSWD = _creds[CredKey.ES_PSWD]
            if CredKey.LOG_ES_USER in _creds:
                self.LOG_ES_USER = _creds[CredKey.LOG_ES_USER]
            if CredKey.LOG_ES_PSWD in _creds:
                self.LOG_ES_PSWD = _creds[CredKey.LOG_ES_PSWD]
            if CredKey.GIT_TOKEN in _creds:
                self.GIT_TOKEN = _creds[CredKey.GIT_TOKEN]
            if CredKey.JWT_SECRET in _creds:
                self.AUTH_JWT_SECRET = _creds[CredKey.JWT_SECRET]
            if CredKey.MAIL_CLIENT_ID in _creds:
                self.MAIL_CLIENT_ID = _creds[CredKey.MAIL_CLIENT_ID]
            if CredKey.MAIL_CLIENT_SECRET in _creds:
                self.MAIL_CLIENT_SECRET = _creds[CredKey.MAIL_CLIENT_SECRET]
            if CredKey.MAIL_OAUTH2_TOKEN_CACHE in _creds:
                self.MAIL_OAUTH2_TOKEN_CACHE = _creds[CredKey.MAIL_OAUTH2_TOKEN_CACHE]
            if CredKey.LLM_API_KEY in _creds:
                self.LLM_BACKEND_AUTH_TOKEN = _creds[CredKey.LLM_API_KEY]

        # --- Re-apply LOG_ES fallback after credentials.db override ---
        # The initial fallback (above) ran before credentials.db was
        # loaded, so LOG_ES_* may still be empty when only the main ES
        # credentials were stored in the database.
        if not self.LOG_ES_USER:
            self.LOG_ES_USER = self.ES_USER
        if not self.LOG_ES_PSWD:
            self.LOG_ES_PSWD = self.ES_PSWD

        # --- Environment variable override for LLM API key -----------
        env_api_key = os.getenv("SURICATA_LLM_API_KEY")
        if env_api_key:
            self.LLM_BACKEND_AUTH_TOKEN = env_api_key

        # --- Validate required credentials ----------------------------
        if not self.ES_USER or not self.ES_PSWD:
            raise ValueError(
                "elasticsearch.user and elasticsearch.password must be set "
                "(via conf file or credentials.db)."
            )

        # --- Discover supported mail providers ------------------------
        provider_config_dir = os.path.join(base_dir, "configs", "mail_providers")
        if os.path.exists(provider_config_dir):
            for f in os.listdir(provider_config_dir):
                if f.endswith(".toml"):
                    self.SUPPORTED_MAIL_PROVIDERS.append(f[:-5])

        # --- Load Model Profiles --------------------------------------
        self.load_model_profiles(self.MODEL_PROFILES_FILE)

        # --- Load LLM Prompt Templates --------------------------------
        from .llm_prompt import load_prompt_templates
        load_prompt_templates(self.LLM_PROMPT_FILE)

    @staticmethod
    def get_today_index() -> str:
        """Generate today's index name based on the current date."""
        today = datetime.now().strftime("%Y.%m.%d")
        return f"suricata-eve-{today}"

    def load_model_profiles(self, filepath: str) -> None:
        """Load model performance profiles from a TOML file.

        At least one profile is required.  The first profile is used to
        build the initial ``CURRENT_PERF_CONFIG``.
        """
        if not filepath or not os.path.isfile(filepath):
            logger.error("Model profiles file not found: %s", filepath)
            sys.exit(1)

        try:
            raw_data = _load_toml(filepath)
        except Exception as exc:
            logger.error("Failed to load model profiles %s: %s", filepath, exc)
            sys.exit(1)

        models = raw_data.get("model")
        if not isinstance(models, dict) or not models:
            logger.error("Model profiles file %s has no [model.*] sections.", filepath)
            sys.exit(1)

        profiles: Dict[str, ModelProfile] = {}
        for name, payload in models.items():
            if not isinstance(payload, dict):
                logger.warning("Model profile '%s' is not a table, skipping.", name)
                continue

            try:
                ctx = payload.get("context_length", {})
                npred = payload.get("num_predict", {})
                conc = payload.get("concurrency", {})
                bsz = payload.get("batch_size", {})
                pint = payload.get("poll_interval", {})

                profile = ModelProfile(
                    name=str(name),
                    baseline_tps=float(payload.get("baseline_tps", 30.0)),
                    quality_score=float(payload.get("quality_score", 0.5)),
                    vram_calibration_context=int(payload.get("vram_calibration_context", 0)),
                    vram_calibration_mb=int(payload.get("vram_calibration_mb", 0)),
                    context_length_min=int(ctx.get("min", 2048)) if isinstance(ctx, dict) else 2048,
                    context_length_max=int(ctx.get("max", 16384)) if isinstance(ctx, dict) else 16384,
                    num_predict_min=int(npred.get("min", 128)) if isinstance(npred, dict) else 128,
                    num_predict_max=int(npred.get("max", 512)) if isinstance(npred, dict) else 512,
                    concurrency_min=int(conc.get("min", 1)) if isinstance(conc, dict) else 1,
                    concurrency_max=int(conc.get("max", 8)) if isinstance(conc, dict) else 8,
                    batch_size_min=int(bsz.get("min", 10)) if isinstance(bsz, dict) else 10,
                    batch_size_max=int(bsz.get("max", 100)) if isinstance(bsz, dict) else 100,
                    poll_interval_min=int(pint.get("min", 5)) if isinstance(pint, dict) else 5,
                    poll_interval_max=int(pint.get("max", 30)) if isinstance(pint, dict) else 30,
                    temperature=float(payload.get("temperature", 0.2)),
                    top_p=float(payload.get("top_p", 0.9)),
                    top_k=int(payload.get("top_k", 40)),
                    supports_tool_use=payload.get("supports_tool_use"),
                    backend_type=str(payload.get("backend_type", self.LLM_BACKEND_TYPE)),
                    backend_base_url=str(payload.get("backend_base_url", "")),
                    backend_auth_token=str(payload.get("backend_auth_token", "")),
                    total_params_b=float(payload.get("total_params_b", 0.0)),
                    active_params_b=float(payload.get("active_params_b", 0.0)),
                    bytes_per_param=float(payload.get("bytes_per_param", 0.0)),
                    cost_per_1k_prompt=float(payload.get("cost_per_1k_prompt", 0.0)),
                    cost_per_1k_completion=float(payload.get("cost_per_1k_completion", 0.0)),
                    max_requests_per_minute=int(payload.get("max_requests_per_minute", 0)),
                )
                profiles[name] = profile
            except (TypeError, ValueError) as exc:
                logger.warning("Invalid model profile '%s': %s", name, exc)
                continue

        if not profiles:
            logger.error("No valid model profiles found in %s.", filepath)
            sys.exit(1)

        self.MODEL_PROFILES = profiles
        logger.info("Loaded %d model profile(s): %s", len(profiles), ", ".join(profiles.keys()))

        # Legacy: total_vram_mb may still appear in ModelProfiles.toml for
        # backward compatibility; [gpu].total_vram_mb takes precedence.
        vram = raw_data.get("total_vram_mb")
        if vram is not None and self.TOTAL_VRAM_MB == 0:
            self.TOTAL_VRAM_MB = int(vram)

        # Build initial CURRENT_PERF_CONFIG from the first profile
        first_profile = next(iter(profiles.values()))
        self.CURRENT_PERF_CONFIG = PerfConfig(
            index=0,
            PERF_INDEX_MIN=0,
            PERF_INDEX_MAX=999,
            OLLAMA_MODEL=first_profile.name,
            OLLAMA_NUM_PREDICT=first_profile.num_predict_max,
            OLLAMA_TEMPERATURE=first_profile.temperature,
            OLLAMA_TOP_P=first_profile.top_p,
            OLLAMA_TOP_K=first_profile.top_k,
            LLM_CONCURRENCY=first_profile.concurrency_min,
            BATCH_SIZE=first_profile.batch_size_min,
            POLL_INTERVAL=first_profile.poll_interval_min,
            OLLAMA_CONTEXT_LENGTH=first_profile.context_length_max,
        )


config = Config()
