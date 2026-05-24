#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         models.py
Description:  Executor data models for capabilities, actions, policies, and audit entries.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class ActionStatus(str, enum.Enum):
    """Lifecycle status of an execution request."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    SUCCESS = "success"
    FAILED = "failed"
    DRY_RUN = "dry_run"


class AuditLevel(str, enum.Enum):
    """Severity level for audit log entries."""
    INFO = "info"
    WARN = "warn"
    DENY = "deny"
    ERROR = "error"


class PathAccess(str, enum.Enum):
    """File-system access mode declared by a capability."""
    READ = "read"
    WRITE = "write"


# ---------------------------------------------------------------------------
# Capability declarations — loaded from TOML
# ---------------------------------------------------------------------------

@dataclass
class ParamConstraint:
    """Validation constraint for a single capability parameter."""
    name: str
    type: str  # "string" | "integer" | "float" | "boolean"
    required: bool = True
    pattern: str = ""          # regex for strings
    min_value: Optional[float] = None  # for integer / float
    max_value: Optional[float] = None
    choices: List[str] = field(default_factory=list)


@dataclass
class RateLimit:
    """Per-capability invocation rate limit."""
    max_calls: int = 0        # 0 = unlimited
    window_seconds: int = 3600


@dataclass
class Capability:
    """Declarative definition of a single executable action.

    Loaded from a TOML file in ``configs/capabilities/``.
    """
    name: str
    description: str = ""
    handler: str = ""          # handler function key in HandlerRegistry
    allowed_roles: List[str] = field(default_factory=list)
    params: List[ParamConstraint] = field(default_factory=list)
    rate_limit: Optional[RateLimit] = None
    paths: Dict[PathAccess, List[str]] = field(default_factory=dict)
    enabled: bool = True
    requires_approval: bool = False
    # Explicit set of param names that carry file-system paths.
    # When non-empty, PathGuard only inspects these params.
    # When empty, the runtime falls back to heuristic detection.
    path_params: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Execution request / result — runtime objects
# ---------------------------------------------------------------------------

@dataclass
class ActionRequest:
    """An LLM- or user-originated request to execute a capability."""
    capability: str            # must match a registered Capability.name
    params: Dict[str, Any] = field(default_factory=dict)
    actor_role: str = "Agent"  # U-A-P role of the requester
    actor_id: str = ""         # user ID / "llm" / etc.
    request_id: str = ""       # caller-provided or auto-generated
    api_key: str = ""          # raw API key for internal identity verification
    # Populated by ExecutorRuntime before handler dispatch.
    # Handlers MUST validate their write targets against this list.
    resolved_write_dirs: List[str] = field(default_factory=list, repr=False)


@dataclass
class ExecutionResult:
    """Outcome of an execution attempt."""
    request_id: str
    capability: str
    status: ActionStatus
    detail: str = ""
    output: Any = None


# ---------------------------------------------------------------------------
# Policy decision — returned by PolicyEngine before execution
# ---------------------------------------------------------------------------

@dataclass
class PolicyDecision:
    """Result of pre-execution policy evaluation."""
    allowed: bool
    reason: str = ""


# ---------------------------------------------------------------------------
# Audit entry — written to AuditDB
# ---------------------------------------------------------------------------

@dataclass
class AuditEntry:
    """Immutable record of an execution attempt (write-once)."""
    request_id: str
    capability: str
    actor_role: str
    actor_id: str
    status: str  # ActionStatus.value
    detail: str = ""
    params_json: str = ""   # JSON-serialised parameters
    timestamp: str = ""     # ISO-8601 UTC
    level: str = "info"     # AuditLevel.value
