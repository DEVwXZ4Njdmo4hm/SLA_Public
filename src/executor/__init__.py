#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         __init__.py
Description:  Executor subsystem module exports and public builder interface.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from .audit import AuditDB
from .handlers import HandlerRegistry, get_global_registry
from .models import (
    ActionRequest,
    ActionStatus,
    AuditEntry,
    AuditLevel,
    Capability,
    ExecutionResult,
    ParamConstraint,
    PathAccess,
    PolicyDecision,
    RateLimit,
)
from .path_guard import PathGuard, check_write_path
from .policy import PolicyEngine
from .registry import CapabilityRegistry
from .runtime import ExecutorRuntime

logger = logging.getLogger(__name__)

__all__ = [
    # Core types
    "ActionRequest",
    "ActionStatus",
    "AuditDB",
    "AuditEntry",
    "AuditLevel",
    "Capability",
    "CapabilityRegistry",
    "ExecutionResult",
    "ExecutorRuntime",
    "HandlerRegistry",
    "ParamConstraint",
    "PathAccess",
    "PathGuard",
    "PolicyDecision",
    "PolicyEngine",
    "RateLimit",
    # Utilities
    "check_write_path",
    # Factory
    "build_executor",
]


def build_executor(
    capabilities_dir: str | Path = "",
    audit_db_path: str | Path = "",
    sandbox_root: Optional[str] = None,
    dry_run: bool = False,
    handler_registry: Optional[HandlerRegistry] = None,
    user_db: object | None = None,
    path_vars: Optional[dict[str, str]] = None,
) -> ExecutorRuntime:
    """Convenience factory that assembles the full executor stack.

    Parameters
    ----------
    capabilities_dir:
        Directory containing ``*.toml`` capability declarations.
        If empty or non-existent, the executor starts with no capabilities.
    audit_db_path:
        Path to the SQLite audit database.  If empty, auditing is disabled.
    sandbox_root:
        Optional global file-system sandbox (all path operations must stay
        within this directory tree).
    dry_run:
        When *True*, the executor will not actually execute any handler —
        it performs policy checks and records DRY_RUN audit entries only.
    handler_registry:
        Custom handler registry.  Defaults to the global singleton.
    user_db:
        Optional U-A-P user database for identity and API-key verification.
    path_vars:
        Variable mapping for ``{var}`` expansion in capability ``paths``
        declarations.  Typical keys: ``repo_dir``, ``rules_path``.

    Returns
    -------
    ExecutorRuntime
        Ready-to-use executor instance.
    """
    registry = CapabilityRegistry()
    if capabilities_dir:
        cap_path = Path(capabilities_dir)
        if cap_path.is_dir():
            loaded = registry.load_dir(cap_path, path_vars=path_vars)
            logger.info(
                "Loaded %d capability declaration(s) from %s.", loaded, cap_path,
            )
        else:
            logger.info(
                "Capabilities directory not found: %s (executor starts empty).",
                cap_path,
            )

    policy = PolicyEngine(user_db=user_db)
    path_guard = PathGuard(sandbox_root)

    audit_db: Optional[AuditDB] = None
    if audit_db_path:
        audit_db = AuditDB(audit_db_path)
        logger.info("Executor audit database: %s", audit_db_path)

    return ExecutorRuntime(
        registry=registry,
        policy=policy,
        path_guard=path_guard,
        audit_db=audit_db,
        handler_registry=handler_registry or get_global_registry(),
        dry_run=dry_run,
        user_db=user_db,
    )
