#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         runtime.py
Description:  Top-level executor runtime orchestrating policy check, dispatch, and audit.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Optional

from .audit import AuditDB
from .handlers import HandlerRegistry, get_global_registry
from .models import (
    ActionRequest,
    ActionStatus,
    AuditEntry,
    AuditLevel,
    ExecutionResult,
    PathAccess,
)
from .path_guard import PathGuard
from .policy import PolicyEngine
from .registry import CapabilityRegistry

logger = logging.getLogger(__name__)


class ExecutorRuntime:
    """Top-level executor: policy check → handler dispatch → audit record.

    Parameters
    ----------
    registry:
        Loaded capability declarations.
    policy:
        Pre-execution policy evaluator (role / param / rate-limit).
    path_guard:
        File-system sandbox enforcer.
    audit_db:
        Audit log database (``None`` → auditing disabled).
    handler_registry:
        Handler callable lookup (defaults to the global registry).
    dry_run:
        When *True*, executor **never** executes — only evaluates policy
        and records a ``DRY_RUN`` audit entry.  Useful for initial
        deployment when trust has not yet been established.
    user_db:
        Optional U-A-P user database for API-key verification.
    """

    def __init__(
        self,
        registry: CapabilityRegistry,
        policy: PolicyEngine,
        path_guard: PathGuard,
        audit_db: Optional[AuditDB] = None,
        handler_registry: Optional[HandlerRegistry] = None,
        dry_run: bool = False,
        user_db: object | None = None,
    ) -> None:
        self._registry = registry
        self._policy = policy
        self._path_guard = path_guard
        self._audit = audit_db
        self._handlers = handler_registry or get_global_registry()
        self._dry_run = dry_run
        self._user_db = user_db

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def dry_run(self) -> bool:
        return self._dry_run

    @dry_run.setter
    def dry_run(self, value: bool) -> None:
        self._dry_run = value

    @property
    def registry(self) -> CapabilityRegistry:
        return self._registry

    @property
    def audit_db(self) -> Optional[AuditDB]:
        return self._audit

    # ------------------------------------------------------------------
    # Core entry point
    # ------------------------------------------------------------------

    def execute(self, request: ActionRequest) -> ExecutionResult:
        """Execute (or dry-run) an action request.

        Flow:
        1. Assign request ID if missing.
        2. Look up capability in registry.
        3. Evaluate policy (role, params, rate limit).
        4. Validate file-path parameters against PathGuard.
        5. If dry_run → record and return DRY_RUN status.
        6. Dispatch to handler.
        7. Audit the outcome.
        """
        # 1. Ensure request ID
        if not request.request_id:
            request.request_id = uuid.uuid4().hex[:16]

        # 2. Capability lookup
        cap = self._registry.get(request.capability)
        if cap is None:
            return self._reject(
                request, f"Unknown capability: '{request.capability}'.",
            )

        # 3. Policy evaluation
        decision = self._policy.evaluate(
            cap, request.actor_role, request.actor_id, request.params,
        )
        if not decision.allowed:
            return self._deny(request, decision.reason)

        # 3b. API-key verification (only when user_db is available and key supplied)
        if self._user_db is not None and request.api_key:
            verified_user = self._user_db.verify_api_key(request.api_key)
            if verified_user is None:
                return self._deny(request, "Invalid or revoked API key.")
            if str(verified_user.id) != request.actor_id:
                return self._deny(
                    request,
                    f"API key does not belong to actor_id '{request.actor_id}'.",
                )

        # 4. Path guard — check any string params that look like file-system
        #    paths against the capability's declared path whitelist.
        #    Only inspect params whose name appears in the capability's
        #    declared path_params set (if configured) or, as a legacy
        #    fallback, any param whose value starts with "/" or "\\".
        path_param_names = cap.path_params
        for access_mode in (PathAccess.READ, PathAccess.WRITE):
            allowed_dirs = cap.paths.get(access_mode, [])
            if not allowed_dirs:
                continue
            for pname, pval in request.params.items():
                if not isinstance(pval, str):
                    continue
                is_path_param = pname in path_param_names if path_param_names else (
                    pval.startswith("/") or pval.startswith("\\\\")
                )
                if is_path_param:
                    if not self._path_guard.check(pval, allowed_dirs):
                        return self._deny(
                            request,
                            f"Path '{pval}' is outside allowed directories "
                            f"for {access_mode.value} access.",
                        )

        # 5. Dry-run → audit and return early
        if self._dry_run:
            result = ExecutionResult(
                request_id=request.request_id,
                capability=request.capability,
                status=ActionStatus.DRY_RUN,
                detail="Dry-run mode: action was not executed.",
            )
            self._audit_record(request, result, AuditLevel.INFO)
            return result

        # 6. Inject resolved write directories so handlers can validate
        #    their actual file-system targets before writing.
        write_dirs = cap.paths.get(PathAccess.WRITE, [])
        request.resolved_write_dirs = list(write_dirs)

        # 7. Dispatch to handler
        handler = self._handlers.get(cap.handler)
        if handler is None:
            return self._reject(
                request,
                f"No handler registered for '{cap.handler}'.",
            )

        try:
            result = handler(request)
        except Exception as exc:
            logger.error(
                "Handler '%s' raised for request %s: %s",
                cap.handler, request.request_id, exc,
            )
            result = ExecutionResult(
                request_id=request.request_id,
                capability=request.capability,
                status=ActionStatus.FAILED,
                detail=str(exc),
            )

        # 7. Audit
        level = AuditLevel.INFO if result.status == ActionStatus.SUCCESS else AuditLevel.ERROR
        self._audit_record(request, result, level)
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _reject(self, request: ActionRequest, reason: str) -> ExecutionResult:
        """Capability not found or handler missing."""
        result = ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.REJECTED,
            detail=reason,
        )
        self._audit_record(request, result, AuditLevel.WARN)
        return result

    def _deny(self, request: ActionRequest, reason: str) -> ExecutionResult:
        """Policy denied execution."""
        result = ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.REJECTED,
            detail=reason,
        )
        self._audit_record(request, result, AuditLevel.DENY)
        return result

    def _audit_record(
        self,
        request: ActionRequest,
        result: ExecutionResult,
        level: AuditLevel,
    ) -> None:
        if self._audit is None:
            return
        try:
            params_json = json.dumps(request.params, ensure_ascii=False, default=str)
        except Exception:
            params_json = "{}"
        entry = AuditEntry(
            request_id=request.request_id,
            capability=request.capability,
            actor_role=request.actor_role,
            actor_id=request.actor_id,
            status=result.status.value,
            detail=result.detail,
            params_json=params_json,
            level=level.value,
        )
        try:
            self._audit.record(entry)
        except Exception as exc:
            logger.error("Failed to write audit entry: %s", exc)
