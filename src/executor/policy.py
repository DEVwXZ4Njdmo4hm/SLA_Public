#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         policy.py
Description:  Policy engine for role checks, parameter validation, and rate limiting.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import logging
import re
import time
from collections import defaultdict, deque
from threading import Lock
from typing import Any, Deque, Dict, List, Tuple

from .models import Capability, ParamConstraint, PolicyDecision, RateLimit

logger = logging.getLogger(__name__)

# Type for the sliding-window rate-limit store:
#   key = (capability_name, actor_id)  →  deque of timestamps
_RateBucket = Deque[float]

# Optional import — UserDB may not be available in minimal deployments.
try:
    from ..auth.database import UserDB as _UserDB
except Exception:  # pragma: no cover
    _UserDB = None  # type: ignore[assignment,misc]


class PolicyEngine:
    """Pre-execution policy evaluator.

    Responsibilities:
    1. **Role gate** — Is the actor's role in the capability's allowed list?
    2. **Identity verification** — Does ``actor_id`` map to a real user with
       a matching role in the U-A-P database (when available)?
    3. **Parameter validation** — Do supplied params satisfy declared constraints?
    4. **Rate limiting** — Has the actor exceeded the per-capability rate limit?
    """

    def __init__(self, user_db: object | None = None) -> None:
        self._rate_lock = Lock()
        self._rate_buckets: Dict[Tuple[str, str], _RateBucket] = defaultdict(deque)
        self._user_db = user_db

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def evaluate(
        self,
        capability: Capability,
        actor_role: str,
        actor_id: str,
        params: Dict[str, Any],
    ) -> PolicyDecision:
        """Run all policy checks.  Returns a single decision."""

        # 1. Capability enabled?
        if not capability.enabled:
            return PolicyDecision(False, f"Capability '{capability.name}' is disabled.")

        # 2. Role check
        decision = self._check_role(capability, actor_role)
        if not decision.allowed:
            return decision

        # 3. Identity verification against U-A-P database
        decision = self._check_identity(actor_role, actor_id)
        if not decision.allowed:
            return decision

        # 4. Parameter validation
        decision = self._check_params(capability, params)
        if not decision.allowed:
            return decision

        # 5. Rate limit
        decision = self._check_rate(capability, actor_id)
        if not decision.allowed:
            return decision

        return PolicyDecision(True)

    # ------------------------------------------------------------------
    # Role gate
    # ------------------------------------------------------------------

    @staticmethod
    def _check_role(cap: Capability, actor_role: str) -> PolicyDecision:
        if not cap.allowed_roles:
            # No role restriction declared → open to all.
            return PolicyDecision(True)
        if actor_role not in cap.allowed_roles:
            return PolicyDecision(
                False,
                f"Role '{actor_role}' is not permitted for capability '{cap.name}'. "
                f"Allowed: {cap.allowed_roles}",
            )
        return PolicyDecision(True)

    # ------------------------------------------------------------------
    # Identity verification (U-A-P database)
    # ------------------------------------------------------------------

    def _check_identity(
        self, actor_role: str, actor_id: str,
    ) -> PolicyDecision:
        """Verify *actor_id* corresponds to a real user whose role matches.

        When no ``user_db`` is configured (tests, standalone executor) this
        check is a no-op — preserving backward compatibility.
        """
        if self._user_db is None:
            return PolicyDecision(True)
        if not actor_id:
            return PolicyDecision(
                False, "actor_id is required when U-A-P database is active.",
            )
        try:
            user = self._user_db.get_user_by_id(int(actor_id))
        except (ValueError, TypeError):
            return PolicyDecision(
                False,
                f"actor_id '{actor_id}' is not a valid user identifier.",
            )
        if user is None:
            return PolicyDecision(
                False,
                f"No user found for actor_id '{actor_id}' in U-A-P database.",
            )
        if user.role.value != actor_role:
            return PolicyDecision(
                False,
                f"Role mismatch: actor_id '{actor_id}' has role '{user.role.value}' "
                f"but request claims '{actor_role}'.",
            )
        return PolicyDecision(True)

    # ------------------------------------------------------------------
    # Parameter validation
    # ------------------------------------------------------------------

    @staticmethod
    def _check_params(cap: Capability, params: Dict[str, Any]) -> PolicyDecision:
        supplied = set(params.keys())
        declared = {p.name: p for p in cap.params}

        # Check required params
        for pc in cap.params:
            if pc.required and pc.name not in supplied:
                return PolicyDecision(
                    False, f"Missing required parameter '{pc.name}' for '{cap.name}'.",
                )

        # Reject undeclared params (strict whitelist)
        for key in supplied:
            if key not in declared:
                return PolicyDecision(
                    False,
                    f"Unknown parameter '{key}' for capability '{cap.name}'.",
                )

        # Per-param type & constraint checks
        for key, value in params.items():
            pc = declared[key]
            decision = PolicyEngine._validate_param(pc, value)
            if not decision.allowed:
                return decision

        return PolicyDecision(True)

    @staticmethod
    def _validate_param(pc: ParamConstraint, value: Any) -> PolicyDecision:
        # Type check
        ok, reason = PolicyEngine._check_type(pc, value)
        if not ok:
            return PolicyDecision(False, reason)

        # String pattern
        if pc.type == "string" and pc.pattern:
            if not re.fullmatch(pc.pattern, str(value)):
                return PolicyDecision(
                    False,
                    f"Parameter '{pc.name}' value does not match pattern '{pc.pattern}'.",
                )

        # Numeric range
        if pc.type in ("integer", "float"):
            num = float(value)
            if pc.min_value is not None and num < pc.min_value:
                return PolicyDecision(
                    False,
                    f"Parameter '{pc.name}' value {value} is below minimum {pc.min_value}.",
                )
            if pc.max_value is not None and num > pc.max_value:
                return PolicyDecision(
                    False,
                    f"Parameter '{pc.name}' value {value} exceeds maximum {pc.max_value}.",
                )

        # Choices (enum-like)
        if pc.choices and str(value) not in pc.choices:
            return PolicyDecision(
                False,
                f"Parameter '{pc.name}' value '{value}' not in allowed choices {pc.choices}.",
            )

        return PolicyDecision(True)

    @staticmethod
    def _check_type(pc: ParamConstraint, value: Any) -> Tuple[bool, str]:
        expected = pc.type
        if expected == "string":
            if not isinstance(value, str):
                return False, f"Parameter '{pc.name}' must be a string."
        elif expected == "integer":
            if not isinstance(value, int) or isinstance(value, bool):
                return False, f"Parameter '{pc.name}' must be an integer."
        elif expected == "float":
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                return False, f"Parameter '{pc.name}' must be a number."
        elif expected == "boolean":
            if not isinstance(value, bool):
                return False, f"Parameter '{pc.name}' must be a boolean."
        return True, ""

    # ------------------------------------------------------------------
    # Rate limiting (sliding window)
    # ------------------------------------------------------------------

    def _check_rate(self, cap: Capability, actor_id: str) -> PolicyDecision:
        rl = cap.rate_limit
        if rl is None or rl.max_calls <= 0:
            return PolicyDecision(True)

        now = time.monotonic()
        key = (cap.name, actor_id)

        with self._rate_lock:
            bucket = self._rate_buckets[key]
            cutoff = now - rl.window_seconds

            # Prune expired entries
            while bucket and bucket[0] < cutoff:
                bucket.popleft()

            if len(bucket) >= rl.max_calls:
                return PolicyDecision(
                    False,
                    f"Rate limit exceeded for '{cap.name}': "
                    f"{rl.max_calls} calls per {rl.window_seconds}s.",
                )

            # Record this invocation
            bucket.append(now)

        return PolicyDecision(True)
