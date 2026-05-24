#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         __init__.py
Description:  Handler registry mapping capability names to callable implementations.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Optional

from ..models import ActionRequest, ActionStatus, ExecutionResult

logger = logging.getLogger(__name__)

# Handler signature:  (request: ActionRequest) -> ExecutionResult
HandlerFunc = Callable[[ActionRequest], ExecutionResult]


class HandlerRegistry:
    """Simple name → callable mapping for capability handlers.

    Handlers are registered either programmatically or by importing
    sub-modules that call ``register()`` at import time.
    """

    def __init__(self) -> None:
        self._handlers: Dict[str, HandlerFunc] = {}

    def register(self, name: str, func: HandlerFunc) -> None:
        """Register a handler function under *name*."""
        self._handlers[name] = func
        logger.debug("Handler registered: %s", name)

    def get(self, name: str) -> Optional[HandlerFunc]:
        return self._handlers.get(name)

    def __contains__(self, name: str) -> bool:
        return name in self._handlers

    def list_names(self) -> list[str]:
        return list(self._handlers.keys())


# Module-level singleton so handler sub-modules can import and register.
_global_registry = HandlerRegistry()


def register_handler(name: str, func: HandlerFunc) -> None:
    """Convenience wrapper to register into the global handler registry."""
    _global_registry.register(name, func)


def get_global_registry() -> HandlerRegistry:
    return _global_registry


# ── Auto-register built-in handlers ─────────────────────────────────────────

def _register_builtin_handlers() -> None:
    """Import and register all built-in handler implementations."""
    from .git_ops import (
        create_github_issue,
        create_github_pr,
        close_github_prs,
        git_commit_and_push,
        git_local_checkout_default,
        git_repo_reset,
        git_clone_repo,
    )
    from .suricata_rules import suricata_rule_suggest

    _global_registry.register("create_github_issue", create_github_issue)
    _global_registry.register("create_github_pr", create_github_pr)
    _global_registry.register("close_github_prs", close_github_prs)
    _global_registry.register("git_commit_and_push", git_commit_and_push)
    _global_registry.register("git_local_checkout_default", git_local_checkout_default)
    _global_registry.register("git_repo_reset", git_repo_reset)
    _global_registry.register("git_clone_repo", git_clone_repo)
    _global_registry.register("suricata_rule_suggest", suricata_rule_suggest)


_register_builtin_handlers()
