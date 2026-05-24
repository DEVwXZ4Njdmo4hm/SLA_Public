#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         path_guard.py
Description:  File-system sandbox enforcer ensuring path operations stay within boundaries.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


class PathGuard:
    """Enforce file-system boundaries for executor operations.

    Every path must resolve inside the *sandbox_root* (when set) **and**
    inside at least one of the per-capability allowed directories.
    Symlink traversal is blocked by resolving paths before comparison.
    """

    def __init__(self, sandbox_root: Optional[str] = None) -> None:
        self._sandbox: Optional[Path] = (
            Path(sandbox_root).resolve() if sandbox_root else None
        )

    @property
    def sandbox_root(self) -> Optional[Path]:
        return self._sandbox

    def check(self, target: str, allowed_dirs: List[str]) -> bool:
        """Return *True* if *target* is within the sandbox and at least
        one of *allowed_dirs*.

        Parameters
        ----------
        target:
            The file or directory path to validate.
        allowed_dirs:
            Per-capability list of allowed parent directories.
        """
        try:
            resolved = Path(target).resolve()
        except (OSError, ValueError):
            return False

        # Global sandbox check
        if self._sandbox is not None:
            if not self._is_under(resolved, self._sandbox):
                logger.debug(
                    "PathGuard: %s is outside sandbox %s", resolved, self._sandbox,
                )
                return False

        # Per-capability directory whitelist
        if not allowed_dirs:
            return False

        for allowed in allowed_dirs:
            try:
                allowed_resolved = Path(allowed).resolve()
            except (OSError, ValueError):
                continue
            if self._is_under(resolved, allowed_resolved):
                return True

        logger.debug(
            "PathGuard: %s is not under any allowed dir %s", resolved, allowed_dirs,
        )
        return False

    @staticmethod
    def _is_under(child: Path, parent: Path) -> bool:
        """Check if *child* is equal to or a descendant of *parent*.

        Uses string comparison on resolved POSIX paths to prevent
        path-traversal attacks.
        """
        # os.path.commonpath raises ValueError on Windows with mixed drives;
        # on POSIX this is safe.
        try:
            return os.path.commonpath([str(child), str(parent)]) == str(parent)
        except ValueError:
            return False


def check_write_path(target: str, allowed_dirs: List[str]) -> Optional[str]:
    """Validate that *target* is within at least one of *allowed_dirs*.

    Returns ``None`` on success, or an error message if the path is
    outside all allowed directories.  If *allowed_dirs* is empty, any
    path is considered invalid.

    This is a standalone utility for use in handlers; the global
    sandbox check is enforced separately by :class:`PathGuard` in the
    runtime.
    """
    if not allowed_dirs:
        return f"No write directories declared; refusing to write '{target}'."
    try:
        resolved = Path(target).resolve()
    except (OSError, ValueError):
        return f"Cannot resolve path: '{target}'."
    for d in allowed_dirs:
        try:
            if PathGuard._is_under(resolved, Path(d).resolve()):
                return None
        except (OSError, ValueError):
            continue
    return (
        f"Write target '{target}' (resolved: {resolved}) is outside "
        f"allowed directories {allowed_dirs}."
    )
