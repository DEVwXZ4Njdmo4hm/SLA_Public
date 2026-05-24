#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         registry.py
Description:  Capability registry loader from declarative TOML files with variable expansion.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import logging
import tomllib
from pathlib import Path
from typing import Dict, List, Optional

from .models import Capability, ParamConstraint, PathAccess, RateLimit

logger = logging.getLogger(__name__)


class CapabilityRegistry:
    """Thread-safe registry of executor capabilities.

    Capabilities are loaded from ``*.toml`` files under a directory.
    Each file may declare one or more capabilities.

    Expected TOML layout::

        [capability.<name>]
        description = "..."
        handler = "handler_key"
        allowed_roles = ["Agent", "Administrator", "Owner"]
        enabled = true

        [capability.<name>.params.<param_name>]
        type = "string"
        required = true
        pattern = "^(alert|drop) .+"

        [capability.<name>.rate_limit]
        max_calls = 20
        window_seconds = 3600

        [capability.<name>.paths.read]
        dirs = ["/app/rules"]

        [capability.<name>.paths.write]
        dirs = ["{repo_dir}/{rules_path}"]

    Path variable expansion
    -----------------------
    Values in ``dirs`` lists support ``{variable}`` placeholders that are
    resolved at load time via the *path_vars* dict passed to
    :meth:`load_dir` / :meth:`load_file`.
    """

    def __init__(self) -> None:
        self._caps: Dict[str, Capability] = {}
        self._path_vars: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def get(self, name: str) -> Optional[Capability]:
        return self._caps.get(name)

    def list_names(self) -> List[str]:
        return list(self._caps.keys())

    def __len__(self) -> int:
        return len(self._caps)

    def __contains__(self, name: str) -> bool:
        return name in self._caps

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_dir(self, directory: Path, path_vars: Optional[Dict[str, str]] = None) -> int:
        """Load all ``*.toml`` files in *directory*.  Returns number of
        capabilities loaded.

        Parameters
        ----------
        path_vars:
            Variable mapping for ``{var}`` expansion in ``paths.*.dirs``
            values.  Stored for subsequent :meth:`load_file` calls.
        """
        if path_vars:
            self._path_vars.update(path_vars)
        count = 0
        if not directory.is_dir():
            return 0
        for filepath in sorted(directory.glob("*.toml")):
            if filepath.name == "examples.toml":
                continue  # reference template, not a real declaration
            count += self._load_file(filepath)
        return count

    def load_file(self, filepath: Path, path_vars: Optional[Dict[str, str]] = None) -> int:
        """Load capabilities from a single TOML file."""
        if path_vars:
            self._path_vars.update(path_vars)
        return self._load_file(filepath)

    def register(self, cap: Capability) -> None:
        """Manually register a capability (e.g. from tests)."""
        self._caps[cap.name] = cap

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _load_file(self, filepath: Path) -> int:
        try:
            with open(filepath, "rb") as fh:
                data = tomllib.load(fh)
        except Exception as exc:
            logger.warning("Failed to parse capability file %s: %s", filepath, exc)
            return 0

        caps_section = data.get("capability", {})
        if not isinstance(caps_section, dict):
            logger.warning("No [capability.*] sections in %s", filepath)
            return 0

        loaded = 0
        for name, payload in caps_section.items():
            if not isinstance(payload, dict):
                continue
            cap = self._parse_capability(name, payload, filepath)
            if cap is not None:
                self._caps[name] = cap
                loaded += 1

        return loaded

    def _parse_capability(
        self, name: str, payload: dict, source: Path
    ) -> Optional[Capability]:
        try:
            params = self._parse_params(payload.get("params", {}))
            rate_limit = self._parse_rate_limit(payload.get("rate_limit"))
            paths = self._parse_paths(payload.get("paths", {}))

            return Capability(
                name=name,
                description=str(payload.get("description", "")),
                handler=str(payload.get("handler", name)),
                allowed_roles=list(payload.get("allowed_roles", [])),
                params=params,
                rate_limit=rate_limit,
                paths=paths,
                enabled=bool(payload.get("enabled", True)),
                requires_approval=bool(payload.get("requires_approval", False)),
                path_params=list(payload.get("path_params", [])),
            )
        except Exception as exc:
            logger.warning(
                "Invalid capability '%s' in %s: %s", name, source, exc,
            )
            return None

    @staticmethod
    def _parse_params(raw: dict) -> List[ParamConstraint]:
        params: List[ParamConstraint] = []
        if not isinstance(raw, dict):
            return params
        for pname, pspec in raw.items():
            if not isinstance(pspec, dict):
                continue
            params.append(ParamConstraint(
                name=str(pname),
                type=str(pspec.get("type", "string")),
                required=bool(pspec.get("required", True)),
                pattern=str(pspec.get("pattern", "")),
                min_value=pspec.get("min") if pspec.get("min") is not None else None,
                max_value=pspec.get("max") if pspec.get("max") is not None else None,
                choices=list(pspec.get("choices", [])),
            ))
        return params

    @staticmethod
    def _parse_rate_limit(raw) -> Optional[RateLimit]:
        if not isinstance(raw, dict):
            return None
        return RateLimit(
            max_calls=int(raw.get("max_calls", 0)),
            window_seconds=int(raw.get("window_seconds", 3600)),
        )

    def _parse_paths(self, raw: dict) -> Dict[PathAccess, List[str]]:
        paths: Dict[PathAccess, List[str]] = {}
        if not isinstance(raw, dict):
            return paths
        for mode_str, spec in raw.items():
            try:
                mode = PathAccess(mode_str)
            except ValueError:
                continue
            dirs = spec.get("dirs", []) if isinstance(spec, dict) else []
            if isinstance(dirs, list):
                resolved: List[str] = []
                for d in dirs:
                    s = str(d)
                    if self._path_vars:
                        try:
                            s = s.format_map(self._path_vars)
                        except KeyError as exc:
                            logger.warning(
                                "Unresolved path variable %s in '%s' — "
                                "check that path_vars is correctly configured.",
                                exc, d,
                            )
                    resolved.append(s)
                paths[mode] = resolved
        return paths
