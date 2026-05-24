#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         utils.py
Description:  Utility functions for program checks, subprocess execution, and TOML loading.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import os
import pwd
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

from .constants import EXCLUDE_DIR_NAMES, EXCLUDE_SUFFIXES, REQUIRED_PROGRAMS
from .log import _fatal, _info


def _ensure_interactive() -> None:
    """Abort early if not attached to a real terminal."""
    if not sys.stdin.isatty():
        _fatal(
            "deploy.py 需要在交互式终端中运行（不支持自动/IDE 内执行）。\n"
            "请在终端中手动执行：python3 deploy.py"
        )


def _check_programs() -> None:
    missing = [p for p in REQUIRED_PROGRAMS if shutil.which(p) is None]
    if missing:
        _fatal(f"缺少必需程序: {', '.join(missing)}")


def _run(
    cmd: list[str], *, check: bool = True, capture: bool = False, **kw,
) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check, capture_output=capture, text=True, **kw)


def _sudo(cmd: list[str], *, run_as: int = 0, **kw) -> subprocess.CompletedProcess:
    """Run *cmd* with elevated privileges.

    When *run_as* is a non-zero UID different from the current user,
    ``sudo -u <user>`` is used so that file operations happen under the
    target user's identity (rootless deployment).  Otherwise plain
    ``sudo`` (root) is used.
    """
    if run_as and run_as != os.getuid():
        user = pwd.getpwuid(run_as).pw_name
        return _run(["sudo", "-u", user] + cmd, **kw)
    return _run(["sudo"] + cmd, **kw)


def _sudo_systemctl(args: list[str], *, run_as: int = 0, **kw) -> subprocess.CompletedProcess:
    """Run ``systemctl`` with correct scope for the *run_as* UID.

    For rootless (run_as != 0) this invokes ``systemctl --user`` under
    the target user with the required ``XDG_RUNTIME_DIR`` and
    ``DBUS_SESSION_BUS_ADDRESS`` environment variables.
    """
    if run_as and run_as != os.getuid():
        user = pwd.getpwuid(run_as).pw_name
        xdg = f"/run/user/{run_as}"
        dbus = f"unix:path={xdg}/bus"
        return _run(
            ["sudo", "-u", user, "env",
             f"XDG_RUNTIME_DIR={xdg}",
             f"DBUS_SESSION_BUS_ADDRESS={dbus}",
             "systemctl", "--user"] + args,
            **kw,
        )
    return _run(["sudo", "systemctl"] + args, **kw)


# ── TOML helpers ─────────────────────────────────────────────────────────────
def _load_toml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        _fatal(f"TOML 文件不存在: {path}")
    with open(path, "rb") as f:
        return tomllib.load(f)


def _resolve_dotpath(data: dict[str, Any], dotpath: str) -> str:
    """Walk a dot-separated path into nested dicts, return the leaf as str."""
    keys = dotpath.split(".")
    current: Any = data
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            _fatal(f"引用路径解析失败: '{dotpath}'，键 '{key}' 不存在。")
    return str(current)


# ── File helpers ─────────────────────────────────────────────────────────────
def _should_exclude(name: str) -> bool:
    """Check whether a directory entry name should be excluded from copying."""
    if name in EXCLUDE_DIR_NAMES:
        return True
    for suffix in EXCLUDE_SUFFIXES:
        if name.endswith(suffix):
            return True
    return False


def _copytree_filtered(src: Path, dst: Path) -> None:
    """Copy a directory tree, skipping __pycache__, *.egg-info, and *.pyc."""
    dst.mkdir(parents=True, exist_ok=True)
    for item in src.iterdir():
        if _should_exclude(item.name):
            continue
        target = dst / item.name
        if item.is_dir():
            _copytree_filtered(item, target)
        elif item.suffix != ".pyc":
            shutil.copy2(item, target)
