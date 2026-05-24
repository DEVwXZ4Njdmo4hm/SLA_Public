#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         workdir.py
Description:  Work directory preparation and filtered file copying for build context.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import TYPE_CHECKING

from .constants import COPY_DIRS, COPY_FILES, SOURCE_DIR
from .log import _fatal, _info, _ok, _warn
from .utils import _copytree_filtered

if TYPE_CHECKING:
    from .config import DeployConfig


def _resolve_copy_source(
    cfg: "DeployConfig",
    raw_path: str,
    *,
    prefer_agent_dir: bool = False,
) -> Path:
    """Resolve a build-context source path.

    Resolution order for relative paths:
    1. Agent-config directory (when ``prefer_agent_dir`` is True)
    2. deploy.toml base directory
    3. project source root

    This allows experiment config groups to override runtime config files
    (e.g. ``llm_prompt.toml``, ``ModelProfiles.toml``) with local variants
    that live beside the group-specific ``suricata-llm-agent.toml``.
    """
    candidate = Path(raw_path)
    if candidate.is_absolute():
        return candidate

    candidates: list[Path] = []
    if prefer_agent_dir:
        candidates.append((cfg.agent_conf_path.parent / candidate).resolve())
    candidates.append((cfg._base_dir / candidate).resolve())  # type: ignore[attr-defined]
    candidates.append((SOURCE_DIR / candidate).resolve())

    for resolved in candidates:
        if resolved.exists():
            return resolved
    return candidates[0]


def _prepare_work_dir(
    cfg: DeployConfig,
    implicit_files: list[str] | None = None,
    implicit_dirs: list[str] | None = None,
) -> Path:
    """Create the work directory and populate it with build context files."""
    work = cfg.work_dir

    if work.exists():
        _warn(f"工作目录已存在，将清空: {work}")
        shutil.rmtree(work)
    work.mkdir(parents=True)
    _info(f"已创建工作目录: {work}")

    # Copy individual files
    for fname in COPY_FILES:
        src = _resolve_copy_source(cfg, fname, prefer_agent_dir=True)
        if not src.is_file():
            _fatal(f"必需文件不存在: {src}")
        shutil.copy2(src, work / fname)

    # Copy directories (filtered)
    for dname in COPY_DIRS:
        src = _resolve_copy_source(cfg, dname, prefer_agent_dir=True)
        if not src.is_dir():
            _fatal(f"必需目录不存在: {src}")
        _copytree_filtered(src, work / dname)

    # Copy extra files declared in deploy.toml
    for entry in cfg.deploy["container"].get("extra_files", []):
        src_path = _resolve_copy_source(cfg, entry["source"])
        if not src_path.exists():
            _fatal(f"extra_files 中指定的文件不存在: {src_path}")
        if src_path.is_dir():
            _copytree_filtered(src_path, work / src_path.name)
        else:
            shutil.copy2(src_path, work / src_path.name)

    # Copy implicitly referenced files from agent config.
    if implicit_files:
        for fpath in implicit_files:
            src = _resolve_copy_source(cfg, fpath, prefer_agent_dir=True)
            if not src.is_file():
                _fatal(f"Agent 配置隐含引用的文件不存在: {src}")
            shutil.copy2(src, work / src.name)
            _info(f"  隐含配置引用文件已复制: {fpath}")

    # Copy implicitly referenced directories from agent config.
    if implicit_dirs:
        for dpath in implicit_dirs:
            src = _resolve_copy_source(cfg, dpath, prefer_agent_dir=True)
            if not src.is_dir():
                _fatal(f"Agent 配置隐含引用的目录不存在: {src}")
            _copytree_filtered(src, work / dpath)
            _info(f"  隐含配置引用目录已复制: {dpath}")

    _ok("构建上下文文件复制完成。")
    return work
