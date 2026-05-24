#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         config.py
Description:  Deployment configuration aggregator loading multiple TOML sources.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .log import _fatal, _info, _ok
from .utils import _load_toml


class DeployConfig:
    """Load and validate all deployment configuration from multiple sources."""

    def __init__(self, deploy_toml_path: Path):
        self.deploy = _load_toml(deploy_toml_path)
        self._base_dir = deploy_toml_path.resolve().parent

        # Secrets
        secrets_rel = self.deploy["secrets"]["secrets"]
        self.secrets = _load_toml(self._base_dir / secrets_rel)

        # Agent TOML config
        agent_rel = self.deploy["general"]["agent_config"]
        self.agent_conf_path = (self._base_dir / agent_rel).resolve()
        if not self.agent_conf_path.is_file():
            _fatal(f"Agent 配置文件不存在: {self.agent_conf_path}")
        self.agent_conf = _load_toml(self.agent_conf_path)

        # Config directory
        self._cfg_dir = (
            self._base_dir / self.deploy["general"]["project_config_dir"]
        ).resolve()

        # Container base
        base_name = self.deploy["container"]["base"]
        self.container_base = _load_toml(
            self._cfg_dir / "container_base" / f"{base_name}.toml"
        )

        # Package manager
        pm_name = self.container_base["package"]["package_manager"]
        self.pm = _load_toml(self._cfg_dir / "package_manager" / f"{pm_name}.toml")

        # Templates
        self._tpl_dir = self._cfg_dir / "templates"
        self.containerfile_tpl = self._tpl_dir / "Containerfile.in"
        self.quadlet_tpl = self._tpl_dir / "suricata-llm-agent.container.in"
        for p in (self.containerfile_tpl, self.quadlet_tpl):
            if not p.is_file():
                _fatal(f"模板文件不存在: {p}")

        # Work directory
        self.work_dir = Path(self.deploy["general"]["deployment_work_dir"])

        # Shortcuts
        self.workdir = self.deploy["container"]["workdir"]  # e.g. "/app"
        self.image_url = self.container_base["image"]["url"]
        self.maintainer = self.deploy["container"]["maintainer"]
        self.run_as = int(self.deploy["quadlet"]["run_as"])

        # Deployment mode validation
        mode = self.deploy["deployment"]["mode"]
        if mode != "podman":
            _fatal(f"不支持的部署模式: '{mode}'（当前仅支持 'podman'）")

        _ok("部署配置加载完成。")
        _info(f"  容器基础镜像: {base_name} → {self.image_url}")
        _info(f"  包管理器:     {pm_name}")
        _info(f"  工作目录:     {self.work_dir}")
