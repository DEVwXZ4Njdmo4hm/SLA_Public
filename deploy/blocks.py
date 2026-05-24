#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         blocks.py
Description:  Containerfile and Quadlet block generators for template composition.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import DeployConfig


def _gen_pm_block(cfg: DeployConfig) -> str:
    """Generate @@ PM @@: refresh cache, then install packages (separate RUN)."""
    pm_binary = cfg.pm["commands"]["pm_binary"]
    pm_cmds = {c["name"]: c["cmd"] for c in cfg.pm["commands"]["pm_commands"]}
    packages = cfg.container_base["package"]["required_packages"]

    lines: list[str] = []
    if "refresh" in pm_cmds:
        lines.append(f"RUN {pm_binary} {pm_cmds['refresh']}")
    if packages:
        pkg_str = " ".join(packages)
        lines.append(f"RUN {pm_binary} {pm_cmds['install']} {pkg_str}")
    return "\n".join(lines)


def _gen_args_block(cfg: DeployConfig) -> str:
    """Generate @@ ARGS @@ from containerfile_args."""
    args_list = cfg.deploy["container"].get("containerfile_args", [])
    if not args_list:
        return ""
    return "\n".join(f"ARG {a['key']}={a['value']}" for a in args_list)


def _gen_extra_files_block(
    cfg: DeployConfig,
    implicit_files: list[str] | None = None,
) -> str:
    """Generate @@ Extra Files @@ from extra_files + implicit files."""
    lines: list[str] = []
    workdir = cfg.workdir

    for entry in cfg.deploy["container"].get("extra_files", []):
        src_basename = Path(entry["source"]).name
        dst = entry["destination"]
        lines.append(f"COPY {src_basename} {dst}")

    # Implicitly referenced files from agent config.
    if implicit_files:
        for fpath in implicit_files:
            basename = os.path.basename(fpath)
            lines.append(f"COPY {basename} {workdir}/{basename}")

    return "\n".join(lines)


def _gen_extra_cmd_block(cfg: DeployConfig) -> str:
    """Generate @@ Extra CMD @@ from extra_commands."""
    cmds = cfg.deploy["container"].get("extra_commands", [])
    if not cmds:
        return ""
    return "\n".join(f"RUN {c}" for c in cmds)


def _gen_environment_block(cfg: DeployConfig) -> str:
    """Generate @@ Environment @@ for the Quadlet service file."""
    env_list = cfg.deploy["quadlet"].get("environment", [])
    if not env_list:
        return ""
    return "\n".join(
        f"Environment={e['key']}={e['value']}" for e in env_list
    )


def _gen_auth_volume_block(cfg: DeployConfig) -> str:
    """Generate @@ Auth Volume @@ for the Quadlet service file.

    Bind-mounts the host directory containing the SQLite credentials
    database into the container.  The mount targets a subdirectory of
    the container workdir so that WAL/SHM companion files are captured.
    """
    agent_auth = cfg.agent_conf.get("auth", {})
    db_path = agent_auth.get("db_path", "")
    if not db_path:
        return ""
    host_dir = cfg.deploy.get("auth", {}).get("db_host_dir", "")
    if not host_dir:
        return ""
    workdir = cfg.workdir
    db_dir = os.path.dirname(db_path)
    if not db_dir:
        db_dir = "auth-data"
    return f"Volume={host_dir}:{workdir}/{db_dir}:Z"


def _format_port_mapping(cfg: DeployConfig) -> str:
    pm = cfg.deploy["networking"]["PortMapping"]
    return f"{pm['host_netseg']}:{pm['host_port']}:{pm['container_port']}"


def _format_addhost(cfg: DeployConfig) -> str:
    ah = cfg.deploy["networking"]["AddHost"]
    return f"{ah['hostname']}:{ah['ip']}"


def _gen_git_volume_block(cfg: DeployConfig) -> str:
    """Generate @@ Git Volume @@ for the Quadlet service file.

    The git workspace is ephemeral and lives only inside the container.
    It is cloned fresh on each container start by ``_init_git_workspace()``,
    so no host bind-mount is needed.  Returns an empty string.
    """
    return ""
