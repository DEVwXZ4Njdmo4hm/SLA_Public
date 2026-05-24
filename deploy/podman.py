#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         podman.py
Description:  Podman image build, Quadlet installation, and systemd service management.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

from .constants import SERVICE_NAME
from .log import _err, _fatal, _info, _ok
from .utils import _run, _sudo, _sudo_systemctl

if TYPE_CHECKING:
    from .config import DeployConfig


def _build_image(cfg: DeployConfig, work_dir: Path) -> None:
    """Build the container image from the generated build context."""
    image_name = cfg.deploy["quadlet"]["image_name"]
    _info(f"正在构建容器镜像: {image_name} ...")

    result = _sudo(
        ["podman", "build", "-t", image_name, str(work_dir)],
        run_as=cfg.run_as, check=False, capture=True,
    )
    if result.returncode != 0:
        _err("容器镜像构建失败：")
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        sys.exit(1)

    _ok(f"容器镜像构建完成: {image_name}")


def _resolve_quadlet_dir(cfg: DeployConfig) -> Path:
    """Determine the Quadlet installation directory based on run_as UID."""
    if cfg.run_as == 0:
        return Path("/etc/containers/systemd")
    import pwd
    try:
        pw = pwd.getpwuid(cfg.run_as)
    except KeyError:
        _fatal(f"UID {cfg.run_as} 不存在，无法确定 Quadlet 安装路径。")
    return Path(pw.pw_dir) / ".config" / "containers" / "systemd"


def _install_quadlet(cfg: DeployConfig, quadlet_content: str) -> None:
    """Install the generated Quadlet service file to the systemd path."""
    if not cfg.deploy["quadlet"].get("enable", True):
        _info("Quadlet 未启用，跳过安装。")
        return

    quadlet_dir = _resolve_quadlet_dir(cfg)
    unit_name = cfg.deploy["quadlet"]["container_name"] + ".container"
    target = quadlet_dir / unit_name

    _sudo(["mkdir", "-p", str(quadlet_dir)], run_as=cfg.run_as, capture=True)

    result = _sudo(
        ["tee", str(target)],
        run_as=cfg.run_as, input=quadlet_content, check=False, capture=True,
    )
    if result.returncode != 0:
        _fatal(f"安装 Quadlet 文件失败: {result.stderr.strip()}")

    _ok(f"Quadlet 文件已安装: {target}")


def _restart_service(cfg: DeployConfig) -> None:
    """Reload systemd and restart the service, then verify."""
    _info("重载 systemd 并重启服务 ...")

    ra = cfg.run_as
    _sudo_systemctl(["daemon-reload"], run_as=ra, capture=True)
    _sudo_systemctl(
        ["restart", SERVICE_NAME],
        run_as=ra, check=False, capture=True,
    )

    probe = _sudo_systemctl(
        ["is-active", SERVICE_NAME],
        run_as=ra, check=False, capture=True,
    )
    state = probe.stdout.strip() if probe.stdout else "unknown"

    if state == "active":
        _ok(f"服务 {SERVICE_NAME} 已重启，当前状态: {state}")
    else:
        _err(f"服务 {SERVICE_NAME} 重启后状态异常: {state}")
        if ra and ra != __import__('os').getuid():
            import pwd as _pwd
            _user = _pwd.getpwuid(ra).pw_name
            _xdg = f"/run/user/{ra}"
            _dbus = f"unix:path={_xdg}/bus"
            journal = _run(
                ["sudo", "-u", _user, "env",
                 f"XDG_RUNTIME_DIR={_xdg}",
                 f"DBUS_SESSION_BUS_ADDRESS={_dbus}",
                 "journalctl", "--user",
                 "-u", SERVICE_NAME, "-n", "20", "--no-pager"],
                check=False, capture=True,
            )
        else:
            journal = _sudo(
                ["journalctl", "-u", SERVICE_NAME, "-n", "20", "--no-pager"],
                check=False, capture=True,
            )
        if journal.stdout:
            print(journal.stdout)
        sys.exit(1)
