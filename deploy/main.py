#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         main.py
Description:  Main deployment orchestration workflow from config to service installation.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import argparse
import os
import pwd
import shutil
import subprocess
from pathlib import Path

from .blocks import (
    _format_addhost,
    _format_port_mapping,
    _gen_args_block,
    _gen_auth_volume_block,
    _gen_environment_block,
    _gen_extra_cmd_block,
    _gen_extra_files_block,
    _gen_git_volume_block,
    _gen_pm_block,
)
from .config import DeployConfig
from .constants import SOURCE_DIR
from .log import _c, _fatal, _info, _ok
from .oauth2 import _handle_oauth2
from .podman import _build_image, _install_quadlet, _restart_service
from .preflight import _preflight_check
from .template import _render_template
from .utils import _check_programs, _ensure_interactive, _sudo
from .workdir import _prepare_work_dir


def _provision_auth_db(cfg: DeployConfig) -> None:
    """Create the host directory for the credentials database, bootstrap
    the Owner user from ``secrets.toml``, and write all service
    credentials into the ``credentials`` table.

    The database is built in ``cfg.work_dir`` so that subsequent
    deployment steps (e.g. OAuth2 token provisioning) can read from /
    write to it *before* it is finally copied to the host volume.

    If a database already exists on the host, the Owner is left
    untouched but credentials are always upserted so that rotated
    secrets take effect on the next deployment.
    """
    host_dir = cfg.deploy.get("auth", {}).get("db_host_dir", "")
    if not host_dir:
        return

    agent_auth = cfg.agent_conf.get("auth", {})
    db_path = agent_auth.get("db_path", "")
    if not db_path:
        return

    db_filename = os.path.basename(db_path)
    db_host_path = os.path.join(host_dir, db_filename)

    # Create host directory — uses run_as identity for rootless paths.
    _sudo(["mkdir", "-p", host_dir], run_as=cfg.run_as)
    _ok(f"认证数据库宿主目录已就绪: {host_dir}")

    # Read Owner credentials from secrets.toml.
    owner = cfg.secrets.get("auth", {}).get("owner", {})
    owner_user = owner.get("username", "")
    owner_pass = owner.get("password", "")
    owner_email = owner.get("email", "")
    if not owner_user or not owner_pass or not owner_email:
        _fatal(
            "secrets.toml 中 [auth.owner] 缺少 username / password / email，"
            "无法初始化认证数据库。"
        )

    # Build the database in the work directory, then copy to host.
    import sys
    sys.path.insert(0, str(SOURCE_DIR))
    from src.auth.database import UserDB
    from src.auth.models import CredKey, Role

    # If the database already exists on the host, copy it into the work
    # directory so we can update it in-place, preserving existing users.
    # NOTE: Use ``sudo test -f`` instead of ``os.path.isfile`` because the
    # host directory may live under another user's home (e.g.
    # /home/sla_test/…) where the current user lacks traverse permission.
    tmp_db = cfg.work_dir / db_filename
    rc = _sudo(["test", "-f", db_host_path], check=False,
               run_as=cfg.run_as).returncode
    if rc == 0:
        # Copy existing DB from host to work dir.  In rootless mode the
        # source lives under another user's home and the destination
        # under the deployer's tmpdir — neither user can do both, so
        # pipe via cat (target user reads) → file (deployer writes).
        if cfg.run_as and cfg.run_as != os.getuid():
            user = pwd.getpwuid(cfg.run_as).pw_name
            with open(tmp_db, "wb") as f:
                subprocess.run(
                    ["sudo", "-u", user, "cat", db_host_path],
                    stdout=f, check=True,
                )
        else:
            _sudo(["cp", db_host_path, str(tmp_db)])
            _sudo(["chown", f"{os.getuid()}:{os.getgid()}", str(tmp_db)])
        _info(f"  已复制现有数据库到工作目录: {tmp_db}")

    user_db = UserDB(str(tmp_db))

    # --- Bootstrap Owner (idempotent) ----------------------------------
    if not user_db.has_owner():
        user_db.create_user(
            username=owner_user,
            email=owner_email,
            password=owner_pass,
            role=Role.OWNER,
        )
        _ok(f"Owner 用户 '{owner_user}' 已写入认证数据库。")
    else:
        _info("  Owner 用户已存在，跳过创建。")

    # --- Write all service credentials ---------------------------------
    creds: dict[str, str] = {}

    # Elasticsearch
    es = cfg.secrets.get("elasticsearch", {})
    if isinstance(es.get("username"), dict) and es["username"].get("value"):
        creds[CredKey.ES_USER] = str(es["username"]["value"])
    if isinstance(es.get("password"), dict) and es["password"].get("value"):
        creds[CredKey.ES_PSWD] = str(es["password"]["value"])

    # Log-output ES (optional separate credentials)
    log_out = cfg.secrets.get("log_output", {})
    if isinstance(log_out.get("username"), dict) and log_out["username"].get("value"):
        creds[CredKey.LOG_ES_USER] = str(log_out["username"]["value"])
    if isinstance(log_out.get("password"), dict) and log_out["password"].get("value"):
        creds[CredKey.LOG_ES_PSWD] = str(log_out["password"]["value"])

    # Auth JWT secret
    auth_sec = cfg.secrets.get("auth", {})
    jwt_entry = auth_sec.get("jwt_secret", {})
    if isinstance(jwt_entry, dict) and jwt_entry.get("value"):
        creds[CredKey.JWT_SECRET] = str(jwt_entry["value"])

    # Git token
    git_sec = cfg.secrets.get("git", {})
    token_entry = git_sec.get("token", {})
    if isinstance(token_entry, dict) and token_entry.get("value"):
        creds[CredKey.GIT_TOKEN] = str(token_entry["value"])

    # LLM API key (from secrets.toml [llm] or agent config [llm.backend] fallback)
    llm_sec = cfg.secrets.get("llm", {})
    llm_api_entry = llm_sec.get("api_key", {})
    if isinstance(llm_api_entry, dict) and llm_api_entry.get("value"):
        creds[CredKey.LLM_API_KEY] = str(llm_api_entry["value"])
    elif not creds.get(CredKey.LLM_API_KEY):
        # Fallback to agent config (for dev use)
        backend_conf = cfg.agent_conf.get("llm", {}).get("backend", {})
        if backend_conf.get("auth_token"):
            creds[CredKey.LLM_API_KEY] = str(backend_conf["auth_token"])

    # Mail credentials (from secrets.toml [mail] or agent config fallback)
    mail_sec = cfg.secrets.get("mail", {})
    mail_client_id = None
    mail_client_secret = None
    if isinstance(mail_sec.get("client_id"), dict) and mail_sec["client_id"].get("value"):
        mail_client_id = str(mail_sec["client_id"]["value"])
    if isinstance(mail_sec.get("client_secret"), dict) and mail_sec["client_secret"].get("value"):
        mail_client_secret = str(mail_sec["client_secret"]["value"])
    # Fallback to agent config (for backward compatibility / dev use)
    if not mail_client_id:
        mail_conf = cfg.agent_conf.get("mail", {})
        if mail_conf.get("client_id"):
            mail_client_id = str(mail_conf["client_id"])
    if not mail_client_secret:
        mail_conf = cfg.agent_conf.get("mail", {})
        if mail_conf.get("client_secret"):
            mail_client_secret = str(mail_conf["client_secret"])
    if mail_client_id:
        creds[CredKey.MAIL_CLIENT_ID] = mail_client_id
    if mail_client_secret:
        creds[CredKey.MAIL_CLIENT_SECRET] = mail_client_secret

    user_db.set_credentials(creds)
    user_db.close()
    _ok(f"已写入 {len(creds)} 条服务凭据到认证数据库。")


def _deploy_auth_db(cfg: DeployConfig) -> None:
    """Copy the credentials database from the work directory to the host
    volume.  Call this *after* all provisioning steps (auth-db bootstrap,
    OAuth2 token) have finished writing into the ``work_dir`` copy.
    """
    host_dir = cfg.deploy.get("auth", {}).get("db_host_dir", "")
    if not host_dir:
        return
    agent_auth = cfg.agent_conf.get("auth", {})
    db_path = agent_auth.get("db_path", "")
    if not db_path:
        return

    db_filename = os.path.basename(db_path)
    db_host_path = os.path.join(host_dir, db_filename)
    tmp_db = cfg.work_dir / db_filename

    if not tmp_db.is_file():
        return

    # Copy DB from work dir back to host.  Reverse of the read path:
    # deployer reads, target user writes.
    if cfg.run_as and cfg.run_as != os.getuid():
        user = pwd.getpwuid(cfg.run_as).pw_name
        with open(tmp_db, "rb") as f:
            subprocess.run(
                ["sudo", "-u", user, "tee", db_host_path],
                stdin=f, stdout=subprocess.DEVNULL, check=True,
            )
    else:
        _sudo(["cp", str(tmp_db), db_host_path])
    tmp_db.unlink(missing_ok=True)
    for suffix in ("-wal", "-shm"):
        companion = tmp_db.parent / (tmp_db.name + suffix)
        companion.unlink(missing_ok=True)
    _ok(f"认证数据库已部署到: {db_host_path}")


def main() -> None:
    _ensure_interactive()

    parser = argparse.ArgumentParser(
        description="Suricata LLM Agent 部署脚本（模板驱动、基于 TOML 配置）",
    )
    parser.add_argument(
        "--deploy-conf",
        default=None,
        help="指定 deploy.toml 的路径（默认自动检测项目根目录）",
    )
    args = parser.parse_args()

    print()
    print(_c("1;36", "═" * 60))
    print(_c("1;36", "  Suricata LLM Agent — 部署脚本"))
    print(_c("1;36", "═" * 60))
    print()

    _check_programs()

    # ── Step 1: Load all configuration ───────────────────────────────────
    deploy_conf_path = (
        Path(args.deploy_conf) if args.deploy_conf
        else SOURCE_DIR / "deploy.toml"
    )
    if not deploy_conf_path.is_file():
        _fatal(f"deploy.toml 不存在: {deploy_conf_path}")

    cfg = DeployConfig(deploy_conf_path)

    # ── Step 1.5: Pre-flight configuration validation ────────────────────
    implicit_files, implicit_dirs = _preflight_check(cfg)
    if implicit_files:
        _info(f"  隐含文件引用: {', '.join(implicit_files)}")
    if implicit_dirs:
        _info(f"  隐含目录引用: {', '.join(implicit_dirs)}")

    # ── Step 2: Obtain sudo early (single password prompt) ───────────────
    _info("正在获取 sudo 权限 ...")
    _sudo(["true"], run_as=cfg.run_as)
    _ok("sudo 权限已获取。")

    # ── Step 3: Prepare work directory ───────────────────────────────────
    work_dir = _prepare_work_dir(cfg, implicit_files, implicit_dirs)

    # ── Step 3.5: Provision auth database in work directory ────────────
    _provision_auth_db(cfg)

    # ── Step 4: OAuth2 provisioning (reads/writes credentials.db) ────
    _handle_oauth2(cfg)

    # ── Step 4.5: Deploy credentials.db to host volume ───────────────
    _deploy_auth_db(cfg)

    # ── Step 5: Render Containerfile from template ───────────────────
    containerfile_vars: dict[str, str] = {
        "image_url": cfg.image_url,
        "maintainer": f'"{cfg.maintainer}"',
        "workdir": cfg.workdir,
        "agent_config": cfg.agent_conf_path.name,
    }
    containerfile_blocks: dict[str, str] = {
        "ARGS": _gen_args_block(cfg),
        "PM": _gen_pm_block(cfg),
        "Extra Files": _gen_extra_files_block(cfg, implicit_files),
        "Extra CMD": _gen_extra_cmd_block(cfg),
    }

    containerfile_content = _render_template(
        cfg.containerfile_tpl, containerfile_vars, containerfile_blocks,
    )
    containerfile_out = work_dir / "Containerfile"
    containerfile_out.write_text(containerfile_content, encoding="utf-8")
    _ok(f"Containerfile 已生成: {containerfile_out}")

    # ── Step 6: Render Quadlet service file from template ────────────────
    quadlet_vars: dict[str, str] = {
        "image_name": cfg.deploy["quadlet"]["image_name"],
        "container_name": cfg.deploy["quadlet"]["container_name"],
        "network": cfg.deploy["networking"]["Network"],
        "port_mapping": _format_port_mapping(cfg),
        "addhost": _format_addhost(cfg),
    }
    quadlet_blocks: dict[str, str] = {
        "Auth Volume": _gen_auth_volume_block(cfg),
        "Git Volume": _gen_git_volume_block(cfg),
        "Environment": _gen_environment_block(cfg),
    }
    quadlet_content = _render_template(
        cfg.quadlet_tpl,
        quadlet_vars,
        quadlet_blocks,
    )

    # Also save to work dir for inspection.
    quadlet_out = work_dir / "suricata-llm-agent.container"
    quadlet_out.write_text(quadlet_content, encoding="utf-8")
    _ok(f"Quadlet 服务文件已生成: {quadlet_out}")

    # ── Step 7: Build container image ─────────────────────────────────
    _build_image(cfg, work_dir)

    # ── Step 8: Install Quadlet and restart service ──────────────────────
    _install_quadlet(cfg, quadlet_content)
    _restart_service(cfg)

    # ── Done ─────────────────────────────────────────────────────────────
    # Clean up work directory on success.
    shutil.rmtree(work_dir)
    _ok(f"工作目录已清理: {work_dir}")

    print()
    _ok("部署完成！")
    print()
