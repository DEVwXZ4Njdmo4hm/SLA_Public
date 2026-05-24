#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         oauth2.py
Description:  OAuth2 token provisioning for mail providers during deployment.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from .constants import SOURCE_DIR
from .log import _fatal, _info, _ok, _warn
from .utils import _load_toml

if TYPE_CHECKING:
    from .config import DeployConfig


def _load_provider_config(provider: str) -> dict:
    cfg_path = SOURCE_DIR / "configs" / "mail_providers" / f"{provider}.toml"
    if not cfg_path.is_file():
        _fatal(
            f"邮件提供商 '{provider}' 的配置文件不存在: {cfg_path}\n"
            f"请在 configs/mail_providers/ 下添加 {provider}.toml。"
        )
    data = _load_toml(cfg_path)
    provider_data = data.get("mail_provider", {}).get(provider)
    if not provider_data:
        _fatal(f"配置文件 {cfg_path} 中缺少 [mail_provider.{provider}] 段。")
    return provider_data


def _provision_oauth2_token(
    client_id: str,
    client_secret: str,
    provider_cfg: dict,
    existing_cache_data: str | None,
) -> str:
    """Run an interactive OAuth2 Authorization Code flow.

    Returns the serialised MSAL token cache (JSON string) to be
    persisted by the caller.
    """
    try:
        import msal
    except ImportError:
        _fatal("msal 包未安装。请先执行: pip install msal")

    if not client_id or not client_secret:
        _fatal("credentials.db 中的 mail_client_id 和 mail_client_secret 不能为空。")

    oauth2 = provider_cfg.get("oauth2", {})
    authority = oauth2.get("authority")
    scopes = oauth2.get("scopes")
    if not authority or not scopes:
        _fatal("provider config 缺少 authority 或 scopes 字段。")

    redirect_uri = "http://localhost"

    cache = msal.SerializableTokenCache()
    if existing_cache_data:
        try:
            cache.deserialize(existing_cache_data)
            _info("已从 credentials.db 加载已有 token cache。")
        except Exception:
            _warn("无法反序列化已有 token cache，将重新生成。")

    app = msal.ConfidentialClientApplication(
        client_id,
        authority=authority,
        client_credential=client_secret,
        token_cache=cache,
    )

    # 1) Try silent refresh first
    accounts = app.get_accounts()
    result = None
    if accounts:
        _info(f"尝试静默刷新缓存账号: {accounts[0].get('username', '?')}")
        result = app.acquire_token_silent(scopes, account=accounts[0])
        if result and "access_token" in result:
            _ok("Token 静默刷新成功。")
        else:
            result = None

    # 2) Interactive flow
    if result is None:
        flow = app.initiate_auth_code_flow(
            scopes, redirect_uri=redirect_uri,
        )
        if "auth_uri" not in flow:
            _fatal("无法生成授权 URL，请检查 client_id / authority 配置。")

        print()
        print("=" * 80)
        print("请复制以下链接到浏览器中打开，登录您的 Microsoft 账户并授权：")
        print()
        print(f"  {flow['auth_uri']}")
        print()
        print("=" * 80)
        print("授权后，浏览器会跳转到 localhost（可能显示为错误页面）。")
        print("请复制浏览器地址栏中的 完整 URL，然后粘贴到下方：")
        print()

        try:
            full_url = input("粘贴完整的回调 URL: ").strip()
        except (EOFError, KeyboardInterrupt):
            _fatal("输入被中断。")

        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(full_url)
        qs = parse_qs(parsed.query)
        auth_response = {k: v[0] for k, v in qs.items()}

        result = app.acquire_token_by_auth_code_flow(
            flow, auth_response,
        )

        if "access_token" not in result:
            err_desc = result.get(
                "error_description", result.get("error", "unknown"),
            )
            _fatal(f"Token 获取失败: {err_desc}")

        _ok("OAuth2 Token 获取成功。")

    # Return serialised cache for storage in credentials.db
    return cache.serialize()


def _handle_oauth2(cfg: DeployConfig) -> None:
    """
    Provision OAuth2 token if needed by mail or daily-report features.

    Reads ``client_id`` / ``client_secret`` and any existing token cache
    from the credentials database that was already built by
    ``_provision_auth_db``.  The refreshed or newly obtained token cache
    is written back into the same database under
    ``CredKey.MAIL_OAUTH2_TOKEN_CACHE``.
    """
    ac = cfg.agent_conf
    daily_enabled = ac.get("daily_report", {}).get("enabled", False)
    notif_enabled = ac.get("mail", {}).get("enable_notification", False)

    if not daily_enabled and not notif_enabled:
        _info("邮件功能未启用，跳过 OAuth2 Token 检查。")
        return

    provider = str(ac.get("mail", {}).get("provider", "")).strip().lower()
    if not provider:
        _fatal("邮件功能已启用，但 [mail] provider 未设置。")

    _info(f"邮件功能已启用，提供商: {provider}")

    provider_cfg = _load_provider_config(provider)
    smtp = provider_cfg.get("smtp", {})
    auth_methods = smtp.get("auth_methods", ["password"])
    auth_method = auth_methods[0].lower() if auth_methods else "password"
    _info(f"提供商 '{provider}' 的认证方式: {auth_method}")

    if auth_method != "oauth2":
        _info("认证方式非 OAuth2，无需 Token 刷新。")
        return

    # --- Open the credentials database (already built by _provision_auth_db) ---
    import sys
    sys.path.insert(0, str(SOURCE_DIR))
    from src.auth.database import UserDB
    from src.auth.models import CredKey

    agent_auth = ac.get("auth", {})
    db_path = agent_auth.get("db_path", "")
    db_filename = os.path.basename(db_path) if db_path else ""
    tmp_db = cfg.work_dir / db_filename if db_filename else None
    if not tmp_db or not tmp_db.is_file():
        _fatal("credentials.db 尚未构建，无法进行 OAuth2 Token 准备。")

    user_db = UserDB(str(tmp_db))
    creds = user_db.get_all_credentials()

    client_id = creds.get(CredKey.MAIL_CLIENT_ID, "").strip()
    client_secret = creds.get(CredKey.MAIL_CLIENT_SECRET, "").strip()
    existing_cache = creds.get(CredKey.MAIL_OAUTH2_TOKEN_CACHE) or None

    _info("正在从 credentials.db 读取 OAuth2 凭据 ...")

    cache_data = _provision_oauth2_token(
        client_id, client_secret, provider_cfg, existing_cache,
    )

    user_db.set_credential(CredKey.MAIL_OAUTH2_TOKEN_CACHE, cache_data)
    user_db.close()
    _ok("OAuth2 Token cache 已写入 credentials.db。")
