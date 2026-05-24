#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         models.py
Description:  U-A-P model definitions including roles, users, credentials, and permissions.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional


class Role(str, enum.Enum):
    OWNER = "Owner"
    ADMINISTRATOR = "Administrator"
    AGENT = "Agent"
    WATCHER = "Watcher"

    @classmethod
    def from_str(cls, value: str) -> "Role":
        for member in cls:
            if member.value.lower() == value.strip().lower():
                return member
        raise ValueError(f"Unknown role: {value!r}")


# Mail event categories and their minimum required roles.
MAIL_PERMISSION_MAP: dict[str, list[Role]] = {
    "startup_shutdown": [Role.OWNER, Role.ADMINISTRATOR],
    "daily_report":     [Role.OWNER, Role.ADMINISTRATOR, Role.WATCHER],
    "alert":            [Role.OWNER, Role.ADMINISTRATOR],
    "critical_alert":   [Role.OWNER, Role.ADMINISTRATOR, Role.WATCHER],
}


@dataclass
class User:
    id: int
    username: str
    email: str
    role: Role
    password_hash: str = ""
    created_at: str = ""
    updated_at: str = ""


@dataclass
class APIKeyRecord:
    id: int
    user_id: int
    key_hash: str
    label: str = ""
    created_at: str = ""
    expires_at: Optional[str] = None
    revoked: bool = False


@dataclass
class AgentIdentity:
    """Runtime identity of the internal Agent system user.

    Holds the authenticated ``User`` record and the raw API key issued
    during bootstrap so that internal components (processor,
    daily-report, git-init) can construct genuinely authenticated
    ``ActionRequest`` objects.

    ``key_record_id`` is the database primary key of the API key row,
    retained so the key can be revoked when the owning component is
    destroyed.
    """
    user: User
    api_key: str
    key_record_id: int = 0

    @property
    def actor_role(self) -> str:
        return self.user.role.value

    @property
    def actor_id(self) -> str:
        return str(self.user.id)


# Well-known credential keys stored in the ``credentials`` table.
class CredKey:
    """String constants for the ``credentials`` table keys."""
    ES_USER = "es_user"
    ES_PSWD = "es_pswd"
    LOG_ES_USER = "log_es_user"
    LOG_ES_PSWD = "log_es_pswd"
    GIT_TOKEN = "git_token"
    JWT_SECRET = "jwt_secret"
    MAIL_CLIENT_ID = "mail_client_id"
    MAIL_CLIENT_SECRET = "mail_client_secret"
    MAIL_OAUTH2_TOKEN_CACHE = "mail_oauth2_token_cache"
    LLM_API_KEY = "llm_api_key"
