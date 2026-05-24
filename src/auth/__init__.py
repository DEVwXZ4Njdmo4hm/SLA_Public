#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         __init__.py
Description:  U-A-P (User-Actor-Permission) authentication subsystem module exports.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from .models import AgentIdentity, CredKey, Role, User
from .database import UserDB
from .passwords import hash_password, verify_password
from .tokens import create_jwt, decode_jwt, generate_api_key
from .dependencies import get_current_user, require_role
from .log_broadcast import LogBroadcaster

__all__ = [
    "AgentIdentity",
    "CredKey",
    "Role",
    "User",
    "UserDB",
    "hash_password",
    "verify_password",
    "create_jwt",
    "decode_jwt",
    "generate_api_key",
    "get_current_user",
    "require_role",
    "LogBroadcaster",
]
