#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         recipients.py
Description:  Multi-user mail recipient resolution based on U-A-P role permissions.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import logging
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..auth.database import UserDB
    from ..auth.models import Role

logger = logging.getLogger(__name__)

# Module-level reference; set once at startup via init_mail_recipients().
_user_db: Optional["UserDB"] = None


def init_mail_recipients(user_db: "UserDB") -> None:
    """Wire the user database for recipient lookups."""
    global _user_db
    _user_db = user_db


def get_recipients_for_event(event_type: str) -> List[str]:
    """Return the email addresses that should receive mail for *event_type*.

    Recipients are resolved from the U-A-P user database via
    :data:`~src.auth.models.MAIL_PERMISSION_MAP`.
    Returns an empty list when no database is available or no matching
    roles are found.
    """
    if _user_db is not None:
        from ..auth.models import MAIL_PERMISSION_MAP
        roles = MAIL_PERMISSION_MAP.get(event_type)
        if roles:
            emails = _user_db.get_emails_by_roles(roles)
            if emails:
                return emails
    return []
