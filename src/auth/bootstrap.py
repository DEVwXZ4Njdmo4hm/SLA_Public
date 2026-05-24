#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         bootstrap.py
Description:  System user bootstrap for Owner and Agent roles with API key generation.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import logging
import secrets as _secrets
from typing import Optional

from .database import UserDB
from .models import AgentIdentity, Role
from .tokens import generate_api_key

logger = logging.getLogger(__name__)

# Well-known prefix for the internal Agent system user.
AGENT_USERNAME_PREFIX = "suricata-analyzer-agent"
AGENT_USERNAME = AGENT_USERNAME_PREFIX          # for backward compat / tests
AGENT_EMAIL_DOMAIN = "localhost"
AGENT_API_KEY_LABEL = "system-bootstrap"

# Track Agent user IDs that belong to the current process.  Any Agent
# user whose ID is *not* in this set is a leftover from a previous run
# and will be purged on the next ``bootstrap_agent()`` call.
_active_agent_ids: set[int] = set()


def bootstrap_owner(
    db: UserDB,
    username: str,
    password: str,
    email: str,
) -> None:
    """Create the Owner user if not yet present.

    Called once at startup.  If an Owner already exists the call is a
    harmless no-op.
    """
    if db.has_owner():
        logger.info("Owner user already exists – skipping bootstrap.")
        return

    if not username or not password or not email:
        logger.warning(
            "Owner bootstrap skipped: username, password, or email not provided in secrets."
        )
        return

    try:
        user = db.create_user(username=username, email=email, password=password, role=Role.OWNER)
        logger.info("Owner user '%s' created successfully (id=%d).", user.username, user.id)
    except Exception as exc:
        logger.error("Failed to bootstrap Owner user: %s", exc)


def bootstrap_agent(db: UserDB) -> Optional[AgentIdentity]:
    """Create a dedicated Agent user for this ``LLMHandler`` instance.

    Each call creates a **new** Agent user (with a unique suffix) and
    issues one API key for it.  On the first call of a process, any
    leftover Agent users from a previous run are purged.

    When the owning ``LLMHandler`` is destroyed, ``revoke_agent_session``
    deletes that user and its key — no credentials survive the instance.

    Returns ``None`` only when the database operation fails unexpectedly.
    """
    try:
        # ── Purge leftover Agent users from previous runs ─────────────
        for user in db.list_users():
            if user.role == Role.AGENT and user.id not in _active_agent_ids:
                n_keys = db.delete_all_user_keys(user.id)
                db.delete_user(user.id)
                logger.info(
                    "Purged leftover Agent user (id=%d) and %d API key(s).",
                    user.id, n_keys,
                )

        # ── Create a new Agent user with a unique suffix ──────────────
        suffix = _secrets.token_hex(4)
        username = f"{AGENT_USERNAME_PREFIX}-{suffix}"
        email = f"agent-{suffix}@{AGENT_EMAIL_DOMAIN}"
        random_pw = _secrets.token_urlsafe(32)
        user = db.create_user(
            username=username,
            email=email,
            password=random_pw,
            role=Role.AGENT,
        )
        logger.info(
            "Agent system user '%s' created (id=%d).",
            user.username, user.id,
        )
        _active_agent_ids.add(user.id)

        # Issue exactly one API key for this handler's session.
        raw_key = generate_api_key()
        key_record = db.create_api_key(user.id, raw_key, label=AGENT_API_KEY_LABEL)
        logger.info("Agent API key issued for runtime session (key_id=%d).", key_record.id)

        return AgentIdentity(user=user, api_key=raw_key, key_record_id=key_record.id)
    except Exception as exc:
        logger.error("Failed to bootstrap Agent system user: %s", exc)
        return None


def revoke_agent_session(db: UserDB, identity: AgentIdentity) -> None:
    """Destroy the Agent user and all its keys for this handler.

    Called when the ``LLMHandler`` owning *identity* is destroyed.
    The user row and all associated API keys are hard-deleted.
    """
    try:
        n_keys = db.delete_all_user_keys(identity.user.id)
        db.delete_user(identity.user.id)
        _active_agent_ids.discard(identity.user.id)
        logger.info(
            "Agent session destroyed: user_id=%s deleted with %d API key(s).",
            identity.actor_id, n_keys,
        )
    except Exception as exc:
        logger.warning("Failed to fully revoke Agent session: %s", exc)
