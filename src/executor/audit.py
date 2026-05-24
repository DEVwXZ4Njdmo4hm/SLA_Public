#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         audit.py
Description:  Write-once SQLite audit log for all execution attempts and policy decisions.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import AuditEntry, AuditLevel

logger = logging.getLogger(__name__)

_SCHEMA_SQL = """\
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id  TEXT    NOT NULL,
    capability  TEXT    NOT NULL,
    actor_role  TEXT    NOT NULL,
    actor_id    TEXT    NOT NULL DEFAULT '',
    status      TEXT    NOT NULL,
    detail      TEXT    NOT NULL DEFAULT '',
    params_json TEXT    NOT NULL DEFAULT '{}',
    level       TEXT    NOT NULL DEFAULT 'info',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_capability  ON audit_log(capability);
CREATE INDEX IF NOT EXISTS idx_audit_actor       ON audit_log(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_created     ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_request_id  ON audit_log(request_id);
"""


def _row_to_entry(row: sqlite3.Row) -> AuditEntry:
    return AuditEntry(
        request_id=row["request_id"],
        capability=row["capability"],
        actor_role=row["actor_role"],
        actor_id=row["actor_id"],
        status=row["status"],
        detail=row["detail"],
        params_json=row["params_json"],
        timestamp=row["created_at"],
        level=row["level"],
    )


class AuditDB:
    """Thread-safe, write-once SQLite audit log for executor operations.

    Follows the same pattern as ``auth.database.UserDB``.
    """

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = str(db_path)
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_schema(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.executescript(_SCHEMA_SQL)
                conn.commit()
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def record(self, entry: AuditEntry) -> int:
        """Insert a single audit entry.  Returns the new row ID."""
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute(
                    "INSERT INTO audit_log "
                    "(request_id, capability, actor_role, actor_id, "
                    " status, detail, params_json, level) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        entry.request_id,
                        entry.capability,
                        entry.actor_role,
                        entry.actor_id,
                        entry.status,
                        entry.detail,
                        entry.params_json,
                        entry.level,
                    ),
                )
                conn.commit()
                return cur.lastrowid or 0
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # Query (read-only, for RMI)
    # ------------------------------------------------------------------

    def list_recent(self, limit: int = 50) -> List[AuditEntry]:
        """Return the most recent audit entries, newest first."""
        limit = max(1, min(limit, 1000))
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
                return [_row_to_entry(r) for r in rows]
            finally:
                conn.close()

    def list_by_capability(self, capability: str, limit: int = 50) -> List[AuditEntry]:
        limit = max(1, min(limit, 1000))
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM audit_log WHERE capability = ? "
                    "ORDER BY id DESC LIMIT ?",
                    (capability, limit),
                ).fetchall()
                return [_row_to_entry(r) for r in rows]
            finally:
                conn.close()

    def list_by_actor(self, actor_id: str, limit: int = 50) -> List[AuditEntry]:
        limit = max(1, min(limit, 1000))
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM audit_log WHERE actor_id = ? "
                    "ORDER BY id DESC LIMIT ?",
                    (actor_id, limit),
                ).fetchall()
                return [_row_to_entry(r) for r in rows]
            finally:
                conn.close()

    def get_by_request_id(self, request_id: str) -> Optional[AuditEntry]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT * FROM audit_log WHERE request_id = ? "
                    "ORDER BY id DESC LIMIT 1",
                    (request_id,),
                ).fetchone()
                return _row_to_entry(row) if row else None
            finally:
                conn.close()

    def count(self) -> int:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute("SELECT COUNT(*) AS cnt FROM audit_log").fetchone()
                return int(row["cnt"]) if row else 0
            finally:
                conn.close()

    def close(self) -> None:
        """No-op — connections are opened/closed per operation."""
        pass
