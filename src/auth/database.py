#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         database.py
Description:  SQLite-backed user account, API key, and service credential storage.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from pathlib import Path
from typing import Dict, List, Optional

from .models import APIKeyRecord, Role, User
from .passwords import hash_password, verify_password
from .tokens import hash_api_key

logger = logging.getLogger(__name__)

_SCHEMA_SQL = """\
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    UNIQUE NOT NULL,
    email         TEXT    UNIQUE NOT NULL,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL CHECK(role IN ('Owner','Administrator','Agent','Watcher')),
    created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_single_owner
    ON users(role) WHERE role = 'Owner';

CREATE TABLE IF NOT EXISTS api_keys (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_hash    TEXT    UNIQUE NOT NULL,
    label       TEXT    NOT NULL DEFAULT '',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    expires_at  TEXT,
    revoked     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS credentials (
    key         TEXT    PRIMARY KEY NOT NULL,
    value       TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);
"""


def _row_to_user(row: sqlite3.Row) -> User:
    return User(
        id=row["id"],
        username=row["username"],
        email=row["email"],
        role=Role.from_str(row["role"]),
        password_hash=row["password_hash"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _row_to_api_key(row: sqlite3.Row) -> APIKeyRecord:
    return APIKeyRecord(
        id=row["id"],
        user_id=row["user_id"],
        key_hash=row["key_hash"],
        label=row["label"],
        created_at=row["created_at"],
        expires_at=row["expires_at"],
        revoked=bool(row["revoked"]),
    )


class UserDB:
    """Thread-safe SQLite user database."""

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
    # User CRUD
    # ------------------------------------------------------------------
    def create_user(
        self,
        username: str,
        email: str,
        password: str,
        role: Role,
    ) -> User:
        pw_hash = hash_password(password)
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute(
                    "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
                    (username, email, pw_hash, role.value),
                )
                conn.commit()
                row = conn.execute("SELECT * FROM users WHERE id = ?", (cur.lastrowid,)).fetchone()
                return _row_to_user(row)
            finally:
                conn.close()

    def get_user_by_id(self, user_id: int) -> Optional[User]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
                return _row_to_user(row) if row else None
            finally:
                conn.close()

    def get_user_by_username(self, username: str) -> Optional[User]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
                return _row_to_user(row) if row else None
            finally:
                conn.close()

    def get_user_by_email(self, email: str) -> Optional[User]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
                return _row_to_user(row) if row else None
            finally:
                conn.close()

    def authenticate(self, username: str, password: str) -> Optional[User]:
        """Return the user if credentials are valid, else ``None``."""
        user = self.get_user_by_username(username)
        if user is None:
            return None
        if verify_password(password, user.password_hash):
            return user
        return None

    def list_users(self) -> List[User]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute("SELECT * FROM users ORDER BY id").fetchall()
                return [_row_to_user(r) for r in rows]
            finally:
                conn.close()

    def update_user(
        self,
        user_id: int,
        *,
        username: Optional[str] = None,
        email: Optional[str] = None,
        password: Optional[str] = None,
        role: Optional[Role] = None,
    ) -> Optional[User]:
        sets: list[str] = []
        vals: list = []
        if username is not None:
            sets.append("username = ?")
            vals.append(username)
        if email is not None:
            sets.append("email = ?")
            vals.append(email)
        if password is not None:
            sets.append("password_hash = ?")
            vals.append(hash_password(password))
        if role is not None:
            sets.append("role = ?")
            vals.append(role.value)
        if not sets:
            return self.get_user_by_id(user_id)

        sets.append("updated_at = datetime('now')")
        vals.append(user_id)

        with self._lock:
            conn = self._connect()
            try:
                conn.execute(f"UPDATE users SET {', '.join(sets)} WHERE id = ?", vals)
                conn.commit()
                row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
                return _row_to_user(row) if row else None
            finally:
                conn.close()

    def delete_user(self, user_id: int) -> bool:
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()

    def get_emails_by_roles(self, roles: list[Role]) -> list[str]:
        """Return email addresses of all users whose role is in *roles*."""
        if not roles:
            return []
        placeholders = ",".join("?" * len(roles))
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    f"SELECT email FROM users WHERE role IN ({placeholders})",
                    [r.value for r in roles],
                ).fetchall()
                return [r["email"] for r in rows]
            finally:
                conn.close()

    def has_owner(self) -> bool:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute("SELECT 1 FROM users WHERE role = 'Owner' LIMIT 1").fetchone()
                return row is not None
            finally:
                conn.close()

    def has_agent(self) -> bool:
        """Return *True* if an Agent system user already exists."""
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute("SELECT 1 FROM users WHERE role = 'Agent' LIMIT 1").fetchone()
                return row is not None
            finally:
                conn.close()

    def get_agent_user(self) -> Optional[User]:
        """Return the Agent system user, or ``None`` if not bootstrapped."""
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute("SELECT * FROM users WHERE role = 'Agent' LIMIT 1").fetchone()
                return _row_to_user(row) if row else None
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # API Keys
    # ------------------------------------------------------------------
    def create_api_key(
        self,
        user_id: int,
        raw_key: str,
        label: str = "",
        expires_at: Optional[str] = None,
    ) -> APIKeyRecord:
        kh = hash_api_key(raw_key)
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute(
                    "INSERT INTO api_keys (user_id, key_hash, label, expires_at) VALUES (?, ?, ?, ?)",
                    (user_id, kh, label, expires_at),
                )
                conn.commit()
                row = conn.execute("SELECT * FROM api_keys WHERE id = ?", (cur.lastrowid,)).fetchone()
                return _row_to_api_key(row)
            finally:
                conn.close()

    def verify_api_key(self, raw_key: str) -> Optional[User]:
        """Look up an API key (by hash), return the owning user or ``None``."""
        kh = hash_api_key(raw_key)
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT * FROM api_keys WHERE key_hash = ? AND revoked = 0",
                    (kh,),
                ).fetchone()
                if row is None:
                    return None
                rec = _row_to_api_key(row)
                if rec.expires_at:
                    from datetime import datetime, timezone
                    try:
                        exp = datetime.fromisoformat(rec.expires_at)
                        if exp.tzinfo is None:
                            exp = exp.replace(tzinfo=timezone.utc)
                        if exp < datetime.now(timezone.utc):
                            return None
                    except ValueError:
                        pass
                user_row = conn.execute("SELECT * FROM users WHERE id = ?", (rec.user_id,)).fetchone()
                return _row_to_user(user_row) if user_row else None
            finally:
                conn.close()

    def list_api_keys(self, user_id: int) -> list[APIKeyRecord]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM api_keys WHERE user_id = ? ORDER BY id", (user_id,)
                ).fetchall()
                return [_row_to_api_key(r) for r in rows]
            finally:
                conn.close()

    def revoke_api_key(self, key_id: int) -> bool:
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute("UPDATE api_keys SET revoked = 1 WHERE id = ?", (key_id,))
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()

    def revoke_all_user_keys(self, user_id: int) -> int:
        """Revoke every non-revoked API key belonging to *user_id*.

        Returns the number of keys actually revoked.
        """
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute(
                    "UPDATE api_keys SET revoked = 1 WHERE user_id = ? AND revoked = 0",
                    (user_id,),
                )
                conn.commit()
                return cur.rowcount
            finally:
                conn.close()

    def delete_all_user_keys(self, user_id: int) -> int:
        """Hard-delete every API key row belonging to *user_id*.

        Returns the number of rows deleted.
        """
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute("DELETE FROM api_keys WHERE user_id = ?", (user_id,))
                conn.commit()
                return cur.rowcount
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # Credentials (key-value store for service secrets)
    # ------------------------------------------------------------------
    def set_credential(self, key: str, value: str) -> None:
        """Insert or update a credential.  *value* is stored as-is."""
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT INTO credentials (key, value, updated_at) "
                    "VALUES (?, ?, datetime('now')) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
                    "updated_at = datetime('now')",
                    (key, value),
                )
                conn.commit()
            finally:
                conn.close()

    def set_credentials(self, mapping: Dict[str, str]) -> None:
        """Bulk insert/update multiple credentials in a single transaction."""
        if not mapping:
            return
        with self._lock:
            conn = self._connect()
            try:
                conn.executemany(
                    "INSERT INTO credentials (key, value, updated_at) "
                    "VALUES (?, ?, datetime('now')) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
                    "updated_at = datetime('now')",
                    list(mapping.items()),
                )
                conn.commit()
            finally:
                conn.close()

    def get_credential(self, key: str) -> Optional[str]:
        """Return the value for *key*, or ``None`` if absent."""
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT value FROM credentials WHERE key = ?", (key,)
                ).fetchone()
                return row["value"] if row else None
            finally:
                conn.close()

    def get_credentials(self, keys: List[str]) -> Dict[str, str]:
        """Return a mapping for the requested *keys* (missing keys omitted)."""
        if not keys:
            return {}
        placeholders = ",".join("?" * len(keys))
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    f"SELECT key, value FROM credentials WHERE key IN ({placeholders})",
                    keys,
                ).fetchall()
                return {r["key"]: r["value"] for r in rows}
            finally:
                conn.close()

    def get_all_credentials(self) -> Dict[str, str]:
        """Return every credential as a dict."""
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute("SELECT key, value FROM credentials").fetchall()
                return {r["key"]: r["value"] for r in rows}
            finally:
                conn.close()

    def delete_credential(self, key: str) -> bool:
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute("DELETE FROM credentials WHERE key = ?", (key,))
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()

    def close(self) -> None:
        """No persistent connection to close, but satisfies the interface."""
        pass
