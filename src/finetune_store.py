#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         finetune_store.py
Description:  Fine-tuning training data collection store.
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
from typing import List, Optional

logger = logging.getLogger(__name__)

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS training_samples (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    model_name    TEXT    NOT NULL,
    system_prompt TEXT    NOT NULL,
    user_input    TEXT    NOT NULL,
    llm_response  TEXT    NOT NULL,
    threat_level  TEXT    NOT NULL DEFAULT '',
    event_type    TEXT    NOT NULL DEFAULT '',
    comm_pair     TEXT    NOT NULL DEFAULT '',
    auto_label    TEXT    NOT NULL DEFAULT 'accepted',
    human_label   TEXT    NOT NULL DEFAULT '',
    human_note    TEXT    NOT NULL DEFAULT '',
    corrected_response TEXT NOT NULL DEFAULT '',
    status        TEXT    NOT NULL DEFAULT 'pending',
    updated_at    TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_status ON training_samples(status);
CREATE INDEX IF NOT EXISTS idx_created ON training_samples(created_at);
CREATE INDEX IF NOT EXISTS idx_threat ON training_samples(threat_level);
CREATE INDEX IF NOT EXISTS idx_human_label ON training_samples(human_label);
"""


class FinetuneStore:
    """Thread-safe fine-tuning training data collection store.

    Each instance manages a dedicated SQLite database file at *db_path*.
    All public methods are protected by a :class:`threading.Lock` for
    thread-safe access from concurrent pipeline workers.
    """

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = str(db_path)
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        """Create the database schema if it does not exist."""
        conn = sqlite3.connect(self._db_path)
        try:
            conn.executescript(_CREATE_TABLE)
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Write API
    # ------------------------------------------------------------------

    def add_sample(
        self,
        model_name: str,
        system_prompt: str,
        user_input: str,
        llm_response: str,
        threat_level: str = "",
        event_type: str = "",
        comm_pair: str = "",
    ) -> int:
        """Write a training sample and return the row id."""
        with self._lock:
            conn = sqlite3.connect(self._db_path)
            try:
                cur = conn.execute(
                    """INSERT INTO training_samples
                       (model_name, system_prompt, user_input, llm_response,
                        threat_level, event_type, comm_pair)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (model_name, system_prompt, user_input, llm_response,
                     threat_level, event_type, comm_pair),
                )
                conn.commit()
                return cur.lastrowid  # type: ignore[return-value]
            finally:
                conn.close()

    def set_human_label(
        self,
        sample_id: int,
        label: str,
        note: str = "",
        corrected_response: str = "",
    ) -> bool:
        """Set human annotation.  *label*: ``confirmed`` / ``rejected`` / ``corrected``."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = sqlite3.connect(self._db_path)
            try:
                cur = conn.execute(
                    """UPDATE training_samples
                       SET human_label = ?, human_note = ?,
                           corrected_response = ?, status = 'labeled',
                           updated_at = ?
                       WHERE id = ?""",
                    (label, note, corrected_response, now, sample_id),
                )
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # Read API
    # ------------------------------------------------------------------

    def get_sample(self, sample_id: int) -> dict | None:
        """Return a single sample by id, or *None* if not found."""
        conn = sqlite3.connect(self._db_path)
        try:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM training_samples WHERE id = ?", (sample_id,),
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def query_samples(
        self,
        status: str | None = None,
        threat_level: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[dict]:
        """Query samples with optional status/threat_level filters."""
        sql = "SELECT * FROM training_samples WHERE 1=1"
        params: list = []
        if status:
            sql += " AND status = ?"
            params.append(status)
        if threat_level:
            sql += " AND threat_level = ?"
            params.append(threat_level)
        sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        conn = sqlite3.connect(self._db_path)
        try:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(sql, params).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def count(self, status: str | None = None) -> int:
        """Return the number of samples, optionally filtered by status."""
        sql = "SELECT COUNT(*) FROM training_samples"
        params: list = []
        if status:
            sql += " WHERE status = ?"
            params.append(status)
        conn = sqlite3.connect(self._db_path)
        try:
            return conn.execute(sql, params).fetchone()[0]
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Export API
    # ------------------------------------------------------------------

    def export_jsonl(
        self,
        output_path: str | Path,
        human_label_filter: str | None = "confirmed",
        min_date: str | None = None,
        max_date: str | None = None,
    ) -> int:
        """Export samples to JSONL format (OpenAI fine-tuning compatible).

        Returns the number of exported records.
        """
        sql = "SELECT * FROM training_samples WHERE 1=1"
        params: list = []
        if human_label_filter:
            sql += " AND human_label = ?"
            params.append(human_label_filter)
        if min_date:
            sql += " AND created_at >= ?"
            params.append(min_date)
        if max_date:
            sql += " AND created_at <= ?"
            params.append(max_date)
        sql += " ORDER BY created_at"

        count = 0
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self._db_path)
        try:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(sql, params).fetchall()
        finally:
            conn.close()
        with open(output_path, "w", encoding="utf-8") as f:
            for row in rows:
                record = {
                    "messages": [
                        {"role": "system", "content": row["system_prompt"]},
                        {"role": "user", "content": row["user_input"]},
                        {"role": "assistant", "content":
                            row["corrected_response"] or row["llm_response"]},
                    ],
                    "metadata": {
                        "threat_level": row["threat_level"],
                        "model": row["model_name"],
                        "created_at": row["created_at"],
                        "human_label": row["human_label"],
                    },
                }
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
                count += 1
        return count
