#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         mail_queue.py
Description:  Email queue with persistence, exponential backoff retry, and dead-letter handling.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
_DEFAULT_SPOOL_DIR = os.path.join(
    os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir)),
    "mail_spool",
)
_DEFAULT_MAX_RETRIES = 5
_DEFAULT_BASE_DELAY = 60        # seconds
_DEFAULT_MAX_DELAY = 3600       # 1 hour
_DEFAULT_POLL_INTERVAL = 30     # how often the retry thread checks the spool


# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------
@dataclass
class _SpooledMessage:
    """In-memory representation of a spooled email JSON file."""
    file_path: str
    subject: str
    html_body: str
    recipients: Optional[List[str]]
    attachments: Optional[List[str]]
    attempt: int
    next_retry_at: float          # unix timestamp
    created_at: float             # unix timestamp

    @classmethod
    def from_file(cls, path: str) -> "_SpooledMessage":
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return cls(
            file_path=path,
            subject=data["subject"],
            html_body=data["html_body"],
            recipients=data.get("recipients"),
            attachments=data.get("attachments"),
            attempt=int(data.get("attempt", 0)),
            next_retry_at=float(data.get("next_retry_at", 0)),
            created_at=float(data.get("created_at", 0)),
        )

    def to_dict(self) -> dict:
        return {
            "subject": self.subject,
            "html_body": self.html_body,
            "recipients": self.recipients,
            "attachments": self.attachments,
            "attempt": self.attempt,
            "next_retry_at": self.next_retry_at,
            "created_at": self.created_at,
        }

    def save(self) -> None:
        tmp = self.file_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, ensure_ascii=False)
        os.replace(tmp, self.file_path)


# ---------------------------------------------------------------------------
# MailQueue
# ---------------------------------------------------------------------------
class MailQueue:
    """Persistent mail spool with background exponential-backoff retry."""

    def __init__(
        self,
        spool_dir: str = _DEFAULT_SPOOL_DIR,
        max_retries: int = _DEFAULT_MAX_RETRIES,
        base_delay: float = _DEFAULT_BASE_DELAY,
        max_delay: float = _DEFAULT_MAX_DELAY,
        poll_interval: float = _DEFAULT_POLL_INTERVAL,
    ) -> None:
        self.spool_dir = spool_dir
        self.dead_letter_dir = os.path.join(spool_dir, "dead_letter")
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.poll_interval = poll_interval

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        # Ensure directories exist
        os.makedirs(self.spool_dir, exist_ok=True)
        os.makedirs(self.dead_letter_dir, exist_ok=True)

    # ----- public API -----------------------------------------------------

    def enqueue(
        self,
        subject: str,
        html_body: str,
        recipients: Optional[List[str]] = None,
        attachments: Optional[List[str]] = None,
    ) -> str:
        """Persist an unsent email to the spool directory.

        Returns the spool file path.
        """
        now = time.time()
        delay = self._calc_delay(0)
        msg_id = f"{int(now)}_{uuid.uuid4().hex[:12]}"
        filename = f"{msg_id}.json"
        filepath = os.path.join(self.spool_dir, filename)

        msg = _SpooledMessage(
            file_path=filepath,
            subject=subject,
            html_body=html_body,
            recipients=recipients,
            attachments=attachments,
            attempt=0,
            next_retry_at=now + delay,
            created_at=now,
        )
        msg.save()
        logger.info(
            "Mail spooled for retry: %s (next attempt in %.0fs) [%s]",
            subject, delay, filepath,
        )
        return filepath

    @property
    def pending_count(self) -> int:
        """Number of messages waiting in the spool (excluding dead-letter)."""
        try:
            return sum(
                1 for f in os.listdir(self.spool_dir)
                if f.endswith(".json") and os.path.isfile(os.path.join(self.spool_dir, f))
            )
        except OSError:
            return 0

    @property
    def dead_letter_count(self) -> int:
        """Number of permanently failed messages."""
        try:
            return sum(
                1 for f in os.listdir(self.dead_letter_dir)
                if f.endswith(".json") and os.path.isfile(os.path.join(self.dead_letter_dir, f))
            )
        except OSError:
            return 0

    def start(self) -> None:
        """Start the background retry thread."""
        if self._thread is not None and self._thread.is_alive():
            logger.debug("Mail queue retry thread already running.")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._retry_loop, name="mail-queue-retry", daemon=True,
        )
        self._thread.start()
        pending = self.pending_count
        if pending > 0:
            logger.info(
                "Mail queue started. %d message(s) pending from previous run.", pending,
            )
        else:
            logger.info("Mail queue started (spool dir: %s).", self.spool_dir)

    def stop(self, timeout: float = 10.0) -> None:
        """Signal the retry thread to stop and wait for it to finish."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None
        logger.info("Mail queue stopped. %d message(s) still pending.", self.pending_count)

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ----- internal -------------------------------------------------------

    def _calc_delay(self, attempt: int) -> float:
        """Exponential backoff: base_delay * 2^attempt, capped at max_delay."""
        return min(self.base_delay * (2 ** attempt), self.max_delay)

    def _retry_loop(self) -> None:
        """Background loop: scan spool and retry due messages."""
        logger.debug("Mail queue retry loop entered.")
        while not self._stop_event.is_set():
            try:
                self._process_spool()
            except Exception as exc:
                logger.error("Mail queue retry loop error: %s", exc, exc_info=True)
            self._stop_event.wait(timeout=self.poll_interval)
        logger.debug("Mail queue retry loop exiting.")

    def _process_spool(self) -> None:
        """Scan the spool directory once and retry any due messages."""
        now = time.time()
        try:
            entries = sorted(os.listdir(self.spool_dir))
        except OSError as exc:
            logger.warning("Cannot list spool dir %s: %s", self.spool_dir, exc)
            return

        for filename in entries:
            if not filename.endswith(".json"):
                continue
            filepath = os.path.join(self.spool_dir, filename)
            if not os.path.isfile(filepath):
                continue

            try:
                msg = _SpooledMessage.from_file(filepath)
            except Exception as exc:
                logger.warning("Cannot parse spooled message %s: %s", filepath, exc)
                continue

            if msg.next_retry_at > now:
                continue  # not due yet

            # Attempt to resend
            msg.attempt += 1
            logger.info(
                "Retrying spooled mail (attempt %d/%d): %s",
                msg.attempt, self.max_retries, msg.subject,
            )

            success = self._try_send(msg)
            if success:
                logger.info("Spooled mail sent successfully: %s", msg.subject)
                try:
                    os.remove(filepath)
                except OSError:
                    pass
                continue

            # Failed again
            if msg.attempt >= self.max_retries:
                logger.error(
                    "Mail permanently failed after %d attempts, moved to dead-letter: %s",
                    msg.attempt, msg.subject,
                )
                self._move_to_dead_letter(filepath)
            else:
                delay = self._calc_delay(msg.attempt)
                msg.next_retry_at = time.time() + delay
                msg.save()
                logger.warning(
                    "Mail retry failed (attempt %d/%d). Next retry in %.0fs: %s",
                    msg.attempt, self.max_retries, delay, msg.subject,
                )

    def _try_send(self, msg: _SpooledMessage) -> bool:
        """Attempt to send a spooled message via the raw send function."""
        # Import here to avoid circular import; use the low-level sender
        from .send_mail import _send_email_raw
        try:
            return _send_email_raw(
                subject=msg.subject,
                html_body=msg.html_body,
                recipients=msg.recipients,
                attachments=msg.attachments,
            )
        except Exception as exc:
            logger.error("Send attempt raised exception: %s", exc)
            return False

    def _move_to_dead_letter(self, filepath: str) -> None:
        """Move a permanently failed message to the dead-letter directory."""
        try:
            dest = os.path.join(self.dead_letter_dir, os.path.basename(filepath))
            shutil.move(filepath, dest)
        except Exception as exc:
            logger.error("Failed to move %s to dead-letter: %s", filepath, exc)


# ---------------------------------------------------------------------------
# Module-level singleton (lazily initialised by start_mail_queue)
# ---------------------------------------------------------------------------
_mail_queue: Optional[MailQueue] = None
_queue_lock = threading.Lock()


def get_mail_queue() -> Optional[MailQueue]:
    """Return the currently active MailQueue, or None if not started."""
    return _mail_queue


def start_mail_queue(
    spool_dir: str = _DEFAULT_SPOOL_DIR,
    max_retries: int = _DEFAULT_MAX_RETRIES,
    base_delay: float = _DEFAULT_BASE_DELAY,
    max_delay: float = _DEFAULT_MAX_DELAY,
    poll_interval: float = _DEFAULT_POLL_INTERVAL,
) -> MailQueue:
    """Create (if needed) and start the global MailQueue singleton."""
    global _mail_queue
    with _queue_lock:
        if _mail_queue is None:
            _mail_queue = MailQueue(
                spool_dir=spool_dir,
                max_retries=max_retries,
                base_delay=base_delay,
                max_delay=max_delay,
                poll_interval=poll_interval,
            )
        _mail_queue.start()
        return _mail_queue


def stop_mail_queue() -> None:
    """Stop the global MailQueue (if running)."""
    global _mail_queue
    with _queue_lock:
        if _mail_queue is not None:
            _mail_queue.stop()
