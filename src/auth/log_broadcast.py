#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         log_broadcast.py
Description:  Async log broadcaster for Server-Sent Events (SSE) subscriber fan-out.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional, Set

logger = logging.getLogger(__name__)


class LogBroadcaster:
    """Fan-out log messages to multiple async SSE subscribers."""

    def __init__(self, max_queue_size: int = 200) -> None:
        self._subscribers: Set[asyncio.Queue[str]] = set()
        self._max_queue_size = max_queue_size

    def subscribe(self) -> asyncio.Queue[str]:
        q: asyncio.Queue[str] = asyncio.Queue(maxsize=self._max_queue_size)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[str]) -> None:
        self._subscribers.discard(q)

    def publish(self, message: str) -> None:
        """Publish a log line to all subscribers (non-blocking, drops on full)."""
        for q in list(self._subscribers):
            try:
                q.put_nowait(message)
            except asyncio.QueueFull:
                pass  # slow consumer – drop

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)


class BroadcastLogHandler(logging.Handler):
    """Logging handler that feeds messages into a :class:`LogBroadcaster`."""

    def __init__(self, broadcaster: LogBroadcaster) -> None:
        super().__init__()
        self._broadcaster = broadcaster

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            self._broadcaster.publish(msg)
        except Exception:
            self.handleError(record)
