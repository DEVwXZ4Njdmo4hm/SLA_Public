#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         global_memory.py
Description:  Global FIFO memory baseline for ablation experiments.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

import logging
from collections import deque
from threading import Lock
from typing import List

logger = logging.getLogger(__name__)


class GlobalMemory:
    """Global FIFO memory — all events share one context window.

    This is an experiment-only baseline.  It stores the most recent
    *max_entries* summaries regardless of which communication pair
    produced them.

    When *rolling* is ``True`` the deque has no ``maxlen``; entries are
    only removed by explicit ``compact_oldest()`` calls.  A hard cap of
    ``2 × max_entries`` prevents unbounded growth if compaction stalls.
    """

    __slots__ = ("_max", "_entries", "_lock", "_rolling")

    def __init__(self, max_entries: int = 50, *, rolling: bool = False):
        self._max = max(1, max_entries)
        self._rolling = rolling
        if rolling:
            self._entries: deque[str] = deque()
        else:
            self._entries: deque[str] = deque(maxlen=self._max)
        self._lock = Lock()

    def add(self, entry: str) -> None:
        if not entry:
            return
        with self._lock:
            self._entries.append(entry)
            if self._rolling:
                hard_cap = 2 * self._max
                if len(self._entries) > hard_cap:
                    overflow = len(self._entries) - self._max
                    for _ in range(overflow):
                        self._entries.popleft()
                    logger.warning(
                        "GlobalMemory hard-cap reached (%d); "
                        "truncated to %d entries — compaction may be failing.",
                        hard_cap, self._max,
                    )

    def get_snapshot(self) -> List[str]:
        """Return all entries (oldest first)."""
        with self._lock:
            return list(self._entries)

    @property
    def max_entries(self) -> int:
        return self._max

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._entries)

    def replace_entries(self, new_entries: List[str]) -> None:
        """Atomically replace all entries."""
        with self._lock:
            if self._rolling:
                self._entries = deque(new_entries)
            else:
                self._entries = deque(new_entries, maxlen=self._max)

    def compact_oldest(self, n: int, replacement: str) -> bool:
        """Atomically remove the oldest *n* entries and prepend *replacement*.

        Returns ``True`` if performed, ``False`` if fewer than *n* entries.
        """
        with self._lock:
            if len(self._entries) < n:
                return False
            for _ in range(n):
                self._entries.popleft()
            self._entries.appendleft(replacement)
            return True
