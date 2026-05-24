#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         comm_proto_pair_memory.py
Description:  Communication-protocol-pair memory for Suricata LLM analysis.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import Lock
from typing import Deque, Dict, List

logger = logging.getLogger(__name__)


def make_pair_key(id_a: str, id_b: str) -> str:
    """Create a canonical bidirectional communication-pair key."""
    a, b = str(id_a or "").strip(), str(id_b or "").strip()
    if a > b:
        a, b = b, a
    return f"{a} <-> {b}"


def make_event_key(app_proto: str = "", event_type: str = "") -> str:
    """Return Event_Z: app_proto first, event_type fallback, then Unknown."""
    for candidate in (app_proto, event_type):
        value = str(candidate or "").strip().lower()
        if value:
            return value
    return "Unknown"


def parse_suricata_timestamp(timestamp: str | None) -> float | None:
    """Parse common Suricata/Elasticsearch ISO timestamps to epoch seconds."""
    value = str(timestamp or "").strip()
    if not value:
        return None

    candidates = [value]
    if value.endswith("Z"):
        candidates.append(value[:-1] + "+00:00")
    if len(value) >= 5 and (value[-5] in ("+", "-")) and value[-3] != ":":
        candidates.append(value[:-2] + ":" + value[-2:])

    for candidate in candidates:
        try:
            dt = datetime.fromisoformat(candidate)
        except ValueError:
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    return None


def event_active_ts(event_timestamp: str | None) -> float:
    """Return parsed event timestamp seconds, falling back to wall clock."""
    parsed = parse_suricata_timestamp(event_timestamp)
    if parsed is not None:
        return parsed
    return time.time()


@dataclass
class _ProtoEventBucket:
    entries: Deque[str]
    compact_lock: Lock = field(default_factory=Lock)


@dataclass
class _ProtoPairBucket:
    last_active: float
    events: Dict[str, _ProtoEventBucket] = field(default_factory=dict)


class CommProtoPairMemory:
    """Multi-bucket memory keyed by pair, then protocol/event bucket."""

    def __init__(
        self,
        max_pairs: int,
        per_pair_len: int,
        *,
        lat_lru_seconds: float,
        maxpair_lru_evict: int,
        rolling: bool = False,
    ):
        self._max_pairs = max(1, int(max_pairs))
        self._per_pair_len = max(1, int(per_pair_len))
        self._lat_lru_seconds = max(0.000001, float(lat_lru_seconds))
        self._maxpair_lru_evict = max(1, int(maxpair_lru_evict))
        self._rolling = bool(rolling)
        self._pairs: Dict[str, _ProtoPairBucket] = {}
        self._lock = Lock()

    @staticmethod
    def _make_pair_key(id_a: str, id_b: str) -> str:
        return make_pair_key(id_a, id_b)

    @staticmethod
    def _make_event_key(event_key: str) -> str:
        value = str(event_key or "").strip()
        if not value:
            return "Unknown"
        return value if value == "Unknown" else value.lower()

    def add(
        self,
        src_id: str,
        dest_id: str,
        event_key: str,
        entry: str,
        *,
        active_ts: float,
    ) -> None:
        """Add an entry to the selected pair + Event_Z bucket."""
        if not entry or not src_id or not dest_id:
            return

        pair_key = self._make_pair_key(src_id, dest_id)
        event_bucket_key = self._make_event_key(event_key)
        with self._lock:
            if pair_key not in self._pairs:
                self._prune_stale_pairs(active_ts)
                if len(self._pairs) >= self._max_pairs:
                    self._evict_oldest_pairs()
                self._pairs[pair_key] = _ProtoPairBucket(last_active=active_ts)

            pair = self._pairs[pair_key]
            pair.last_active = max(pair.last_active, active_ts)
            bucket = pair.events.get(event_bucket_key)
            if bucket is None:
                maxlen = None if self._rolling else self._per_pair_len
                bucket = _ProtoEventBucket(entries=deque(maxlen=maxlen))
                pair.events[event_bucket_key] = bucket

            bucket.entries.append(entry)
            if self._rolling:
                hard_cap = 2 * self._per_pair_len
                if len(bucket.entries) > hard_cap:
                    overflow = len(bucket.entries) - self._per_pair_len
                    for _ in range(overflow):
                        bucket.entries.popleft()
                    logger.warning(
                        "CommProtoPairMemory hard-cap reached for %s:%s (%d); "
                        "truncated to %d - compaction may be failing.",
                        pair_key,
                        event_bucket_key,
                        hard_cap,
                        self._per_pair_len,
                    )

    def get(self, src_id: str, dest_id: str, event_key: str) -> List[str]:
        """Return entries for the selected pair + Event_Z bucket."""
        if not src_id or not dest_id:
            return []
        pair_key = self._make_pair_key(src_id, dest_id)
        event_bucket_key = self._make_event_key(event_key)
        with self._lock:
            pair = self._pairs.get(pair_key)
            if pair is None:
                return []
            bucket = pair.events.get(event_bucket_key)
            if bucket is None:
                return []
            return list(bucket.entries)

    def compact_oldest(
        self,
        src_id: str,
        dest_id: str,
        event_key: str,
        n: int,
        replacement: str,
    ) -> bool:
        """Replace the oldest *n* entries in one Event_Z bucket."""
        pair_key = self._make_pair_key(src_id, dest_id)
        event_bucket_key = self._make_event_key(event_key)
        with self._lock:
            pair = self._pairs.get(pair_key)
            if pair is None:
                return False
            bucket = pair.events.get(event_bucket_key)
            if bucket is None or len(bucket.entries) < n:
                return False
            for _ in range(n):
                bucket.entries.popleft()
            bucket.entries.appendleft(replacement)
            return True

    def get_compact_lock(self, src_id: str, dest_id: str, event_key: str) -> Lock | None:
        """Return the compaction lock for an existing pair + Event_Z bucket."""
        if not src_id or not dest_id:
            return None
        pair_key = self._make_pair_key(src_id, dest_id)
        event_bucket_key = self._make_event_key(event_key)
        with self._lock:
            pair = self._pairs.get(pair_key)
            if pair is None:
                return None
            bucket = pair.events.get(event_bucket_key)
            return bucket.compact_lock if bucket is not None else None

    @property
    def pair_count(self) -> int:
        with self._lock:
            return len(self._pairs)

    @property
    def max_pairs(self) -> int:
        return self._max_pairs

    @property
    def per_pair_len(self) -> int:
        return self._per_pair_len

    def _prune_stale_pairs(self, active_ts: float) -> None:
        stale = [
            key for key, bucket in self._pairs.items()
            if active_ts - bucket.last_active >= self._lat_lru_seconds
        ]
        for key in stale:
            del self._pairs[key]

    def _evict_oldest_pairs(self) -> None:
        evict_count = min(self._maxpair_lru_evict, len(self._pairs))
        victims = sorted(
            self._pairs,
            key=lambda key: self._pairs[key].last_active,
        )[:evict_count]
        for key in victims:
            del self._pairs[key]
