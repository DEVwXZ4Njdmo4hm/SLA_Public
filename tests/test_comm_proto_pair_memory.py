#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         test_comm_proto_pair_memory.py
Description:  Tests for CommProtoPairMemory multi-bucket memory.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

from src.comm_proto_pair_memory import (
    CommProtoPairMemory,
    make_event_key,
    parse_suricata_timestamp,
)


class TestEventKey:
    def test_app_proto_wins_over_event_type(self):
        assert make_event_key("HTTP", "alert") == "http"

    def test_event_type_fallback(self):
        assert make_event_key("", "ALERT") == "alert"

    def test_unknown_fallback(self):
        assert make_event_key("  ", "") == "Unknown"


class TestTimestampParsing:
    def test_parse_zulu_timestamp(self):
        assert parse_suricata_timestamp("2026-05-03T10:00:00Z") == 1777802400.0

    def test_parse_compact_utc_offset(self):
        assert parse_suricata_timestamp("2026-05-03T10:00:00+0000") == 1777802400.0

    def test_invalid_timestamp_returns_none(self):
        assert parse_suricata_timestamp("not-a-date") is None


class TestCommProtoPairMemoryBasic:
    def test_bidirectional_pair_and_event_bucket(self):
        mem = CommProtoPairMemory(
            max_pairs=5,
            per_pair_len=3,
            lat_lru_seconds=3600,
            maxpair_lru_evict=2,
        )
        mem.add("A", "B", "ssh", "e1", active_ts=100.0)
        mem.add("B", "A", "ssh", "e2", active_ts=101.0)
        assert mem.get("A", "B", "ssh") == ["e1", "e2"]
        assert mem.get("B", "A", "ssh") == ["e1", "e2"]

    def test_same_pair_event_buckets_are_isolated(self):
        mem = CommProtoPairMemory(
            max_pairs=5,
            per_pair_len=3,
            lat_lru_seconds=3600,
            maxpair_lru_evict=2,
        )
        mem.add("A", "B", "ssh", "ssh event", active_ts=100.0)
        mem.add("A", "B", "smb", "smb event", active_ts=101.0)
        assert mem.get("A", "B", "ssh") == ["ssh event"]
        assert mem.get("A", "B", "smb") == ["smb event"]

    def test_non_rolling_event_bucket_is_fifo_bounded(self):
        mem = CommProtoPairMemory(
            max_pairs=5,
            per_pair_len=3,
            lat_lru_seconds=3600,
            maxpair_lru_evict=2,
        )
        for i in range(6):
            mem.add("A", "B", "http", f"e{i}", active_ts=100.0 + i)
        assert mem.get("A", "B", "http") == ["e3", "e4", "e5"]

    def test_rolling_bucket_uses_hard_cap_without_implicit_fifo(self):
        mem = CommProtoPairMemory(
            max_pairs=5,
            per_pair_len=3,
            lat_lru_seconds=3600,
            maxpair_lru_evict=2,
            rolling=True,
        )
        for i in range(7):
            mem.add("A", "B", "http", f"e{i}", active_ts=100.0 + i)
        assert mem.get("A", "B", "http") == ["e4", "e5", "e6"]

    def test_lat_lru_evicts_stale_pair_before_new_pair(self):
        mem = CommProtoPairMemory(
            max_pairs=5,
            per_pair_len=3,
            lat_lru_seconds=10,
            maxpair_lru_evict=2,
        )
        mem.add("A", "B", "ssh", "old", active_ts=100.0)
        mem.add("C", "D", "ssh", "new", active_ts=111.0)
        assert mem.get("A", "B", "ssh") == []
        assert mem.get("C", "D", "ssh") == ["new"]

    def test_max_pairs_lru_batch_evicts_oldest_pairs(self):
        mem = CommProtoPairMemory(
            max_pairs=3,
            per_pair_len=3,
            lat_lru_seconds=3600,
            maxpair_lru_evict=2,
        )
        mem.add("A", "B", "ssh", "e1", active_ts=100.0)
        mem.add("C", "D", "ssh", "e2", active_ts=101.0)
        mem.add("E", "F", "ssh", "e3", active_ts=102.0)
        mem.add("G", "H", "ssh", "e4", active_ts=103.0)
        assert mem.pair_count == 2
        assert mem.get("A", "B", "ssh") == []
        assert mem.get("C", "D", "ssh") == []
        assert mem.get("E", "F", "ssh") == ["e3"]
        assert mem.get("G", "H", "ssh") == ["e4"]

    def test_compact_oldest_only_replaces_selected_event_bucket(self):
        mem = CommProtoPairMemory(
            max_pairs=5,
            per_pair_len=10,
            lat_lru_seconds=3600,
            maxpair_lru_evict=2,
        )
        for i in range(4):
            mem.add("A", "B", "ssh", f"ssh{i}", active_ts=100.0 + i)
            mem.add("A", "B", "smb", f"smb{i}", active_ts=100.0 + i)

        assert mem.compact_oldest("A", "B", "ssh", 3, "[merged]") is True
        assert mem.get("A", "B", "ssh") == ["[merged]", "ssh3"]
        assert mem.get("A", "B", "smb") == ["smb0", "smb1", "smb2", "smb3"]

    def test_evicted_pair_lock_is_not_accessible(self):
        mem = CommProtoPairMemory(
            max_pairs=3,
            per_pair_len=3,
            lat_lru_seconds=3600,
            maxpair_lru_evict=2,
        )
        mem.add("A", "B", "ssh", "e1", active_ts=100.0)
        assert mem.get_compact_lock("A", "B", "ssh") is not None
        mem.add("C", "D", "ssh", "e2", active_ts=101.0)
        mem.add("E", "F", "ssh", "e3", active_ts=102.0)
        assert mem.get_compact_lock("A", "B", "ssh") is not None
        mem.add("G", "H", "ssh", "e4", active_ts=103.0)
        assert mem.get_compact_lock("A", "B", "ssh") is None
