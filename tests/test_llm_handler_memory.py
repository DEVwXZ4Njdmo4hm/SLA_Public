#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         test_llm_handler_memory.py
Description:  Tests for CommPairMemory bidirectional tracking and LRU eviction.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations
import threading
import pytest
from src.llm_handler import CommPairMemory, LLMHandler


# ── CommPairMemory basic operations ────────────────────────────────────

class TestCommPairMemoryBasic:
    def test_add_and_get(self):
        mem = CommPairMemory(max_pairs=5, per_pair_len=3)
        mem.add("A", "B", "entry1")
        entries = mem.get("A", "B")
        assert entries == ["entry1"]

    def test_bidirectional(self):
        mem = CommPairMemory(max_pairs=5, per_pair_len=3)
        mem.add("A", "B", "e1")
        mem.add("B", "A", "e2")
        entries = mem.get("A", "B")
        assert entries == ["e1", "e2"]
        entries2 = mem.get("B", "A")
        assert entries2 == ["e1", "e2"]

    def test_empty_params_ignored(self):
        mem = CommPairMemory(max_pairs=5, per_pair_len=3)
        mem.add("", "B", "e1")
        mem.add("A", "", "e1")
        mem.add("A", "B", "")
        assert mem.pair_count == 0

    def test_get_empty(self):
        mem = CommPairMemory(max_pairs=5, per_pair_len=3)
        assert mem.get("A", "B") == []
        assert mem.get("", "") == []

    def test_per_pair_len_bounded(self):
        mem = CommPairMemory(max_pairs=5, per_pair_len=3)
        for i in range(10):
            mem.add("A", "B", f"entry{i}")
        entries = mem.get("A", "B")
        assert len(entries) == 3
        # Should be the 3 most recent
        assert entries == ["entry7", "entry8", "entry9"]

    def test_pair_count(self):
        mem = CommPairMemory(max_pairs=5, per_pair_len=3)
        mem.add("A", "B", "e1")
        mem.add("C", "D", "e2")
        assert mem.pair_count == 2

    def test_properties(self):
        mem = CommPairMemory(max_pairs=10, per_pair_len=20)
        assert mem.max_pairs == 10
        assert mem.per_pair_len == 20


# ── CommPairMemory LRU eviction ───────────────────────────────────────

class TestCommPairMemoryEviction:
    def test_evicts_oldest_pair(self):
        mem = CommPairMemory(max_pairs=2, per_pair_len=5)
        mem.add("A", "B", "e1")
        mem.add("C", "D", "e2")
        # Now at capacity (2 pairs). Adding a third should evict the oldest.
        mem.add("E", "F", "e3")
        assert mem.pair_count == 2
        # A<->B was oldest, should be evicted
        assert mem.get("A", "B") == []
        assert mem.get("C", "D") == ["e2"]
        assert mem.get("E", "F") == ["e3"]

    def test_updating_resets_timestamp(self):
        mem = CommPairMemory(max_pairs=2, per_pair_len=5)
        mem.add("A", "B", "e1")
        mem.add("C", "D", "e2")
        # Touch A<->B again, making C<->D the oldest
        mem.add("A", "B", "e3")
        # Now adding new pair should evict C<->D (oldest)
        mem.add("E", "F", "e4")
        assert mem.get("A", "B") == ["e1", "e3"]
        assert mem.get("C", "D") == []

    def test_min_max_pairs_clamped(self):
        mem = CommPairMemory(max_pairs=0, per_pair_len=0)
        assert mem.max_pairs == 1
        assert mem.per_pair_len == 1


# ── CommPairMemory thread safety ──────────────────────────────────────

class TestCommPairMemoryThreadSafety:
    def test_concurrent_add_get(self):
        mem = CommPairMemory(max_pairs=100, per_pair_len=50)
        errors = []

        def writer(pair_id: int):
            try:
                for i in range(100):
                    mem.add(f"src{pair_id}", f"dst{pair_id}", f"entry{i}")
            except Exception as e:
                errors.append(e)

        def reader(pair_id: int):
            try:
                for _ in range(100):
                    mem.get(f"src{pair_id}", f"dst{pair_id}")
            except Exception as e:
                errors.append(e)

        threads = []
        for p in range(10):
            threads.append(threading.Thread(target=writer, args=(p,)))
            threads.append(threading.Thread(target=reader, args=(p,)))

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert errors == [], f"Thread errors: {errors}"


# ── LLMHandler memory integration ────────────────────────────────────

class TestLLMHandlerMemory:
    def test_update_summary_memory(self):
        handler = LLMHandler()
        handler.update_summary_memory(
            "DNS query to evil.com",
            src_ip="10.0.0.1",
            dest_ip="10.0.0.2",
            event_type="dns",
            event_timestamp="2026-01-01T12:00:00Z",
        )
        entries = handler.get_memory_snapshot("10.0.0.1", "10.0.0.2")
        assert len(entries) == 1
        assert "evil.com" in entries[0]
        assert "[2026-01-01T12:00:00Z]" in entries[0]

    def test_update_prefers_hostname(self):
        handler = LLMHandler()
        handler.update_summary_memory(
            "test",
            src_ip="10.0.0.1",
            src_hostname="host-a",
            dest_ip="10.0.0.2",
            dest_hostname="host-b",
        )
        # Should be stored under hostname key
        entries = handler.get_memory_snapshot("host-a", "host-b")
        assert len(entries) == 1

    def test_empty_summary_ignored(self):
        handler = LLMHandler()
        handler.update_summary_memory("", src_ip="1", dest_ip="2")
        entries = handler.get_memory_snapshot("1", "2")
        assert entries == []

    def test_empty_ids_ignored(self):
        handler = LLMHandler()
        handler.update_summary_memory("test", src_ip="", dest_ip="")
        assert handler._comm_pair_memory.pair_count == 0


# ── LLMHandler metrics ────────────────────────────────────────────────

class TestLLMHandlerMetrics:
    def test_drain_empty(self):
        handler = LLMHandler()
        assert handler.drain_batch_metrics() == []

    def test_record_and_drain(self):
        from src.llm_backend import LLMMetrics
        handler = LLMHandler()
        m = LLMMetrics(model="test", completion_tokens=10)
        handler.record_metrics(m)
        handler.record_metrics(m)
        drained = handler.drain_batch_metrics()
        assert len(drained) == 2
        # Second drain should be empty
        assert handler.drain_batch_metrics() == []
