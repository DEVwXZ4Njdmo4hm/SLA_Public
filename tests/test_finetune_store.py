#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         test_finetune_store.py
Description:  Tests for FinetuneStore (Improvement 30.7-C).
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import json
import os
import tempfile

import pytest

from src.finetune_store import FinetuneStore


@pytest.fixture
def store(tmp_path):
    """Create a FinetuneStore backed by a temp directory."""
    db_path = tmp_path / "test_finetune.db"
    return FinetuneStore(db_path)


class TestAddAndQuery:
    """Test basic write → query round-trip."""

    def test_add_and_query(self, store):
        row_id = store.add_sample(
            model_name="qwen3:32b",
            system_prompt="You are a security expert.",
            user_input="alert data here",
            llm_response='{"summary": "test"}',
            threat_level="中",
            event_type="alert",
            comm_pair="10.0.0.1 <-> 10.0.0.2",
        )
        assert row_id is not None and row_id > 0

        samples = store.query_samples()
        assert len(samples) >= 1
        sample = samples[0]
        assert sample["model_name"] == "qwen3:32b"
        assert sample["system_prompt"] == "You are a security expert."
        assert sample["user_input"] == "alert data here"
        assert sample["llm_response"] == '{"summary": "test"}'
        assert sample["threat_level"] == "中"
        assert sample["event_type"] == "alert"
        assert sample["comm_pair"] == "10.0.0.1 <-> 10.0.0.2"
        assert sample["auto_label"] == "accepted"
        assert sample["status"] == "pending"

    def test_query_by_status(self, store):
        store.add_sample("m", "sys", "in", "out")
        assert len(store.query_samples(status="pending")) == 1
        assert len(store.query_samples(status="labeled")) == 0

    def test_query_by_threat_level(self, store):
        store.add_sample("m", "sys", "in1", "out1", threat_level="高")
        store.add_sample("m", "sys", "in2", "out2", threat_level="低")
        high = store.query_samples(threat_level="高")
        assert len(high) == 1
        assert high[0]["threat_level"] == "高"

    def test_query_pagination(self, store):
        for i in range(5):
            store.add_sample("m", "sys", f"in{i}", f"out{i}")
        page1 = store.query_samples(limit=2, offset=0)
        page2 = store.query_samples(limit=2, offset=2)
        assert len(page1) == 2
        assert len(page2) == 2
        # Should be different samples
        assert page1[0]["id"] != page2[0]["id"]


class TestGetSample:
    def test_get_existing_sample(self, store):
        rid = store.add_sample("m", "sys", "in", "out")
        sample = store.get_sample(rid)
        assert sample is not None
        assert sample["id"] == rid

    def test_get_nonexistent_sample(self, store):
        assert store.get_sample(9999) is None


class TestSetHumanLabel:
    """Test human annotation status transitions."""

    def test_set_human_label_confirmed(self, store):
        rid = store.add_sample("m", "sys", "in", "out")
        ok = store.set_human_label(rid, label="confirmed", note="looks good")
        assert ok is True

        sample = store.get_sample(rid)
        assert sample["human_label"] == "confirmed"
        assert sample["human_note"] == "looks good"
        assert sample["status"] == "labeled"
        assert sample["updated_at"] != ""

    def test_set_human_label_rejected(self, store):
        rid = store.add_sample("m", "sys", "in", "out")
        ok = store.set_human_label(rid, label="rejected")
        assert ok is True
        sample = store.get_sample(rid)
        assert sample["human_label"] == "rejected"
        assert sample["status"] == "labeled"

    def test_set_human_label_corrected(self, store):
        rid = store.add_sample("m", "sys", "in", "out")
        ok = store.set_human_label(
            rid, label="corrected",
            corrected_response='{"summary": "fixed"}',
        )
        assert ok is True
        sample = store.get_sample(rid)
        assert sample["human_label"] == "corrected"
        assert sample["corrected_response"] == '{"summary": "fixed"}'

    def test_set_human_label_nonexistent(self, store):
        ok = store.set_human_label(9999, label="confirmed")
        assert ok is False


class TestCount:
    def test_count_all(self, store):
        assert store.count() == 0
        store.add_sample("m", "sys", "in1", "out1")
        store.add_sample("m", "sys", "in2", "out2")
        assert store.count() == 2

    def test_count_by_status(self, store):
        rid = store.add_sample("m", "sys", "in1", "out1")
        store.add_sample("m", "sys", "in2", "out2")
        store.set_human_label(rid, "confirmed")
        assert store.count(status="pending") == 1
        assert store.count(status="labeled") == 1


class TestExportJsonl:
    """Test JSONL export format compliance."""

    def test_export_jsonl_format(self, store, tmp_path):
        rid = store.add_sample(
            model_name="test-model",
            system_prompt="sys prompt",
            user_input="user data",
            llm_response="llm output",
            threat_level="低",
        )
        store.set_human_label(rid, "confirmed")

        out = tmp_path / "export.jsonl"
        count = store.export_jsonl(out, human_label_filter="confirmed")
        assert count == 1

        with open(out) as f:
            line = f.readline()
            record = json.loads(line)

        assert "messages" in record
        msgs = record["messages"]
        assert len(msgs) == 3
        assert msgs[0]["role"] == "system"
        assert msgs[0]["content"] == "sys prompt"
        assert msgs[1]["role"] == "user"
        assert msgs[1]["content"] == "user data"
        assert msgs[2]["role"] == "assistant"
        assert msgs[2]["content"] == "llm output"

        assert record["metadata"]["threat_level"] == "低"
        assert record["metadata"]["model"] == "test-model"
        assert record["metadata"]["human_label"] == "confirmed"

    def test_export_uses_corrected_response(self, store, tmp_path):
        rid = store.add_sample("m", "sys", "in", "original output")
        store.set_human_label(rid, "corrected", corrected_response="fixed output")

        out = tmp_path / "export.jsonl"
        count = store.export_jsonl(out, human_label_filter="corrected")
        assert count == 1

        with open(out) as f:
            record = json.loads(f.readline())
        assert record["messages"][2]["content"] == "fixed output"

    def test_export_skips_rejected(self, store, tmp_path):
        rid1 = store.add_sample("m", "sys", "in1", "out1")
        rid2 = store.add_sample("m", "sys", "in2", "out2")
        store.set_human_label(rid1, "confirmed")
        store.set_human_label(rid2, "rejected")

        out = tmp_path / "export.jsonl"
        count = store.export_jsonl(out, human_label_filter="confirmed")
        assert count == 1

    def test_export_skips_pending(self, store, tmp_path):
        store.add_sample("m", "sys", "in1", "out1")  # pending
        out = tmp_path / "export.jsonl"
        count = store.export_jsonl(out, human_label_filter="confirmed")
        assert count == 0

    def test_export_date_filter(self, store, tmp_path):
        rid = store.add_sample("m", "sys", "in", "out")
        store.set_human_label(rid, "confirmed")

        out = tmp_path / "export.jsonl"
        # Use a future date that won't match
        count = store.export_jsonl(out, human_label_filter="confirmed", min_date="2099-01-01")
        assert count == 0

    def test_export_creates_parent_dirs(self, store, tmp_path):
        rid = store.add_sample("m", "sys", "in", "out")
        store.set_human_label(rid, "confirmed")

        out = tmp_path / "nested" / "deep" / "export.jsonl"
        count = store.export_jsonl(out)
        assert count == 1
        assert out.exists()


class TestThreadSafety:
    """Basic smoke test for thread safety."""

    def test_concurrent_writes(self, store):
        import threading
        errors = []

        def add_samples(n):
            try:
                for i in range(n):
                    store.add_sample("m", "sys", f"in-{threading.current_thread().name}-{i}", "out")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=add_samples, args=(20,)) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert store.count() == 80
