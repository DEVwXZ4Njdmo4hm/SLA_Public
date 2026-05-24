#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         test_main_helpers.py
Description:  Tests for main module helper classes like StatsWindow.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations
import time
import pytest
from src.main import StatsWindow, TokenStatsWindow, _build_notification_html
from src.llm_backend import LLMMetrics


# ── StatsWindow ────────────────────────────────────────────────────────

class TestStatsWindow:
    def test_empty_snapshot(self):
        sw = StatsWindow()
        snap = sw.snapshot()
        assert snap["5min_processed"] == 0
        assert snap["5min_failed"] == 0
        assert snap["15min_processed"] == 0
        assert snap["60min_processed"] == 0

    def test_tick_and_snapshot(self):
        sw = StatsWindow()
        sw.tick(10, 2)
        snap = sw.snapshot()
        assert snap["5min_processed"] == 10
        assert snap["5min_failed"] == 2
        assert snap["5min_total"] == 12
        assert snap["15min_processed"] == 10
        assert snap["60min_processed"] == 10

    def test_multiple_ticks(self):
        sw = StatsWindow()
        sw.tick(5, 1)
        sw.tick(3, 0)
        snap = sw.snapshot()
        assert snap["5min_processed"] == 8
        assert snap["5min_failed"] == 1

    def test_zero_tick_no_event_recorded(self):
        sw = StatsWindow()
        sw.tick(0, 0)
        snap = sw.snapshot()
        assert snap["5min_processed"] == 0

    def test_custom_windows(self):
        sw = StatsWindow(windows=(60, 120))
        sw.tick(7, 3)
        snap = sw.snapshot()
        assert "1min_processed" in snap
        assert "2min_processed" in snap
        assert snap["1min_processed"] == 7

    def test_prune_old_events(self):
        sw = StatsWindow(windows=(1,))  # 1-second window
        sw.tick(10, 0)
        # Wait for events to age out
        time.sleep(1.1)
        snap = sw.snapshot()
        # Key format: 0min (1s / 60 = 0)
        key = "0min_processed"
        assert snap[key] == 0


# ── _build_notification_html ───────────────────────────────────────────

class TestBuildNotificationHtml:
    def test_basic(self):
        html = _build_notification_html("Test Title", ["Line 1", "Line 2"])
        assert "<title>Test Title</title>" in html
        assert "Line 1" in html
        assert "Line 2" in html
        assert "<!doctype html>" in html


# ── TokenStatsWindow ──────────────────────────────────────────────────

class TestTokenStatsWindow:
    def _make_metrics(self, prompt: int = 100, completion: int = 50, model: str = "test") -> LLMMetrics:
        return LLMMetrics(model=model, prompt_tokens=prompt, completion_tokens=completion)

    def test_empty_snapshot(self):
        tw = TokenStatsWindow()
        snap = tw.snapshot()
        assert snap["token_total"] == 0
        assert snap["token_total_prompt"] == 0
        assert snap["token_total_completion"] == 0
        assert snap["1min_total_tokens"] == 0
        assert snap["5min_total_tokens"] == 0
        assert snap["30min_total_tokens"] == 0
        assert snap["1h_total_tokens"] == 0
        assert snap["6h_total_tokens"] == 0
        assert snap["24h_total_tokens"] == 0

    def test_record_single_batch(self):
        tw = TokenStatsWindow()
        tw.record([self._make_metrics(100, 50)])
        snap = tw.snapshot()
        assert snap["token_total"] == 150
        assert snap["token_total_prompt"] == 100
        assert snap["token_total_completion"] == 50
        assert snap["1min_prompt_tokens"] == 100
        assert snap["1min_completion_tokens"] == 50
        assert snap["1min_total_tokens"] == 150
        # All larger windows should also include it
        assert snap["5min_total_tokens"] == 150
        assert snap["24h_total_tokens"] == 150

    def test_record_multiple_batches(self):
        tw = TokenStatsWindow()
        tw.record([self._make_metrics(100, 50)])
        tw.record([self._make_metrics(200, 80), self._make_metrics(50, 20)])
        snap = tw.snapshot()
        assert snap["token_total_prompt"] == 350
        assert snap["token_total_completion"] == 150
        assert snap["token_total"] == 500
        assert snap["1min_total_tokens"] == 500

    def test_record_empty_batch(self):
        tw = TokenStatsWindow()
        tw.record([])
        snap = tw.snapshot()
        assert snap["token_total"] == 0

    def test_record_zero_tokens(self):
        tw = TokenStatsWindow()
        tw.record([self._make_metrics(0, 0)])
        snap = tw.snapshot()
        assert snap["token_total"] == 0
        # No event should have been appended
        assert len(tw._events) == 0

    def test_prune_old_events(self):
        tw = TokenStatsWindow()
        tw.record([self._make_metrics(100, 50)])
        # Manually age out the event beyond the 1-minute window
        with tw._lock:
            ts, pt, ct = tw._events[0]
            tw._events[0] = (ts - 61, pt, ct)
        snap = tw.snapshot()
        # 1min window should be 0, but 5min should still include it
        assert snap["1min_total_tokens"] == 0
        assert snap["5min_total_tokens"] == 150
        # Totals are cumulative and unaffected by pruning
        assert snap["token_total"] == 150

    def test_totals_survive_full_prune(self):
        tw = TokenStatsWindow()
        tw.record([self._make_metrics(100, 50)])
        # Age it out beyond all windows (>24h)
        with tw._lock:
            ts, pt, ct = tw._events[0]
            tw._events[0] = (ts - 86401, pt, ct)
        snap = tw.snapshot()
        for label in ("1min", "5min", "30min", "1h", "6h", "24h"):
            assert snap[f"{label}_total_tokens"] == 0
        # Cumulative totals persist
        assert snap["token_total"] == 150
        assert snap["token_total_prompt"] == 100
        assert snap["token_total_completion"] == 50

    def test_snapshot_keys_completeness(self):
        tw = TokenStatsWindow()
        snap = tw.snapshot()
        expected_keys = {"token_total", "token_total_prompt", "token_total_completion"}
        for label in ("1min", "5min", "30min", "1h", "6h", "24h"):
            expected_keys.add(f"{label}_prompt_tokens")
            expected_keys.add(f"{label}_completion_tokens")
            expected_keys.add(f"{label}_total_tokens")
        assert expected_keys == set(snap.keys())

    def test_escapes_html(self):
        html = _build_notification_html("Title", ["<script>alert(1)</script>"])
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_empty_lines(self):
        html = _build_notification_html("Title", [])
        assert "<pre" in html
