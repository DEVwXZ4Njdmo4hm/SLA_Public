#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         test_auth_log_broadcast.py
Description:  Tests for async log broadcaster queue and SSE subscriber management.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import asyncio
import logging

import pytest

from src.auth.log_broadcast import BroadcastLogHandler, LogBroadcaster


class TestLogBroadcaster:
    def test_subscribe_and_publish(self):
        lb = LogBroadcaster()
        q = lb.subscribe()
        assert lb.subscriber_count == 1
        lb.publish("hello")
        assert q.get_nowait() == "hello"

    def test_unsubscribe(self):
        lb = LogBroadcaster()
        q = lb.subscribe()
        lb.unsubscribe(q)
        assert lb.subscriber_count == 0

    def test_publish_to_multiple(self):
        lb = LogBroadcaster()
        q1 = lb.subscribe()
        q2 = lb.subscribe()
        lb.publish("msg")
        assert q1.get_nowait() == "msg"
        assert q2.get_nowait() == "msg"

    def test_drops_when_full(self):
        lb = LogBroadcaster(max_queue_size=2)
        q = lb.subscribe()
        lb.publish("a")
        lb.publish("b")
        lb.publish("c")  # should be silently dropped
        assert q.qsize() == 2

    def test_unsubscribe_idempotent(self):
        lb = LogBroadcaster()
        q = lb.subscribe()
        lb.unsubscribe(q)
        lb.unsubscribe(q)  # should not raise
        assert lb.subscriber_count == 0


class TestBroadcastLogHandler:
    def test_handler_feeds_broadcaster(self):
        lb = LogBroadcaster()
        q = lb.subscribe()
        handler = BroadcastLogHandler(lb)
        handler.setFormatter(logging.Formatter("%(message)s"))

        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="log line", args=(), exc_info=None,
        )
        handler.emit(record)
        assert q.get_nowait() == "log line"
