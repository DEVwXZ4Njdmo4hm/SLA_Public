#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         rate_limiter.py
Description:  Thread-safe token-bucket rate limiter for LLM backend requests.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import threading
import time


class TokenBucketRateLimiter:
    """A token-bucket rate limiter.

    Allows *capacity* requests per *period* seconds, with burst tolerance
    up to *capacity*.  Thread-safe; ``acquire()`` blocks until a token
    is available.

    When ``capacity <= 0`` or ``period <= 0``, the limiter is disabled
    (``acquire()`` always returns immediately).
    """

    def __init__(self, capacity: float, period: float = 60.0) -> None:
        self._capacity = max(0.0, capacity)
        self._period = max(0.0, period)
        self._enabled = self._capacity > 0 and self._period > 0

        if self._enabled:
            self._refill_rate = self._capacity / self._period  # tokens/sec
            self._tokens = self._capacity  # start full
        else:
            self._refill_rate = 0.0
            self._tokens = 0.0

        self._last_refill = time.monotonic()
        self._lock = threading.Lock()
        self._cv = threading.Condition(self._lock)

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def capacity(self) -> float:
        return self._capacity

    def reconfigure(self, capacity: float, period: float = 60.0) -> None:
        """Update capacity and period in-place.

        Threads blocked in ``acquire()`` will see the new parameters
        on their next wake-up, avoiding orphaned waits on a replaced
        object.
        """
        with self._cv:
            self._capacity = max(0.0, capacity)
            self._period = max(0.0, period)
            self._enabled = self._capacity > 0 and self._period > 0
            if self._enabled:
                self._refill_rate = self._capacity / self._period
                # Clamp existing tokens to new capacity
                self._tokens = min(self._tokens, self._capacity)
            else:
                self._refill_rate = 0.0
            self._cv.notify_all()

    def acquire(self, timeout: float | None = None) -> bool:
        """Block until a token is available, then consume it.

        Parameters
        ----------
        timeout : float or None
            Maximum seconds to wait.  ``None`` = wait forever.
            ``0`` = non-blocking (equivalent to ``try_acquire()``).

        Returns
        -------
        bool
            ``True`` if a token was acquired, ``False`` on timeout.
        """
        if not self._enabled:
            return True

        deadline = None if timeout is None else time.monotonic() + timeout

        with self._cv:
            while True:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True
                # Calculate wait time until next token
                wait = (1.0 - self._tokens) / self._refill_rate
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return False
                    wait = min(wait, remaining)
                self._cv.wait(timeout=wait)

    def try_acquire(self) -> bool:
        """Non-blocking: consume a token if available."""
        return self.acquire(timeout=0)

    def _refill(self) -> None:
        """Add tokens based on elapsed time since last refill.

        Must be called while holding ``self._lock``.
        """
        now = time.monotonic()
        elapsed = now - self._last_refill
        if elapsed > 0:
            self._tokens = min(
                self._capacity,
                self._tokens + elapsed * self._refill_rate,
            )
            self._last_refill = now
