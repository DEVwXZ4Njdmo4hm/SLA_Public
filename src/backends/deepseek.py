#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         deepseek.py
Description:  Native DeepSeek API backend implementation.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import logging
import time as _time
from typing import Dict, List
from urllib.parse import urlparse

import requests

from ..llm_backend import (
    ChatMessage,
    ChatResult,
    GenerateResult,
    LLMMetrics,
)

logger = logging.getLogger(__name__)

DEFAULT_DEEPSEEK_BASE_URL = "https://api.deepseek.com"

_LOCAL_HOSTS = frozenset({
    "localhost",
    "127.0.0.1",
    "::1",
    "host.containers.internal",
    "host.docker.internal",
})

_ERROR_HINTS = {
    400: "invalid request body format",
    401: "authentication failed",
    402: "insufficient account balance",
    422: "invalid request parameters",
    429: "rate limit reached",
    500: "DeepSeek server error",
    503: "DeepSeek server overloaded",
}


class DeepSeekBackend:
    """Native DeepSeek API backend.

    This backend targets DeepSeek's official OpenAI-format Chat Completion
    endpoint directly: ``POST /chat/completions`` under
    ``https://api.deepseek.com``.  It intentionally stays separate from the
    generic OpenAI-compatible backend so DeepSeek-specific endpoint paths and
    ``thinking`` controls do not affect OpenAI, Azure OpenAI, vLLM, or other
    compatible servers.
    """

    def __init__(
        self,
        base_url: str = DEFAULT_DEEPSEEK_BASE_URL,
        api_key: str = "",
        timeout: int = 300,
        extra_headers: Dict[str, str] | None = None,
        rate_limiter: "TokenBucketRateLimiter | None" = None,
    ) -> None:
        self._base_url = (base_url or DEFAULT_DEEPSEEK_BASE_URL).rstrip("/")
        self._timeout = timeout
        self._headers: Dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            self._headers["Authorization"] = f"Bearer {api_key}"
        if extra_headers:
            self._headers.update(extra_headers)
        self._api_key = api_key
        self._rate_limiter = rate_limiter

        if not self._is_local(self._base_url):
            logger.warning(
                "DeepSeek backend configured for remote endpoint (%s). "
                "Log data will be sent to an external service. "
                "Ensure this complies with your data handling policies.",
                self._base_url,
            )

    @property
    def backend_type(self) -> str:
        return "deepseek"

    def set_rate_limiter(self, limiter: "TokenBucketRateLimiter") -> None:
        """Update the rate limiter when a stricter profile is loaded."""
        self._rate_limiter = limiter

    def update_auth_token(self, token: str) -> None:
        """Hot-reload the DeepSeek API key."""
        self._api_key = token
        if token:
            self._headers["Authorization"] = f"Bearer {token}"
        else:
            self._headers.pop("Authorization", None)

    _MAX_429_RETRIES = 5
    _INITIAL_RETRY_DELAY = 1.0
    _MAX_RETRY_DELAY = 60.0

    def generate(
        self,
        model: str,
        prompt: str,
        *,
        max_tokens: int = 512,
        context_length: int = 8192,
        temperature: float = 0.7,
        top_p: float = 0.9,
        top_k: int = 40,
        stop: List[str] | None = None,
        think: bool = False,
        keep_alive: str | None = None,
    ) -> GenerateResult:
        payload: Dict = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
            "temperature": temperature,
            "top_p": top_p,
            "stream": False,
            "thinking": {"type": "enabled" if think else "disabled"},
        }
        if stop:
            payload["stop"] = stop

        data, wall_clock = self._post_chat_completion(payload, model, "generate")
        usage = data.get("usage", {})
        choice = (data.get("choices") or [{}])[0]
        text = choice.get("message", {}).get("content", "")

        metrics = LLMMetrics(
            model=model,
            prompt_tokens=int(usage.get("prompt_tokens", 0)),
            completion_tokens=int(usage.get("completion_tokens", 0)),
            total_duration_sec=wall_clock,
        )
        return GenerateResult(text=text.strip() if text else "", metrics=metrics)

    def chat(
        self,
        model: str,
        messages: List[Dict],
        *,
        tools: List[Dict] | None = None,
        max_tokens: int = 512,
        context_length: int = 8192,
        temperature: float = 0.7,
        top_p: float = 0.9,
        top_k: int = 40,
        stop: List[str] | None = None,
        think: bool = False,
        keep_alive: str | None = None,
    ) -> ChatResult:
        payload: Dict = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "top_p": top_p,
            "stream": False,
            "thinking": {"type": "enabled" if think else "disabled"},
        }
        if tools:
            payload["tools"] = tools
        if stop:
            payload["stop"] = stop

        data, wall_clock = self._post_chat_completion(payload, model, "chat")
        usage = data.get("usage", {})
        choice = (data.get("choices") or [{}])[0]
        msg = choice.get("message", {})

        metrics = LLMMetrics(
            model=model,
            prompt_tokens=int(usage.get("prompt_tokens", 0)),
            completion_tokens=int(usage.get("completion_tokens", 0)),
            total_duration_sec=wall_clock,
        )
        return ChatResult(
            message=ChatMessage(
                role=msg.get("role", "assistant"),
                content=msg.get("content", "") or "",
                tool_calls=msg.get("tool_calls"),
            ),
            metrics=metrics,
        )

    def stop_model(self, model: str) -> bool:
        return False

    def detect_tool_support(self, model: str) -> bool | None:
        return True

    def _post_chat_completion(
        self,
        payload: Dict,
        model: str,
        operation: str,
    ) -> tuple[Dict, float]:
        limiter = self._rate_limiter
        if limiter is not None:
            limiter.acquire()

        url = f"{self._base_url}/chat/completions"
        t0 = _time.monotonic()
        delay = self._INITIAL_RETRY_DELAY

        for attempt in range(self._MAX_429_RETRIES + 1):
            resp = requests.post(
                url,
                json=payload,
                headers=self._headers,
                timeout=self._timeout,
            )
            if resp.status_code == 429:
                if attempt >= self._MAX_429_RETRIES:
                    resp.raise_for_status()
                retry_after = (getattr(resp, "headers", None) or {}).get("Retry-After")
                if retry_after:
                    try:
                        wait = float(retry_after)
                    except (ValueError, TypeError):
                        wait = delay
                else:
                    wait = delay
                logger.warning(
                    "DeepSeek rate limited (429) on attempt %d/%d, retrying in %.1fs",
                    attempt + 1,
                    self._MAX_429_RETRIES,
                    wait,
                )
                _time.sleep(wait)
                delay = min(delay * 2, self._MAX_RETRY_DELAY)
                continue

            if not (200 <= int(resp.status_code) < 300):
                self._log_error_response(resp, model, operation)
            resp.raise_for_status()
            break

        return resp.json(), _time.monotonic() - t0

    @staticmethod
    def _log_error_response(resp: requests.Response, model: str, operation: str) -> None:
        status = int(getattr(resp, "status_code", 0) or 0)
        hint = _ERROR_HINTS.get(status, "HTTP error")
        text = str(getattr(resp, "text", "") or "")
        logger.error(
            "DeepSeek %s() error %d for model %s (%s): %s",
            operation,
            status,
            model,
            hint,
            text[:500],
        )

    @staticmethod
    def _is_local(base_url: str) -> bool:
        try:
            hostname = urlparse(base_url).hostname or ""
            return hostname.lower() in _LOCAL_HOSTS
        except Exception:
            return False
