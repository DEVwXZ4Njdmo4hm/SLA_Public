#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         ollama.py
Description:  Ollama REST API backend implementation.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import logging
import time as _time
from typing import Dict, List, Optional

import requests

from ..llm_backend import (
    ChatMessage,
    ChatResult,
    GenerateResult,
    LLMMetrics,
)

logger = logging.getLogger(__name__)


class OllamaBackend:
    """Ollama REST API backend.

    Wraps ``/api/generate``, ``/api/chat``, ``/api/stop`` and ``/api/show``.

    Parameters
    ----------
    base_url:
        Ollama server URL (e.g. ``http://localhost:11434``).
    timeout:
        HTTP request timeout in seconds.
    auth_token:
        Optional Bearer token for remote Ollama instances.
    """

    def __init__(
        self,
        base_url: str,
        timeout: int = 300,
        auth_token: str = "",
        rate_limiter: "TokenBucketRateLimiter | None" = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._headers: Dict[str, str] = {}
        if auth_token:
            self._headers["Authorization"] = f"Bearer {auth_token}"
        self._rate_limiter = rate_limiter

    # ------------------------------------------------------------------
    # Protocol properties
    # ------------------------------------------------------------------

    @property
    def backend_type(self) -> str:
        return "ollama"

    def update_auth_token(self, token: str) -> None:
        """Hot-reload the authentication token."""
        if token:
            self._headers["Authorization"] = f"Bearer {token}"
        else:
            self._headers.pop("Authorization", None)

    def set_rate_limiter(self, limiter: "TokenBucketRateLimiter") -> None:
        """Update the rate limiter (called when a stricter profile is loaded)."""
        self._rate_limiter = limiter

    # ------------------------------------------------------------------
    # 429 retry parameters
    # ------------------------------------------------------------------

    _MAX_429_RETRIES = 5
    _INITIAL_RETRY_DELAY = 1.0   # seconds
    _MAX_RETRY_DELAY = 60.0      # seconds

    # ------------------------------------------------------------------
    # generate  (POST /api/generate)
    # ------------------------------------------------------------------

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
        limiter = self._rate_limiter
        if limiter is not None:
            limiter.acquire()

        url = f"{self._base_url}/api/generate"
        payload: Dict = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "think": think,
            "options": {
                "num_predict": max_tokens,
                "num_ctx": context_length,
                "temperature": temperature,
                "top_p": top_p,
                "top_k": top_k,
            },
        }
        if stop:
            payload["options"]["stop"] = stop
        if keep_alive is not None:
            payload["keep_alive"] = keep_alive

        t0 = _time.monotonic()
        delay = self._INITIAL_RETRY_DELAY
        for attempt in range(self._MAX_429_RETRIES + 1):
            resp = requests.post(
                url, json=payload, headers=self._headers, timeout=self._timeout,
            )
            if resp.status_code == 429:
                if attempt >= self._MAX_429_RETRIES:
                    resp.raise_for_status()
                retry_after = resp.headers.get("Retry-After")
                if retry_after:
                    try:
                        wait = float(retry_after)
                    except (ValueError, TypeError):
                        wait = delay
                else:
                    wait = delay
                logger.warning(
                    "Rate limited (429) on attempt %d/%d, retrying in %.1fs",
                    attempt + 1, self._MAX_429_RETRIES, wait,
                )
                _time.sleep(wait)
                delay = min(delay * 2, self._MAX_RETRY_DELAY)
                continue
            resp.raise_for_status()
            break

        data = resp.json()
        wall_clock = _time.monotonic() - t0

        metrics = LLMMetrics(
            model=str(data.get("model", model)),
            prompt_tokens=int(data.get("prompt_eval_count", 0) or 0),
            completion_tokens=int(data.get("eval_count", 0) or 0),
            total_duration_sec=wall_clock,
            prompt_eval_duration_sec=int(data.get("prompt_eval_duration", 0) or 0) / 1e9,
            completion_duration_sec=int(data.get("eval_duration", 0) or 0) / 1e9,
        )
        text = str(data.get("response", "")).strip()
        return GenerateResult(text=text, metrics=metrics)

    # ------------------------------------------------------------------
    # chat  (POST /api/chat)
    # ------------------------------------------------------------------

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
        limiter = self._rate_limiter
        if limiter is not None:
            limiter.acquire()

        url = f"{self._base_url}/api/chat"
        payload: Dict = {
            "model": model,
            "messages": messages,
            "stream": False,
            "think": think,
            "options": {
                "num_predict": max_tokens,
                "num_ctx": context_length,
                "temperature": temperature,
                "top_p": top_p,
                "top_k": top_k,
            },
        }
        if tools:
            payload["tools"] = tools
        if stop:
            payload["options"]["stop"] = stop
        if keep_alive is not None:
            payload["keep_alive"] = keep_alive

        t0 = _time.monotonic()
        delay = self._INITIAL_RETRY_DELAY
        for attempt in range(self._MAX_429_RETRIES + 1):
            resp = requests.post(
                url, json=payload, headers=self._headers, timeout=self._timeout,
            )
            if resp.status_code == 429:
                if attempt >= self._MAX_429_RETRIES:
                    resp.raise_for_status()
                retry_after = resp.headers.get("Retry-After")
                if retry_after:
                    try:
                        wait = float(retry_after)
                    except (ValueError, TypeError):
                        wait = delay
                else:
                    wait = delay
                logger.warning(
                    "Rate limited (429) on attempt %d/%d, retrying in %.1fs",
                    attempt + 1, self._MAX_429_RETRIES, wait,
                )
                _time.sleep(wait)
                delay = min(delay * 2, self._MAX_RETRY_DELAY)
                continue
            resp.raise_for_status()
            break

        data = resp.json()
        wall_clock = _time.monotonic() - t0

        metrics = LLMMetrics(
            model=str(data.get("model", model)),
            prompt_tokens=int(data.get("prompt_eval_count", 0) or 0),
            completion_tokens=int(data.get("eval_count", 0) or 0),
            total_duration_sec=wall_clock,
            prompt_eval_duration_sec=int(data.get("prompt_eval_duration", 0) or 0) / 1e9,
            completion_duration_sec=int(data.get("eval_duration", 0) or 0) / 1e9,
        )

        msg = data.get("message", {})
        return ChatResult(
            message=ChatMessage(
                role=msg.get("role", "assistant"),
                content=msg.get("content", ""),
                tool_calls=msg.get("tool_calls"),
            ),
            metrics=metrics,
        )

    # ------------------------------------------------------------------
    # stop_model  (POST /api/stop, fallback /api/generate keep_alive=0)
    # ------------------------------------------------------------------

    def stop_model(self, model: str) -> bool:
        if not model:
            return False

        short_timeout = max(1, min(10, self._timeout))

        # Try /api/stop first
        stop_url = f"{self._base_url}/api/stop"
        try:
            resp = requests.post(
                stop_url,
                json={"model": model},
                headers=self._headers,
                timeout=short_timeout,
            )
            if resp.status_code != 404:
                resp.raise_for_status()
                return True
        except Exception as exc:
            logger.warning("Failed to stop model via /api/stop: %s", exc)

        # Fallback: keep_alive=0
        gen_url = f"{self._base_url}/api/generate"
        payload = {
            "model": model,
            "prompt": " ",
            "stream": False,
            "keep_alive": 0,
            "options": {"num_predict": 1},
        }
        try:
            resp = requests.post(
                gen_url,
                json=payload,
                headers=self._headers,
                timeout=short_timeout,
            )
            resp.raise_for_status()
            return True
        except Exception as exc:
            logger.warning("Failed to stop model via keep_alive=0: %s", exc)
            return False

    # ------------------------------------------------------------------
    # detect_tool_support  (POST /api/show)
    # ------------------------------------------------------------------

    def detect_tool_support(self, model: str) -> bool | None:
        """Query Ollama ``/api/show`` for tool-use capability.

        Returns ``True``/``False`` based on model metadata, or ``None``
        if detection fails.
        """
        if not model:
            return None

        url = f"{self._base_url}/api/show"
        try:
            resp = requests.post(
                url,
                json={"model": model},
                headers=self._headers,
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            logger.warning(
                "Tool-use detection: /api/show request failed for model '%s': %s",
                model, exc,
            )
            return None

        # Strategy 1: capabilities list (Ollama >= 0.6)
        capabilities = data.get("capabilities")
        if isinstance(capabilities, list) and "tools" in capabilities:
            logger.info(
                "Tool-use detection: model '%s' advertises 'tools' capability.",
                model,
            )
            return True

        # Strategy 2: chat template inspection
        model_info: Optional[dict] = data.get("model_info")
        if isinstance(model_info, dict):
            template = str(model_info.get("tokenizer.chat_template", ""))
            if _template_mentions_tools(template):
                logger.info(
                    "Tool-use detection: model '%s' chat template contains "
                    "tool-related tokens.", model,
                )
                return True

        # Strategy 3: top-level template field (older Ollama)
        template_field = data.get("template", "")
        if isinstance(template_field, str) and _template_mentions_tools(template_field):
            logger.info(
                "Tool-use detection: model '%s' template field contains "
                "tool-related tokens.", model,
            )
            return True

        logger.info(
            "Tool-use detection: model '%s' does not appear to support tools.",
            model,
        )
        return False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _template_mentions_tools(template: str) -> bool:
    """Heuristic: does *template* reference tool / function calling tokens?"""
    if not template:
        return False
    lower = template.lower()
    markers = ("tools", "tool_call", "function_call", "<tool_call>", "<|tool", "tool_use")
    return any(m in lower for m in markers)
