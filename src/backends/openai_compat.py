#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         openai_compat.py
Description:  OpenAI-compatible API backend (OpenAI, Azure OpenAI, vLLM, etc.).
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import logging
import re
import time as _time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

from ..llm_backend import (
    ChatMessage,
    ChatResult,
    GenerateResult,
    LLMMetrics,
)

logger = logging.getLogger(__name__)

_LOCAL_HOSTS = frozenset({
    "localhost",
    "127.0.0.1",
    "::1",
    "host.containers.internal",
    "host.docker.internal",
})


def _is_provider_sensitive_response(resp: requests.Response) -> bool:
    if getattr(resp, "status_code", None) != 422:
        return False
    text = str(getattr(resp, "text", "") or "").lower()
    return (
        "new_sensitive" in text
        or "output_sensitive" in text
        or "input_sensitive" in text
        or "1027" in text
        or "1026" in text
    )


# ---------------------------------------------------------------------------
# vLLM Prometheus metrics (optional)
# ---------------------------------------------------------------------------

@dataclass
class VLLMMetrics:
    """Snapshot of vLLM Prometheus metrics.

    Populated by periodic scraping of the ``/metrics`` endpoint exposed by
    vLLM.  All fields default to ``None`` (unavailable) so callers can
    distinguish "not enabled" from "enabled but value is zero".
    """
    num_requests_running: Optional[float] = None
    avg_generation_throughput_toks_per_s: Optional[float] = None
    gpu_cache_usage_perc: Optional[float] = None
    timestamp: float = field(default_factory=_time.monotonic)


# Pre-compiled patterns for the three metrics we care about.
_VLLM_METRIC_PATTERNS: Dict[str, re.Pattern] = {
    "num_requests_running": re.compile(
        r'^vllm:num_requests_running(?:\{[^}]*\})?\s+([\d.eE+-]+)', re.MULTILINE,
    ),
    "avg_generation_throughput_toks_per_s": re.compile(
        r'^vllm:avg_generation_throughput_toks_per_s(?:\{[^}]*\})?\s+([\d.eE+-]+)', re.MULTILINE,
    ),
    "gpu_cache_usage_perc": re.compile(
        r'^vllm:gpu_cache_usage_perc(?:\{[^}]*\})?\s+([\d.eE+-]+)', re.MULTILINE,
    ),
}


def _parse_vllm_metrics(text: str) -> VLLMMetrics:
    """Parse a vLLM Prometheus ``/metrics`` text-format response."""
    values: Dict[str, Optional[float]] = {}
    for key, pattern in _VLLM_METRIC_PATTERNS.items():
        m = pattern.search(text)
        values[key] = float(m.group(1)) if m else None
    return VLLMMetrics(
        num_requests_running=values["num_requests_running"],
        avg_generation_throughput_toks_per_s=values["avg_generation_throughput_toks_per_s"],
        gpu_cache_usage_perc=values["gpu_cache_usage_perc"],
    )


class OpenAICompatBackend:
    """OpenAI-compatible API backend (OpenAI, Azure OpenAI, vLLM, etc.).

    Parameters
    ----------
    base_url:
        API base URL (e.g. ``https://api.openai.com``, ``http://vllm:8000``).
        Endpoint paths (``/v1/chat/completions``) are appended automatically.
    api_key:
        Bearer token / API key.  May be empty for unauthenticated local
        endpoints (e.g. vLLM without auth).
    timeout:
        HTTP request timeout in seconds.
    extra_headers:
        Additional HTTP headers (e.g. for Azure ``api-version``).
    vllm_prometheus_url:
        Optional URL to a vLLM Prometheus ``/metrics`` endpoint (e.g.
        ``http://vllm-host:8000/metrics``).  When set, the backend
        periodically scrapes the endpoint and exposes the result via
        :attr:`vllm_metrics`.  Only meaningful when the underlying
        server is vLLM.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str = "",
        timeout: int = 300,
        extra_headers: Dict[str, str] | None = None,
        vllm_prometheus_url: str = "",
        rate_limiter: "TokenBucketRateLimiter | None" = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._headers: Dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            self._headers["Authorization"] = f"Bearer {api_key}"
        if extra_headers:
            self._headers.update(extra_headers)

        # vLLM Prometheus metrics (optional)
        self._vllm_prometheus_url: str = vllm_prometheus_url.rstrip("/") if vllm_prometheus_url else ""
        self._vllm_metrics: Optional[VLLMMetrics] = None

        self._api_key = api_key

        # Rate limiter (Improvement 30.6)
        self._rate_limiter = rate_limiter

        # One-time data-egress warning for remote endpoints
        if not self._is_local(self._base_url):
            logger.warning(
                "LLM backend configured for remote endpoint (%s). "
                "Log data will be sent to an external service. "
                "Ensure this complies with your data handling policies.",
                self._base_url,
            )

    # ------------------------------------------------------------------
    # Protocol properties
    # ------------------------------------------------------------------

    @property
    def backend_type(self) -> str:
        return "openai"

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
    # generate  (/v1/chat/completions wrapping prompt as user message)
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
        keep_alive: str | None = None,  # Ollama-only; ignored here
    ) -> GenerateResult:
        limiter = self._rate_limiter
        if limiter is not None:
            limiter.acquire()

        url = f"{self._base_url}/v1/chat/completions"
        payload: Dict = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
            "temperature": temperature,
            "top_p": top_p,
            "stream": False,
        }
        if stop:
            payload["stop"] = stop

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
            if not resp.ok:
                if _is_provider_sensitive_response(resp):
                    logger.warning(
                        "OpenAI-compat generate() blocked by provider content-safety "
                        "policy for model %s: %s",
                        model, resp.text[:500],
                    )
                else:
                    logger.error(
                        "OpenAI-compat generate() error %d for model %s: %s",
                        resp.status_code, model, resp.text[:500],
                    )
            resp.raise_for_status()
            break

        data = resp.json()
        wall_clock = _time.monotonic() - t0

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

    # ------------------------------------------------------------------
    # chat  (/v1/chat/completions)
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
        keep_alive: str | None = None,  # Ollama-only; ignored here
    ) -> ChatResult:
        limiter = self._rate_limiter
        if limiter is not None:
            limiter.acquire()

        url = f"{self._base_url}/v1/chat/completions"
        payload: Dict = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "top_p": top_p,
            "stream": False,
        }
        if tools:
            payload["tools"] = tools
        if stop:
            payload["stop"] = stop

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
            if not resp.ok:
                if _is_provider_sensitive_response(resp):
                    logger.warning(
                        "OpenAI-compat chat() blocked by provider content-safety "
                        "policy for model %s: %s",
                        model, resp.text[:500],
                    )
                else:
                    logger.error(
                        "OpenAI-compat chat() error %d for model %s: %s",
                        resp.status_code, model, resp.text[:500],
                    )
            resp.raise_for_status()
            break

        data = resp.json()
        wall_clock = _time.monotonic() - t0

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

    # ------------------------------------------------------------------
    # stop_model / detect_tool_support  (not applicable)
    # ------------------------------------------------------------------

    def stop_model(self, model: str) -> bool:
        return False

    def detect_tool_support(self, model: str) -> bool | None:
        # OpenAI-compatible APIs generally support function/tool calling.
        return True

    def update_auth_token(self, token: str) -> None:
        """Hot-reload the authentication token / API key."""
        self._api_key = token
        if token:
            self._headers["Authorization"] = f"Bearer {token}"
        else:
            self._headers.pop("Authorization", None)

    # ------------------------------------------------------------------
    # vLLM Prometheus metrics (optional)
    # ------------------------------------------------------------------

    @property
    def vllm_metrics(self) -> Optional[VLLMMetrics]:
        """Return the last scraped vLLM metrics, or ``None`` if disabled."""
        return self._vllm_metrics

    def scrape_vllm_metrics(self) -> Optional[VLLMMetrics]:
        """Scrape the vLLM Prometheus ``/metrics`` endpoint.

        Returns the parsed :class:`VLLMMetrics` on success, or ``None``
        if the feature is disabled or the request fails.  The result is
        also cached in :attr:`vllm_metrics`.
        """
        if not self._vllm_prometheus_url:
            return None
        try:
            resp = requests.get(self._vllm_prometheus_url, timeout=5)
            resp.raise_for_status()
            self._vllm_metrics = _parse_vllm_metrics(resp.text)
            return self._vllm_metrics
        except Exception as exc:
            logger.debug("Failed to scrape vLLM metrics from %s: %s", self._vllm_prometheus_url, exc)
            return None

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _is_local(base_url: str) -> bool:
        """Return ``True`` if *base_url* points to a local address."""
        try:
            hostname = urlparse(base_url).hostname or ""
            return hostname.lower() in _LOCAL_HOSTS
        except Exception:
            return False
