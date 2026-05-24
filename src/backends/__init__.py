#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         __init__.py
Description:  LLM backend factory – instantiates the configured backend.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import threading
from typing import Dict

from ..config import config
from ..llm_backend import LLMBackend
from .rate_limiter import TokenBucketRateLimiter

_backend_cache: Dict[str, LLMBackend] = {}
_limiter_cache: Dict[str, TokenBucketRateLimiter] = {}
_cache_lock = threading.Lock()


def create_backend_for_model(profile) -> LLMBackend:
    """Create or reuse a backend instance routed by model profile.

    Backends sharing the same ``(backend_type, base_url, auth_token)``
    triple are cached so that a single HTTP session is reused.
    """
    bt = profile.backend_type
    base_url = profile.backend_base_url
    auth = profile.backend_auth_token or getattr(config, "LLM_BACKEND_AUTH_TOKEN", "")

    if bt == "ollama":
        effective_url = base_url or config.OLLAMA_BASE_URL
        cache_key = f"ollama|{effective_url}|{auth}"
    elif bt == "openai":
        effective_url = base_url or getattr(config, "LLM_BACKEND_BASE_URL", "")
        cache_key = f"openai|{effective_url}|{auth}"
    else:
        raise ValueError(f"Unknown backend type in profile '{profile.name}': {bt!r}")

    rpm = getattr(profile, "max_requests_per_minute", 0) or 0

    with _cache_lock:
        # --- Rate limiter management (Improvement 30.6) ---
        if rpm > 0:
            if cache_key in _limiter_cache:
                existing = _limiter_cache[cache_key]
                # Multiple profiles sharing the same backend: use strictest limit.
                # Reconfigure in-place so threads blocked on acquire() see the
                # new parameters on wake-up (no orphaned old-object waits).
                if rpm < existing.capacity:
                    existing.reconfigure(capacity=float(rpm), period=60.0)
            else:
                _limiter_cache[cache_key] = TokenBucketRateLimiter(
                    capacity=float(rpm), period=60.0,
                )

        limiter = _limiter_cache.get(cache_key)

        if cache_key in _backend_cache:
            backend = _backend_cache[cache_key]
            # Update limiter reference (may have changed due to stricter profile)
            if hasattr(backend, "set_rate_limiter") and limiter is not None:
                backend.set_rate_limiter(limiter)
            return backend

        # Create inside lock to avoid duplicate instances from concurrent
        # cold-start requests (backends are lightweight to construct).
        if bt == "ollama":
            from .ollama import OllamaBackend
            backend = OllamaBackend(
                base_url=effective_url,
                timeout=config.OLLAMA_TIMEOUT,
                auth_token=auth,
                rate_limiter=limiter,
            )
        else:
            from .openai_compat import OpenAICompatBackend
            backend = OpenAICompatBackend(
                base_url=effective_url,
                api_key=auth,
                timeout=config.OLLAMA_TIMEOUT,
                vllm_prometheus_url=getattr(config, "LLM_BACKEND_VLLM_PROMETHEUS_URL", ""),
                rate_limiter=limiter,
            )

        _backend_cache[cache_key] = backend
        return backend


def clear_backend_cache() -> None:
    """Clear the per-model backend cache (useful for testing)."""
    with _cache_lock:
        _backend_cache.clear()
        _limiter_cache.clear()


def create_backend() -> LLMBackend:
    """Create an LLM backend instance based on current configuration."""
    backend_type = getattr(config, "LLM_BACKEND_TYPE", "ollama")

    if backend_type == "ollama":
        from .ollama import OllamaBackend
        return OllamaBackend(
            base_url=config.OLLAMA_BASE_URL,
            timeout=config.OLLAMA_TIMEOUT,
            auth_token=getattr(config, "LLM_BACKEND_AUTH_TOKEN", ""),
        )
    elif backend_type == "openai":
        from .openai_compat import OpenAICompatBackend
        return OpenAICompatBackend(
            base_url=getattr(config, "LLM_BACKEND_BASE_URL", ""),
            api_key=getattr(config, "LLM_BACKEND_AUTH_TOKEN", ""),
            timeout=config.OLLAMA_TIMEOUT,
            vllm_prometheus_url=getattr(config, "LLM_BACKEND_VLLM_PROMETHEUS_URL", ""),
        )
    else:
        raise ValueError(f"Unknown LLM backend type: {backend_type!r}")
