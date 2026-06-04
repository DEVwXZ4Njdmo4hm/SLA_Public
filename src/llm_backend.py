#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         llm_backend.py
Description:  LLM backend protocol and shared data types.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Protocol, runtime_checkable


# ---------------------------------------------------------------------------
# Backend-agnostic metrics
# ---------------------------------------------------------------------------

@dataclass
class LLMMetrics:
    """Backend-agnostic token-level metrics from a single LLM request.

    *total_duration_sec* is always available (wall-clock, measured by the
    backend layer).  *prompt_eval_duration_sec* and
    *completion_duration_sec* are populated only by backends that report
    per-phase timing (e.g. Ollama); for others they remain ``0.0`` and
    the derived ``*_per_sec`` properties fall back to wall-clock.
    """
    model: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_duration_sec: float = 0.0
    prompt_eval_duration_sec: float = 0.0
    completion_duration_sec: float = 0.0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    @property
    def completion_tokens_per_sec(self) -> float:
        """Token generation speed.

        Uses backend-native completion duration when available, falling
        back to wall-clock total duration.
        """
        dur = self.completion_duration_sec or self.total_duration_sec
        if dur <= 0:
            return 0.0
        return self.completion_tokens / dur

    @property
    def prompt_tokens_per_sec(self) -> float:
        dur = self.prompt_eval_duration_sec or self.total_duration_sec
        if dur <= 0:
            return 0.0
        return self.prompt_tokens / dur


# ---------------------------------------------------------------------------
# Result containers
# ---------------------------------------------------------------------------

@dataclass
class GenerateResult:
    """Result of a text-generation (completion) request."""
    text: str
    metrics: LLMMetrics


@dataclass
class ChatMessage:
    role: str
    content: str
    tool_calls: List[Dict] | None = None


@dataclass
class ChatResult:
    """Result of a chat-completion request."""
    message: ChatMessage
    metrics: LLMMetrics


# ---------------------------------------------------------------------------
# Backend protocol
# ---------------------------------------------------------------------------

@runtime_checkable
class LLMBackend(Protocol):
    """Abstract LLM backend protocol.

    Implementations must provide ``generate()`` and ``chat()``.
    ``stop_model()`` and ``detect_tool_support()`` are optional – not all
    backends support them.
    """

    @property
    def backend_type(self) -> str:
        """Return backend identifier: ``'ollama'``, ``'openai'``, ``'deepseek'``, etc."""
        ...

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
        """Synchronous text completion."""
        ...

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
        """Synchronous chat completion with optional tool calling."""
        ...

    def stop_model(self, model: str) -> bool:
        """Attempt to unload the model.  Returns ``False`` if unsupported."""
        ...

    def detect_tool_support(self, model: str) -> bool | None:
        """Detect tool-use capability.

        Returns ``None`` if detection is not supported by this backend.
        """
        ...
