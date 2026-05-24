#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         test_orchestrator.py
Description:  Tests for ReAct loop orchestration and tool calling.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

from src.executor.models import (
    ActionRequest,
    ActionStatus,
    Capability,
    ExecutionResult,
    ParamConstraint,
)
from src.executor.registry import CapabilityRegistry
from src.llm_backend import LLMMetrics
from src.orchestrator import AgentOrchestrator, OrchestratorResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@dataclass
class FakeIdentity:
    actor_role: str = "Agent"
    actor_id: str = "test-agent"
    api_key: str = "test-key"


def _make_registry(*caps: Capability) -> CapabilityRegistry:
    reg = CapabilityRegistry()
    for c in caps:
        reg.register(c)
    return reg


def _make_metrics(total_tokens: int = 100) -> LLMMetrics:
    return LLMMetrics(
        model="test",
        prompt_tokens=total_tokens // 2,
        completion_tokens=total_tokens // 2,
    )


def _assistant_final(content: str, tokens: int = 100) -> Dict[str, Any]:
    """Simulate an LLM response with no tool_calls (final answer)."""
    return {
        "role": "assistant",
        "content": content,
        "_metrics": _make_metrics(tokens),
    }


def _assistant_tool_call(
    name: str, arguments: dict, content: str = "", tokens: int = 100
) -> Dict[str, Any]:
    """Simulate an LLM response with a tool_call."""
    return {
        "role": "assistant",
        "content": content,
        "tool_calls": [
            {
                "function": {
                    "name": name,
                    "arguments": arguments,
                },
            }
        ],
        "_metrics": _make_metrics(tokens),
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestOrchestratorFinalAnswer:
    """LLM gives a final answer immediately — no tool calls."""

    def test_direct_answer(self):
        llm = MagicMock()
        llm.call_llm_chat.return_value = _assistant_final("All clear.")

        executor = MagicMock()
        registry = _make_registry()

        orch = AgentOrchestrator(
            llm_handler=llm,
            executor=executor,
            agent_identity=FakeIdentity(),
            capability_registry=registry,
        )
        result = orch.run("system", "user msg", [])

        assert result.final_answer == "All clear."
        assert result.tool_calls_made == []
        assert result.rounds == 1
        assert result.terminated_by == "final_answer"


class TestOrchestratorToolCall:
    """LLM makes a tool call then gives a final answer."""

    def test_single_tool_call_then_answer(self):
        llm = MagicMock()
        llm.call_llm_chat.side_effect = [
            _assistant_tool_call("create_github_issue", {"title": "Alert", "body": "Details"}),
            _assistant_final("Issue created."),
        ]

        executor = MagicMock()
        executor.execute.return_value = ExecutionResult(
            request_id="", capability="create_github_issue",
            status=ActionStatus.SUCCESS, detail="Issue #42",
        )

        registry = _make_registry(Capability(
            name="create_github_issue", handler="h",
        ))

        orch = AgentOrchestrator(
            llm_handler=llm,
            executor=executor,
            agent_identity=FakeIdentity(),
            capability_registry=registry,
        )
        result = orch.run("system", "user msg", [{"type": "function"}])

        assert result.final_answer == "Issue created."
        assert len(result.tool_calls_made) == 1
        assert result.tool_calls_made[0]["capability"] == "create_github_issue"
        assert result.rounds == 2
        assert result.terminated_by == "final_answer"

        # Verify credentials injection
        call_args = executor.execute.call_args
        req: ActionRequest = call_args[0][0]
        assert req.actor_role == "Agent"
        assert req.actor_id == "test-agent"
        assert req.api_key == "test-key"


class TestOrchestratorRequiresApproval:
    """Tool with requires_approval is downgraded to issue."""

    def test_downgrade_to_issue(self):
        llm = MagicMock()
        llm.call_llm_chat.side_effect = [
            _assistant_tool_call("create_github_pr", {"title": "PR", "head_branch": "ai-rules/20260301"}),
            _assistant_final("Done."),
        ]

        executor = MagicMock()
        executor.execute.return_value = ExecutionResult(
            request_id="", capability="create_github_issue",
            status=ActionStatus.SUCCESS, detail="Issue #99",
        )

        registry = _make_registry(Capability(
            name="create_github_pr", handler="h", requires_approval=True,
        ))

        orch = AgentOrchestrator(
            llm_handler=llm,
            executor=executor,
            agent_identity=FakeIdentity(),
            capability_registry=registry,
        )
        result = orch.run("system", "user msg", [])

        assert len(result.tool_calls_made) == 1
        record = result.tool_calls_made[0]
        assert "downgraded" in record["status"]
        assert record["capability"] == "create_github_pr"


class TestOrchestratorBudget:
    """Budget enforcement: max_rounds, token_budget."""

    def test_max_rounds(self):
        llm = MagicMock()
        # Always return tool calls — never gives a final answer
        llm.call_llm_chat.return_value = _assistant_tool_call(
            "create_github_issue", {"title": "t", "body": "b"}, tokens=10,
        )

        executor = MagicMock()
        executor.execute.return_value = ExecutionResult(
            request_id="", capability="create_github_issue",
            status=ActionStatus.SUCCESS, detail="ok",
        )

        registry = _make_registry(Capability(
            name="create_github_issue", handler="h",
        ))

        orch = AgentOrchestrator(
            llm_handler=llm,
            executor=executor,
            agent_identity=FakeIdentity(),
            capability_registry=registry,
            max_rounds=3,
        )
        result = orch.run("system", "user msg", [])

        assert result.terminated_by == "max_rounds"
        assert result.rounds == 3

    def test_token_budget_with_forced_final(self):
        """Budget exceeded with tool calls → no force-final (processor handles it)."""
        llm = MagicMock()
        llm.call_llm_chat.side_effect = [
            _assistant_tool_call("create_github_issue", {"title": "t", "body": "b"}, tokens=5000),
        ]

        executor = MagicMock()
        executor.execute.return_value = ExecutionResult(
            request_id="", capability="create_github_issue",
            status=ActionStatus.SUCCESS,
        )

        registry = _make_registry(Capability(
            name="create_github_issue", handler="h",
        ))

        orch = AgentOrchestrator(
            llm_handler=llm,
            executor=executor,
            agent_identity=FakeIdentity(),
            capability_registry=registry,
            max_tokens=2000,
        )
        result = orch.run("system", "user msg", [])

        # Budget exceeded after round 1 (eval_count=2500 > 2000).
        # Tool calls exist, so force-final is skipped.
        assert "token_budget" in result.terminated_by
        assert result.final_answer == ""
        assert len(result.tool_calls_made) == 1

    def test_token_budget_force_final_fails(self):
        """Budget exceeded with tool calls → empty answer, no force-final attempted."""
        llm = MagicMock()
        llm.call_llm_chat.side_effect = [
            _assistant_tool_call("create_github_issue", {"title": "t", "body": "b"}, tokens=5000),
        ]

        executor = MagicMock()
        executor.execute.return_value = ExecutionResult(
            request_id="", capability="create_github_issue",
            status=ActionStatus.SUCCESS,
        )

        registry = _make_registry(Capability(
            name="create_github_issue", handler="h",
        ))

        orch = AgentOrchestrator(
            llm_handler=llm,
            executor=executor,
            agent_identity=FakeIdentity(),
            capability_registry=registry,
            max_tokens=2000,
        )
        result = orch.run("system", "user msg", [])

        # Tool calls made → force-final skipped → empty answer is expected.
        assert result.terminated_by == "token_budget"
        assert result.final_answer == ""
        assert len(result.tool_calls_made) == 1
        # LLM called exactly once (no force-final attempt)
        assert llm.call_llm_chat.call_count == 1


class TestOrchestratorEmptyFinalAnswer:
    """LLM returns empty content after tool execution → force-final fires."""

    def test_empty_content_after_tool_call_skips_force(self):
        """Tool call followed by empty-content final → force skipped (processor handles it)."""
        llm = MagicMock()
        llm.call_llm_chat.side_effect = [
            # Round 1: tool call
            _assistant_tool_call("create_github_issue", {"title": "t", "body": "b"}, tokens=500),
            # Round 2: empty content, no tool_calls ("final_answer" with empty)
            {"role": "assistant", "content": "", "_metrics": _make_metrics(200)},
        ]

        executor = MagicMock()
        executor.execute.return_value = ExecutionResult(
            request_id="", capability="create_github_issue",
            status=ActionStatus.SUCCESS, detail="ok",
        )

        registry = _make_registry(Capability(name="create_github_issue", handler="h"))

        orch = AgentOrchestrator(
            llm_handler=llm,
            executor=executor,
            agent_identity=FakeIdentity(),
            capability_registry=registry,
        )
        result = orch.run("system", "user msg", [])

        # Tool calls exist → force-final is NOT attempted → empty answer
        assert result.terminated_by == "final_answer"
        assert result.final_answer == ""
        assert len(result.tool_calls_made) == 1
        # Only 2 LLM calls (round 1 + round 2), no force-final
        assert llm.call_llm_chat.call_count == 2

    def test_empty_content_no_tool_calls_force_fails(self):
        """Direct empty answer with no tool calls and force also fails."""
        llm = MagicMock()
        llm.call_llm_chat.side_effect = [
            # Round 1: empty content, no tool calls
            {"role": "assistant", "content": "", "_metrics": _make_metrics(200)},
            # Force-final: also fails
            RuntimeError("Model error"),
        ]

        orch = AgentOrchestrator(
            llm_handler=llm,
            executor=MagicMock(),
            agent_identity=FakeIdentity(),
            capability_registry=_make_registry(),
        )
        result = orch.run("system", "user msg", [])

        assert result.final_answer == ""
        assert result.terminated_by == "final_answer"


class TestOrchestratorLLMError:
    """LLM call failure."""

    def test_error_terminates(self):
        llm = MagicMock()
        llm.call_llm_chat.side_effect = RuntimeError("Model not loaded")

        orch = AgentOrchestrator(
            llm_handler=llm,
            executor=MagicMock(),
            agent_identity=FakeIdentity(),
            capability_registry=_make_registry(),
        )
        result = orch.run("system", "user msg", [])

        assert result.terminated_by == "error"
        assert result.rounds == 0
