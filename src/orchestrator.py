#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         orchestrator.py
Description:  ReAct loop implementation for LLM-driven tool calling with execution.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .executor.runtime import ExecutorRuntime
    from .executor.registry import CapabilityRegistry
    from .llm_handler import LLMHandler

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------

@dataclass
class OrchestratorResult:
    """Outcome of a single orchestrator run."""
    final_answer: str = ""
    tool_calls_made: List[Dict[str, Any]] = field(default_factory=list)
    rounds: int = 0
    total_tokens: int = 0
    terminated_by: str = "final_answer"  # final_answer | max_rounds | timeout | token_budget


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class AgentOrchestrator:
    """ReAct-style orchestrator that lets the LLM drive tool execution.

    The orchestrator owns no credentials — it **borrows** them from the
    ``agent_identity`` passed at construction time.  Every
    :class:`ActionRequest` is injected with the agent's role, user-id and
    API key before being handed to the executor.

    Parameters
    ----------
    llm_handler:
        The :class:`LLMHandler` instance (provides ``call_llm_chat``).
    executor:
        The :class:`ExecutorRuntime` instance.
    agent_identity:
        Agent identity object (must expose ``.actor_role``, ``.actor_id``,
        ``.api_key``).
    capability_registry:
        The :class:`CapabilityRegistry` used to look up capability metadata
        (e.g. ``requires_approval``).
    max_rounds:
        Maximum number of LLM↔tool round-trips.
    total_timeout:
        Wall-clock time budget in seconds.
    max_tokens:
        Cumulative token budget across all rounds.
    """

    def __init__(
        self,
        llm_handler: LLMHandler,
        executor: ExecutorRuntime,
        agent_identity,
        capability_registry: CapabilityRegistry,
        *,
        max_rounds: int = 2,
        total_timeout: float = 60.0,
        max_tokens: int = 16384,
    ) -> None:
        self._llm = llm_handler
        self._executor = executor
        self._identity = agent_identity
        self._registry = capability_registry
        self.max_rounds = max_rounds
        self.total_timeout = total_timeout
        self.max_tokens = max_tokens

    @property
    def registry(self) -> CapabilityRegistry:
        """The capability registry used for tool-call resolution."""
        return self._registry

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(
        self,
        system_prompt: str,
        user_message: str,
        tools: List[Dict[str, Any]],
    ) -> OrchestratorResult:
        """Execute a ReAct loop.

        Parameters
        ----------
        system_prompt:
            System-level instructions for the LLM.
        user_message:
            The user / log-entry message to analyse.
        tools:
            Ollama tool schema list (from :func:`tool_schema.capabilities_to_tools`).

        Returns
        -------
        OrchestratorResult
        """
        messages: List[Dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ]

        result = OrchestratorResult()
        t0 = time.monotonic()

        for round_num in range(1, self.max_rounds + 1):
            # ---- Budget checks ----------------------------------------
            elapsed = time.monotonic() - t0
            if elapsed >= self.total_timeout:
                result.terminated_by = "timeout"
                logger.warning(
                    "Orchestrator: timeout after %.1fs (round %d).",
                    elapsed,
                    round_num,
                )
                break

            if result.total_tokens >= self.max_tokens:
                result.terminated_by = "token_budget"
                logger.warning(
                    "Orchestrator: token budget exhausted (%d tokens, round %d).",
                    result.total_tokens,
                    round_num,
                )
                break

            # ---- LLM call ---------------------------------------------
            try:
                response_msg = self._llm.call_llm_chat(messages, tools)
            except Exception as exc:
                logger.error("Orchestrator: LLM call failed in round %d: %s", round_num, exc)
                result.terminated_by = "error"
                break

            result.rounds = round_num

            # Track token usage — only count *output* (completion) tokens.
            # prompt tokens repeat the full context every round and
            # would cause false budget exhaustion in multi-round chats.
            metrics = response_msg.pop("_metrics", None)
            if metrics is not None:
                result.total_tokens += metrics.completion_tokens

            # ---- Check for tool calls ---------------------------------
            tool_calls = response_msg.get("tool_calls")
            content = response_msg.get("content", "")

            if not tool_calls:
                # Final answer — no more tool calls
                result.final_answer = content
                result.terminated_by = "final_answer"
                messages.append({"role": "assistant", "content": content})
                break

            # Record the assistant message with tool calls
            messages.append(response_msg)

            # ---- Execute each tool call -------------------------------
            for tc in tool_calls:
                tc_record = self._execute_tool_call(tc)
                result.tool_calls_made.append(tc_record)

                # Append tool result as observation for the LLM
                messages.append({
                    "role": "tool",
                    "content": tc_record["result"],
                })
        else:
            # Loop exhausted without break — max_rounds reached
            result.terminated_by = "max_rounds"
            logger.warning(
                "Orchestrator: max rounds (%d) reached.", self.max_rounds,
            )

        # If terminated without a final answer AND no tool calls were
        # made, attempt one forced call without tool schemas to coerce
        # the LLM into a text conclusion.  When tool calls exist, the
        # processor already handles the empty-answer case — burning an
        # extra LLM round would only slow things down.
        if not result.final_answer and result.terminated_by != "error" and not result.tool_calls_made:
            forced = self._force_final_answer(messages)
            if forced:
                result.final_answer = forced
                result.terminated_by = f"{result.terminated_by}+forced"

        # Last resort: extract any assistant content from the conversation.
        if not result.final_answer and messages:
            for msg in reversed(messages):
                if msg.get("role") == "assistant" and msg.get("content"):
                    result.final_answer = msg["content"]
                    break

        return result

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _force_final_answer(self, messages: List[Dict[str, Any]]) -> str:
        """Last-resort: request a final answer with no tool schemas.

        Appends a directive to the conversation copy and calls the LLM
        without any ``tools``, forcing it to produce a text response.
        Returns an empty string if the attempt fails.
        """
        try:
            summary_messages = list(messages)
            summary_messages.append({
                "role": "user",
                "content": (
                    "请立即给出你的最终分析结论，以要求的 JSON 格式输出。"
                    "不要调用任何工具。"
                ),
            })
            resp = self._llm.call_llm_chat(summary_messages, tools=None)
            content = resp.get("content", "")
            if content:
                logger.info(
                    "Orchestrator: forced final answer obtained (%d chars).",
                    len(content),
                )
            return content
        except Exception as exc:
            logger.warning(
                "Orchestrator: forced final-answer request failed: %s", exc,
            )
            return ""

    def _execute_tool_call(self, tool_call: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a single tool_call, dispatch via executor, return a record."""
        from .processor import _issue_dedup

        func = tool_call.get("function", {})
        cap_name = func.get("name", "")
        raw_args = func.get("arguments", {})

        # Ollama may return arguments as a JSON string in some versions
        if isinstance(raw_args, str):
            try:
                raw_args = json.loads(raw_args)
            except (json.JSONDecodeError, TypeError):
                raw_args = {}

        record: Dict[str, Any] = {
            "capability": cap_name,
            "params": raw_args,
            "status": "unknown",
            "result": "",
        }

        # Dedup guard for create_github_issue — prevent flood of similar issues.
        if cap_name == "create_github_issue":
            title = raw_args.get("title", "") if isinstance(raw_args, dict) else ""
            dedup_key = title[:120]
            if dedup_key and not _issue_dedup.check_and_add(dedup_key):
                logger.info("Issue dedup: suppressed duplicate agent issue — %s", dedup_key[:60])
                record["status"] = "skipped"
                record["result"] = "Issue suppressed: duplicate title within dedup window."
                return record

        # Check requires_approval (downgrade to issue)
        cap = self._registry.get(cap_name) if cap_name else None
        if cap is not None and getattr(cap, "requires_approval", False):
            record = self._downgrade_to_issue(cap_name, raw_args)
            return record

        # Build ActionRequest with injected credentials
        from .executor.models import ActionRequest

        req = ActionRequest(
            capability=cap_name,
            params=raw_args if isinstance(raw_args, dict) else {},
            actor_role=self._identity.actor_role if self._identity else "Agent",
            actor_id=self._identity.actor_id if self._identity else "orchestrator",
            api_key=self._identity.api_key if self._identity else "",
        )

        try:
            exec_result = self._executor.execute(req)
            record["status"] = exec_result.status.value
            detail = exec_result.detail or ""
            output = exec_result.output
            if output is not None:
                record["result"] = f"{detail}\nOutput: {json.dumps(output, ensure_ascii=False, default=str)}" if detail else json.dumps(output, ensure_ascii=False, default=str)
            else:
                record["result"] = detail or f"Capability '{cap_name}' executed with status {exec_result.status.value}."
        except Exception as exc:
            record["status"] = "error"
            record["result"] = f"Execution error: {exc}"
            logger.error("Orchestrator: tool execution error for '%s': %s", cap_name, exc)

        return record

    def _downgrade_to_issue(
        self,
        original_capability: str,
        original_params: Any,
    ) -> Dict[str, Any]:
        """Downgrade a ``requires_approval`` capability to an issue notification."""
        from .executor.models import ActionRequest

        title = f"[审批请求] Agent 请求执行: {original_capability}"
        body_parts = [
            f"**原始能力**: `{original_capability}`",
            f"**原始参数**:\n```json\n{json.dumps(original_params, indent=2, ensure_ascii=False, default=str)}\n```",
            "",
            "此操作需要人工审批。Agent 已将此请求转为 issue 通知。",
            "",
            "---",
            "*Auto-generated by Suricata AI Agent (requires_approval)*",
        ]

        req = ActionRequest(
            capability="create_github_issue",
            params={
                "title": title[:256],
                "body": "\n".join(body_parts),
                "labels": "requires-approval,agent-request",
            },
            actor_role=self._identity.actor_role if self._identity else "Agent",
            actor_id=self._identity.actor_id if self._identity else "orchestrator",
            api_key=self._identity.api_key if self._identity else "",
        )

        record: Dict[str, Any] = {
            "capability": original_capability,
            "params": original_params,
            "status": "downgraded",
            "result": "",
        }

        try:
            exec_result = self._executor.execute(req)
            record["status"] = f"downgraded_to_issue:{exec_result.status.value}"
            record["result"] = (
                f"操作 '{original_capability}' 需要人工审批，已自动转为 GitHub issue 通知管理员。"
                f" Issue 创建状态: {exec_result.status.value}."
            )
        except Exception as exc:
            record["status"] = "downgrade_failed"
            record["result"] = f"审批降级失败: {exc}"
            logger.error(
                "Orchestrator: failed to downgrade '%s' to issue: %s",
                original_capability,
                exc,
            )

        return record
