#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         processor.py
Description:  Log processor for batch processing and LLM-based threat assessment.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

import logging
import random
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from threading import Lock
from typing import List, Dict, Optional, TYPE_CHECKING

from .es_client import ESClient
from .llm_handler import LLMHandler
from .config import config

if TYPE_CHECKING:
    from .executor import ExecutorRuntime
    from .orchestrator import AgentOrchestrator

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Dedup cache for auto-issued GitHub issues (keyed by summary hash).
# Prevents the same high-threat event from spawning repeated issues within
# a sliding window.
# ---------------------------------------------------------------------------

class _IssueDedupCache:
    """Bounded LRU cache that tracks recently created issue titles."""

    def __init__(self, max_size: int = 200, ttl_seconds: int = 3600):
        self._max_size = max_size
        self._ttl = ttl_seconds
        self._lock = Lock()
        self._cache: OrderedDict[str, float] = OrderedDict()

    def check_and_add(self, key: str) -> bool:
        """Return True if the key is new (not a duplicate)."""
        now = time.monotonic()
        with self._lock:
            # Prune expired entries
            expired = [k for k, ts in self._cache.items() if now - ts > self._ttl]
            for k in expired:
                del self._cache[k]
            if key in self._cache:
                return False
            if len(self._cache) >= self._max_size:
                self._cache.popitem(last=False)
            self._cache[key] = now
            return True


_issue_dedup = _IssueDedupCache()


class LogProcessor:
    def __init__(
        self,
        es_client: ESClient | None = None,
        executor: Optional['ExecutorRuntime'] = None,
        llm_handler: Optional[LLMHandler] = None,
        orchestrator: Optional['AgentOrchestrator'] = None,
    ):
        self.es_client = es_client or ESClient()
        self.llm_handler = llm_handler or LLMHandler()
        self._executor = executor
        self._orchestrator = orchestrator
        self.stats = {
            "processed": 0,
            "failed": 0,
            "last_run": None
        }

    @property
    def _agent_identity(self):
        """Delegate to the LLMHandler's identity."""
        return self.llm_handler.agent_identity

    @property
    def executor(self) -> Optional['ExecutorRuntime']:
        return self._executor

    @executor.setter
    def executor(self, value: Optional['ExecutorRuntime']) -> None:
        self._executor = value

    def _build_update(self, log: Dict, processed_at: int) -> Optional[Dict]:
        # Dual-mode: Agent mode (orchestrator-driven) vs Pipeline mode (legacy)
        if self._orchestrator is not None and self.llm_handler.supports_tool_use:
            return self._build_update_agent(log, processed_at)
        return self._build_update_pipeline(log, processed_at)

    def _build_update_agent(self, log: Dict, processed_at: int) -> Optional[Dict]:
        """Agent mode: LLM decides actions via tool calls."""
        from .llm_prompt import build_agent_system_prompt, build_agent_user_message
        from .tool_schema import capabilities_to_tools

        source = log.get("_source", {})
        src_ip = source.get("src_ip", "")
        dest_ip = source.get("dest_ip", "")
        src_hostname = source.get("src_hostname", "")
        dest_hostname = source.get("dest_hostname", "")
        event_type = source.get("event_type", "")
        app_proto = source.get("app_proto", "")
        src_id = (src_hostname or "").strip() or (src_ip or "").strip()
        dest_id = (dest_hostname or "").strip() or (dest_ip or "").strip()
        memory_summaries = self.llm_handler.get_memory_snapshot(
            src_id,
            dest_id,
            app_proto=app_proto,
            event_type=event_type,
        )

        system_prompt = build_agent_system_prompt()
        memory_scope_label = (
            "该通信对中同 Event_Z"
            if getattr(self.llm_handler, "_memory_mode", "")
            in ("proto_pair", "proto_pair_rolling")
            else "该通信对"
        )
        user_message = build_agent_user_message(
            source,
            memory_summaries=memory_summaries,
            doc_id=log['_id'],
            memory_scope_label=memory_scope_label,
        )

        # Noise-flagged logs must never trigger tool calls.
        # Pass empty tools list to hardware-block issue creation.
        is_noise = 'noise' in source
        if is_noise:
            tools = []
        else:
            tools = capabilities_to_tools(
                self._orchestrator.registry,
                actor_role="Agent",
                include_names={"create_github_issue"},
            )

        try:
            orch_result = self._orchestrator.run(system_prompt, user_message, tools)
        except Exception as exc:
            logger.error("Orchestrator failed for doc ID %s: %s, falling back to pipeline.", log['_id'], exc)
            return self._build_update_pipeline(log, processed_at)

        ai_advice = orch_result.final_answer
        if not ai_advice:
            if orch_result.tool_calls_made:
                # Agent already executed tool calls (e.g. created issues).
                # Do NOT fall back to pipeline — that would create
                # duplicate actions.  Log the gap and skip this entry.
                logger.info(
                    "Agent mode returned empty analysis for doc ID %s "
                    "but made %d tool call(s) (terminated_by=%s); "
                    "skipping pipeline fallback to avoid duplicate actions.",
                    log['_id'], len(orch_result.tool_calls_made),
                    orch_result.terminated_by,
                )
                return None
            logger.warning(
                "Agent mode returned empty result for doc ID %s "
                "(terminated_by=%s, no tool calls), falling back to pipeline.",
                log['_id'], orch_result.terminated_by,
            )
            return self._build_update_pipeline(log, processed_at)

        parsed = self.llm_handler.parse_json_sections(ai_advice)

        # --- Escalation processing ---
        escalated = self._maybe_escalate(log, parsed, ai_advice) if parsed else None
        if escalated is not None:
            logger.info(
                "Escalated doc %s (agent mode) from %s → %s (model: %s)",
                log['_id'],
                escalated.get("escalated_from", "?"),
                escalated.get("threat_level", "?"),
                config.ESCALATION_MODEL,
            )
            ai_advice = escalated.pop("_escalation_advice", ai_advice)
            parsed = escalated

        # Note: agent mode does NOT call _maybe_create_issue() here because
        # issue creation is handled by the orchestrator via tool calls
        # (create_github_issue capability).  Calling it here would risk
        # duplicate issues.

        # Update memory
        summary = parsed.get("summary") if parsed else None
        if summary:
            event_ts = source.get("@timestamp")
            self.llm_handler.update_summary_memory(
                summary,
                event_timestamp=event_ts,
                src_ip=src_ip,
                dest_ip=dest_ip,
                src_hostname=src_hostname,
                dest_hostname=dest_hostname,
                event_type=event_type,
                app_proto=app_proto,
            )

        return {
            '_index': log['_index'],
            '_id': log['_id'],
            'ai_advice': ai_advice,
            'ai_processed_at': processed_at,
            'ai_fields': parsed,
        }

    def _build_update_pipeline(self, log: Dict, processed_at: int) -> Optional[Dict]:
        """Pipeline mode (legacy): hardcoded threshold decisions."""
        ai_advice = self.llm_handler.generate_advice(log['_source'])

        if not ai_advice:
            logger.warning("LLM returned empty advice for doc ID %s", log['_id'])
            return None

        logger.debug("Generating advice for doc ID %s: %s...", log['_id'], ai_advice[:100])

        parsed = self.llm_handler.parse_json_sections(ai_advice)

        # --- Escalation processing ---
        escalated = self._maybe_escalate(log, parsed, ai_advice) if parsed else None
        if escalated is not None:
            logger.info(
                "Escalated doc %s from %s → %s (model: %s)",
                log['_id'],
                escalated.get("escalated_from", "?"),
                escalated.get("threat_level", "?"),
                config.ESCALATION_MODEL,
            )
            ai_advice = escalated.pop("_escalation_advice", ai_advice)
            parsed = escalated

        summary = parsed.get("summary") if parsed else None
        if summary:
            event_ts = log.get("_source", {}).get("@timestamp")
            src_ip = log.get("_source", {}).get("src_ip", "")
            dest_ip = log.get("_source", {}).get("dest_ip", "")
            src_hostname = log.get("_source", {}).get("src_hostname", "")
            dest_hostname = log.get("_source", {}).get("dest_hostname", "")
            event_type = log.get("_source", {}).get("event_type", "")
            app_proto = log.get("_source", {}).get("app_proto", "")
            self.llm_handler.update_summary_memory(
                summary,
                event_timestamp=event_ts,
                src_ip=src_ip,
                dest_ip=dest_ip,
                src_hostname=src_hostname,
                dest_hostname=dest_hostname,
                event_type=event_type,
                app_proto=app_proto,
            )

        # Trigger auto-issue for high-threat events
        if parsed:
            self._maybe_create_issue(log, parsed)

        return {
            '_index': log['_index'],
            '_id': log['_id'],
            'ai_advice': ai_advice,
            'ai_processed_at': processed_at,
            'ai_fields': parsed,
        }

    # ------------------------------------------------------------------
    # Escalation: re-analyze with a higher-capability model
    # ------------------------------------------------------------------

    _THREAT_ORDER = {"无危": 0, "低": 1, "中": 2, "高": 3, "严重": 4}

    def _maybe_escalate(
        self,
        log: Dict,
        parsed: Dict[str, str],
        ai_advice: str,
    ) -> Optional[Dict[str, str]]:
        """If the initial threat assessment meets or exceeds the escalation
        threshold, invoke a more capable model for deeper analysis.

        Returns the escalated parsed dict (with ``escalated`` / ``escalated_from``
        / ``escalated_model`` keys) or *None* if escalation is not triggered.
        """
        if not config.ESCALATION_ENABLED:
            return None
        if not config.ESCALATION_MODEL:
            return None

        threat_level = parsed.get("threat_level", "")
        threshold = config.ESCALATION_THREAT_THRESHOLD
        if self._THREAT_ORDER.get(threat_level, 0) < self._THREAT_ORDER.get(threshold, 2):
            return None

        # Gather communication-pair history
        source = log.get("_source", {})
        src_id = (source.get("src_hostname") or source.get("src_ip", "")).strip()
        dest_id = (source.get("dest_hostname") or source.get("dest_ip", "")).strip()
        memory_summaries = self.llm_handler.get_memory_snapshot(
            src_id,
            dest_id,
            app_proto=source.get("app_proto", ""),
            event_type=source.get("event_type", ""),
        )

        from .llm_prompt import build_escalation_prompt
        escalation_prompt = build_escalation_prompt(
            source=source,
            initial_analysis=ai_advice,
            memory_summaries=memory_summaries,
            include_raw_fields=config.ESCALATION_INCLUDE_RAW_FIELDS,
        )

        # Resolve backend for escalation model
        profile = config.MODEL_PROFILES.get(config.ESCALATION_MODEL)
        if profile is None:
            logger.warning(
                "Escalation model '%s' not found in MODEL_PROFILES; skipping escalation.",
                config.ESCALATION_MODEL,
            )
            return None

        backend = self.llm_handler.get_backend_for_model(config.ESCALATION_MODEL)

        try:
            result = backend.generate(
                model=config.ESCALATION_MODEL,
                prompt=escalation_prompt,
                max_tokens=config.ESCALATION_MAX_TOKENS,
                context_length=config.ESCALATION_CONTEXT_LENGTH,
                temperature=config.ESCALATION_TEMPERATURE,
                top_p=config.ESCALATION_TOP_P,
                top_k=config.ESCALATION_TOP_K,
            )
        except Exception as exc:
            logger.error("Escalation LLM call failed: %s — keeping initial analysis.", exc)
            return None

        self.llm_handler.record_metrics(result.metrics)

        cleaned = LLMHandler._strip_think(result.text)
        if not cleaned:
            return None

        escalated_parsed = self.llm_handler.parse_json_sections(cleaned)
        if escalated_parsed:
            escalated_parsed["escalated"] = True
            escalated_parsed["escalated_from"] = threat_level
            escalated_parsed["escalated_model"] = config.ESCALATION_MODEL
            escalated_parsed["_escalation_advice"] = cleaned
        return escalated_parsed if escalated_parsed else None

    # ------------------------------------------------------------------
    # Auto-issue: create GitHub issue for high-threat events
    # ------------------------------------------------------------------

    def _maybe_create_issue(self, log: Dict, parsed: Dict[str, str]) -> None:
        """If the event is high-threat and git integration is enabled,
        create a GitHub issue via the executor."""
        if not config.GIT_ENABLED or not config.GIT_AUTO_ISSUE:
            return
        if self._executor is None:
            return

        threat_level = parsed.get("threat_level", "")
        threshold = config.GIT_ISSUE_THREAT_THRESHOLD
        # Check if the threat level meets or exceeds the threshold
        level_order = {"无危": 0, "低": 1, "中": 2, "高": 3, "严重": 4}
        if level_order.get(threat_level, 0) < level_order.get(threshold, 3):
            return

        summary = parsed.get("summary", "")
        if not summary:
            return

        # Dedup check
        dedup_key = summary[:120]
        if not _issue_dedup.check_and_add(dedup_key):
            logger.debug("Issue dedup: skipping repeated alert — %s", dedup_key[:60])
            return

        doc_id = log.get("_id", "")
        index_name = log.get("_index", "")
        source = log.get("_source", {})
        src_host = source.get("src_hostname", "") or source.get("src_ip", "")
        dest_host = source.get("dest_hostname", "") or source.get("dest_ip", "")
        event_type = source.get("event_type", "")
        timestamp = source.get("@timestamp", "")
        alert_info = source.get("alert", {})
        signature = alert_info.get("signature", "") if isinstance(alert_info, dict) else ""
        signature_id = alert_info.get("signature_id", "") if isinstance(alert_info, dict) else ""

        title = f"[{threat_level}] {src_host} → {dest_host} ({event_type})"
        body_parts = [
            f"**威胁等级**: {threat_level}",
            f"**时间**: {timestamp}",
            f"**通信对**: {src_host} → {dest_host}",
            f"**事件类型**: {event_type}",
        ]
        if doc_id:
            body_parts.append(f"**事件 ID**: `{doc_id}`")
        if index_name:
            body_parts.append(f"**索引**: `{index_name}`")
        if signature:
            sig_text = f"{signature} (SID: {signature_id})" if signature_id else signature
            body_parts.append(f"**告警规则**: {sig_text}")
        body_parts.extend([
            "",
            f"**摘要**: {summary}",
        ])
        hint = parsed.get("security_hint", "")
        if hint:
            body_parts.append(f"\n**安全提示**: {hint}")
        recommendation = parsed.get("recommendation", "")
        if recommendation:
            body_parts.append(f"\n**建议措施**: {recommendation}")
        body_parts.append(f"\n---\n*Auto-generated by Suricata AI Agent*")

        from .executor.models import ActionRequest
        req = ActionRequest(
            capability="create_github_issue",
            params={
                "title": title[:256],
                "body": "\n".join(body_parts),
                "labels": f"auto-alert,{threat_level}",
            },
            actor_role=self._agent_identity.actor_role if self._agent_identity else "Agent",
            actor_id=self._agent_identity.actor_id if self._agent_identity else "llm",
            api_key=self._agent_identity.api_key if self._agent_identity else "",
        )
        try:
            result = self._executor.execute(req)
            if result.status.value == "success":
                logger.info("Auto-created issue for %s: %s", threat_level, title[:80])
            else:
                logger.warning("Auto-issue creation returned %s: %s", result.status.value, result.detail)
        except Exception as exc:
            logger.error("Auto-issue creation failed: %s", exc)

    def process_batch(self, index: str | None = None) -> Dict:
        """
        Process a batch of unprocessed log entries.

        Returns:
            Dict: Statistics of the processing run.
        """
        if config.daily_report_active:
            logger.debug("Daily report generation in progress — skipping batch.")
            return {"processed": 0, "failed": 0, "fetched": 0, "duration": 0.0, "backlog": 0, "llm_metrics": []}

        if index is None:
            index = config.get_today_index()

        logger.info(f"Starting batch processing for index: {index}")

        # Step 1: Extract unprocessed logs
        start_time = time.monotonic()
        logs_to_process = list(self.es_client.get_unprocessed_docs(index, config.CURRENT_PERF_CONFIG.BATCH_SIZE))
        fetched = len(logs_to_process)
        total_unprocessed = None
        try:
            total_unprocessed = self.es_client.count_unprocessed_docs(index)
        except Exception as e:
            logger.warning("Failed to count unprocessed docs: %s", e)

        if not logs_to_process:
            logger.debug("No unprocessed logs found.")
            backlog = max(0, (total_unprocessed or 0) - fetched)
            return {"processed": 0, "failed": 0, "fetched": 0, "duration": 0.0, "backlog": backlog, "llm_metrics": []}

        logger.info(f"Fetched {len(logs_to_process)} unprocessed logs.")

        # Step 2: Generate advice for each log using LLM
        updates = []
        current_time = int(datetime.now(timezone.utc).timestamp() * 1000)
        failed_llm = 0
        if config.CURRENT_PERF_CONFIG is None:
            raise RuntimeError("CURRENT_PERF_CONFIG is not set.")

        max_workers = max(1, min(config.CURRENT_PERF_CONFIG.LLM_CONCURRENCY, len(logs_to_process)))

        if max_workers > 1:
            logger.info("Using LLM concurrency: %s", max_workers)
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_map = {
                    executor.submit(self._build_update, log, current_time): log
                    for log in logs_to_process
                }

                for future in as_completed(future_map):
                    log = future_map[future]
                    try:
                        update = future.result()
                    except Exception as e:
                        logger.error("LLM processing failed for doc ID %s: %s", log['_id'], e)
                        failed_llm += 1
                        continue

                    if update:
                        updates.append(update)
        else:
            for log in logs_to_process:
                try:
                    update = self._build_update(log, current_time)
                    if update:
                        updates.append(update)
                except Exception as e:
                    logger.error("LLM processing failed for doc ID %s: %s", log['_id'], e)
                    failed_llm += 1

        if failed_llm:
            self.stats["failed"] += failed_llm

        # Step 3: Bulk update to Elasticsearch
        if updates:
            result = self.es_client.bulk_update_ai_advice(updates)
            self.stats['processed'] += result['success']
            self.stats['failed'] += result['failed']
            self.stats['last_run'] = datetime.now(timezone.utc).isoformat()

            duration = time.monotonic() - start_time
            logger.info(f"Batch processing completed. Processed: {self.stats['processed']}, Failed: {self.stats['failed']}")

            # Step 4: Output a random processed doc for verification
            if updates:
                sample = random.choice(updates)
                logger.info(
                    "Sample processed doc for verification: "
                    "GET %s/%s/_doc/%s?_source_includes=ai",
                    config.ES_HOST,
                    sample["_index"],
                    sample["_id"],
                )

            backlog = max(0, (total_unprocessed or 0) - result.get("success", 0))
            llm_metrics = self.llm_handler.drain_batch_metrics()
            return {
                "processed": result["success"],
                "failed": result["failed"],
                "fetched": fetched,
                "duration": duration,
                "backlog": backlog,
                "llm_metrics": llm_metrics,
            }
        
        duration = time.monotonic() - start_time
        backlog = max(0, (total_unprocessed or 0) - 0)
        llm_metrics = self.llm_handler.drain_batch_metrics()
        return {"processed": 0, "failed": 0, "fetched": fetched, "duration": duration, "backlog": backlog, "llm_metrics": llm_metrics}

    
    def process_all_today(self) -> Dict:
        """
        Process all unprocessed logs in today's index.
        """
        total_processed = 0
        total_failed = 0
        
        index = config.get_today_index()
        
        while True:
            result = self.process_batch(index)
            
            if result['processed'] == 0 and result['failed'] == 0:
                break
                
            total_processed += result['processed']
            total_failed += result['failed']
        
        self.stats['last_run'] = datetime.now(timezone.utc).isoformat()
        
        return {
            "processed": total_processed,
            "failed": total_failed,
            "index": index
        }

    def get_stats(self) -> Dict:
        """
        Get processing statistics.
        """
        return self.stats.copy()
