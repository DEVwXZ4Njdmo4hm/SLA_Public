#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         main.py
Description:  Main entry point and event loop orchestrator for real-time log analysis.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

import time
import signal
import sys
import logging
import threading
from collections import deque
from typing import Deque, Dict, List, Tuple
from datetime import datetime, timezone

from .processor import LogProcessor
from .es_client import ESClient
from .config import config
from .llm_backend import LLMMetrics
from .perf_cacl import perf_index_predict, record_token_stats, adaptive_select, _perf_config_changed
from .rmi import RemoteCommandQueue, apply_remote_commands, start_rmi_server
from .logging_utils import setup_logging, emit_stats_snapshot, shutdown_logging
from .llm_handler import LLMHandler, stop_ollama_model
from .daily_report import DailyReportService
from .mailer import send_email, start_mail_queue, stop_mail_queue, get_recipients_for_event, init_mail_recipients
from .auth.database import UserDB
from .auth.log_broadcast import LogBroadcaster, BroadcastLogHandler
from .executor import build_executor, ExecutorRuntime

setup_logging()
logger = logging.getLogger(__name__)

class StatsWindow:
    def __init__(self, windows: Tuple[int, ...] = (300, 900, 3600)) -> None:
        self._windows = windows
        self._max_window = max(self._windows)
        self._lock = threading.Lock()
        self._events: Deque[Tuple[float, int, int]] = deque()

    def tick(self, processed: int, failed: int) -> None:
        now = time.time()
        with self._lock:
            if processed or failed:
                self._events.append((now, processed, failed))
            self._prune(now)

    def snapshot(self) -> Dict[str, int]:
        now = time.time()
        with self._lock:
            self._prune(now)
            sums = {window: {"processed": 0, "failed": 0} for window in self._windows}
            for ts, processed, failed in self._events:
                age = now - ts
                for window in self._windows:
                    if age <= window:
                        sums[window]["processed"] += processed
                        sums[window]["failed"] += failed

        payload: Dict[str, int] = {}
        for window in self._windows:
            minutes = int(window / 60)
            processed_count = sums[window]["processed"]
            failed_count = sums[window]["failed"]
            payload[f"{minutes}min_processed"] = processed_count
            payload[f"{minutes}min_failed"] = failed_count
            payload[f"{minutes}min_total"] = processed_count + failed_count
        return payload

    def _prune(self, now: float) -> None:
        cutoff = now - self._max_window
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()

class TokenStatsWindow:
    """Sliding time-window tracker for LLM token consumption.

    Maintains {1, 5, 30} minute and {1, 6, 24} hour windows plus
    cumulative totals for prompt / completion tokens.
    """

    WINDOWS: Tuple[int, ...] = (60, 300, 1800, 3600, 21600, 86400)
    _WINDOW_LABELS: Dict[int, str] = {
        60: "1min",
        300: "5min",
        1800: "30min",
        3600: "1h",
        21600: "6h",
        86400: "24h",
    }

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._max_window = max(self.WINDOWS)
        # (timestamp, prompt_tokens, completion_tokens)
        self._events: Deque[Tuple[float, int, int]] = deque()
        self._total_prompt: int = 0
        self._total_completion: int = 0

    def record(self, metrics_batch: List[LLMMetrics]) -> None:
        """Record a batch of LLM metrics."""
        if not metrics_batch:
            return
        now = time.time()
        prompt_sum = sum(m.prompt_tokens for m in metrics_batch)
        completion_sum = sum(m.completion_tokens for m in metrics_batch)
        with self._lock:
            if prompt_sum or completion_sum:
                self._events.append((now, prompt_sum, completion_sum))
                self._total_prompt += prompt_sum
                self._total_completion += completion_sum
            self._prune(now)

    def snapshot(self) -> Dict[str, int]:
        now = time.time()
        with self._lock:
            self._prune(now)
            sums = {w: [0, 0] for w in self.WINDOWS}  # [prompt, completion]
            for ts, pt, ct in self._events:
                age = now - ts
                for w in self.WINDOWS:
                    if age <= w:
                        sums[w][0] += pt
                        sums[w][1] += ct

            payload: Dict[str, int] = {
                "token_total_prompt": self._total_prompt,
                "token_total_completion": self._total_completion,
                "token_total": self._total_prompt + self._total_completion,
            }

        for w in self.WINDOWS:
            label = self._WINDOW_LABELS[w]
            pt, ct = sums[w]
            payload[f"{label}_prompt_tokens"] = pt
            payload[f"{label}_completion_tokens"] = ct
            payload[f"{label}_total_tokens"] = pt + ct

        return payload

    def _prune(self, now: float) -> None:
        cutoff = now - self._max_window
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()


class GracefulShutdown:
    def __init__(self):
        self._stop_event = threading.Event()
        signal.signal(signal.SIGINT, self.request_shutdown)
        signal.signal(signal.SIGTERM, self.request_shutdown)

    @property
    def shutdown_requested(self) -> bool:
        return self._stop_event.is_set()

    def request_shutdown(self, *args):
        logger.info("Shutdown signal received.")
        self._stop_event.set()

    def wait(self, timeout: float) -> None:
        """Sleep for up to *timeout* seconds, returning immediately when shutdown is requested."""
        self._stop_event.wait(timeout)

def wait_for_elasticsearch(es_client: ESClient, max_retries: int = config.MAX_RETRIES, wait_interval: int = config.RETRY_INTERVAL):
    for i in range(max_retries):
        if es_client.health_check():
            logger.info("Connected to Elasticsearch successfully.")
            return True
        else:
            logger.warning(f"Elasticsearch not reachable. Retry {i + 1}/{max_retries} in {wait_interval} seconds.")
            time.sleep(wait_interval)
    
    logger.error("Failed to connect to Elasticsearch after maximum retries.")
    return False


# ── Mail notification helpers ────────────────────────────────────────────────
def _build_notification_html(title: str, lines: list[str]) -> str:
    """Wrap plain-text lines into an HTML email with monospace font."""
    from html import escape

    body_lines = "\n".join(escape(l) for l in lines)
    return (
        '<!doctype html><html lang="zh"><head><meta charset="utf-8"/>'
        f"<title>{escape(title)}</title></head><body>"
        '<pre style="font-family:Consolas,\'Courier New\',monospace;'
        'font-size:13px;line-height:1.5;color:#1f2937;'
        'background:#f8fafc;padding:16px;border-radius:6px;'
        'overflow-x:auto;white-space:pre-wrap;word-break:break-all;">'
        f"\n{body_lines}\n</pre></body></html>"
    )


def _init_git_workspace(executor: ExecutorRuntime, agent_identity=None) -> None:
    """Clone the configured git repo if the local workspace doesn't exist yet.

    Uses the *agent_identity* owned by LLMHandler (borrowed, not revoked here).
    """
    import os
    from .executor.models import ActionRequest, ActionStatus
    repo_path = config.GIT_LOCAL_REPO_PATH
    if os.path.isdir(os.path.join(repo_path, ".git")):
        logger.info("Git workspace already exists at %s.", repo_path)
        return

    logger.info("Cloning git repo to %s ...", repo_path)
    req = ActionRequest(
        capability="git_clone_repo",
        params={},
        actor_role=agent_identity.actor_role if agent_identity else "Agent",
        actor_id=agent_identity.actor_id if agent_identity else "startup",
        api_key=agent_identity.api_key if agent_identity else "",
    )
    res = executor.execute(req)
    if res.status == ActionStatus.SUCCESS:
        logger.info("Git workspace initialised: %s", res.detail)
    else:
        logger.error("Git workspace clone failed: %s", res.detail)


def _scheduled_git_reset(executor: ExecutorRuntime, agent_identity=None) -> None:
    """Daily scheduled git workspace reset — discard local changes and pull.

    Uses the *agent_identity* owned by LLMHandler (borrowed, not revoked here).
    """
    from .executor.models import ActionRequest, ActionStatus

    logger.info("Scheduled daily git workspace reset.")
    req = ActionRequest(
        capability="git_repo_reset",
        params={},
        actor_role=agent_identity.actor_role if agent_identity else "Agent",
        actor_id=agent_identity.actor_id if agent_identity else "scheduler",
        api_key=agent_identity.api_key if agent_identity else "",
    )
    try:
        res = executor.execute(req)
        if res.status == ActionStatus.SUCCESS:
            logger.info("Scheduled git reset succeeded: %s", res.detail)
        else:
            logger.warning("Scheduled git reset failed: %s", res.detail)
    except Exception as exc:
        logger.error("Scheduled git reset error: %s", exc)


def _send_notification_mail(subject: str, lines: list[str]) -> None:
    """Send a startup / shutdown notification email if enabled."""
    if not config.ENABLE_MAIL_NOTIFICATION:
        return
    try:
        recipients = get_recipients_for_event("startup_shutdown") or None
        html_body = _build_notification_html(subject, lines)
        ok = send_email(subject, html_body, recipients=recipients)
        if ok:
            logger.info("Notification email sent: %s", subject)
        else:
            logger.warning("Notification email failed (send_email returned False): %s", subject)
    except Exception as exc:
        logger.warning("Failed to send notification email '%s': %s", subject, exc)


def main():
    def format_list(values):
        if not values:
            return "(none)"
        return ", ".join(values)

    header_line = "=" * 120
    body_lines = [
        f"Starting {config.SOFTWARE_NAME} {config.SOFTWARE_NAME_SUFFIX}",
        f"Version: {config.SOFTWARE_VERSION}",
        f"Author: {config.SOFTWARE_AUTHOR}",
        f"License: {config.SOFTWARE_LICENSE}",
        "Configuration Summary:",
        "  ES:",
        f"    Host: {config.ES_HOST}",
        f"    Index Pattern: {config.ES_INDEX_PATTERN}",
        "  Processing:",
        f"    Batch Size: {config.CURRENT_PERF_CONFIG.BATCH_SIZE}",
        f"    Poll Interval: {config.CURRENT_PERF_CONFIG.POLL_INTERVAL} seconds",
        f"    Max Retries: {config.MAX_RETRIES}",
        f"    Retry Interval: {config.RETRY_INTERVAL} seconds",
        f"    Empty Runs Before Index Refresh: {config.EMPTY_RUNS_BEFORE_INDEX_REFRESH}",
        "  Filters:",
        f"    Supported Event Types: {format_list(config.SUPPORTED_EVENT_TYPES)}",
        f"    Allowed Event Types: {format_list(config.ALLOWED_EVENT_TYPE)}",
        f"    Supported L7 Protocols: {format_list(config.SUPPORTED_L7_PROTOCOLS)}",
        f"    Allowed L7 Protocols: {format_list(config.ALLOWED_L7_PROTOCOL)}",
        f"    Supported L4 Protocols: {format_list(config.SUPPORTED_L4_PROTOCOLS)}",
        f"    Allowed L4 Protocols: {format_list(config.ALLOWED_L4_PROTOCOL)}",
        f"    Supported L3 Protocols: {format_list(config.SUPPORTED_L3_PROTOCOLS)}",
        f"    Allowed L3 Protocols: {format_list(config.ALLOWED_L3_PROTOCOL)}",
        f"    Min Alert Severity: {config.AI_AGENT_MINIMAL_ALERT_SEVERITY}",
        f"    DNS RCODE Filter: {format_list(config.AI_AGENT_DNS_RCODES)}",
        f"    DNS RRType Filter: {format_list(config.AI_AGENT_DNS_RRTYPES)}",
        f"    HTTP Status Min: {config.AI_AGENT_HTTP_STATUS_MIN if config.AI_AGENT_HTTP_STATUS_MIN is not None else 'None'}",
        f"    HTTP Methods: {format_list(config.AI_AGENT_HTTP_METHODS)}",
        f"    TLS Versions: {format_list(config.AI_AGENT_TLS_VERSIONS)}",
        f"    TLS Require SNI: {'Yes' if config.AI_AGENT_TLS_REQUIRE_SNI else 'No'}",
        "  LLM:",
        f"    Backend: {config.LLM_BACKEND_TYPE}",
        f"    Base URL: {config.LLM_BACKEND_BASE_URL or config.OLLAMA_BASE_URL}",
        (
            f"    Model: {config.CURRENT_PERF_CONFIG.OLLAMA_MODEL}"
            if config.CURRENT_PERF_CONFIG
            else "    Model: N/A"
        ),
        f"    Memory Max Pairs: {config.LLM_MEMORY_MAX_PAIRS}",
        f"    Memory Per Pair: {config.LLM_MEMORY_PER_PAIR_LEN}",
        (
            f"    Concurrency: {config.CURRENT_PERF_CONFIG.LLM_CONCURRENCY}"
            if config.CURRENT_PERF_CONFIG
            else "    Concurrency: N/A"
        ),
        (
            f"    Num Predict: {config.CURRENT_PERF_CONFIG.OLLAMA_NUM_PREDICT}"
            if config.CURRENT_PERF_CONFIG
            else "    Num Predict: N/A"
        ),
        (
            f"    Temperature: {config.CURRENT_PERF_CONFIG.OLLAMA_TEMPERATURE}"
            if config.CURRENT_PERF_CONFIG
            else "    Temperature: N/A"
        ),
        (
            f"    Top P: {config.CURRENT_PERF_CONFIG.OLLAMA_TOP_P}"
            if config.CURRENT_PERF_CONFIG
            else "    Top P: N/A"
        ),
        (
            f"    Top K: {config.CURRENT_PERF_CONFIG.OLLAMA_TOP_K}"
            if config.CURRENT_PERF_CONFIG
            else "    Top K: N/A"
        ),
        "  RMI:",
        f"    Enabled: {'Yes' if config.RMI_ENABLED else 'No'}",
        f"    Bind: {f'{config.RMI_HOST}:{config.RMI_PORT}' if config.RMI_ENABLED else 'N/A'}",
    ]

    logger.info(header_line)
    logger.info("\n".join(body_lines))
    logger.info(header_line)

    # --- Auth subsystem (must precede mail so recipients can be resolved) --
    user_db = None
    log_broadcaster = None
    jwt_secret = config.AUTH_JWT_SECRET

    if config.AUTH_DB_PATH:
        user_db = UserDB(config.AUTH_DB_PATH)
        init_mail_recipients(user_db)
        if not user_db.has_owner():
            logger.warning(
                "认证数据库中无 Owner 用户。"
                "请通过部署脚本初始化数据库，或手动创建 Owner。"
            )
        logger.info("Auth subsystem initialised (db=%s).", config.AUTH_DB_PATH)

    # --- Executor subsystem ------------------------------------------------
    executor: ExecutorRuntime | None = None
    if config.EXECUTOR_ENABLED:
        executor = build_executor(
            capabilities_dir=config.EXECUTOR_CAPABILITIES_DIR,
            audit_db_path=config.EXECUTOR_AUDIT_DB_PATH,
            sandbox_root=config.EXECUTOR_SANDBOX_ROOT or config.GIT_LOCAL_REPO_PATH or None,
            dry_run=config.EXECUTOR_DRY_RUN,
            user_db=user_db,
            path_vars={
                "repo_dir": config.GIT_LOCAL_REPO_PATH,
                "rules_path": config.GIT_RULES_PATH,
            },
        )
        logger.info(
            "Executor subsystem initialised (dry_run=%s, capabilities=%d, uap=%s).",
            executor.dry_run,
            len(executor.registry),
            "enabled" if user_db else "disabled",
        )

    # --- LLM handler (sole owner of Agent credentials) --------------------
    llm_handler = LLMHandler(user_db=user_db)
    agent_identity = llm_handler.agent_identity

    # --- Agent orchestrator (tool-calling mode) ---------------------------
    orchestrator = None
    agent_mode = False
    if executor is not None and agent_identity is not None:
        if config.EXECUTOR_DISABLE_AGENT_MODE:
            logger.info(
                "Agent mode MANUALLY DISABLED via disable_agent_mode; using pipeline mode.",
            )
            _send_notification_mail(
                f"{config.SOFTWARE_NAME} — Agent 模式已手动禁用",
                [
                    "配置项 [executor] disable_agent_mode = true，Agent 模式已被管理员手动禁用。",
                    "系统将以传统 Pipeline 模式运行（基于阈值的自动 Issue 创建）。",
                    "如需恢复 Agent 模式，请将 disable_agent_mode 设为 false 并重启服务。",
                ],
            )
        elif llm_handler.supports_tool_use:
            from .orchestrator import AgentOrchestrator
            orchestrator = AgentOrchestrator(
                llm_handler=llm_handler,
                executor=executor,
                agent_identity=agent_identity,
                capability_registry=executor.registry,
            )
            agent_mode = True
            logger.info(
                "Agent mode ENABLED — model '%s' supports tool calling.",
                config.CURRENT_PERF_CONFIG.OLLAMA_MODEL if config.CURRENT_PERF_CONFIG else "N/A",
            )
        else:
            logger.info(
                "Agent mode DISABLED — model '%s' does not support tool calling; using pipeline mode.",
                config.CURRENT_PERF_CONFIG.OLLAMA_MODEL if config.CURRENT_PERF_CONFIG else "N/A",
            )
            _send_notification_mail(
                f"{config.SOFTWARE_NAME} — Pipeline 模式通知",
                [
                    f"当前模型 ({config.CURRENT_PERF_CONFIG.OLLAMA_MODEL if config.CURRENT_PERF_CONFIG else 'N/A'}) 不支持 tool calling。",
                    "系统将以传统 Pipeline 模式运行。",
                    "如需 Agent 模式，请切换到支持 tool-use 的模型，或在 ModelProfiles.toml 中设置 supports_tool_use = true。",
                ],
            )

    # --- Git workspace initialisation --------------------------------------
    if config.GIT_ENABLED and executor is not None:
        _init_git_workspace(executor, agent_identity=agent_identity)

    # Send startup notification email
    now = datetime.now()
    now_utc = datetime.now(timezone.utc)
    ts_lines = [
        f"Timestamp (UNIX): {int(now.timestamp())}",
        f"Timestamp (UTC):  {now_utc.strftime('%H:%M:%S %m/%d/%Y')}",
        f"Agent Mode: {'ENABLED' if agent_mode else 'DISABLED (pipeline fallback)'}",
    ]
    _send_notification_mail(
        f"{config.SOFTWARE_NAME} 启动通知",
        [header_line] + body_lines + [""] + ts_lines + [header_line],
    )

    # Start mail queue for spool-based retry on send failure
    if config.ENABLE_MAIL_NOTIFICATION:
        start_mail_queue()

    # Log broadcaster for SSE /log endpoint
    log_broadcaster = LogBroadcaster()
    broadcast_handler = BroadcastLogHandler(log_broadcaster)
    broadcast_handler.setLevel(logging.INFO)
    logging.getLogger().addHandler(broadcast_handler)

    shutdown_handler = GracefulShutdown()
    es_client = ESClient()
    processor = LogProcessor(es_client=es_client, executor=executor, llm_handler=llm_handler, orchestrator=orchestrator)
    stats_window = StatsWindow()
    token_window = TokenStatsWindow()

    def get_stats_payload() -> Dict[str, int | str | None]:
        base = processor.get_stats()
        payload: Dict[str, int | str | None] = {
            "processed": int(base.get("processed", 0) or 0),
            "failed": int(base.get("failed", 0) or 0),
            "last_run": base.get("last_run"),
        }
        payload.update(stats_window.snapshot())
        payload.update(token_window.snapshot())
        return payload

    config.PERF_INDEX_CURRENT = config.CURRENT_PERF_CONFIG.index if config.CURRENT_PERF_CONFIG else None

    daily_report_service = DailyReportService(es_client, executor=executor, agent_identity=agent_identity, orchestrator=orchestrator, backend=llm_handler.backend)

    remote_cmds = RemoteCommandQueue()
    rmi_server = None
    if config.RMI_ENABLED:
        rmi_server = start_rmi_server(
            remote_cmds,
            host=config.RMI_HOST,
            port=config.RMI_PORT,
            stats_getter=get_stats_payload,
            daily_report_service=daily_report_service,
            user_db=user_db,
            jwt_secret=jwt_secret,
            log_broadcaster=log_broadcaster,
            executor=executor,
            finetune_store=llm_handler.finetune_store,
        )
    else:
        logger.info("RMI server is disabled.")

    if not wait_for_elasticsearch(es_client):
        sys.exit(1)

    processor.es_client.ensure_ai_mapping()
    last_report_date = datetime.now().date()

    # Main processing loop
    logger.info("Entering main processing loop.")
    current_index = config.get_today_index()
    empty_runs = 0
    _last_git_reset_date = None          # tracks daily git-repo reset
    while not shutdown_handler.shutdown_requested:
        try:
            current_date = datetime.now().date()
            if current_date != last_report_date:
                report_date = last_report_date
                logger.info("Date changed. Generating daily report for %s", report_date.strftime("%Y-%m-%d"))
                try:
                    daily_report_service.generate_and_send(report_date)
                except Exception as exc:
                    logger.error("Daily report generation failed: %s", exc)
                last_report_date = current_date

            # --- Scheduled git workspace reset (configurable time, daily) ---
            if (
                config.GIT_ENABLED
                and executor is not None
                and _last_git_reset_date != current_date
                and datetime.now().strftime('%H:%M:%S') >= config.GIT_RESET_TIME
            ):
                _last_git_reset_date = current_date
                _scheduled_git_reset(executor, agent_identity=agent_identity)

            for result in apply_remote_commands(remote_cmds):
                if result.get("status") == "ok":
                    logger.info("Applied remote command: %s", result)
                else:
                    logger.warning("Remote command failed: %s", result)

            result = processor.process_batch(current_index)

            stats_window.tick(
                int(result.get("processed", 0) or 0),
                int(result.get("failed", 0) or 0),
            )

            token_window.record(result.get("llm_metrics", []))

            emit_stats_snapshot(get_stats_payload(), config.PERF_INDEX_CURRENT)

            if result['processed'] > 0:
                logger.info(
                    "Processed %s logs. Failed: %s",
                    result["processed"],
                    result["failed"]
                )
                empty_runs = 0
            elif result['failed'] > 0:
                empty_runs = 0
            else:
                empty_runs += 1

            if empty_runs >= config.EMPTY_RUNS_BEFORE_INDEX_REFRESH:
                empty_runs = 0
                logger.info("Refreshing index due to consecutive empty runs.")
                new_index = config.get_today_index()
                logger.info("Checked for index update: current=%s, new=%s", current_index, new_index)
                if new_index != current_index:
                    logger.info("Date changed. Trying to connect to new index: %s", new_index)
                    if es_client.try_connect_index(new_index):
                        logger.info("Switching index from %s to %s", current_index, new_index)
                        current_index = new_index
                    else:
                        logger.warning("Failed to connect to new index %s. Keeping current index %s", new_index, current_index)

            if config.AUTO_PERF_SELECT and config.CURRENT_PERF_CONFIG is not None:
                # Record token-level stats from Ollama responses
                llm_metrics = result.get("llm_metrics", [])
                if llm_metrics:
                    record_token_stats(llm_metrics)

                predicted = perf_index_predict(
                    observed_count=result.get("fetched", 0),
                    poll_interval=config.CURRENT_PERF_CONFIG.POLL_INTERVAL,
                    backlog=result.get("backlog", 0),
                )

                target_cfg, perf_index, details = adaptive_select(
                    predicted_count=predicted,
                    poll_interval=config.CURRENT_PERF_CONFIG.POLL_INTERVAL,
                    quality_bias=config.ANALYSIS_VALUE_INDEX,
                    model_profiles=config.MODEL_PROFILES,
                    current_model=config.CURRENT_PERF_CONFIG.OLLAMA_MODEL,
                )

                config.PERF_INDEX_CURRENT = perf_index
                config.ADAPTIVE_DETAILS = details

                should_switch = (
                    target_cfg is not None
                    and _perf_config_changed(config.CURRENT_PERF_CONFIG, target_cfg)
                )
                if should_switch:
                    logger.info(
                        "Switching perf config: index=%s -> %s (perf_index=%s, predicted=%.2f, pressure=%.2f)",
                        config.CURRENT_PERF_CONFIG.index,
                        target_cfg.index,
                        perf_index,
                        details.get("predicted_count", 0.0),
                        details.get("pressure", 0.0),
                    )
                    current_model = config.CURRENT_PERF_CONFIG.OLLAMA_MODEL
                    new_model = target_cfg.OLLAMA_MODEL
                    if current_model and current_model != new_model:
                        logger.info("Stopping current model before switch: %s", current_model)
                        stop_ollama_model(current_model, backend=llm_handler.backend)
                    config.CURRENT_PERF_CONFIG = target_cfg

            shutdown_handler.wait(config.CURRENT_PERF_CONFIG.POLL_INTERVAL)

        except KeyboardInterrupt:
            logger.info("Keyboard interrupt received. Shutting down.")
            break
        except Exception as e:
            logger.error(f"An error occurred during processing: {e}")
            shutdown_handler.wait(config.CURRENT_PERF_CONFIG.POLL_INTERVAL)


    logger.info("Exiting main processing loop.")

    if rmi_server is not None:
        rmi_server.stop()

    # Revoke the Agent session key (owned solely by LLMHandler).
    llm_handler.close()

    # Close auth database
    if user_db is not None:
        user_db.close()

    # Close executor audit database
    if executor is not None and executor.audit_db is not None:
        executor.audit_db.close()

    # Stop mail queue (flush remaining retries gracefully)
    stop_mail_queue()

    # Output final statistics
    stats = processor.get_stats()
    shutdown_header = "=" * 60
    shutdown_body = [
        f"Shutting down {config.SOFTWARE_NAME} {config.SOFTWARE_NAME_SUFFIX}",
        f"Total Processed: {stats['processed']}",
        f"Total Failed: {stats['failed']}",
    ]
    logger.info(shutdown_header)
    logger.info("\n".join(shutdown_body))
    logger.info(shutdown_header)

    # Send shutdown notification email
    now = datetime.now()
    now_utc = datetime.now(timezone.utc)
    ts_lines = [
        f"Timestamp (UNIX): {int(now.timestamp())}",
        f"Timestamp (UTC):  {now_utc.strftime('%H:%M:%S %m/%d/%Y')}",
    ]
    _send_notification_mail(
        f"{config.SOFTWARE_NAME} 关闭通知",
        [shutdown_header] + shutdown_body + [""] + ts_lines + [shutdown_header],
    )

    # Flush ES log handler / stats reporter so shutdown messages reach ES
    shutdown_logging()

if __name__ == "__main__":
    main()
