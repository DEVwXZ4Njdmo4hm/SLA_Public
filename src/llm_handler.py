#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         llm_handler.py
Description:  LLM communication handler with bidirectional communication pair memory system.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

import json
import re
import time as _time
from dataclasses import dataclass
from typing import Dict, List
import logging
from collections import deque
from threading import Lock

from .config import config
from .comm_proto_pair_memory import (
    CommProtoPairMemory,
    event_active_ts,
    make_event_key,
    make_pair_key,
)
from .llm_prompt import build_prompt, build_pipeline_messages, build_compact_prompt
from .llm_backend import LLMBackend, LLMMetrics

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Token-level metrics extracted from Ollama /api/generate response
# ---------------------------------------------------------------------------

@dataclass
class OllamaMetrics:
    """Token-level metrics from a single Ollama generation request.

    .. deprecated:: Use :class:`LLMMetrics` from ``llm_backend`` instead.
       This class is retained for backward compatibility and will be
       removed in a future version.
    """
    model: str = ""
    prompt_eval_count: int = 0
    prompt_eval_duration_ns: int = 0
    eval_count: int = 0
    eval_duration_ns: int = 0
    total_duration_ns: int = 0

    @property
    def eval_tokens_per_sec(self) -> float:
        """Token generation speed (tokens/sec)."""
        if self.eval_duration_ns <= 0:
            return 0.0
        return self.eval_count / (self.eval_duration_ns / 1e9)

    @property
    def prompt_tokens_per_sec(self) -> float:
        """Prompt evaluation speed (tokens/sec)."""
        if self.prompt_eval_duration_ns <= 0:
            return 0.0
        return self.prompt_eval_count / (self.prompt_eval_duration_ns / 1e9)

    @property
    def total_tokens(self) -> int:
        return self.prompt_eval_count + self.eval_count


# ---------------------------------------------------------------------------
# Communication-pair based memory for real-time LLM analysis
# ---------------------------------------------------------------------------

class CommPairMemory:
    """
    Communication-pair based memory for real-time LLM analysis.

    Stores memory entries keyed by canonical communication pair (bidirectional).
    A->B and B->A map to the same pair key.

    Each pair has a bounded deque of entries and a *last_modified* monotonic
    timestamp.  When the number of tracked pairs reaches *max_pairs*, the
    pair with the oldest *last_modified* time is evicted first.
    """

    def __init__(self, max_pairs: int, per_pair_len: int, *, rolling: bool = False):
        self._max_pairs = max(1, max_pairs)
        self._per_pair_len = max(1, per_pair_len)
        self._rolling = rolling
        # key -> {"last_modified": float, "entries": deque}
        self._pairs: Dict[str, Dict] = {}
        self._lock = Lock()

    # ------------------------------------------------------------------
    # Pair key: sort identifiers lexicographically so A->B == B->A
    # Identifiers are hostnames when available, falling back to IPs.
    # ------------------------------------------------------------------
    @staticmethod
    def _make_pair_key(id_a: str, id_b: str) -> str:
        """Create a canonical key for a communication pair (bidirectional).

        Identifiers should be hostnames when available, falling back to IPs.
        """
        a, b = id_a.strip(), id_b.strip()
        if a > b:
            a, b = b, a
        return f"{a} <-> {b}"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def add(self, src_id: str, dest_id: str, entry: str) -> None:
        """Add a memory entry for the given communication pair.

        *src_id* / *dest_id* should be hostnames when available, falling
        back to IPs.
        """
        if not entry or not src_id or not dest_id:
            return
        key = self._make_pair_key(src_id, dest_id)
        with self._lock:
            if key not in self._pairs:
                # Evict the least-recently-modified pair if at capacity
                if len(self._pairs) >= self._max_pairs:
                    oldest_key = min(
                        self._pairs,
                        key=lambda k: self._pairs[k]["last_modified"],
                    )
                    logger.debug(
                        "CommPairMemory: evicting oldest pair %s to make room",
                        oldest_key,
                    )
                    del self._pairs[oldest_key]
                maxlen = None if self._rolling else self._per_pair_len
                self._pairs[key] = {
                    "last_modified": _time.monotonic(),
                    "entries": deque(maxlen=maxlen),
                }
            pair = self._pairs[key]
            pair["entries"].append(entry)
            pair["last_modified"] = _time.monotonic()
            if self._rolling:
                hard_cap = 2 * self._per_pair_len
                entries = pair["entries"]
                if len(entries) > hard_cap:
                    overflow = len(entries) - self._per_pair_len
                    for _ in range(overflow):
                        entries.popleft()
                    logger.warning(
                        "CommPairMemory hard-cap reached for %s (%d); "
                        "truncated to %d — compaction may be failing.",
                        key, hard_cap, self._per_pair_len,
                    )

    def get(self, src_id: str, dest_id: str) -> List[str]:
        """Get memory entries for the given communication pair.

        *src_id* / *dest_id* should be hostnames when available, falling
        back to IPs.
        """
        if not src_id or not dest_id:
            return []
        key = self._make_pair_key(src_id, dest_id)
        with self._lock:
            pair = self._pairs.get(key)
            if pair is None:
                return []
            return list(pair["entries"])

    @property
    def pair_count(self) -> int:
        """Return the number of currently tracked communication pairs."""
        with self._lock:
            return len(self._pairs)

    @property
    def max_pairs(self) -> int:
        return self._max_pairs

    @property
    def per_pair_len(self) -> int:
        return self._per_pair_len

    def replace_entries(
        self, src_id: str, dest_id: str, new_entries: List[str],
    ) -> None:
        """Atomically replace all entries for the given pair."""
        key = self._make_pair_key(src_id, dest_id)
        with self._lock:
            pair = self._pairs.get(key)
            if pair is None:
                return
            maxlen = None if self._rolling else self._per_pair_len
            pair["entries"] = deque(new_entries, maxlen=maxlen)
            pair["last_modified"] = _time.monotonic()

    def compact_oldest(
        self, src_id: str, dest_id: str, n: int, replacement: str,
    ) -> bool:
        """Atomically remove the oldest *n* entries and prepend *replacement*.

        Returns ``True`` if the operation was performed.  Returns ``False``
        if the pair does not exist or currently has fewer than *n* entries.
        """
        key = self._make_pair_key(src_id, dest_id)
        with self._lock:
            pair = self._pairs.get(key)
            if pair is None:
                return False
            entries = pair["entries"]
            if len(entries) < n:
                return False
            for _ in range(n):
                entries.popleft()
            entries.appendleft(replacement)
            pair["last_modified"] = _time.monotonic()
            return True


def stop_ollama_model(model: str, backend: LLMBackend) -> bool:
    """
    Attempt to stop/unload the specified model to free resources.

    Delegates to ``backend.stop_model()``.
    """
    if not model:
        return False
    return backend.stop_model(model)


class LLMHandler:
    """
    LLM Processing Handler

    When *user_db* is provided the handler bootstraps its own Agent
    identity on creation and revokes the session API key on ``close()``.
    """

    def __init__(self, user_db=None, backend: LLMBackend | None = None):
        # Memory subsystem — controlled by config.LLM_MEMORY_MODE
        self._memory_mode = config.LLM_MEMORY_MODE
        self._comm_pair_memory = None
        self._comm_proto_pair_memory = None
        self._global_memory = None
        _rolling = self._memory_mode in (
            "pair_rolling", "global_rolling", "proto_pair_rolling"
        )
        if self._memory_mode in ("pair", "pair_rolling"):
            self._comm_pair_memory = CommPairMemory(
                max_pairs=config.LLM_MEMORY_MAX_PAIRS,
                per_pair_len=config.LLM_MEMORY_PER_PAIR_LEN,
                rolling=_rolling,
            )
        elif self._memory_mode in ("proto_pair", "proto_pair_rolling"):
            maxpair_lru_evict = config.LLM_MEMORY_MAXPAIR_LRU_EVICT
            if maxpair_lru_evict == 0:
                maxpair_lru_evict = min(5, max(1, config.LLM_MEMORY_MAX_PAIRS - 1))
            self._comm_proto_pair_memory = CommProtoPairMemory(
                max_pairs=config.LLM_MEMORY_MAX_PAIRS,
                per_pair_len=config.LLM_MEMORY_PER_PAIR_LEN,
                lat_lru_seconds=config.LLM_MEMORY_LAT_LRU_EVICT_SECONDS,
                maxpair_lru_evict=maxpair_lru_evict,
                rolling=_rolling,
            )
        elif self._memory_mode in ("global", "global_rolling"):
            from .global_memory import GlobalMemory
            self._global_memory = GlobalMemory(
                max_entries=config.LLM_MEMORY_LEN,
                rolling=_rolling,
            )
        # else: "none" — no memory

        # Compaction concurrency control (Improvement 30.8.1)
        self._global_compact_lock = Lock()
        self._pair_compact_locks: Dict[str, Lock] = {}
        self._pair_compact_locks_meta = Lock()
        self._last_global_compact: float = 0.0

        self._batch_metrics: List[LLMMetrics] = []
        self._metrics_lock = Lock()

        # Backend injection or auto-creation
        if backend is not None:
            self._backend = backend
        else:
            from .backends import create_backend
            self._backend = create_backend()

        # Fine-tuning data collection (Improvement 30.7)
        self._finetune_store = None
        if config.FINETUNE_COLLECT_ENABLED:
            try:
                from .finetune_store import FinetuneStore
                self._finetune_store = FinetuneStore(config.FINETUNE_DB_PATH)
                logger.info("FinetuneStore initialized at %s", config.FINETUNE_DB_PATH)
            except Exception:
                logger.warning("FinetuneStore init failed; collection disabled.", exc_info=True)

        # Agent identity lifecycle — owned by this instance.
        self._user_db = user_db
        self._agent_identity = None
        if user_db is not None:
            from .auth.bootstrap import bootstrap_agent
            self._agent_identity = bootstrap_agent(user_db)
            if self._agent_identity is None:
                logger.warning(
                    "LLMHandler: Agent identity bootstrap failed — "
                    "executor requests will fall back to unauthenticated mode."
                )
            else:
                logger.info(
                    "LLMHandler: Agent identity ready (user_id=%s, key_id=%d).",
                    self._agent_identity.actor_id,
                    self._agent_identity.key_record_id,
                )

    # ------------------------------------------------------------------
    # Agent identity access
    # ------------------------------------------------------------------

    @property
    def agent_identity(self):
        return self._agent_identity

    @property
    def backend(self) -> LLMBackend:
        """Return the underlying LLM backend instance."""
        return self._backend

    @property
    def finetune_store(self):
        """Return the FinetuneStore instance, or *None* if disabled."""
        return self._finetune_store

    @property
    def supports_tool_use(self) -> bool:
        """Check whether the current model supports tool / function calling.

        Resolution order:
        1. ``ModelProfile.supports_tool_use`` override (``True`` / ``False``).
        2. Backend ``detect_tool_support()`` (Ollama /api/show, OpenAI always True).
        3. ``False`` (safe default).
        """
        if config.CURRENT_PERF_CONFIG is None:
            return False
        model_name = config.CURRENT_PERF_CONFIG.OLLAMA_MODEL
        profile = config.MODEL_PROFILES.get(model_name)
        if profile is not None and profile.supports_tool_use is not None:
            return bool(profile.supports_tool_use)
        backend = self.get_backend_for_model(model_name)
        detection = backend.detect_tool_support(model_name)
        if detection is not None:
            return detection
        return False

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Revoke the session API key created during ``__init__``."""
        if self._agent_identity is not None and self._user_db is not None:
            from .auth.bootstrap import revoke_agent_session
            revoke_agent_session(self._user_db, self._agent_identity)
            logger.info("LLMHandler: Agent session key revoked.")
            self._agent_identity = None

    def record_metrics(self, metrics: LLMMetrics) -> None:
        """Thread-safe recording of per-request LLM metrics."""
        with self._metrics_lock:
            self._batch_metrics.append(metrics)

    def drain_batch_metrics(self) -> List[LLMMetrics]:
        """Return and clear all accumulated metrics since the last drain."""
        with self._metrics_lock:
            metrics = self._batch_metrics
            self._batch_metrics = []
            return metrics

    def get_backend_for_model(self, model_name: str) -> LLMBackend:
        """Return the backend appropriate for *model_name*.

        If the model's profile declares a different backend type (or a
        custom base URL) the per-model backend factory is used; otherwise
        the default ``self._backend`` is returned.
        """
        profile = config.MODEL_PROFILES.get(model_name)
        if profile is None:
            return self._backend
        if (profile.backend_type == self._backend.backend_type
                and not profile.backend_base_url):
            return self._backend
        from .backends import create_backend_for_model
        return create_backend_for_model(profile)

    def get_memory_snapshot(
        self,
        src_id: str = "",
        dest_id: str = "",
        *,
        app_proto: str = "",
        event_type: str = "",
    ) -> List[str]:
        """Return memory entries for the given communication pair.

        Behavior depends on ``memory_mode``:
        - ``"pair"`` / ``"pair_rolling"``: returns entries for the specific (src, dest) pair.
        - ``"proto_pair"`` / ``"proto_pair_rolling"``: returns entries for pair + Event_Z.
        - ``"global"`` / ``"global_rolling"``: returns all entries (ignores src_id/dest_id).
        - ``"none"``: always returns ``[]``.
        """
        if self._memory_mode == "none":
            return []
        if self._memory_mode in ("global", "global_rolling"):
            return self._global_memory.get_snapshot() if self._global_memory else []
        if not src_id or not dest_id:
            return []
        if self._memory_mode in ("proto_pair", "proto_pair_rolling"):
            if self._comm_proto_pair_memory is None:
                return []
            event_key = make_event_key(app_proto, event_type)
            return self._comm_proto_pair_memory.get(src_id, dest_id, event_key)
        # "pair" / "pair_rolling"
        if self._comm_pair_memory is None:
            return []
        return self._comm_pair_memory.get(src_id, dest_id)

    def update_summary_memory(
        self,
        summary: str,
        *,
        src_ip: str = "",
        dest_ip: str = "",
        src_hostname: str = "",
        dest_hostname: str = "",
        event_type: str = "",
        app_proto: str = "",
        event_timestamp: str | None = None,
    ) -> None:
        """
        Store a memory entry for the communication pair.

        The pair is identified by hostname when available, falling back
        to IP address.

        Entry format: [timestamp] event_type summary
        """
        src_id = (src_hostname or "").strip() or (src_ip or "").strip()
        dest_id = (dest_hostname or "").strip() or (dest_ip or "").strip()
        if not src_id or not dest_id:
            return
        summary = (summary or "").strip()
        if not summary:
            return

        event_key = make_event_key(app_proto, event_type)
        entry = self._format_memory_entry(
            summary,
            event_timestamp=event_timestamp,
            event_type=event_type,
            event_key=event_key,
            include_event_key=self._memory_mode in ("proto_pair", "proto_pair_rolling"),
        )

        if self._memory_mode in ("pair", "pair_rolling") and self._comm_pair_memory is not None:
            self._comm_pair_memory.add(src_id, dest_id, entry)
            self._maybe_compact_memory(src_id, dest_id)
        elif (
            self._memory_mode in ("proto_pair", "proto_pair_rolling")
            and self._comm_proto_pair_memory is not None
        ):
            self._comm_proto_pair_memory.add(
                src_id,
                dest_id,
                event_key,
                entry,
                active_ts=event_active_ts(event_timestamp),
            )
            self._maybe_compact_proto_pair_memory(src_id, dest_id, event_key)
        elif self._memory_mode in ("global", "global_rolling") and self._global_memory is not None:
            self._global_memory.add(entry)
            self._maybe_compact_global_memory()
        # "none": discard

    @staticmethod
    def _format_memory_entry(
        summary: str,
        *,
        event_timestamp: str | None,
        event_type: str,
        event_key: str,
        include_event_key: bool,
    ) -> str:
        parts: List[str] = []
        if event_timestamp:
            ts = str(event_timestamp).strip()
            if ts:
                parts.append(f"[{ts}]")
        if include_event_key:
            if event_type:
                parts.append(f"Event_Z={event_key}; event_type={event_type};")
            else:
                parts.append(f"Event_Z={event_key};")
        elif event_type:
            parts.append(event_type)
        parts.append(summary)
        return " ".join(parts)

    # ------------------------------------------------------------------
    # Rolling summary compaction (Improvement 30.8 / 30.8.1)
    # ------------------------------------------------------------------

    def _maybe_compact_memory(self, src_id: str, dest_id: str) -> None:
        """Compact pair memory entries if count exceeds the threshold.

        Only performs work when ``memory_mode == "pair_rolling"``.
        Uses a per-pair trylock to prevent parallel compaction of the
        same pair and a double-check after acquiring the lock.
        """
        if self._memory_mode != "pair_rolling":
            return
        if self._comm_pair_memory is None:
            return

        entries = self._comm_pair_memory.get(src_id, dest_id)
        if len(entries) < config.LLM_MEMORY_COMPACT_THRESHOLD:
            return

        # Obtain or create per-pair lock
        pair_key = CommPairMemory._make_pair_key(src_id, dest_id)
        with self._pair_compact_locks_meta:
            lock = self._pair_compact_locks.get(pair_key)
            if lock is None:
                lock = Lock()
                self._pair_compact_locks[pair_key] = lock

        if not lock.acquire(blocking=False):
            return  # another thread is already compacting this pair

        try:
            # Double-check after acquiring lock
            entries = self._comm_pair_memory.get(src_id, dest_id)
            if len(entries) < config.LLM_MEMORY_COMPACT_THRESHOLD:
                return

            batch_size = config.LLM_MEMORY_COMPACT_BATCH
            to_compact = entries[:batch_size]

            compact_prompt = build_compact_prompt(
                pair_key=pair_key,
                entries=to_compact,
            )

            try:
                model_name = config.CURRENT_PERF_CONFIG.OLLAMA_MODEL
                backend = self.get_backend_for_model(model_name)
                result = backend.chat(
                    model=model_name,
                    messages=[{"role": "user", "content": compact_prompt}],
                    tools=None,
                    max_tokens=512,
                    context_length=config.CURRENT_PERF_CONFIG.OLLAMA_CONTEXT_LENGTH,
                    temperature=0.2,
                    top_p=0.9,
                    top_k=40,
                    think=False,
                    keep_alive=config.OLLAMA_KEEP_ALIVE,
                )
            except Exception:
                logger.warning(
                    "Memory compaction LLM call failed for %s; skipping.",
                    pair_key, exc_info=True,
                )
                return

            compacted_text = self._strip_think(result.message.content).strip()
            if not compacted_text:
                logger.warning("Memory compaction returned empty result for %s", pair_key)
                return

            self.record_metrics(result.metrics)

            compacted_entry = f"[合并摘要] {compacted_text}"
            if not self._comm_pair_memory.compact_oldest(
                src_id, dest_id, batch_size, compacted_entry,
            ):
                logger.warning(
                    "Memory compaction for %s skipped: fewer entries than expected.",
                    pair_key,
                )
                return
            logger.debug(
                "Compacted %d entries into 1 for %s",
                batch_size, pair_key,
            )
        finally:
            lock.release()

    def _maybe_compact_proto_pair_memory(
        self, src_id: str, dest_id: str, event_key: str,
    ) -> None:
        """Compact one proto-pair Event_Z bucket when rolling is enabled."""
        if self._memory_mode != "proto_pair_rolling":
            return
        if self._comm_proto_pair_memory is None:
            return

        entries = self._comm_proto_pair_memory.get(src_id, dest_id, event_key)
        if len(entries) < config.LLM_MEMORY_COMPACT_THRESHOLD:
            return

        lock = self._comm_proto_pair_memory.get_compact_lock(src_id, dest_id, event_key)
        if lock is None:
            return
        if not lock.acquire(blocking=False):
            return

        try:
            entries = self._comm_proto_pair_memory.get(src_id, dest_id, event_key)
            if len(entries) < config.LLM_MEMORY_COMPACT_THRESHOLD:
                return

            batch_size = config.LLM_MEMORY_COMPACT_BATCH
            to_compact = entries[:batch_size]
            pair_key = make_pair_key(src_id, dest_id)
            compact_prompt = build_compact_prompt(
                pair_key=f"{pair_key}:{event_key}",
                entries=to_compact,
            )

            try:
                model_name = config.CURRENT_PERF_CONFIG.OLLAMA_MODEL
                backend = self.get_backend_for_model(model_name)
                result = backend.chat(
                    model=model_name,
                    messages=[{"role": "user", "content": compact_prompt}],
                    tools=None,
                    max_tokens=512,
                    context_length=config.CURRENT_PERF_CONFIG.OLLAMA_CONTEXT_LENGTH,
                    temperature=0.2,
                    top_p=0.9,
                    top_k=40,
                    think=False,
                    keep_alive=config.OLLAMA_KEEP_ALIVE,
                )
            except Exception:
                logger.warning(
                    "Proto-pair memory compaction LLM call failed for %s:%s; skipping.",
                    pair_key, event_key, exc_info=True,
                )
                return

            compacted_text = self._strip_think(result.message.content).strip()
            if not compacted_text:
                logger.warning(
                    "Proto-pair memory compaction returned empty result for %s:%s",
                    pair_key, event_key,
                )
                return

            self.record_metrics(result.metrics)

            compacted_entry = f"[合并摘要] {compacted_text}"
            if not self._comm_proto_pair_memory.compact_oldest(
                src_id, dest_id, event_key, batch_size, compacted_entry,
            ):
                logger.warning(
                    "Proto-pair memory compaction for %s:%s skipped: fewer entries than expected.",
                    pair_key, event_key,
                )
                return
            logger.debug(
                "Compacted %d entries into 1 for %s:%s",
                batch_size, pair_key, event_key,
            )
        finally:
            lock.release()

    def _maybe_compact_global_memory(self) -> None:
        """Compact global memory entries if count exceeds the threshold.

        Only performs work when ``memory_mode == "global_rolling"``.
        Uses a trylock to prevent parallel compaction, a cooldown window
        to prevent serial re-trigger, and a double-check after lock
        acquisition.
        """
        if self._memory_mode != "global_rolling":
            return
        if self._global_memory is None:
            return

        entries = self._global_memory.get_snapshot()
        if len(entries) < config.LLM_MEMORY_COMPACT_THRESHOLD:
            return

        # Cooldown — avoid re-triggering immediately after a successful compaction
        if _time.monotonic() - self._last_global_compact < config.LLM_MEMORY_COMPACT_COOLDOWN:
            return

        if not self._global_compact_lock.acquire(blocking=False):
            return  # another thread is already compacting

        try:
            # Double-check after acquiring lock
            entries = self._global_memory.get_snapshot()
            if len(entries) < config.LLM_MEMORY_COMPACT_THRESHOLD:
                return

            batch_size = config.LLM_MEMORY_COMPACT_BATCH
            to_compact = entries[:batch_size]

            compact_prompt = build_compact_prompt(
                pair_key="全局记忆",
                entries=to_compact,
            )

            try:
                model_name = config.CURRENT_PERF_CONFIG.OLLAMA_MODEL
                backend = self.get_backend_for_model(model_name)
                result = backend.chat(
                    model=model_name,
                    messages=[{"role": "user", "content": compact_prompt}],
                    tools=None,
                    max_tokens=512,
                    context_length=config.CURRENT_PERF_CONFIG.OLLAMA_CONTEXT_LENGTH,
                    temperature=0.2,
                    top_p=0.9,
                    top_k=40,
                    think=False,
                    keep_alive=config.OLLAMA_KEEP_ALIVE,
                )
            except Exception:
                logger.warning(
                    "Global memory compaction LLM call failed; skipping.",
                    exc_info=True,
                )
                return

            compacted_text = self._strip_think(result.message.content).strip()
            if not compacted_text:
                logger.warning("Global memory compaction returned empty result")
                return

            self.record_metrics(result.metrics)

            compacted_entry = f"[合并摘要] {compacted_text}"
            if not self._global_memory.compact_oldest(
                batch_size, compacted_entry,
            ):
                logger.warning(
                    "Global memory compaction skipped: fewer entries than expected.",
                )
                return
            self._last_global_compact = _time.monotonic()
            logger.debug(
                "Compacted %d global entries into 1",
                batch_size,
            )
        finally:
            self._global_compact_lock.release()

    @staticmethod
    def _strip_think(text: str) -> str:
        """
        Remove <think>...</think> blocks from model output.
        """
        if not text:
            return ""
        cleaned = re.sub(r"<think\b[^>]*>.*?</think\s*>", "", text, flags=re.DOTALL | re.IGNORECASE)
        cleaned = re.sub(r"<think\b[^>]*>.*$", "", cleaned, flags=re.DOTALL | re.IGNORECASE)
        cleaned = re.sub(r"</think\s*>", "", cleaned, flags=re.IGNORECASE)
        return cleaned.strip()

    def generate_advice(self, log_entry: Dict) -> str:
        """
        Generate advice based on the log entry using LLM.
        """
        return self._call_llm(log_entry)

    def _call_llm(self, log_entry: Dict) -> str:
        """Call the LLM to generate advice based on the log entry.

        Uses the chat API (``/api/chat``) with separated system/user
        messages to enable Ollama KV cache reuse for the system prompt
        (Improvement 30.7-A).
        """
        if config.CURRENT_PERF_CONFIG is None:
            raise RuntimeError("CURRENT_PERF_CONFIG is not set.")

        src_ip = log_entry.get("src_ip", "")
        dest_ip = log_entry.get("dest_ip", "")
        src_hostname = log_entry.get("src_hostname", "")
        dest_hostname = log_entry.get("dest_hostname", "")
        # Prefer hostname for pair lookup; fall back to IP.
        src_id = (src_hostname or "").strip() or (src_ip or "").strip()
        dest_id = (dest_hostname or "").strip() or (dest_ip or "").strip()
        event_type = log_entry.get("event_type", "")
        app_proto = log_entry.get("app_proto", "")
        memory_summaries = self.get_memory_snapshot(
            src_id,
            dest_id,
            app_proto=app_proto,
            event_type=event_type,
        )
        memory_scope_label = (
            "该通信对中同 Event_Z"
            if self._memory_mode in ("proto_pair", "proto_pair_rolling")
            else "该通信对"
        )
        messages = build_pipeline_messages(
            log_entry,
            memory_summaries=memory_summaries,
            memory_scope_label=memory_scope_label,
        )

        model_name = config.CURRENT_PERF_CONFIG.OLLAMA_MODEL
        backend = self.get_backend_for_model(model_name)

        try:
            result = backend.chat(
                model=model_name,
                messages=messages,
                tools=None,
                max_tokens=config.CURRENT_PERF_CONFIG.OLLAMA_NUM_PREDICT,
                context_length=config.CURRENT_PERF_CONFIG.OLLAMA_CONTEXT_LENGTH,
                temperature=config.CURRENT_PERF_CONFIG.OLLAMA_TEMPERATURE,
                top_p=config.CURRENT_PERF_CONFIG.OLLAMA_TOP_P,
                top_k=config.CURRENT_PERF_CONFIG.OLLAMA_TOP_K,
                stop=["你是一个网络安全专家", "日志条目:", "请用中文提供："],
                think=config.OLLAMA_THINK,
                keep_alive=config.OLLAMA_KEEP_ALIVE,
            )
        except Exception as e:
            logger.error("LLM request failed: %s", e)
            raise

        self.record_metrics(result.metrics)

        cleaned = self._strip_think(result.message.content) if result.message.content else ""

        if not cleaned:
            logger.warning("LLM response contained only <think> content or was empty.")
            return ""

        # Auto-write finetune sample (Improvement 30.7-D)
        if self._finetune_store is not None:
            try:
                parsed = self.parse_json_sections(cleaned)
                self._finetune_store.add_sample(
                    model_name=model_name,
                    system_prompt=messages[0]["content"],
                    user_input=messages[1]["content"],
                    llm_response=cleaned,
                    threat_level=parsed.get("threat_level", ""),
                    event_type=log_entry.get("event_type", ""),
                    comm_pair=f"{src_id} <-> {dest_id}",
                )
            except Exception:
                logger.debug("finetune sample write failed", exc_info=True)

        return cleaned

    # ------------------------------------------------------------------
    # Chat API with tool-call support (Ollama /api/chat)
    # ------------------------------------------------------------------

    def call_llm_chat(
        self,
        messages: List[Dict],
        tools: List[Dict] | None = None,
    ) -> Dict:
        """Call the LLM chat API with optional tool definitions.

        Parameters
        ----------
        messages:
            Chat message list, each ``{"role": ..., "content": ...}``.
        tools:
            Tool schema list (JSON-serialisable).  May be *None* or
            empty to invoke chat mode without tool calling.

        Returns
        -------
        dict
            The ``message`` object from the chat response, containing
            at least ``role`` and ``content``.  If the model invoked tools,
            the ``tool_calls`` key will be present.

        Side-effects
        ------------
        Records ``LLMMetrics`` for each call.
        """
        if config.CURRENT_PERF_CONFIG is None:
            raise RuntimeError("CURRENT_PERF_CONFIG is not set.")

        model_name = config.CURRENT_PERF_CONFIG.OLLAMA_MODEL
        backend = self.get_backend_for_model(model_name)

        try:
            result = backend.chat(
                model=model_name,
                messages=messages,
                tools=tools,
                max_tokens=config.CURRENT_PERF_CONFIG.OLLAMA_NUM_PREDICT,
                context_length=config.CURRENT_PERF_CONFIG.OLLAMA_CONTEXT_LENGTH,
                temperature=config.CURRENT_PERF_CONFIG.OLLAMA_TEMPERATURE,
                top_p=config.CURRENT_PERF_CONFIG.OLLAMA_TOP_P,
                top_k=config.CURRENT_PERF_CONFIG.OLLAMA_TOP_K,
                think=config.OLLAMA_THINK,
            )
        except Exception as e:
            logger.error("LLM chat request failed: %s", e)
            raise

        self.record_metrics(result.metrics)

        # Build backward-compatible dict message
        message: Dict = {
            "role": result.message.role,
            "content": self._strip_think(result.message.content) if result.message.content else "",
        }
        if result.message.tool_calls:
            message["tool_calls"] = result.message.tool_calls

        # Attach metrics to message for orchestrator budget tracking
        message["_metrics"] = result.metrics

        return message

    @staticmethod
    def parse_json_sections(text: str) -> Dict[str, str]:
        """
        Parse JSON output into fields.
        Expected keys (either English or Chinese):
        summary/日志简报, threat_level/威胁评分, security_hint/安全提示, recommendation/建议措施.
        """
        if not text:
            return {}

        cleaned = text.strip()
        cleaned = re.sub(r"^\s*回答[:：]\s*", "", cleaned)
        cleaned = re.sub(r"^```json\s*|```$", "", cleaned, flags=re.IGNORECASE | re.MULTILINE).strip()

        json_text = cleaned
        if not cleaned.startswith("{"):
            start = cleaned.find("{")
            end = cleaned.rfind("}")
            if start != -1 and end != -1 and end > start:
                json_text = cleaned[start:end + 1]

        try:
            data = json.loads(json_text)
        except Exception:
            return {}

        if not isinstance(data, dict):
            return {}

        key_map = {
            "summary": "summary",
            "日志简报": "summary",
            "threat_level": "threat_level",
            "威胁评分": "threat_level",
            "security_hint": "security_hint",
            "安全提示": "security_hint",
            "recommendation": "recommendation",
            "建议措施": "recommendation",
        }

        parsed: Dict[str, str] = {}
        for src_key, dest_key in key_map.items():
            value = data.get(src_key)
            if value is None:
                continue
            value = str(value).strip()
            if value:
                parsed[dest_key] = value

        return parsed

     
