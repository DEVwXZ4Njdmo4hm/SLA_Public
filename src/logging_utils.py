#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         logging_utils.py
Description:  JSON logging formatter and Elasticsearch log handler for centralized logging.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import json
import logging
import queue
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from elasticsearch import Elasticsearch, helpers

from .config import config

_CONFIGURED = False
_STATS_REPORTER: Optional["StatsReporter"] = None
_ES_LOG_HANDLER: Optional["ElasticsearchLogHandler"] = None


class JsonLogFormatter(logging.Formatter):
	def format(self, record: logging.LogRecord) -> str:
		payload = {
			"timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
			"logger": record.name,
			"loglevel": record.levelname,
			"logmsg": record.getMessage(),
		}
		if record.exc_info:
			payload["exception"] = self.formatException(record.exc_info)
		if record.stack_info:
			payload["stack_info"] = record.stack_info
		return json.dumps(payload, ensure_ascii=False)


class ElasticsearchLogHandler(logging.Handler):
	def __init__(
		self,
		es_client: Elasticsearch,
		index_prefix: str,
		queue_size: int = 10000,
		flush_interval: float = 1.0,
		batch_size: int = 200,
	) -> None:
		super().__init__()
		self._client = es_client
		self._index_prefix = index_prefix
		self._queue: queue.Queue[Tuple[str, Dict[str, Any]]] = queue.Queue(maxsize=queue_size)
		self._flush_interval = flush_interval
		self._batch_size = batch_size
		self._stop_event = threading.Event()
		self._worker = threading.Thread(target=self._worker_loop, name="es-log-writer", daemon=True)
		self._worker.start()

	def emit(self, record: logging.LogRecord) -> None:
		try:
			index = self._build_index_name(record)
			doc = self._build_doc(record)
			self._queue.put_nowait((index, doc))
		except queue.Full:
			return
		except Exception:
			self.handleError(record)

	def close(self) -> None:
		self._stop_event.set()
		if self._worker.is_alive():
			self._worker.join(timeout=2)
		super().close()

	def _build_index_name(self, record: logging.LogRecord) -> str:
		date_str = datetime.fromtimestamp(record.created, tz=timezone.utc).strftime("%Y.%m.%d")
		return f"{self._index_prefix}{date_str}"

	def _build_doc(self, record: logging.LogRecord) -> Dict[str, Any]:
		payload = {
			"timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
			"logger": record.name,
			"loglevel": record.levelname,
			"logmsg": record.getMessage(),
		}
		if record.exc_info:
			payload["exception"] = self.formatException(record.exc_info)
		if record.stack_info:
			payload["stack_info"] = record.stack_info
		return payload

	def _worker_loop(self) -> None:
		batch: list[Tuple[str, Dict[str, Any]]] = []
		last_flush = time.time()
		while not self._stop_event.is_set() or not self._queue.empty():
			try:
				item = self._queue.get(timeout=0.2)
				batch.append(item)
			except queue.Empty:
				pass

			should_flush = False
			if batch and len(batch) >= self._batch_size:
				should_flush = True
			elif batch and (time.time() - last_flush) >= self._flush_interval:
				should_flush = True

			if should_flush:
				self._flush_batch(batch)
				batch = []
				last_flush = time.time()

		if batch:
			self._flush_batch(batch)

	def _flush_batch(self, batch: list[Tuple[str, Dict[str, Any]]]) -> None:
		actions = [
			{
				"_op_type": "index",
				"_index": index,
				"_source": doc,
			}
			for index, doc in batch
		]
		try:
			helpers.bulk(self._client, actions, raise_on_error=False)
		except Exception as exc:
			# Use print to stderr to avoid recursive logging when the ES log handler itself fails
			import sys as _sys
			print(f"[es-log-writer] Failed to flush log batch ({len(batch)} docs): {exc}", file=_sys.stderr)
			return


class StatsReporter:
	def __init__(
		self,
		es_client: Elasticsearch,
		index_prefix: str,
		queue_size: int = 10000,
		flush_interval: float = 5.0,
		batch_size: int = 200,
	) -> None:
		self._client = es_client
		self._index_prefix = index_prefix
		self._queue: queue.Queue[Tuple[str, Dict[str, Any]]] = queue.Queue(maxsize=queue_size)
		self._flush_interval = flush_interval
		self._batch_size = batch_size
		self._stop_event = threading.Event()
		self._worker = threading.Thread(target=self._worker_loop, name="es-stats-writer", daemon=True)
		self._worker.start()

	def emit(self, payload: Dict[str, Any]) -> None:
		try:
			timestamp = payload.get("timestamp")
			if not timestamp:
				payload["timestamp"] = datetime.now(timezone.utc).isoformat()
			index = self._build_index_name(payload["timestamp"])
			self._queue.put_nowait((index, payload))
		except queue.Full:
			return
		except Exception:
			return

	def close(self) -> None:
		self._stop_event.set()
		if self._worker.is_alive():
			self._worker.join(timeout=2)

	def _build_index_name(self, timestamp_value: str) -> str:
		try:
			ts = datetime.fromisoformat(timestamp_value.replace("Z", "+00:00"))
		except Exception:
			ts = datetime.now(timezone.utc)
		date_str = ts.astimezone(timezone.utc).strftime("%Y.%m.%d")
		return f"{self._index_prefix}{date_str}"

	def _worker_loop(self) -> None:
		batch: list[Tuple[str, Dict[str, Any]]] = []
		last_flush = time.time()
		while not self._stop_event.is_set() or not self._queue.empty():
			try:
				item = self._queue.get(timeout=0.2)
				batch.append(item)
			except queue.Empty:
				pass

			should_flush = False
			if batch and len(batch) >= self._batch_size:
				should_flush = True
			elif batch and (time.time() - last_flush) >= self._flush_interval:
				should_flush = True

			if should_flush:
				self._flush_batch(batch)
				batch = []
				last_flush = time.time()

		if batch:
			self._flush_batch(batch)

	def _flush_batch(self, batch: list[Tuple[str, Dict[str, Any]]]) -> None:
		actions = [
			{
				"_op_type": "index",
				"_index": index,
				"_source": doc,
			}
			for index, doc in batch
		]
		try:
			helpers.bulk(self._client, actions, raise_on_error=False)
		except Exception as exc:
			import sys as _sys
			print(f"[es-stats-writer] Failed to flush stats batch ({len(batch)} docs): {exc}", file=_sys.stderr)
			return


def ensure_log_index_template(es_client: Elasticsearch) -> Optional[str]:
	"""Create/update the log index template. Returns an error message on failure."""
	index_pattern = config.LOG_INDEX_PATTERN
	template_name = config.LOG_TEMPLATE_NAME
	body = {
		"index_patterns": [index_pattern],
		"priority": 0,
		"template": {
			"settings": {
				"index.mapping.total_fields.limit": config.LOG_FIELD_LIMIT,
			},
			"mappings": {
				"dynamic": True,
				"properties": {
					"timestamp": {"type": "date"},
					"logger": {"type": "keyword"},
					"loglevel": {"type": "keyword"},
					"logmsg": {
						"type": "text",
						"fields": {
							"keyword": {"type": "keyword", "ignore_above": 256}
						}
					},
				}
			},
		},
		"_meta": {
			"managed_by": "suricata-llm-agent",
			"version": config.SOFTWARE_VERSION,
		},
	}
	try:
		es_client.indices.put_index_template(name=template_name, body=body)
		return None
	except Exception as exc:
		msg = (
			f"Could not create log index template '{template_name}': {exc}. "
			f"The ES user '{config.LOG_ES_USER}' may lack the "
			f"'manage_index_templates' cluster privilege. "
			f"Indices will still be created with default dynamic mappings."
		)
		print(f"[setup_logging] {msg}", file=sys.stderr)
		return msg


def ensure_stats_index_template(es_client: Elasticsearch) -> Optional[str]:
	"""Create/update the stats index template. Returns an error message on failure."""
	index_pattern = config.STATS_INDEX_PATTERN
	template_name = config.STATS_TEMPLATE_NAME
	body = {
		"index_patterns": [index_pattern],
		"priority": 10,
		"template": {
			"settings": {
				"index.number_of_replicas": 0,
				"index.mapping.total_fields.limit": config.LOG_FIELD_LIMIT,
			},
			"mappings": {
				"dynamic": True,
				"properties": {
					"timestamp": {"type": "date"},
					"processed_total": {"type": "long"},
					"failed_total": {"type": "long"},
					"perf_index": {"type": "integer"},
					"pressure_score": {"type": "float"},
					"quality_factor": {"type": "float"},
					"effective_tps": {"type": "float"},
					"5min_processed": {"type": "long"},
					"5min_failed": {"type": "long"},
					"5min_total": {"type": "long"},
					"15min_processed": {"type": "long"},
					"15min_failed": {"type": "long"},
					"15min_total": {"type": "long"},
					"60min_processed": {"type": "long"},
					"60min_failed": {"type": "long"},
					"60min_total": {"type": "long"},
					"token_total": {"type": "long"},
					"token_total_prompt": {"type": "long"},
					"token_total_completion": {"type": "long"},
					"1min_prompt_tokens": {"type": "long"},
					"1min_completion_tokens": {"type": "long"},
					"1min_total_tokens": {"type": "long"},
					"5min_prompt_tokens": {"type": "long"},
					"5min_completion_tokens": {"type": "long"},
					"5min_total_tokens": {"type": "long"},
					"30min_prompt_tokens": {"type": "long"},
					"30min_completion_tokens": {"type": "long"},
					"30min_total_tokens": {"type": "long"},
					"1h_prompt_tokens": {"type": "long"},
					"1h_completion_tokens": {"type": "long"},
					"1h_total_tokens": {"type": "long"},
					"6h_prompt_tokens": {"type": "long"},
					"6h_completion_tokens": {"type": "long"},
					"6h_total_tokens": {"type": "long"},
					"24h_prompt_tokens": {"type": "long"},
					"24h_completion_tokens": {"type": "long"},
					"24h_total_tokens": {"type": "long"},
					"avg_tokens_per_log": {"type": "float"},
				},
			},
		},
		"_meta": {
			"managed_by": "suricata-llm-agent",
			"version": config.SOFTWARE_VERSION,
		},
	}
	try:
		es_client.indices.put_index_template(name=template_name, body=body)
		return None
	except Exception as exc:
		msg = (
			f"Could not create stats index template '{template_name}': {exc}. "
			f"The ES user '{config.LOG_ES_USER}' may lack the "
			f"'manage_index_templates' cluster privilege. "
			f"Stats indices will still be created with default dynamic mappings."
		)
		print(f"[setup_logging] {msg}", file=sys.stderr)
		return msg


def _build_es_client() -> Elasticsearch:
	return Elasticsearch(
		hosts=[config.LOG_ES_HOST],
		basic_auth=(config.LOG_ES_USER, config.LOG_ES_PSWD) if config.LOG_ES_USER or config.LOG_ES_PSWD else None,
		verify_certs=False,
		request_timeout=10,
	)


def setup_logging() -> None:
	global _CONFIGURED
	global _STATS_REPORTER
	if _CONFIGURED:
		return

	root = logging.getLogger()
	root.handlers = []
	root.setLevel(logging.INFO)

	stream_handler = logging.StreamHandler(sys.stdout)
	stream_handler.setFormatter(logging.Formatter("%(name)s - %(levelname)s - %(message)s"))
	root.addHandler(stream_handler)

	for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
		log = logging.getLogger(name)
		log.handlers = []
		log.propagate = True

	# Suppress noisy INFO-level HTTP traces from elasticsearch transport
	# (e.g. "PUT http://…/_index_template/… [status:403 …]").
	logging.getLogger("elastic_transport.transport").setLevel(logging.WARNING)

	if config.LOG_OUTPUT_ES:
		global _ES_LOG_HANDLER
		es_client = _build_es_client()
		_deferred_warnings = []
		err = ensure_log_index_template(es_client)
		if err:
			_deferred_warnings.append(err)
		err = ensure_stats_index_template(es_client)
		if err:
			_deferred_warnings.append(err)
		es_handler = ElasticsearchLogHandler(
			es_client,
			index_prefix=config.LOG_INDEX_PREFIX,
			flush_interval=config.LOG_FLUSH_INTERVAL,
			batch_size=config.LOG_BATCH_SIZE,
		)
		_ES_LOG_HANDLER = es_handler
		root.addHandler(es_handler)
		_STATS_REPORTER = StatsReporter(
			es_client,
			index_prefix=config.STATS_INDEX_PREFIX,
			flush_interval=config.LOG_FLUSH_INTERVAL,
			batch_size=config.LOG_BATCH_SIZE,
		)

	_CONFIGURED = True

	# Replay deferred warnings now that logging is fully configured.
	# These will appear in both stdout and (if ES logging succeeded) ES.
	if config.LOG_OUTPUT_ES:
		_log = logging.getLogger(__name__)
		for _warn in _deferred_warnings:
			_log.warning(_warn)


def emit_stats_snapshot(stats: Dict[str, Any], perf_index: Optional[int]) -> None:
	if _STATS_REPORTER is None:
		return
	payload = {
		"timestamp": datetime.now(timezone.utc).isoformat(),
		"processed_total": int(stats.get("processed", 0) or 0),
		"failed_total": int(stats.get("failed", 0) or 0),
		"perf_index": perf_index,
	}
	ad = config.ADAPTIVE_DETAILS
	if ad:
		payload["pressure_score"] = ad.get("pressure_score")
		payload["quality_factor"] = ad.get("quality_factor")
		payload["effective_tps"] = ad.get("effective_tps")
	for minutes in (5, 15, 60):
		payload[f"{minutes}min_processed"] = int(stats.get(f"{minutes}min_processed", 0) or 0)
		payload[f"{minutes}min_failed"] = int(stats.get(f"{minutes}min_failed", 0) or 0)
		payload[f"{minutes}min_total"] = int(stats.get(f"{minutes}min_total", 0) or 0)

	# Token consumption stats
	_TOKEN_KEYS = [
		"token_total", "token_total_prompt", "token_total_completion",
	]
	for label in ("1min", "5min", "30min", "1h", "6h", "24h"):
		_TOKEN_KEYS.append(f"{label}_prompt_tokens")
		_TOKEN_KEYS.append(f"{label}_completion_tokens")
		_TOKEN_KEYS.append(f"{label}_total_tokens")
	for key in _TOKEN_KEYS:
		val = stats.get(key)
		if val is not None:
			payload[key] = int(val)

	# avg_tokens_per_log from perf_cacl EMA
	if ad:
		avg_eval = ad.get("avg_eval_tokens")
		if avg_eval is not None:
			payload["avg_tokens_per_log"] = avg_eval

	last_run = stats.get("last_run") if isinstance(stats, dict) else None
	if last_run:
		payload["last_run"] = last_run
	_STATS_REPORTER.emit(payload)


def shutdown_logging() -> None:
	"""Flush and close the ES log handler and stats reporter so that
	shutdown messages are guaranteed to reach Elasticsearch before the
	process exits.  Safe to call even when ES logging is disabled."""
	global _ES_LOG_HANDLER, _STATS_REPORTER

	if _ES_LOG_HANDLER is not None:
		try:
			_ES_LOG_HANDLER.close()
		except Exception:
			pass
		_ES_LOG_HANDLER = None

	if _STATS_REPORTER is not None:
		try:
			_STATS_REPORTER.close()
		except Exception:
			pass
		_STATS_REPORTER = None
