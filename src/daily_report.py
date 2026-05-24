#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         daily_report.py
Description:  Hierarchical daily report generation with multi-level LLM analysis.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import html
import json
import logging
import os
import re
import smtplib
import tomllib
from collections import Counter
from dataclasses import dataclass
from datetime import date, datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional

from dateutil import parser as date_parser

from .config import config
from .es_client import ESClient
from .executor.models import ActionRequest, ActionStatus
from .llm_prompt import build_daily_report_prompt, build_segment_prompt, build_pair_prompt, build_final_report_prompt, build_rule_generation_prompt
from .llm_backend import LLMBackend
from .llm_handler import stop_ollama_model
from .mailer import send_email

logger = logging.getLogger(__name__)


_VALID_DETAIL_LEVELS = frozenset({"minimal", "extended", "full"})


@dataclass
class DailyReportLLMConfig:
	MODEL: str
	MAX_TOKENS: int
	TEMPERATURE: float
	TOP_P: float
	TOP_K: int
	CONTEXT_LENGTH: int
	DETAIL_LEVEL: str = "minimal"

	# Backward-compatible aliases (read-only) for code that still
	# references the old OLLAMA_* names.
	@property
	def OLLAMA_MODEL(self) -> str:
		return self.MODEL

	@property
	def OLLAMA_NUM_PREDICT(self) -> int:
		return self.MAX_TOKENS

	@property
	def OLLAMA_TEMPERATURE(self) -> float:
		return self.TEMPERATURE

	@property
	def OLLAMA_TOP_P(self) -> float:
		return self.TOP_P

	@property
	def OLLAMA_TOP_K(self) -> int:
		return self.TOP_K

	@property
	def OLLAMA_CONTEXT_LENGTH(self) -> int:
		return self.CONTEXT_LENGTH


# Mapping from new field names to legacy TOML key aliases for backward
# compatibility.  load_daily_report_llm_config() tries the new name
# first, then falls back to the legacy key.
_DR_CONFIG_ALIASES: Dict[str, str] = {
	"MODEL": "OLLAMA_MODEL",
	"MAX_TOKENS": "OLLAMA_NUM_PREDICT",
	"TEMPERATURE": "OLLAMA_TEMPERATURE",
	"TOP_P": "OLLAMA_TOP_P",
	"TOP_K": "OLLAMA_TOP_K",
	"CONTEXT_LENGTH": "OLLAMA_CONTEXT_LENGTH",
}


def load_daily_report_llm_config(filepath: str) -> DailyReportLLMConfig:
	if not filepath:
		raise ValueError("Daily report LLM config path is empty.")

	try:
		with open(filepath, "rb") as file:
			raw_data = tomllib.load(file)
	except Exception as exc:
		raise RuntimeError(f"Failed to load daily report LLM config file {filepath}: {exc}") from exc

	if not isinstance(raw_data, dict) or not raw_data:
		raise ValueError(f"Daily report LLM config file {filepath} is empty or invalid.")

	if len(raw_data) != 1:
		raise ValueError("Daily report LLM config must contain exactly one model configuration.")

	payload = next(iter(raw_data.values()))
	if not isinstance(payload, dict):
		raise ValueError("Daily report LLM config entry must be an object.")

	_SENTINEL = object()

	def _resolve(new_key: str, old_key: str):
		v = payload.get(new_key, _SENTINEL)
		if v is _SENTINEL:
			v = payload.get(old_key, _SENTINEL)
		if v is _SENTINEL:
			raise KeyError(new_key)
		return v

	try:
		detail_level = str(payload.get("detail_level", "minimal")).strip().lower()
		if detail_level not in _VALID_DETAIL_LEVELS:
			raise ValueError(
				f"detail_level must be one of {sorted(_VALID_DETAIL_LEVELS)}, got {detail_level!r}"
			)
		return DailyReportLLMConfig(
			MODEL=str(_resolve("MODEL", "OLLAMA_MODEL")),
			MAX_TOKENS=int(_resolve("MAX_TOKENS", "OLLAMA_NUM_PREDICT")),
			TEMPERATURE=float(_resolve("TEMPERATURE", "OLLAMA_TEMPERATURE")),
			TOP_P=float(_resolve("TOP_P", "OLLAMA_TOP_P")),
			TOP_K=int(_resolve("TOP_K", "OLLAMA_TOP_K")),
			CONTEXT_LENGTH=int(_resolve("CONTEXT_LENGTH", "OLLAMA_CONTEXT_LENGTH")),
			DETAIL_LEVEL=detail_level,
		)
	except (KeyError, TypeError) as exc:
		raise ValueError(f"Daily report LLM config missing key: {exc}") from exc
	except ValueError as exc:
		raise ValueError(f"Daily report LLM config has invalid values: {exc}") from exc


def _strip_think(text: str) -> str:
	if not text:
		return ""
	cleaned = re.sub(r"<think\b[^>]*>.*?</think\s*>", "", text, flags=re.DOTALL | re.IGNORECASE)
	cleaned = re.sub(r"<think\b[^>]*>.*$", "", cleaned, flags=re.DOTALL | re.IGNORECASE)
	cleaned = re.sub(r"</think\s*>", "", cleaned, flags=re.IGNORECASE)
	return cleaned.strip()


def _extract_html_body(raw_html: str) -> str:
	if not raw_html:
		return ""
	lower = raw_html.lower()
	if "<body" not in lower:
		return raw_html.strip()
	start = lower.find("<body")
	if start == -1:
		return raw_html.strip()
	start = lower.find(">", start)
	if start == -1:
		return raw_html.strip()
	end = lower.rfind("</body>")
	if end == -1:
		return raw_html[start + 1 :].strip()
	return raw_html[start + 1 : end].strip()


def _parse_timestamp(value: str) -> datetime:
	if not value:
		return datetime.min
	try:
		return date_parser.isoparse(value)
	except Exception:
		return datetime.min


def _detect_processed_value_for_index(es_client: ESClient, index_name: str) -> Any:
	"""Detect the correct value for ai.processed=true for a specific index."""
	try:
		mappings = es_client.es.indices.get_mapping(index=index_name)
	except Exception:
		return True

	for index_data in mappings.values():
		props = index_data.get("mappings", {}).get("properties", {})
		ai_props = props.get("ai", {}).get("properties", {})
		processed_mapping = ai_props.get("processed", {})
		field_type = processed_mapping.get("type")
		if field_type in ("boolean", None):
			return True
		return "true"

	return True


# Additional ES _source fields fetched when detail_level is "extended".
_EXTENDED_SOURCE_FIELDS = [
	"@timestamp", "ai",
	"src_ip", "dest_ip", "src_port", "dest_port",
	"src_hostname", "dest_hostname",
	"event_type", "proto",
	# extended fields
	"alert.signature", "alert.severity", "alert.signature_id",
	"tls.version", "tls.sni", "tls.ja3.hash",
	"http.hostname", "http.http_method", "http.url", "http.status",
	"dns.rrname", "dns.rcode",
	"flow.bytes_toserver", "flow.bytes_toclient",
]

# Keys extracted from the extended fields into the item dict.
_EXTENDED_ITEM_KEYS: List[tuple[str, str]] = [
	# (dotted ES path, flat key in item dict)
	("alert.signature", "alert_signature"),
	("alert.severity", "alert_severity"),
	("alert.signature_id", "alert_signature_id"),
	("tls.version", "tls_version"),
	("tls.sni", "tls_sni"),
	("tls.ja3.hash", "tls_ja3_hash"),
	("http.hostname", "http_hostname"),
	("http.http_method", "http_method"),
	("http.url", "http_url"),
	("http.status", "http_status"),
	("dns.rrname", "dns_rrname"),
	("dns.rcode", "dns_rcode"),
	("flow.bytes_toserver", "flow_bytes_toserver"),
	("flow.bytes_toclient", "flow_bytes_toclient"),
]


def _resolve_nested(source: Dict, dotted_key: str) -> str:
	"""Resolve a dotted key like 'alert.signature' from a nested dict."""
	parts = dotted_key.split(".")
	obj: Any = source
	for part in parts:
		if not isinstance(obj, dict):
			return ""
		obj = obj.get(part)
		if obj is None:
			return ""
	if isinstance(obj, (dict, list)):
		import json as _json
		return _json.dumps(obj, ensure_ascii=False, default=str)
	return str(obj)


def fetch_processed_summaries(
	es_client: ESClient,
	report_date: date,
	detail_level: str = "minimal",
) -> List[Dict[str, str]]:
	index_name = f"suricata-eve-{report_date.strftime('%Y.%m.%d')}"

	# Check index existence
	try:
		if not es_client.es.indices.exists(index=index_name):
			logger.warning("Index %s does not exist; no summaries to fetch.", index_name)
			return []
	except Exception as exc:
		logger.warning("Failed to check index existence for %s: %s", index_name, exc)

	# Detect processed value specifically for this index (not the cached global one)
	processed_value = _detect_processed_value_for_index(es_client, index_name)

	logger.info(
		"fetch_processed_summaries: index=%s, processed_value=%r (type=%s), detail_level=%s",
		index_name, processed_value, type(processed_value).__name__, detail_level,
	)

	# Determine which _source fields to fetch
	if detail_level == "full":
		source_fields = True  # fetch all fields
	elif detail_level == "extended":
		source_fields = _EXTENDED_SOURCE_FIELDS
	else:
		source_fields = [
			"@timestamp", "ai",
			"src_ip", "dest_ip", "src_port", "dest_port",
			"src_hostname", "dest_hostname",
			"event_type", "proto",
		]

	query: Dict[str, Any] = {
		"query": {
			"bool": {
				"filter": [
					{"term": {"ai.processed": processed_value}},
					{"exists": {"field": "ai.summary"}},
				]
			}
		},
		"sort": [{"@timestamp": {"order": "asc"}}],
		"_source": source_fields,
	}

	items: List[Dict[str, str]] = []
	scroll_id = None

	try:
		response = es_client.es.search(
			index=index_name,
			body=query,
			scroll="2m",
			size=config.DAILY_REPORT_FETCH_SIZE,
		)
		scroll_id = response.get("_scroll_id")
		hits = response.get("hits", {}).get("hits", [])

		while hits:
			for hit in hits:
				source = hit.get("_source", {})
				ai = source.get("ai", {}) or {}
				summary = ai.get("summary")
				timestamp = source.get("@timestamp")
				threat_level = ai.get("threat_level", "")
				if not (summary and timestamp):
					continue

				item: Dict[str, str] = {
					"timestamp": str(timestamp),
					"summary": str(summary),
					"threat_level": str(threat_level) if threat_level else "",
					"src_ip": str(source.get("src_ip", "")),
					"dest_ip": str(source.get("dest_ip", "")),
					"src_hostname": str(source.get("src_hostname", "")),
					"dest_hostname": str(source.get("dest_hostname", "")),
					"src_port": str(source.get("src_port", "")),
					"dest_port": str(source.get("dest_port", "")),
					"event_type": str(source.get("event_type", "")),
					"proto": str(source.get("proto", "")),
				}

				# Extended / full: pull additional fields
				if detail_level in ("extended", "full"):
					item["security_hint"] = str(ai.get("security_hint", ""))
					item["recommendation"] = str(ai.get("recommendation", ""))
					for dotted, flat in _EXTENDED_ITEM_KEYS:
						item[flat] = _resolve_nested(source, dotted)

				# Full: preserve entire _source for serialization
				if detail_level == "full":
					import json as _json
					item["_raw_source"] = _json.dumps(source, ensure_ascii=False, default=str)

				items.append(item)

			response = es_client.es.scroll(scroll_id=scroll_id, scroll="2m")
			scroll_id = response.get("_scroll_id")
			hits = response.get("hits", {}).get("hits", [])

	except Exception as exc:
		logger.warning("Failed to fetch daily report summaries for %s: %s", index_name, exc)
		return []
	finally:
		if scroll_id:
			try:
				es_client.es.clear_scroll(scroll_id=scroll_id)
			except Exception:
				pass

	items.sort(key=lambda item: _parse_timestamp(item.get("timestamp", "")))
	return items


# ---------------------------------------------------------------------------
# Communication-pair grouping and time-gap splitting
# ---------------------------------------------------------------------------

def _make_pair_key(src_id: str, dest_id: str) -> str:
	"""Create a normalized communication pair key (alphabetically sorted identifiers).

	Identifiers should be hostnames when available, falling back to IPs.
	"""
	a, b = (src_id, dest_id) if src_id <= dest_id else (dest_id, src_id)
	return f"{a} <-> {b}"


def _resolve_pair_label(items: List[Dict[str, str]], pair_key: str) -> tuple[str, str]:
	"""Resolve display labels for a pair.

	Pair keys are now based on hostname (or IP when hostname is unavailable).
	This function resolves each identifier back to a rich label of the form
	``hostname(ip)`` when both pieces of information are available.
	"""
	parts = pair_key.split(" <-> ")
	if len(parts) != 2:
		return pair_key, pair_key
	id_a, id_b = parts

	# Build a quick lookup: identifier -> set of associated IPs / hostnames
	ip_for: Dict[str, str] = {}  # identifier -> first seen IP (when id is hostname)
	host_for: Dict[str, str] = {}  # identifier -> first seen hostname (when id is IP)

	for item in items:
		src_ip = item.get("src_ip", "").strip()
		dest_ip = item.get("dest_ip", "").strip()
		src_host = item.get("src_hostname", "").strip()
		dest_host = item.get("dest_hostname", "").strip()

		# For each side, if the identifier is a hostname, record the IP;
		# if the identifier is an IP, record the hostname.
		for ident, host, ip in [
			(id_a, src_host, src_ip), (id_a, dest_host, dest_ip),
			(id_b, src_host, src_ip), (id_b, dest_host, dest_ip),
		]:
			if ident == host and ip and ident not in ip_for:
				ip_for[ident] = ip
			elif ident == ip and host and ident not in host_for:
				host_for[ident] = host

	def _label(ident: str) -> str:
		if ident in ip_for:
			# Identifier is a hostname; show hostname(ip)
			return f"{ident}({ip_for[ident]})"
		if ident in host_for:
			# Identifier is an IP but we found a hostname
			return f"{host_for[ident]}({ident})"
		# No enrichment possible
		return ident

	return _label(id_a), _label(id_b)


def group_by_comm_pair(items: List[Dict[str, str]]) -> Dict[str, List[Dict[str, str]]]:
	"""Group event items by normalized communication pair (src_ip <-> dest_ip).

	Returns a dict mapping pair_key -> list of items, each list sorted by timestamp.
	"""
	from collections import OrderedDict

	groups: Dict[str, List[Dict[str, str]]] = {}
	for item in items:
		src_ip = item.get("src_ip", "").strip()
		dest_ip = item.get("dest_ip", "").strip()
		src_hostname = item.get("src_hostname", "").strip()
		dest_hostname = item.get("dest_hostname", "").strip()
		# Prefer hostname for pair classification; fall back to IP.
		src_id = src_hostname or src_ip
		dest_id = dest_hostname or dest_ip
		if not src_id or not dest_id:
			key = "(unknown)"
		else:
			key = _make_pair_key(src_id, dest_id)
		groups.setdefault(key, []).append(item)

	# Sort each group by timestamp
	for key in groups:
		groups[key].sort(key=lambda x: _parse_timestamp(x.get("timestamp", "")))

	# Sort groups: pairs with more events come first
	sorted_groups = OrderedDict(
		sorted(groups.items(), key=lambda kv: -len(kv[1]))
	)
	return sorted_groups


def split_by_time_gap(
	items: List[Dict[str, str]],
	gap_seconds: int = 1800,
	max_items_per_segment: Optional[int] = None,
) -> List[List[Dict[str, str]]]:
	"""Split a list of time-sorted items into segments based on a time gap threshold.

	If the gap between two consecutive events exceeds gap_seconds, a new segment is started.
	If max_items_per_segment is set, long continuous streams are also chunked by count.
	Returns a list of segments, each being a list of items.
	"""
	if not items:
		return []
	if max_items_per_segment is not None and max_items_per_segment <= 0:
		raise ValueError("max_items_per_segment must be > 0.")

	segments: List[List[Dict[str, str]]] = []
	current_segment: List[Dict[str, str]] = [items[0]]
	prev_ts = _parse_timestamp(items[0].get("timestamp", ""))

	for item in items[1:]:
		curr_ts = _parse_timestamp(item.get("timestamp", ""))
		should_split = False
		if curr_ts != datetime.min and prev_ts != datetime.min:
			gap = (curr_ts - prev_ts).total_seconds()
			if gap > gap_seconds:
				should_split = True
		if (
			not should_split
			and max_items_per_segment is not None
			and len(current_segment) >= max_items_per_segment
		):
			should_split = True
		if should_split:
			segments.append(current_segment)
			current_segment = []
		current_segment.append(item)
		prev_ts = curr_ts

	if current_segment:
		segments.append(current_segment)

	return segments


def _detect_keyword_field(es_client: ESClient, index_name: str, field: str) -> str:
	"""Detect if a field is keyword-typed or has a .keyword sub-field, return the best field name for terms agg."""
	try:
		mappings = es_client.es.indices.get_mapping(index=index_name)
	except Exception:
		return field

	for index_data in mappings.values():
		props = index_data.get("mappings", {}).get("properties", {})

		# Handle nested fields like "ai.threat_level"
		parts = field.split(".")
		current = props
		for part in parts[:-1]:
			current = current.get(part, {}).get("properties", {})
		field_mapping = current.get(parts[-1], {})

		field_type = field_mapping.get("type")
		if field_type == "keyword":
			return field
		if field_type in ("text", None):
			# Check for .keyword sub-field
			sub_fields = field_mapping.get("fields", {})
			if "keyword" in sub_fields:
				return f"{field}.keyword"
		if field_type is None and "properties" in field_mapping:
			# Nested object, skip
			continue
		return field

	return field


def fetch_daily_stats(es_client: ESClient, report_date: date) -> Dict[str, Any]:
	"""Fetch full-day statistics from the raw ES index.

	Returns stats dict with:
	- total_events: all raw events in the index
	- ai_processed_count: events where ai.processed == true
	- ai_has_summary_count: events where ai.summary exists (subset of ai_processed)
	- event_type_breakdown: breakdown of all event types
	- threat_level_breakdown: breakdown of ai.threat_level (only among ai-processed events)
	- time_min/time_max: earliest/latest timestamp
	"""
	index_name = f"suricata-eve-{report_date.strftime('%Y.%m.%d')}"

	empty_stats: Dict[str, Any] = {
		"total_events": 0,
		"ai_processed_count": 0,
		"ai_has_summary_count": 0,
		"event_type_breakdown": {},
		"threat_level_breakdown": {},
		"time_min": None,
		"time_max": None,
	}

	# Check index existence first
	try:
		if not es_client.es.indices.exists(index=index_name):
			logger.warning("Index %s does not exist; daily stats will be empty.", index_name)
			return empty_stats
	except Exception as exc:
		logger.warning("Failed to check index existence for %s: %s", index_name, exc)

	# Detect correct field names and processed value for this specific index
	event_type_field = _detect_keyword_field(es_client, index_name, "event_type")
	threat_level_field = _detect_keyword_field(es_client, index_name, "ai.threat_level")
	processed_value = _detect_processed_value_for_index(es_client, index_name)

	logger.info(
		"Daily stats detection for %s: event_type=%s, threat_level=%s, processed_value=%r",
		index_name, event_type_field, threat_level_field, processed_value,
	)

	query: Dict[str, Any] = {
		"size": 0,
		"query": {"match_all": {}},
		"aggs": {
			"total_events": {"value_count": {"field": "@timestamp"}},
			"event_types": {"terms": {"field": event_type_field, "size": 50}},
			"time_range": {
				"stats": {"field": "@timestamp"},
			},
			# ai.processed == true (using correct type for this index)
			"ai_processed": {
				"filter": {"term": {"ai.processed": processed_value}},
				"aggs": {
					# Among ai-processed events, count those with ai.summary
					"has_summary": {
						"filter": {"exists": {"field": "ai.summary"}},
					},
					# Among ai-processed events, breakdown by ai.threat_level
					"threat_levels": {
						"filter": {"exists": {"field": "ai.threat_level"}},
						"aggs": {
							"levels": {
								"terms": {"field": threat_level_field, "size": 20},
							}
						},
					},
				},
			},
		},
	}

	stats: Dict[str, Any] = dict(empty_stats)

	try:
		response = es_client.es.search(index=index_name, body=query)
		aggs = response.get("aggregations", {})

		total_agg = aggs.get("total_events", {})
		stats["total_events"] = int(total_agg.get("value", 0))

		time_agg = aggs.get("time_range", {})
		stats["time_min"] = time_agg.get("min_as_string")
		stats["time_max"] = time_agg.get("max_as_string")

		for bucket in aggs.get("event_types", {}).get("buckets", []):
			stats["event_type_breakdown"][bucket["key"]] = bucket["doc_count"]

		ai_agg = aggs.get("ai_processed", {})
		stats["ai_processed_count"] = int(ai_agg.get("doc_count", 0))

		summary_agg = ai_agg.get("has_summary", {})
		stats["ai_has_summary_count"] = int(summary_agg.get("doc_count", 0))

		threat_agg = ai_agg.get("threat_levels", {})
		for bucket in threat_agg.get("levels", {}).get("buckets", []):
			stats["threat_level_breakdown"][bucket["key"]] = bucket["doc_count"]

		logger.info(
			"Daily stats for %s: total=%s, ai_processed=%s, ai_has_summary=%s, threat_levels=%s",
			index_name, stats["total_events"], stats["ai_processed_count"],
			stats["ai_has_summary_count"], stats["threat_level_breakdown"],
		)

	except Exception as exc:
		logger.error("Failed to fetch daily stats for %s: %s", index_name, exc, exc_info=True)

	return stats


def call_daily_report_llm(prompt: str, llm_conf: DailyReportLLMConfig, backend: LLMBackend) -> str:
	if not prompt:
		return ""

	# Route to model-specific backend when the profile differs from the
	# injected default (e.g. daily report using an OpenAI model while
	# the default backend is Ollama).
	effective_backend = backend
	profile = config.MODEL_PROFILES.get(llm_conf.MODEL)
	if profile is not None and (
		profile.backend_type != backend.backend_type
		or profile.backend_base_url
	):
		from .backends import create_backend_for_model
		effective_backend = create_backend_for_model(profile)

	result = effective_backend.generate(
		model=llm_conf.MODEL,
		prompt=prompt,
		max_tokens=llm_conf.MAX_TOKENS,
		context_length=llm_conf.CONTEXT_LENGTH,
		temperature=llm_conf.TEMPERATURE,
		top_p=llm_conf.TOP_P,
		top_k=llm_conf.TOP_K,
	)
	raw = result.text

	cleaned = _strip_think(raw)
	cleaned = cleaned.replace("```html", "").replace("```", "").strip()
	return _extract_html_body(cleaned)


def _is_provider_sensitive_error(exc: Exception) -> bool:
	response = getattr(exc, "response", None)
	if getattr(response, "status_code", None) != 422:
		return False
	text = str(getattr(response, "text", "") or "").lower()
	return (
		"new_sensitive" in text
		or "output_sensitive" in text
		or "input_sensitive" in text
		or "1027" in text
		or "1026" in text
	)


def _format_counter(counter: Counter[str], *, limit: int = 5) -> str:
	if not counter:
		return "none"
	parts = [
		f"{label}: {count}"
		for label, count in counter.most_common(limit)
	]
	remaining = sum(counter.values()) - sum(count for _, count in counter.most_common(limit))
	if remaining > 0:
		parts.append(f"other: {remaining}")
	return ", ".join(parts)


def _build_segment_fallback_analysis(
	host_a: str,
	host_b: str,
	segment: List[Dict[str, str]],
) -> str:
	if not segment:
		return "Deterministic fallback summary: no events are available for this segment."

	time_start = segment[0].get("timestamp", "N/A")
	time_end = segment[-1].get("timestamp", "N/A")
	threat_levels: Counter[str] = Counter(
		item.get("threat_level") or "未知"
		for item in segment
	)
	event_types: Counter[str] = Counter(
		item.get("event_type") or "未知"
		for item in segment
	)
	protocols: Counter[str] = Counter(
		item.get("proto") or "未知"
		for item in segment
	)

	return (
		"Deterministic fallback summary: provider content-safety policy blocked "
		"LLM generation for this segment, so the report uses structured counts. "
		f"Communication pair {host_a} <-> {host_b} had {len(segment)} events "
		f"from {time_start} to {time_end}. "
		f"Threat level distribution: {_format_counter(threat_levels)}. "
		f"Event type distribution: {_format_counter(event_types)}. "
		f"Protocol distribution: {_format_counter(protocols)}. "
		"Review the raw logs and per-event real-time analysis for details."
	)


_HIGH_THREAT_LEVELS = {"高", "严重"}

# Severity order for sorting: higher threat first
_THREAT_LEVEL_ORDER = {"严重": 0, "高": 1, "中": 2, "低": 3, "无危": 4}


def build_report_html(
	report_date: date,
	items: List[Dict[str, str]],
	analysis_html: str,
	daily_stats: Optional[Dict[str, Any]] = None,
	pair_results: Optional[List[Dict[str, Any]]] = None,
) -> str:
	report_date_str = report_date.strftime("%Y-%m-%d")

	# --- Full-day statistics section ---
	stats = daily_stats or {}
	total_events = stats.get("total_events", 0)
	ai_processed_count = stats.get("ai_processed_count", 0)
	ai_has_summary_count = stats.get("ai_has_summary_count", 0)
	# Compute high/critical count from ES aggregation (not from items list)
	high_count_from_stats = sum(
		count for level, count in stats.get("threat_level_breakdown", {}).items()
		if level in _HIGH_THREAT_LEVELS
	)
	time_min = stats.get("time_min") or "N/A"
	time_max = stats.get("time_max") or "N/A"
	event_type_bd = stats.get("event_type_breakdown", {})
	threat_level_bd = stats.get("threat_level_breakdown", {})

	# Build event type breakdown rows
	et_rows = []
	for etype, count in sorted(event_type_bd.items(), key=lambda x: -x[1]):
		et_rows.append(f"<tr><td>{html.escape(str(etype))}</td><td>{count}</td></tr>")
	et_table = (
		"<table>"
		"<thead><tr><th>事件类型</th><th>数量</th></tr></thead>"
		f"<tbody>{''.join(et_rows) if et_rows else '<tr><td colspan=2>无数据</td></tr>'}</tbody>"
		"</table>"
	)

	# Build threat level breakdown rows (sorted by severity: 严重 > 高 > 中 > 低 > 无危)
	tl_rows = []
	for level, count in sorted(threat_level_bd.items(), key=lambda x: _THREAT_LEVEL_ORDER.get(x[0], 99)):
		tl_rows.append(f"<tr><td>{html.escape(str(level))}</td><td>{count}</td></tr>")
	tl_table = (
		"<table>"
		"<thead><tr><th>威胁等级</th><th>数量</th></tr></thead>"
		f"<tbody>{''.join(tl_rows) if tl_rows else '<tr><td colspan=2>无数据</td></tr>'}</tbody>"
		"</table>"
	)

	# --- Filter: only show high / critical threat events ---
	high_items = [
		item for item in items
		if item.get("threat_level", "") in _HIGH_THREAT_LEVELS
	]
	high_count = len(high_items)

	rows = []
	for item in high_items:
		ts = html.escape(item.get("timestamp", ""))
		level = html.escape(item.get("threat_level", ""))
		summary = html.escape(item.get("summary", ""))
		color = "#dc2626" if item.get("threat_level") == "严重" else "#ea580c"
		rows.append(
			f'<tr><td>{ts}</td><td style="color:{color};font-weight:bold;">{level}</td><td>{summary}</td></tr>'
		)

	table_html = (
		"<table>"
		'<thead><tr><th>时间</th><th>威胁等级</th><th>摘要</th></tr></thead>'
		f"<tbody>{''.join(rows) if rows else '<tr><td colspan=3>无高危/严重事件</td></tr>'}</tbody>"
		"</table>"
	)

	analysis_block = analysis_html.strip() if analysis_html else "<p>无可用分析内容。</p>"

	# --- Per-pair analysis section ---
	pair_section_html = ""
	if pair_results:
		pair_cards = []
		for pr in pair_results:
			pair_label = html.escape(str(pr.get("pair", "N/A")))
			p_event_count = pr.get("event_count", 0)
			p_segment_count = pr.get("segment_count", 0)
			p_analysis = html.escape(str(pr.get("analysis", "(无分析)"))).replace("\n", "<br/>")
			pair_cards.append(
				f'<div class="pair-card">'
				f'<h4>{pair_label}</h4>'
				f'<div class="pair-meta">事件数: {p_event_count} | 时间段数: {p_segment_count}</div>'
				f'<div class="pair-analysis">{p_analysis}</div>'
				f'</div>'
			)
		pair_section_html = (
			'<div class="section">'
			'<h2>通信对分析明细</h2>'
			f'<div class="pair-grid">{"".join(pair_cards)}</div>'
			'</div>'
		)

	return f"""<!doctype html>
<html lang=\"zh\">
<head>
  <meta charset=\"utf-8\" />
  <title>Suricata AI 每日日报 - {report_date_str}</title>
  <style>
	body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; color: #1f2937; margin: 24px; }}
	h1, h2, h3, h4 {{ color: #0f172a; }}
	.meta {{ margin-bottom: 16px; color: #475569; }}
	table {{ border-collapse: collapse; width: 100%; margin-top: 12px; }}
	th, td {{ border: 1px solid #e2e8f0; padding: 8px 10px; text-align: left; vertical-align: top; }}
	th {{ background: #f8fafc; }}
	.section {{ margin-top: 24px; }}
	.stats-grid {{ display: flex; flex-wrap: wrap; gap: 16px; margin-top: 12px; }}
	.stat-card {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px 16px; min-width: 180px; }}
	.stat-card .label {{ font-size: 13px; color: #64748b; }}
	.stat-card .value {{ font-size: 22px; font-weight: bold; color: #0f172a; margin-top: 4px; }}
	.pair-grid {{ display: flex; flex-direction: column; gap: 12px; margin-top: 12px; }}
	.pair-card {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; }}
	.pair-card h4 {{ margin: 0 0 8px 0; color: #1e40af; }}
	.pair-meta {{ font-size: 13px; color: #64748b; margin-bottom: 8px; }}
	.pair-analysis {{ font-size: 14px; line-height: 1.6; }}
  </style>
</head>
<body>
  <h1>Suricata AI 每日日报</h1>
  <div class=\"meta\">日期：{report_date_str}</div>

  <div class=\"section\">
	<h2>全天流量概览</h2>
	<div class=\"stats-grid\">
	  <div class=\"stat-card\"><div class=\"label\">原始事件总数</div><div class=\"value\">{total_events}</div></div>
	  <div class=\"stat-card\"><div class=\"label\">AI 已处理事件</div><div class=\"value\">{ai_processed_count}</div></div>
	  <div class=\"stat-card\"><div class=\"label\">AI 有摘要事件</div><div class=\"value\">{ai_has_summary_count}</div></div>
	  <div class=\"stat-card\"><div class=\"label\">高危/严重事件</div><div class=\"value\">{high_count_from_stats}</div></div>
	  <div class=\"stat-card\"><div class=\"label\">通信对总数</div><div class=\"value\">{len(pair_results) if pair_results else 0}</div></div>
	  <div class=\"stat-card\"><div class=\"label\">数据时间范围</div><div class=\"value\" style=\"font-size:14px;\">{html.escape(str(time_min))}<br/>~ {html.escape(str(time_max))}</div></div>
	</div>
  </div>

  <div class=\"section\">
	<h2>事件类型分布</h2>
	{et_table}
  </div>

  <div class=\"section\">
	<h2>威胁等级分布</h2>
	{tl_table}
  </div>

  <div class=\"section\">
	<h2>AI 综合分析与关联分析</h2>
	{analysis_block}
  </div>

  {pair_section_html}

  <div class=\"section\">
	<h2>高危/严重事件明细（共 {high_count} 条）</h2>
	{table_html}
  </div>
</body>
</html>"""


def _save_report_html(report_date: date, html_body: str) -> Optional[str]:
	if not config.DAILY_REPORT_OUTPUT_DIR:
		return None

	try:
		os.makedirs(config.DAILY_REPORT_OUTPUT_DIR, exist_ok=True)
		filename = f"daily_report_{report_date.strftime('%Y%m%d')}.html"
		filepath = os.path.join(config.DAILY_REPORT_OUTPUT_DIR, filename)
		with open(filepath, "w", encoding="utf-8") as file:
			file.write(html_body)
		return filepath
	except Exception as exc:
		logger.warning("Failed to save daily report HTML: %s", exc)
		return None


def send_daily_report_email(report_date: date, html_body: str) -> list[str]:
	"""Send the daily report email.  Returns the resolved recipient list."""
	subject_prefix = config.DAILY_REPORT_SUBJECT_PREFIX or "Suricata AI 每日日报"
	exp_tag = config.DAILY_REPORT_EXPERIMENT_TAG
	if exp_tag:
		subject = f"[EXP-{exp_tag}] {subject_prefix} - {report_date.strftime('%Y-%m-%d')}"
	else:
		subject = f"{subject_prefix} - {report_date.strftime('%Y-%m-%d')}"

	from .mailer import get_recipients_for_event
	recipients = get_recipients_for_event("daily_report")
	if not recipients:
		raise RuntimeError("No recipients resolved for daily_report event. Check U-A-P user database.")
	success = send_email(subject, html_body, recipients=recipients)
	if not success:
		raise RuntimeError("Failed to send daily report email via configured mailer.")
	return recipients


class DailyReportService:
	def __init__(self, es_client: Optional[ESClient] = None, executor: Optional[Any] = None, agent_identity: Optional[Any] = None, orchestrator: Optional[Any] = None, backend: Optional[LLMBackend] = None):
		self.es_client = es_client or ESClient()
		self._llm_conf: Optional[DailyReportLLMConfig] = None
		self._executor = executor
		self._orchestrator = orchestrator

		# LLM backend — injected or auto-created.
		if backend is not None:
			self._backend: Optional[LLMBackend] = backend
		else:
			from .backends import create_backend
			self._backend = create_backend()

		# Agent identity — borrowed from LLMHandler, not owned by this instance.
		self._agent_identity = agent_identity
		if agent_identity is not None:
			logger.info(
				"DailyReportService: using Agent identity (user_id=%s).",
				agent_identity.actor_id,
			)

	@property
	def executor(self):
		return self._executor

	@executor.setter
	def executor(self, value) -> None:
		self._executor = value

	def _get_llm_conf(self) -> DailyReportLLMConfig:
		if self._llm_conf is None:
			self._llm_conf = load_daily_report_llm_config(config.DAILY_REPORT_LLM_CONFIG_FILE)
		return self._llm_conf

	def _analyze_segment(
		self,
		host_a: str,
		host_b: str,
		segment: List[Dict[str, str]],
		llm_conf: DailyReportLLMConfig,
	) -> str:
		"""Analyze a single time segment of a communication pair via LLM."""
		prompt = build_segment_prompt(host_a, host_b, segment, detail_level=llm_conf.DETAIL_LEVEL)
		if not prompt:
			return ""
		try:
			result = call_daily_report_llm(prompt, llm_conf, backend=self._backend)
			return result.strip() if result else ""
		except Exception as exc:
			if _is_provider_sensitive_error(exc):
				logger.warning(
					"Segment LLM analysis blocked by provider content-safety policy "
					"for %s <-> %s; using deterministic fallback summary.",
					host_a, host_b,
				)
				return _build_segment_fallback_analysis(host_a, host_b, segment)
			logger.error(
				"Segment LLM analysis failed for %s <-> %s: %s",
				host_a, host_b, exc,
			)
			return ""

	def _analyze_pair(
		self,
		host_a: str,
		host_b: str,
		pair_items: List[Dict[str, str]],
		llm_conf: DailyReportLLMConfig,
		gap_seconds: int,
	) -> Dict[str, Any]:
		"""Analyze a communication pair: split into segments, analyze each, then combine.

		Returns a dict with keys: pair, host_a, host_b, event_count, segment_count, max_threat, analysis.
		"""
		pair_label = f"{host_a} <-> {host_b}"

		# Compute max threat level across all items in the pair
		max_threat = ""
		max_threat_rank = 999
		for _item in pair_items:
			tl = _item.get("threat_level", "")
			rank = _THREAT_LEVEL_ORDER.get(tl, 99)
			if rank < max_threat_rank:
				max_threat_rank = rank
				max_threat = tl

		result: Dict[str, Any] = {
			"pair": pair_label,
			"host_a": host_a,
			"host_b": host_b,
			"event_count": len(pair_items),
			"segment_count": 0,
			"max_threat": max_threat,
			"analysis": "",
		}

		segments = split_by_time_gap(
			pair_items,
			gap_seconds,
			max_items_per_segment=config.DAILY_REPORT_MAX_SEGMENT_EVENTS,
		)
		result["segment_count"] = len(segments)

		if not segments:
			result["analysis"] = "(无事件)"
			return result

		logger.info(
			"Analyzing pair %s: %d events, %d segments",
			pair_label, len(pair_items), len(segments),
		)

		# Level 1: analyze each segment
		segment_analyses: List[Dict[str, str]] = []
		for seg_idx, segment in enumerate(segments):
			time_start = segment[0].get("timestamp", "N/A")
			time_end = segment[-1].get("timestamp", "N/A")
			time_range = f"{time_start} ~ {time_end}"

			logger.info(
				"  Segment %d/%d for %s: %d events (%s)",
				seg_idx + 1, len(segments), pair_label, len(segment), time_range,
			)

			seg_analysis = self._analyze_segment(host_a, host_b, segment, llm_conf)
			segment_analyses.append({
				"time_range": time_range,
				"analysis": seg_analysis if seg_analysis else "(分析失败)",
			})

		# Level 2: combine segments into pair analysis
		if len(segment_analyses) == 1:
			# Only one segment — use its analysis directly as pair analysis
			result["analysis"] = segment_analyses[0]["analysis"]
		else:
			# Multiple segments — call LLM to combine
			pair_prompt = build_pair_prompt(host_a, host_b, segment_analyses)
			if pair_prompt:
				try:
					pair_analysis = call_daily_report_llm(pair_prompt, llm_conf, backend=self._backend)
					result["analysis"] = pair_analysis.strip() if pair_analysis else "(合并分析失败)"
				except Exception as exc:
					logger.error("Pair LLM analysis failed for %s: %s", pair_label, exc)
					# Fallback: concatenate segment analyses
					fallback_lines = []
					for sa in segment_analyses:
						fallback_lines.append(f"[{sa['time_range']}] {sa['analysis']}")
					result["analysis"] = "\n".join(fallback_lines)

		return result

	# ── Rule generation pipeline ──────────────────────────────────────────

	def _collect_existing_sids(self) -> List[int]:
		"""Scan the local rules directory for existing SIDs."""
		import re as _re
		sid_re = _re.compile(r"sid\s*:\s*(\d+)")
		sids: List[int] = []
		rules_dir = os.path.join(config.GIT_LOCAL_REPO_PATH, config.GIT_RULES_PATH)
		if not os.path.isdir(rules_dir):
			return sids
		for root, _dirs, files in os.walk(rules_dir):
			for fname in files:
				if not fname.endswith(".rules"):
					continue
				try:
					with open(os.path.join(root, fname), "r", encoding="utf-8") as f:
						for line in f:
							m = sid_re.search(line)
							if m:
								sids.append(int(m.group(1)))
				except Exception:
					pass
		return sids

	def _run_rule_generation(
		self,
		pair_results: List[Dict[str, Any]],
		llm_conf: DailyReportLLMConfig,
		report_date: date,
	) -> None:
		"""Post-report: route to agent or pipeline mode for rule generation."""
		if not config.GIT_ENABLED or self._executor is None:
			return

		# Agent mode: orchestrator drives the full decision flow
		if self._orchestrator is not None:
			self._run_rule_generation_agent(pair_results, llm_conf, report_date)
			return

		# Pipeline mode: legacy hardcoded path
		self._run_rule_generation_pipeline(pair_results, llm_conf, report_date)

	def _run_rule_generation_agent(
		self,
		pair_results: List[Dict[str, Any]],
		llm_conf: DailyReportLLMConfig,
		report_date: date,
	) -> None:
		"""Agent mode: let the orchestrator decide which pairs need rules and PR."""
		from .llm_prompt import build_daily_report_agent_system_prompt, build_daily_report_agent_user_message
		from .tool_schema import capabilities_to_tools

		# Filter to high/critical pairs (same filter as pipeline — give agent focused context)
		high_pairs: List[str] = []
		for pr in pair_results:
			threat = pr.get("max_threat", "")
			if threat in ("高", "严重"):
				snippet = pr.get("analysis", "")[:1500]
				label = pr.get("pair", "unknown")
				high_pairs.append(f"[{label}] (威胁:{threat})\n{snippet}")

		if not high_pairs:
			logger.info("No high-threat pairs found; skipping rule generation (agent mode).")
			return

		existing_sids = self._collect_existing_sids()
		date_str = report_date.strftime("%Y-%m-%d")

		system_prompt = build_daily_report_agent_system_prompt()
		user_message = build_daily_report_agent_user_message(
			high_pairs=high_pairs,
			existing_sids=existing_sids,
			report_date=date_str,
		)
		tools = capabilities_to_tools(
			self._orchestrator.registry,
			actor_role="Agent",
		)

		try:
			orch_result = self._orchestrator.run(system_prompt, user_message, tools)
		except Exception as exc:
			logger.error(
				"Agent-mode rule generation failed: %s. Falling back to pipeline mode.",
				exc,
			)
			try:
				self._run_rule_generation_pipeline(pair_results, llm_conf, report_date)
			except Exception as fallback_exc:
				logger.error("Pipeline fallback also failed: %s", fallback_exc)
			return

		logger.info(
			"Agent-mode rule generation complete: %d tool calls, %d rounds, terminated_by=%s",
			len(orch_result.tool_calls_made),
			orch_result.rounds,
			orch_result.terminated_by,
		)

	def _run_rule_generation_pipeline(
		self,
		pair_results: List[Dict[str, Any]],
		llm_conf: DailyReportLLMConfig,
		report_date: date,
	) -> None:
		"""Pipeline mode (legacy): ask LLM to suggest Suricata rules, validate, commit, PR."""
		if not config.GIT_ENABLED or self._executor is None:
			return

		# Filter to high/critical pairs
		high_pairs: List[str] = []
		for pr in pair_results:
			threat = pr.get("max_threat", "")
			if threat in ("高", "严重"):
				snippet = pr.get("analysis", "")[:1500]
				label = pr.get("pair", "unknown")
				high_pairs.append(f"[{label}] (威胁:{threat})\n{snippet}")

		if not high_pairs:
			logger.info("No high-threat pairs found; skipping rule generation.")
			return

		existing_sids = self._collect_existing_sids()
		prompt = build_rule_generation_prompt(
			analysis_summary="\n---\n".join(high_pairs),
			high_threat_pairs=high_pairs,
			existing_sids=existing_sids,
		)

		# Call LLM for rule generation
		try:
			raw = call_daily_report_llm(prompt, llm_conf, backend=self._backend)
		except Exception as exc:
			logger.error("Rule generation LLM call failed: %s", exc)
			return

		# Parse JSON from LLM output — tolerate markdown fences
		raw_stripped = raw.strip()
		if raw_stripped.startswith("```"):
			raw_stripped = re.sub(r"^```[a-z]*\n?", "", raw_stripped)
			raw_stripped = re.sub(r"\n?```$", "", raw_stripped.strip())
		try:
			result_data = json.loads(raw_stripped)
		except json.JSONDecodeError:
			logger.error("Rule generation LLM returned invalid JSON:\n%s", raw[:300])
			return

		rules = result_data.get("rules", [])
		if not rules:
			logger.info("LLM suggested no rules.")
			return

		date_str = report_date.strftime("%Y%m%d")
		# In fork mode we work on the default branch directly; otherwise
		# use a dated feature branch.
		use_fork = bool(config.GIT_FORK_OWNER)
		branch_name = "" if use_fork else f"ai-rules/{date_str}"
		written_count = 0

		for item in rules:
			rule_text = item.get("rule_text", "").strip()
			priority = item.get("priority", 5)
			reason = item.get("reason", "")
			if not rule_text:
				continue

			req = ActionRequest(
				capability="suricata_rule_suggest",
				params={
					"rule_text": rule_text,
					"priority": priority,
					"reference": reason[:200],
				},
				actor_role=self._agent_identity.actor_role if self._agent_identity else "Agent",
				actor_id=self._agent_identity.actor_id if self._agent_identity else "daily_report",
				api_key=self._agent_identity.api_key if self._agent_identity else "",
			)
			res = self._executor.execute(req)
			if res.status == ActionStatus.SUCCESS:
				written_count += 1
				logger.info("Rule accepted: %s", res.detail)
			else:
				logger.warning("Rule rejected: %s", res.detail)

		if written_count == 0:
			logger.info("No rules passed validation; skipping commit/PR.")
			return

		# Commit and push
		commit_params: dict = {
			"commit_message": f"[AI] Add {written_count} suggested Suricata rule(s) — {date_str}",
		}
		if branch_name:
			commit_params["branch"] = branch_name
		commit_req = ActionRequest(
			capability="git_commit_and_push",
			params=commit_params,
			actor_role=self._agent_identity.actor_role if self._agent_identity else "Agent",
			actor_id=self._agent_identity.actor_id if self._agent_identity else "daily_report",
			api_key=self._agent_identity.api_key if self._agent_identity else "",
		)
		commit_res = self._executor.execute(commit_req)
		if commit_res.status != ActionStatus.SUCCESS:
			logger.error("git commit/push failed: %s", commit_res.detail)
			return

		# Create PR if configured
		if config.GIT_AUTO_PR:
			# In fork mode, close stale open PRs before creating a new one.
			if use_fork:
				close_req = ActionRequest(
					capability="close_github_prs",
					params={},
					actor_role=self._agent_identity.actor_role if self._agent_identity else "Agent",
					actor_id=self._agent_identity.actor_id if self._agent_identity else "daily_report",
					api_key=self._agent_identity.api_key if self._agent_identity else "",
				)
				close_res = self._executor.execute(close_req)
				if close_res.status != ActionStatus.SUCCESS:
					logger.warning("Closing old PRs failed: %s", close_res.detail)

			# In fork mode head_branch is the default branch; the handler
			# will prefix it with the fork owner automatically.
			pr_head = config.GIT_DEFAULT_BRANCH if use_fork else branch_name
			pr_req = ActionRequest(
				capability="create_github_pr",
				params={
					"title": f"[AI] Suggested Suricata rules — {date_str}",
					"body": (
						f"Auto-generated by Suricata AI Agent daily report.\n\n"
						f"**Rules added:** {written_count}\n"
						f"**Date:** {report_date.strftime('%Y-%m-%d')}\n\n"
						f"These rules were generated based on high-threat communication pairs "
						f"identified during daily analysis. Each rule passed light (regex) "
						f"and medium (suricata -T) validation."
					),
					"head_branch": pr_head,
					"base_branch": config.GIT_DEFAULT_BRANCH,
				},
				actor_role=self._agent_identity.actor_role if self._agent_identity else "Agent",
				actor_id=self._agent_identity.actor_id if self._agent_identity else "daily_report",
				api_key=self._agent_identity.api_key if self._agent_identity else "",
			)
			pr_res = self._executor.execute(pr_req)
			if pr_res.status == ActionStatus.SUCCESS:
				logger.info("PR created for AI rules: %s", pr_res.detail)
			else:
				logger.error("PR creation failed: %s", pr_res.detail)

		logger.info(
			"Rule generation pipeline complete: %d rules written, branch=%s",
			written_count, branch_name or config.GIT_DEFAULT_BRANCH,
		)

		# Local-only cleanup: switch back to the default branch and discard
		# uncommitted leftovers so the working directory is ready for the next
		# cycle.  We deliberately do NOT call git_repo_reset here — that
		# capability force-pushes in fork mode, which destroys the PR we just
		# created.  Full remote synchronisation is handled by the scheduled
		# reset_time task.
		local_reset_req = ActionRequest(
			capability="git_local_checkout_default",
			params={},
			actor_role=self._agent_identity.actor_role if self._agent_identity else "Agent",
			actor_id=self._agent_identity.actor_id if self._agent_identity else "daily_report",
			api_key=self._agent_identity.api_key if self._agent_identity else "",
		)
		local_reset_res = self._executor.execute(local_reset_req)
		if local_reset_res.status != ActionStatus.SUCCESS:
			logger.warning("Post-rule-generation local checkout failed: %s", local_reset_res.detail)

	def _run_flat_analysis(
		self,
		items: List[Dict[str, str]],
		daily_stats: Dict[str, Any],
		report_date: date,
		llm_conf: DailyReportLLMConfig,
	) -> tuple[str, List[Dict[str, Any]]]:
		"""Run a single-pass (non-hierarchical) analysis as an ablation baseline.

		All items are fed into ``build_daily_report_prompt`` (the legacy
		single-shot prompt) and analysed in one LLM call.  No pair grouping,
		no segment splitting, no multi-level merging.

		Returns (analysis_html, []) — pair_results is always empty because
		flat mode does not produce per-pair breakdowns.
		"""
		logger.info(
			"Flat analysis (ablation baseline): %d items, report_date=%s",
			len(items), report_date,
		)
		prompt = build_daily_report_prompt(
			report_date.strftime("%Y-%m-%d"),
			items,
			daily_stats=daily_stats,
		)
		analysis_html = ""
		try:
			analysis_html = call_daily_report_llm(prompt, llm_conf, backend=self._backend)
		except Exception as exc:
			logger.error("Flat analysis LLM call failed: %s", exc)
		return analysis_html, []

	def _run_pair_only_analysis(
		self,
		items: List[Dict[str, str]],
		daily_stats: Dict[str, Any],
		report_date: date,
		llm_conf: DailyReportLLMConfig,
	) -> tuple[str, List[Dict[str, Any]]]:
		"""Run pair-grouped analysis without time segmentation or global synthesis.

		Events are grouped by communication pair and each pair is analysed
		in a single LLM call (no time-gap splitting into segments, no L1).
		The per-pair analyses are concatenated directly into the final
		report (no L3 global synthesis).

		This is the intermediate ablation level between ``flat`` (no
		grouping at all) and ``hierarchical`` (full L1→L2→L3 pipeline).
		"""
		pair_groups = group_by_comm_pair(items)
		logger.info(
			"Pair-only analysis (ablation): %d items grouped into %d communication pairs",
			len(items), len(pair_groups),
		)

		pair_results: List[Dict[str, Any]] = []
		html_parts: List[str] = []

		for pair_key, pair_items in pair_groups.items():
			label_a, label_b = _resolve_pair_label(pair_items, pair_key)
			pair_label = f"{label_a} <-> {label_b}"

			# Single LLM call per pair — no segment splitting
			prompt = build_daily_report_prompt(
				report_date.strftime("%Y-%m-%d"),
				pair_items,
				daily_stats=None,
			)
			pair_analysis = ""
			try:
				pair_analysis = call_daily_report_llm(prompt, llm_conf, backend=self._backend)
			except Exception as exc:
				logger.error("Pair-only LLM call failed for %s: %s", pair_label, exc)

			max_threat = ""
			max_threat_rank = 999
			for _item in pair_items:
				tl = _item.get("threat_level", "")
				rank = _THREAT_LEVEL_ORDER.get(tl, 99)
				if rank < max_threat_rank:
					max_threat_rank = rank
					max_threat = tl

			pair_results.append({
				"pair": pair_label,
				"host_a": label_a,
				"host_b": label_b,
				"event_count": len(pair_items),
				"segment_count": 1,
				"max_threat": max_threat,
				"analysis": pair_analysis,
			})
			if pair_analysis:
				html_parts.append(f"<h3>{pair_label} ({len(pair_items)} events)</h3>\n{pair_analysis}")

		# No L3 global synthesis — concatenate per-pair analyses directly
		analysis_html = "\n<hr>\n".join(html_parts) if html_parts else ""
		return analysis_html, pair_results

	def _run_multilevel_analysis(
		self,
		items: List[Dict[str, str]],
		daily_stats: Dict[str, Any],
		report_date: date,
		llm_conf: DailyReportLLMConfig,
	) -> tuple[str, List[Dict[str, Any]]]:
		"""Run the full multi-level analysis pipeline.

		Returns (analysis_html, pair_results).
		"""
		gap_seconds = config.DAILY_REPORT_SESSION_GAP

		# Group by communication pair
		pair_groups = group_by_comm_pair(items)
		logger.info(
			"Multi-level analysis: %d items grouped into %d communication pairs "
			"(session_gap=%ds, max_segment_events=%d)",
			len(items), len(pair_groups), gap_seconds, config.DAILY_REPORT_MAX_SEGMENT_EVENTS,
		)

		# Analyze each pair (Level 1 + Level 2)
		pair_results: List[Dict[str, Any]] = []
		pair_analyses_for_report: List[Dict[str, str]] = []

		for pair_key, pair_items in pair_groups.items():
			label_a, label_b = _resolve_pair_label(pair_items, pair_key)
			pair_result = self._analyze_pair(label_a, label_b, pair_items, llm_conf, gap_seconds)
			pair_results.append(pair_result)
			pair_analyses_for_report.append({
				"pair": pair_result["pair"],
				"event_count": pair_result["event_count"],
				"analysis": pair_result["analysis"],
			})

		# Level 3: generate final report from all pair analyses
		analysis_html = ""
		if pair_analyses_for_report:
			final_prompt = build_final_report_prompt(
				report_date.strftime("%Y-%m-%d"),
				pair_analyses_for_report,
				daily_stats=daily_stats,
			)
			try:
				analysis_html = call_daily_report_llm(final_prompt, llm_conf, backend=self._backend)
			except Exception as exc:
				logger.error("Final report LLM call failed: %s", exc)

		return analysis_html, pair_results

	def generate_and_send(self, report_date: date, force: bool = False) -> bool:
		"""Generate and send daily report using multi-level communication pair analysis.

		The analysis pipeline:
		1. Group events by communication pair (src_ip <-> dest_ip)
		2. Split each pair's events by time gap into segments
		3. Level 1: Analyze each time segment via LLM
		4. Level 2: Combine segment analyses into per-pair analysis via LLM
		5. Level 3: Combine all pair analyses into the final daily report via LLM

		Args:
			report_date: The date to generate the report for.
			force: If True, skip the DAILY_REPORT_ENABLED check (used by manual RMI trigger).
		"""
		if not force and not config.DAILY_REPORT_ENABLED:
			logger.info("Daily report is disabled; skipping.")
			return False

		config.set_daily_report_active()
		logger.info("Daily report generation started — real-time analysis paused.")

		try:
			return self._generate_and_send_inner(report_date)
		finally:
			config.clear_daily_report_active()
			logger.info("Daily report generation finished — real-time analysis resumed.")

	def _generate_and_send_inner(self, report_date: date) -> bool:
		"""Inner implementation of generate_and_send (runs under the pause flag)."""
		daily_stats: Dict[str, Any] = {}
		try:
			daily_stats = fetch_daily_stats(self.es_client, report_date)
			logger.info(
				"Daily stats for %s: total_events=%s, ai_processed=%s",
				report_date, daily_stats.get("total_events", 0), daily_stats.get("ai_processed_count", 0),
			)
		except Exception as exc:
			logger.error("Failed to fetch daily stats: %s", exc)

		try:
			llm_conf = self._get_llm_conf()
			items = fetch_processed_summaries(
				self.es_client, report_date,
				detail_level=llm_conf.DETAIL_LEVEL,
			)
		except Exception as exc:
			logger.error("Failed to fetch summaries for daily report: %s", exc)
			return False

		# Stop current real-time model and load daily report model
		analysis_html = ""
		pair_results: List[Dict[str, Any]] = []
		try:
			if config.CURRENT_PERF_CONFIG and config.CURRENT_PERF_CONFIG.OLLAMA_MODEL:
				stopped = stop_ollama_model(config.CURRENT_PERF_CONFIG.OLLAMA_MODEL, backend=self._backend)
				logger.info("Stopped current model before daily report: %s", stopped)

			if items:
				if config.DAILY_REPORT_ANALYSIS_MODE == "flat":
					analysis_html, pair_results = self._run_flat_analysis(
						items, daily_stats, report_date, llm_conf,
					)
				elif config.DAILY_REPORT_ANALYSIS_MODE == "pair_only":
					analysis_html, pair_results = self._run_pair_only_analysis(
						items, daily_stats, report_date, llm_conf,
					)
				else:
					analysis_html, pair_results = self._run_multilevel_analysis(
						items, daily_stats, report_date, llm_conf,
					)
			else:
				logger.info("No processed summaries found; generating report with stats only.")
				# Fall back to stats-only report prompt
				prompt = build_daily_report_prompt(
					report_date.strftime("%Y-%m-%d"), items, daily_stats=daily_stats,
				)
				try:
					analysis_html = call_daily_report_llm(prompt, llm_conf, backend=self._backend)
				except Exception as exc:
					logger.error("Fallback daily report LLM call failed: %s", exc)
		except Exception as exc:
			logger.error("Daily report LLM analysis pipeline failed: %s", exc)

		html_body = build_report_html(
			report_date, items, analysis_html,
			daily_stats=daily_stats, pair_results=pair_results,
		)

		# Inject experiment tag banner before saving/sending
		exp_tag = config.DAILY_REPORT_EXPERIMENT_TAG
		if exp_tag:
			banner = (
				f'<div style="background:#fff3cd;border:1px solid #ffc107;padding:8px 12px;'
				f'margin-bottom:12px;font-weight:bold;">'
				f'\u26a0 \u5b9e\u9a8c\u8fd0\u884c\uff1a{html.escape(exp_tag)}</div>'
			)
			html_body = banner + html_body

		# Always save to output_dir when configured
		saved_path = _save_report_html(report_date, html_body)
		if saved_path:
			logger.info("Daily report HTML saved to %s", saved_path)

		# Only send email when mail notification is enabled
		if config.ENABLE_MAIL_NOTIFICATION:
			try:
				actual_recipients = send_daily_report_email(report_date, html_body)
				logger.info("Daily report email sent to %s", ", ".join(actual_recipients))
			except Exception as exc:
				logger.error("Daily report email failed: %s", exc)
				return False
		else:
			logger.info("Mail notification disabled; daily report saved to file only.")

		# Post-report: rule generation pipeline
		if pair_results:
			try:
				self._run_rule_generation(pair_results, llm_conf, report_date)
			except Exception as exc:
				logger.error("Rule generation pipeline failed: %s", exc)

		return True
