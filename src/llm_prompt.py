#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         llm_prompt.py
Description:  Prompt template loading and rendering system with safe variable substitution.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

import logging
import tomllib
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Template storage – populated by load_prompt_templates()
# ---------------------------------------------------------------------------
_templates: Dict[str, Any] = {}
_loaded: bool = False


def load_prompt_templates(filepath: str) -> None:
    """Load prompt templates from an external TOML file.

    Must be called once during startup (from Config.__post_init__) before
    any build_*() function is used.
    """
    global _templates, _loaded
    with open(filepath, "rb") as f:
        _templates = tomllib.load(f)
    _loaded = True
    logger.info("Loaded prompt templates from %s", filepath)


def _get_template(*keys: str) -> str:
    """Retrieve a nested template string from the loaded TOML data.

    Example: _get_template("daily_report", "segment") returns
    _templates["daily_report"]["segment"]["template"].
    """
    if not _loaded:
        raise RuntimeError(
            "Prompt templates have not been loaded. "
            "Call load_prompt_templates() during startup."
        )
    node: Any = _templates
    for key in keys:
        node = node[key]
    return _resolve_shared(str(node["template"]))


def get_shared_prompt() -> str:
    """Return the ``[shared].shared_prompt`` fragment, or ``""`` if absent."""
    if not _loaded:
        return ""
    shared = _templates.get("shared", {})
    return str(shared.get("shared_prompt", "")).strip()


class _SafeDict(dict):
  def __missing__(self, key):
    return "{" + key + "}"


def _resolve_shared(text: str) -> str:
    """Replace ``{shared_prompt}`` in *text* with the shared fragment."""
    return text.replace("{shared_prompt}", get_shared_prompt())


def _extract_alert_values(log_entry: Dict) -> Dict[str, str]:
  """Extract common alert field values from a log entry."""
  return {
    "event_type": log_entry.get("event_type", "N/A"),
    "timestamp": log_entry.get("@timestamp", "N/A"),
    "src_ip": log_entry.get("src_ip", "N/A"),
    "src_city": log_entry.get("src_geoip", {}).get("geo", {}).get("city_name", "N/A"),
    "src_country": log_entry.get("src_geoip", {}).get("geo", {}).get("country_name", "N/A"),
    "src_asn": log_entry.get("src_asn", {}).get("as", {}).get("organization", {}).get("name", "N/A"),
    "dest_ip": log_entry.get("dest_ip", "N/A"),
    "dest_city": log_entry.get("dest_geoip", {}).get("geo", {}).get("city_name", "N/A"),
    "dest_country": log_entry.get("dest_geoip", {}).get("geo", {}).get("country_name", "N/A"),
    "dest_asn": log_entry.get("dest_asn", {}).get("as", {}).get("organization", {}).get("name", "N/A"),
    "src_port": log_entry.get("src_port", "N/A"),
    "dest_port": log_entry.get("dest_port", "N/A"),
    "src_hostname": log_entry.get("src_hostname", "N/A"),
    "dest_hostname": log_entry.get("dest_hostname", "N/A"),
    "proto": log_entry.get("proto", "N/A"),
    "alert": log_entry.get("alert", {}).get("signature", "N/A"),
    "severity": log_entry.get("alert", {}).get("severity", "N/A"),
    "is_noise": 'true' if 'noise' in log_entry else 'false',
  }


def _build_memory_block(
    memory_summaries: Optional[List[str]] = None,
    *,
    scope_label: str = "该通信对",
) -> str:
  """Build the memory context block from communication pair history."""
  if not memory_summaries:
    return ""
  cleaned_summaries = [
    str(item).strip() for item in memory_summaries
    if item is not None and str(item).strip()
  ]
  if not cleaned_summaries:
    return ""
  label = scope_label.strip() or "该通信对"
  return f"{label}的历史记忆（按时间从旧到新），请结合这些上下文进行关联分析：\n" + "\n".join(
    f"- {summary}" for summary in cleaned_summaries
  )


def build_prompt(
    log_entry: Dict,
    memory_summaries: Optional[List[str]] = None,
    *,
    memory_scope_label: str = "该通信对",
) -> str:
  """
  Build the LLM prompt from a log entry.
  """
  values = _extract_alert_values(log_entry)
  values["memory_block"] = _build_memory_block(
      memory_summaries, scope_label=memory_scope_label,
  )
  values["system_prompt_end"] = ""  # Strip marker in flat prompt mode
  return _get_template("realtime").format_map(_SafeDict(values))


def _get_system_template() -> str:
  """Return the system prompt portion of the realtime template.

  The realtime template is assumed to have a ``{system_prompt_end}``
  marker separating the system instructions from the per-alert user
  data.  If the marker is absent, the *entire* template up to the
  first ``{event_type}`` reference is used as a fallback.
  """
  full_template = _get_template("realtime")
  marker = "{system_prompt_end}"
  idx = full_template.find(marker)
  if idx != -1:
    return full_template[:idx].strip()
  # Fallback: look for the first field placeholder as boundary
  for field_marker in ("{event_type}", "事件类型"):
    pos = full_template.find(field_marker)
    if pos != -1:
      # Walk backwards to find the last newline before the field
      nl = full_template.rfind("\n", 0, pos)
      if nl != -1:
        return full_template[:nl].strip()
  # Last resort: return the whole template as system prompt
  return full_template.strip()


def _format_alert_with_memory(
    log_entry: Dict,
    memory_summaries: Optional[List[str]] = None,
    *,
    memory_scope_label: str = "该通信对",
) -> str:
  """Format alert data + memory block as user content for chat mode.

  This extracts the user-data portion of the prompt (alert fields +
  memory context) without the system instructions.
  """
  values = _extract_alert_values(log_entry)
  values["memory_block"] = _build_memory_block(
      memory_summaries, scope_label=memory_scope_label,
  )

  full_template = _get_template("realtime")
  marker = "{system_prompt_end}"
  idx = full_template.find(marker)
  if idx != -1:
    user_template = full_template[idx + len(marker):].strip()
  else:
    # Fallback: mirror _get_system_template boundary detection
    user_template = full_template
    for field_marker in ("{event_type}", "事件类型"):
      pos = full_template.find(field_marker)
      if pos != -1:
        nl = full_template.rfind("\n", 0, pos)
        if nl != -1:
          user_template = full_template[nl:].strip()
          break
  return user_template.format_map(_SafeDict(values))


def build_pipeline_messages(
    log_entry: Dict,
    memory_summaries: Optional[List[str]] = None,
    *,
    memory_scope_label: str = "该通信对",
) -> List[Dict[str, str]]:
  """Build pipeline mode chat messages array.

  Separates system prompt from user data into independent role messages
  so that Ollama's KV cache can reuse system prompt attention computation
  across requests.

  Returns
  -------
  list[dict[str, str]]
      ``[{"role": "system", ...}, {"role": "user", ...}]``
  """
  system_prompt = _get_system_template()
  user_content = _format_alert_with_memory(
      log_entry,
      memory_summaries,
      memory_scope_label=memory_scope_label,
  )
  return [
      {"role": "system", "content": system_prompt},
      {"role": "user", "content": user_content},
  ]


def build_compact_prompt(pair_key: str, entries: List[str]) -> str:
  """Render the memory compaction prompt from the ``[memory_compact]`` template.

  Used by the rolling summary compaction mechanism (Improvement 30.8).
  """
  entries_text = "\n".join(f"- {e}" for e in entries)
  return _get_template("memory_compact").format_map(_SafeDict({
      "entry_count": str(len(entries)),
      "pair_key": pair_key,
      "entries_text": entries_text,
  }))


# ---------------------------------------------------------------------------
# Agent-mode prompt builders (ReAct / tool-calling)
# ---------------------------------------------------------------------------

def build_agent_system_prompt() -> str:
  """Return the system prompt for agent (tool-calling) mode."""
  return _get_agent_template("realtime_agent", "system_template")


def build_agent_user_message(
    log_entry: Dict,
    memory_summaries: Optional[List[str]] = None,
    doc_id: str = "",
    memory_scope_label: str = "该通信对",
) -> str:
  """Build the user message for agent mode from a log entry."""
  values = {
    "event_type": log_entry.get("event_type", "N/A"),
    "timestamp": log_entry.get("@timestamp", "N/A"),
    "src_ip": log_entry.get("src_ip", "N/A"),
    "src_city": log_entry.get("src_geoip", {}).get("geo", {}).get("city_name", "N/A"),
    "src_country": log_entry.get("src_geoip", {}).get("geo", {}).get("country_name", "N/A"),
    "src_asn": log_entry.get("src_asn", {}).get("as", {}).get("organization", {}).get("name", "N/A"),
    "dest_ip": log_entry.get("dest_ip", "N/A"),
    "dest_city": log_entry.get("dest_geoip", {}).get("geo", {}).get("city_name", "N/A"),
    "dest_country": log_entry.get("dest_geoip", {}).get("geo", {}).get("country_name", "N/A"),
    "dest_asn": log_entry.get("dest_asn", {}).get("as", {}).get("organization", {}).get("name", "N/A"),
    "src_port": log_entry.get("src_port", "N/A"),
    "dest_port": log_entry.get("dest_port", "N/A"),
    "src_hostname": log_entry.get("src_hostname", "N/A"),
    "dest_hostname": log_entry.get("dest_hostname", "N/A"),
    "proto": log_entry.get("proto", "N/A"),
    "alert": log_entry.get("alert", {}).get("signature", "N/A"),
    "severity": log_entry.get("alert", {}).get("severity", "N/A"),
    "is_noise": 'true' if 'noise' in log_entry else 'false',
    "doc_id": doc_id or "N/A",
  }

  memory_block = ""
  if memory_summaries:
    cleaned_summaries = [
      str(item).strip() for item in memory_summaries
      if item is not None and str(item).strip()
    ]
    if cleaned_summaries:
      label = memory_scope_label.strip() or "该通信对"
      memory_block = f"{label}的历史记忆（按时间从旧到新），请结合这些上下文进行关联分析：\n" + "\n".join(
        f"- {summary}" for summary in cleaned_summaries
      )

  values["memory_block"] = memory_block

  return _get_agent_template("realtime_agent", "user_template").format_map(_SafeDict(values))


def _get_agent_template(*keys: str) -> str:
  """Retrieve a template string from the loaded TOML data.

  Unlike :func:`_get_template`, this looks for a direct key name
  rather than a nested ``template`` sub-key.
  """
  if not _loaded:
    raise RuntimeError(
      "Prompt templates have not been loaded. "
      "Call load_prompt_templates() during startup."
    )
  node: Any = _templates
  path = list(keys)
  # Navigate to the parent, then get the leaf
  for key in path[:-1]:
    node = node[key]
  return _resolve_shared(str(node[path[-1]]))


# ---------------------------------------------------------------------------
# Daily-report agent-mode prompt builders
# ---------------------------------------------------------------------------

def build_daily_report_agent_system_prompt() -> str:
  """Return the system prompt for daily-report agent (rule generation) mode."""
  return _get_agent_template("daily_report_agent", "system_template")


def build_daily_report_agent_user_message(
    high_pairs: List[str],
    existing_sids: List[int],
    report_date: str,
) -> str:
  """Build the user message for daily-report agent mode."""
  high_pairs_text = "\n---\n".join(high_pairs) if high_pairs else "(无)"
  existing_sids_text = (
      ", ".join(str(s) for s in existing_sids) if existing_sids else "(无已有规则)"
  )
  values = {
      "report_date": report_date,
      "high_pairs_text": high_pairs_text,
      "existing_sids_text": existing_sids_text,
  }
  return _get_agent_template("daily_report_agent", "user_template").format_map(_SafeDict(values))


def build_rule_generation_prompt(
    analysis_summary: str,
    high_threat_pairs: Union[List[str], str],
    existing_sids: Union[List[int], str],
) -> str:
    """Build a prompt for the LLM to generate Suricata rules based on analysis."""
    if isinstance(high_threat_pairs, list):
        high_threat_pairs = "\n".join(high_threat_pairs)
    if isinstance(existing_sids, list):
        existing_sids = ", ".join(str(s) for s in existing_sids) if existing_sids else "(无)"
    values = {
        "analysis_summary": analysis_summary or "(无分析摘要)",
        "high_threat_pairs": high_threat_pairs or "(无高威胁通信对)",
        "existing_sids": existing_sids or "(无已有规则)",
    }
    return _get_template("rule_generation").format_map(_SafeDict(values))


_HIGH_THREAT_LEVELS = {"高", "严重"}
_THREAT_LEVEL_ORDER = {"严重": 0, "高": 1, "中": 2, "低": 3, "无危": 4}


def build_daily_report_prompt(
  report_date: str,
  summary_items: List[Dict],
  daily_stats: Optional[Dict[str, Any]] = None,
) -> str:
  """
  Build the LLM prompt for the daily report.
  Only high/critical events are included in the summary list for LLM analysis.
  Full-day statistics are always included.
  """
  stats = daily_stats or {}

  # Filter: only high / critical items for the LLM
  high_items = [
    item for item in summary_items
    if str(item.get("threat_level", "")) in _HIGH_THREAT_LEVELS
  ]

  lines = []
  for item in high_items:
    timestamp = str(item.get("timestamp", "")).strip() or "N/A"
    threat_level = str(item.get("threat_level", "")).strip()
    summary = str(item.get("summary", "")).strip() or "(空)"
    lines.append(f"- [{threat_level}] {timestamp} | {summary}")

  summary_list = "\n".join(lines) if lines else "- (无高危/严重事件)"

  # Build event type breakdown text
  et_bd = stats.get("event_type_breakdown", {})
  if et_bd:
    et_lines = [f"- {etype}: {count}" for etype, count in sorted(et_bd.items(), key=lambda x: -x[1])]
    event_type_breakdown = "\n".join(et_lines)
  else:
    event_type_breakdown = "- (无数据)"

  # Build threat level breakdown text (sorted by severity: 严重 > 高 > 中 > 低 > 无危)
  tl_bd = stats.get("threat_level_breakdown", {})
  if tl_bd:
    tl_lines = [f"- {level}: {count}" for level, count in sorted(tl_bd.items(), key=lambda x: _THREAT_LEVEL_ORDER.get(x[0], 99))]
    threat_level_breakdown = "\n".join(tl_lines)
  else:
    threat_level_breakdown = "- (无数据)"

  values = {
    "report_date": report_date,
    "total_events": str(stats.get("total_events", 0)),
    "ai_processed_count": str(stats.get("ai_processed_count", 0)),
    "ai_has_summary_count": str(stats.get("ai_has_summary_count", 0)),
    "time_min": str(stats.get("time_min") or "N/A"),
    "time_max": str(stats.get("time_max") or "N/A"),
    "event_type_breakdown": event_type_breakdown,
    "threat_level_breakdown": threat_level_breakdown,
    "summary_list": summary_list,
    "high_event_count": str(len(high_items)),
  }

  return _get_template("daily_report", "legacy").format_map(_SafeDict(values))


# ---------------------------------------------------------------------------
# Multi-level prompt builders
# ---------------------------------------------------------------------------

def _format_event_minimal(item: Dict) -> str:
  """Format a single event as: - [threat] timestamp | summary"""
  ts = str(item.get("timestamp", "")).strip() or "N/A"
  threat = str(item.get("threat_level", "")).strip()
  summary = str(item.get("summary", "")).strip() or "(空)"
  prefix = f"[{threat}] " if threat else ""
  return f"- {prefix}{ts} | {summary}"


def _format_event_extended(item: Dict) -> str:
  """Format a single event with extra network/alert context."""
  ts = str(item.get("timestamp", "")).strip() or "N/A"
  threat = str(item.get("threat_level", "")).strip()
  event_type = str(item.get("event_type", "")).strip()
  proto = str(item.get("proto", "")).strip()
  summary = str(item.get("summary", "")).strip() or "(空)"
  prefix = f"[{threat}] " if threat else ""
  parts = [f"- {prefix}{ts}"]
  if event_type:
    parts.append(event_type)
  if proto:
    parts.append(proto)
  # Ports
  sp = str(item.get("src_port", "")).strip()
  dp = str(item.get("dest_port", "")).strip()
  if sp and dp:
    parts.append(f"{sp}->{dp}")
  parts.append(summary)
  # Optional enriched fields
  alert_sig = str(item.get("alert_signature", "")).strip()
  if alert_sig:
    parts.append(f"[alert: {alert_sig}]")
  hint = str(item.get("security_hint", "")).strip()
  if hint:
    parts.append(f"[hint: {hint}]")
  tls_sni = str(item.get("tls_sni", "")).strip()
  if tls_sni:
    parts.append(f"[sni: {tls_sni}]")
  dns_rr = str(item.get("dns_rrname", "")).strip()
  if dns_rr:
    parts.append(f"[dns: {dns_rr}]")
  http_url = str(item.get("http_url", "")).strip()
  if http_url:
    parts.append(f"[url: {http_url}]")
  return " | ".join(parts)


def _format_event_full(item: Dict) -> str:
  """Serialize the entire item as indented JSON."""
  import json as _json
  raw = item.get("_raw_source")
  if raw:
    try:
      obj = _json.loads(raw)
      return _json.dumps(obj, ensure_ascii=False, indent=2, default=str)
    except Exception:
      pass
  # Fallback: dump the item dict itself (minus the _raw_source key)
  filtered = {k: v for k, v in item.items() if k != "_raw_source" and v}
  return _json.dumps(filtered, ensure_ascii=False, indent=2, default=str)


def build_segment_prompt(
  host_a: str,
  host_b: str,
  events: List[Dict],
  detail_level: str = "minimal",
) -> str:
  """Build prompt for analyzing a single time segment of a communication pair.

  detail_level controls how much information is included per event:
    - "minimal": [threat] timestamp | summary  (default, backward compatible)
    - "extended": adds event_type, proto, ports, alert signature, security_hint, etc.
    - "full": serializes the entire event as JSON
  """
  if not events:
    return ""

  time_start = str(events[0].get("timestamp", "N/A"))
  time_end = str(events[-1].get("timestamp", "N/A"))

  if detail_level == "full":
    formatter = _format_event_full
  elif detail_level == "extended":
    formatter = _format_event_extended
  else:
    formatter = _format_event_minimal

  lines = [formatter(item) for item in events]
  event_summaries = "\n".join(lines)

  values = {
    "host_a": host_a,
    "host_b": host_b,
    "time_start": time_start,
    "time_end": time_end,
    "event_count": str(len(events)),
    "event_summaries": event_summaries,
  }
  return _get_template("daily_report", "segment").format_map(_SafeDict(values))


def build_pair_prompt(
  host_a: str,
  host_b: str,
  segment_analyses: List[Dict[str, str]],
) -> str:
  """Build prompt for combining segment analyses into a pair-level analysis.

  segment_analyses: list of {"time_range": "...", "analysis": "..."}
  """
  if not segment_analyses:
    return ""

  lines = []
  for i, seg in enumerate(segment_analyses, 1):
    time_range = seg.get("time_range", "N/A")
    analysis = seg.get("analysis", "(无分析)")
    lines.append(f"## 时间段 {i}（{time_range}）\n{analysis}")

  values = {
    "host_a": host_a,
    "host_b": host_b,
    "segment_count": str(len(segment_analyses)),
    "segment_analyses": "\n\n".join(lines),
  }
  return _get_template("daily_report", "pair").format_map(_SafeDict(values))


def build_final_report_prompt(
  report_date: str,
  pair_analyses: List[Dict[str, str]],
  daily_stats: Optional[Dict[str, Any]] = None,
) -> str:
  """Build prompt for the final daily report from all pair analyses.

  pair_analyses: list of {"pair": "A <-> B", "event_count": N, "analysis": "..."}
  """
  stats = daily_stats or {}

  # Build event type breakdown text
  et_bd = stats.get("event_type_breakdown", {})
  if et_bd:
    et_lines = [f"- {etype}: {count}" for etype, count in sorted(et_bd.items(), key=lambda x: -x[1])]
    event_type_breakdown = "\n".join(et_lines)
  else:
    event_type_breakdown = "- (无数据)"

  # Build threat level breakdown text
  tl_bd = stats.get("threat_level_breakdown", {})
  if tl_bd:
    tl_lines = [
      f"- {level}: {count}"
      for level, count in sorted(tl_bd.items(), key=lambda x: _THREAT_LEVEL_ORDER.get(x[0], 99))
    ]
    threat_level_breakdown = "\n".join(tl_lines)
  else:
    threat_level_breakdown = "- (无数据)"

  # Build pair analyses text
  pa_lines = []
  for i, pa in enumerate(pair_analyses, 1):
    pair_label = pa.get("pair", "N/A")
    event_count = pa.get("event_count", 0)
    analysis = pa.get("analysis", "(无分析)")
    pa_lines.append(f"## 通信对 {i}: {pair_label}（共 {event_count} 条事件）\n{analysis}")

  pair_analyses_text = "\n\n".join(pa_lines) if pa_lines else "- (无通信对分析数据)"

  values = {
    "report_date": report_date,
    "total_events": str(stats.get("total_events", 0)),
    "ai_processed_count": str(stats.get("ai_processed_count", 0)),
    "ai_has_summary_count": str(stats.get("ai_has_summary_count", 0)),
    "time_min": str(stats.get("time_min") or "N/A"),
    "time_max": str(stats.get("time_max") or "N/A"),
    "event_type_breakdown": event_type_breakdown,
    "threat_level_breakdown": threat_level_breakdown,
    "pair_count": str(len(pair_analyses)),
    "pair_analyses": pair_analyses_text,
  }
  return _get_template("daily_report", "final").format_map(_SafeDict(values))


# ---------------------------------------------------------------------------
# Escalation prompt builder
# ---------------------------------------------------------------------------

def build_escalation_prompt(
    source: Dict,
    initial_analysis: str,
    memory_summaries: Optional[List[str]] = None,
    include_raw_fields: bool = True,
) -> str:
  """Build the prompt for escalation analysis.

  Parameters
  ----------
  source:
      The ``_source`` dict from the original Elasticsearch document.
  initial_analysis:
      The LLM's initial analysis text (ai_advice).
  memory_summaries:
      Historical memory entries for this communication pair.
  include_raw_fields:
      If *True*, include key raw event fields in the prompt;
      otherwise provide only hostnames/IPs and event type.
  """
  if include_raw_fields:
    raw_lines = [
        f"事件类型: {source.get('event_type', 'N/A')}",
        f"时间戳: {source.get('@timestamp', 'N/A')}",
        f"源: {source.get('src_hostname', '') or source.get('src_ip', 'N/A')}:{source.get('src_port', 'N/A')}",
        f"目标: {source.get('dest_hostname', '') or source.get('dest_ip', 'N/A')}:{source.get('dest_port', 'N/A')}",
        f"协议: {source.get('proto', 'N/A')}",
    ]
    alert = source.get("alert", {})
    if isinstance(alert, dict) and alert.get("signature"):
      raw_lines.append(f"告警规则: {alert['signature']}")
      if alert.get("severity"):
        raw_lines.append(f"严重性: {alert['severity']}")
    tls = source.get("tls", {})
    if isinstance(tls, dict):
      if tls.get("version"):
        raw_lines.append(f"TLS版本: {tls['version']}")
      if tls.get("sni"):
        raw_lines.append(f"TLS SNI: {tls['sni']}")
    dns = source.get("dns", {})
    if isinstance(dns, dict) and dns.get("rrname"):
      raw_lines.append(f"DNS查询: {dns['rrname']}")
    http = source.get("http", {})
    if isinstance(http, dict) and http.get("hostname"):
      raw_lines.append(f"HTTP主机: {http['hostname']}")
      if http.get("url"):
        raw_lines.append(f"HTTP URL: {http['url']}")
    raw_event_block = "\n".join(raw_lines)
  else:
    src = source.get("src_hostname", "") or source.get("src_ip", "N/A")
    dest = source.get("dest_hostname", "") or source.get("dest_ip", "N/A")
    raw_event_block = (
        f"事件类型: {source.get('event_type', 'N/A')}\n"
        f"通信对: {src} → {dest}"
    )

  memory_block = ""
  if memory_summaries:
    cleaned = [str(s).strip() for s in memory_summaries if s and str(s).strip()]
    if cleaned:
      memory_block = "\n".join(f"- {s}" for s in cleaned)
  if not memory_block:
    memory_block = "(无历史记录)"

  values = {
      "raw_event_block": raw_event_block,
      "initial_analysis": initial_analysis,
      "memory_block": memory_block,
  }
  return _get_template("escalation").format_map(_SafeDict(values))
