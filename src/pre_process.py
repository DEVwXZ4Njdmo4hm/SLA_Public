#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         pre_process.py
Description:  Query builder and event filtering logic for Elasticsearch document queries.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

from typing import Dict, List, Optional

from .config import config


def _build_terms_or_missing(field: str, allowed: List[str]) -> Optional[Dict]:
	if not allowed:
		return None
	return {
		"bool": {
			"should": [
				{"terms": {field: allowed}},
				{"bool": {"must_not": {"exists": {"field": field}}}},
			],
			"minimum_should_match": 1,
		}
	}

def _build_alert_severity_filter(
	allowed_event_types: List[str],
	minimal_alert_severity: Optional[int],
) -> Optional[Dict]:
	if not allowed_event_types or "alert" not in allowed_event_types:
		return None
	if minimal_alert_severity is None:
		return None
	return {
		"bool": {
			"should": [
				{
					"bool": {
						"must": [
							{"term": {"event_type": "alert"}},
							{"range": {"alert.severity": {"lte": minimal_alert_severity}}},
						]
					}
				},
				{"bool": {"must_not": {"term": {"event_type": "alert"}}}},
			],
			"minimum_should_match": 1,
		}
	}


def _build_event_type_filter(allowed_event_types: List[str]) -> Optional[Dict]:
	if not allowed_event_types:
		return None

	filtered_types = {"dns", "http", "tls"}
	base_types: List[str] = [
		event_type
		for event_type in allowed_event_types
		if event_type not in filtered_types
	]
	should_clauses: List[Dict] = []

	if base_types:
		should_clauses.append({"terms": {"event_type": base_types}})

	if "dns" in allowed_event_types:
		dns_should: List[Dict] = []
		if config.AI_AGENT_DNS_RCODES:
			dns_should.append({"terms": {"dns.rcode": config.AI_AGENT_DNS_RCODES}})
		if config.AI_AGENT_DNS_RRTYPES:
			dns_should.append({"terms": {"dns.rrtype": config.AI_AGENT_DNS_RRTYPES}})
		
		# If we have specific DNS filters, use them in conjunction with event_type
		if dns_should:
			should_clauses.append({
				"bool": {
					"must": [{"term": {"event_type": "dns"}}],
					"should": dns_should,
					"minimum_should_match": 1,
				}
			})
		# Otherwise just filter by event_type
		else:
			should_clauses.append({"term": {"event_type": "dns"}})

	if "http" in allowed_event_types:
		http_should: List[Dict] = []
		if config.AI_AGENT_HTTP_STATUS_MIN is not None:
			http_should.append({"range": {"http.status": {"gte": config.AI_AGENT_HTTP_STATUS_MIN}}})
			http_should.append({"range": {"http.status_code": {"gte": config.AI_AGENT_HTTP_STATUS_MIN}}})
		if config.AI_AGENT_HTTP_METHODS:
			http_should.append({"terms": {"http.method": config.AI_AGENT_HTTP_METHODS}})
			http_should.append({"terms": {"http.http_method": config.AI_AGENT_HTTP_METHODS}})
		
		# If we have specific HTTP filters
		if http_should:
			should_clauses.append({
				"bool": {
					"must": [{"term": {"event_type": "http"}}],
					"should": http_should,
					"minimum_should_match": 1,
				}
			})
		else:
			should_clauses.append({"term": {"event_type": "http"}})

	if "tls" in allowed_event_types:
		tls_should: List[Dict] = []
		if config.AI_AGENT_TLS_VERSIONS:
			tls_should.append({"terms": {"tls.version": config.AI_AGENT_TLS_VERSIONS}})
		if config.AI_AGENT_TLS_REQUIRE_SNI:
			# Both tls.sni and tls.server_name must be absent to consider SNI missing
			tls_should.append({
				"bool": {
					"must": [
						{"bool": {"must_not": {"exists": {"field": "tls.sni"}}}},
						{"bool": {"must_not": {"exists": {"field": "tls.server_name"}}}},
					]
				}
			})
		if config.AI_AGENT_TLS_JA3_HASHES:
			# Match known malicious JA3 client fingerprints
			tls_should.append({"terms": {"tls.ja3.hash": config.AI_AGENT_TLS_JA3_HASHES}})
			tls_should.append({"terms": {"tls.ja3.hash.keyword": config.AI_AGENT_TLS_JA3_HASHES}})
		if config.AI_AGENT_TLS_JA3S_HASHES:
			# Match known malicious JA3S server fingerprints
			tls_should.append({"terms": {"tls.ja3s.hash": config.AI_AGENT_TLS_JA3S_HASHES}})
			tls_should.append({"terms": {"tls.ja3s.hash.keyword": config.AI_AGENT_TLS_JA3S_HASHES}})
		
		# If we have specific TLS filters
		if tls_should:
			should_clauses.append({
				"bool": {
					"must": [{"term": {"event_type": "tls"}}],
					"should": tls_should,
					"minimum_should_match": 1,
				}
			})
		else:
			should_clauses.append({"term": {"event_type": "tls"}})

	if not should_clauses:
		return None

	return {
		"bool": {
			"should": should_clauses,
			"minimum_should_match": 1,
		}
	}


def build_log_filters(
	*,
	allowed_event_types: Optional[List[str]] = None,
	allowed_l7_protocols: Optional[List[str]] = None,
	allowed_l4_protocols: Optional[List[str]] = None,
	allowed_l3_protocols: Optional[List[str]] = None,
	minimal_alert_severity: Optional[int] = None,
) -> List[Dict]:
	event_types = config.ALLOWED_EVENT_TYPE if allowed_event_types is None else allowed_event_types
	l7_protocols = config.ALLOWED_L7_PROTOCOL if allowed_l7_protocols is None else allowed_l7_protocols
	l4_protocols = config.ALLOWED_L4_PROTOCOL if allowed_l4_protocols is None else allowed_l4_protocols
	l3_protocols = config.ALLOWED_L3_PROTOCOL if allowed_l3_protocols is None else allowed_l3_protocols
	minimal_severity = (
		config.AI_AGENT_MINIMAL_ALERT_SEVERITY
		if minimal_alert_severity is None
		else minimal_alert_severity
	)

	filters: List[Dict] = []
	event_type_filter = _build_event_type_filter(event_types)
	if event_type_filter:
		filters.append(event_type_filter)

	l7_filter = _build_terms_or_missing("app_proto", l7_protocols)
	if l7_filter:
		filters.append(l7_filter)

	l4_filter = _build_terms_or_missing("proto", l4_protocols)
	if l4_filter:
		filters.append(l4_filter)

	l3_filter = _build_terms_or_missing("network.type", l3_protocols)
	if l3_filter:
		filters.append(l3_filter)

	alert_filter = _build_alert_severity_filter(event_types, minimal_severity)
	if alert_filter:
		filters.append(alert_filter)

	return filters


def build_unprocessed_bool_query(
	processed_value: bool | str,
	*,
	allowed_event_types: Optional[List[str]] = None,
	allowed_l7_protocols: Optional[List[str]] = None,
	allowed_l4_protocols: Optional[List[str]] = None,
	allowed_l3_protocols: Optional[List[str]] = None,
	minimal_alert_severity: Optional[int] = None,
) -> Dict:
	filters = build_log_filters(
		allowed_event_types=allowed_event_types,
		allowed_l7_protocols=allowed_l7_protocols,
		allowed_l4_protocols=allowed_l4_protocols,
		allowed_l3_protocols=allowed_l3_protocols,
		minimal_alert_severity=minimal_alert_severity,
	)

	bool_query: Dict = {
		"should": [
			{"term": {"ai.processed": processed_value}},
			{"bool": {"must_not": {"exists": {"field": "ai.processed"}}}},
		],
		"minimum_should_match": 1,
	}

	if filters:
		bool_query["filter"] = filters

	return bool_query

