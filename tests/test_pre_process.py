#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         test_pre_process.py
Description:  Tests for query builder and Elasticsearch filter construction.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations
import pytest
from src.pre_process import (
    _build_terms_or_missing,
    _build_alert_severity_filter,
    _build_event_type_filter,
    build_log_filters,
    build_unprocessed_bool_query,
)


# ── _build_terms_or_missing ──────────────────────────────────────────────

class TestBuildTermsOrMissing:
    def test_empty_list_returns_none(self):
        assert _build_terms_or_missing("proto", []) is None

    def test_single_value(self):
        result = _build_terms_or_missing("proto", ["tcp"])
        assert result is not None
        should = result["bool"]["should"]
        assert len(should) == 2
        assert should[0] == {"terms": {"proto": ["tcp"]}}
        assert should[1]["bool"]["must_not"]["exists"]["field"] == "proto"

    def test_multiple_values(self):
        result = _build_terms_or_missing("app_proto", ["dns", "http"])
        terms = result["bool"]["should"][0]["terms"]["app_proto"]
        assert set(terms) == {"dns", "http"}


# ── _build_alert_severity_filter ────────────────────────────────────────

class TestBuildAlertSeverityFilter:
    def test_no_alert_in_event_types(self):
        assert _build_alert_severity_filter(["dns", "http"], 2) is None

    def test_alert_but_no_severity(self):
        assert _build_alert_severity_filter(["alert"], None) is None

    def test_empty_event_types(self):
        assert _build_alert_severity_filter([], 2) is None

    def test_valid_alert_severity(self):
        result = _build_alert_severity_filter(["alert", "dns"], 2)
        assert result is not None
        should = result["bool"]["should"]
        assert len(should) == 2
        # First branch: alert + severity range
        alert_branch = should[0]["bool"]["must"]
        assert alert_branch[0] == {"term": {"event_type": "alert"}}
        assert alert_branch[1] == {"range": {"alert.severity": {"lte": 2}}}
        # Second branch: not alert
        non_alert = should[1]["bool"]["must_not"]
        assert non_alert == {"term": {"event_type": "alert"}}


# ── _build_event_type_filter ────────────────────────────────────────────

class TestBuildEventTypeFilter:
    def test_empty_returns_none(self):
        assert _build_event_type_filter([]) is None

    def test_base_types_only(self, fake_config):
        result = _build_event_type_filter(["alert", "ssh"])
        should = result["bool"]["should"]
        assert len(should) == 1
        assert should[0] == {"terms": {"event_type": ["alert", "ssh"]}}

    def test_dns_with_filters(self, fake_config):
        result = _build_event_type_filter(["dns"])
        should = result["bool"]["should"]
        assert len(should) == 1
        dns_clause = should[0]["bool"]
        assert dns_clause["must"] == [{"term": {"event_type": "dns"}}]
        assert dns_clause["minimum_should_match"] == 1

    def test_dns_without_filters(self, fake_config):
        fake_config.AI_AGENT_DNS_RCODES = []
        fake_config.AI_AGENT_DNS_RRTYPES = []
        result = _build_event_type_filter(["dns"])
        should = result["bool"]["should"]
        assert should[0] == {"term": {"event_type": "dns"}}
        # Restore
        fake_config.AI_AGENT_DNS_RCODES = ["NXDOMAIN", "SERVFAIL"]
        fake_config.AI_AGENT_DNS_RRTYPES = ["ANY", "TXT"]

    def test_http_with_filters(self, fake_config):
        result = _build_event_type_filter(["http"])
        should = result["bool"]["should"]
        http_clause = should[0]["bool"]
        assert http_clause["must"] == [{"term": {"event_type": "http"}}]

    def test_tls_with_all_filters(self, fake_config):
        result = _build_event_type_filter(["tls"])
        should = result["bool"]["should"]
        tls_clause = should[0]["bool"]
        assert tls_clause["must"] == [{"term": {"event_type": "tls"}}]
        # Should have version + sni_missing + ja3 + ja3s sub-clauses
        assert len(tls_clause["should"]) >= 3

    def test_mixed_types(self, fake_config):
        result = _build_event_type_filter(["alert", "dns", "http", "tls"])
        should = result["bool"]["should"]
        # alert goes into base_types, dns/http/tls each get their own clause
        assert len(should) == 4


# ── build_log_filters ───────────────────────────────────────────────────

class TestBuildLogFilters:
    def test_explicit_overrides(self, fake_config):
        filters = build_log_filters(
            allowed_event_types=["alert"],
            allowed_l7_protocols=["dns"],
            allowed_l4_protocols=["tcp"],
            allowed_l3_protocols=["ipv4"],
            minimal_alert_severity=1,
        )
        # Should have: event_type + l7 + l4 + l3 + alert_severity = 5
        assert len(filters) == 5

    def test_no_l4_l3_means_fewer_filters(self, fake_config):
        filters = build_log_filters(
            allowed_event_types=["dns"],
            allowed_l7_protocols=["dns"],
            allowed_l4_protocols=[],
            allowed_l3_protocols=[],
            minimal_alert_severity=None,
        )
        # event_type + l7 = 2 (no l4, l3, alert)
        assert len(filters) == 2


# ── build_unprocessed_bool_query ────────────────────────────────────────

class TestBuildUnprocessedBoolQuery:
    def test_boolean_processed_value(self, fake_config):
        q = build_unprocessed_bool_query(False)
        should = q["should"]
        assert {"term": {"ai.processed": False}} in should
        assert q["minimum_should_match"] == 1

    def test_string_processed_value(self, fake_config):
        q = build_unprocessed_bool_query("false")
        should = q["should"]
        assert {"term": {"ai.processed": "false"}} in should

    def test_filters_present(self, fake_config):
        q = build_unprocessed_bool_query(
            False,
            allowed_event_types=["alert"],
            minimal_alert_severity=2,
        )
        assert "filter" in q
        assert len(q["filter"]) >= 1
