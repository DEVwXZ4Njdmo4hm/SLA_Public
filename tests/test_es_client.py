#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         test_es_client.py
Description:  Tests for Elasticsearch client helper methods with mocked ES.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations
from unittest.mock import MagicMock, patch
import pytest


# ── ESClient helper methods ─────────────────────────────────────────────

class TestESClientHelpers:
    def _make_client(self):
        """Create an ESClient with a mocked Elasticsearch connection."""
        with patch("src.es_client.Elasticsearch") as MockES:
            mock_es = MockES.return_value
            from src.es_client import ESClient
            client = ESClient()
            client.es = mock_es
            return client, mock_es

    def test_get_processed_value_boolean(self):
        client, mock_es = self._make_client()
        client._ai_processed_type = "boolean"
        assert client._get_processed_value(True) is True
        assert client._get_processed_value(False) is False

    def test_get_processed_value_text(self):
        client, mock_es = self._make_client()
        client._ai_processed_type = "text"
        assert client._get_processed_value(True) == "true"
        assert client._get_processed_value(False) == "false"

    def test_get_processed_value_none_defaults_boolean(self):
        client, mock_es = self._make_client()
        client._ai_processed_type = None
        mock_es.indices.get_mapping.return_value = {}
        assert client._get_processed_value(True) is True

    def test_get_processed_at_value_date(self):
        client, mock_es = self._make_client()
        client._ai_processed_at_type = "date"
        assert client._get_processed_at_value(1700000000000) == 1700000000000

    def test_get_processed_at_value_text(self):
        client, mock_es = self._make_client()
        client._ai_processed_at_type = "text"
        assert client._get_processed_at_value(1700000000000) == "1700000000000"

    def test_detect_ai_field_type(self):
        client, mock_es = self._make_client()
        mock_es.indices.get_mapping.return_value = {
            "test-index": {
                "mappings": {
                    "properties": {
                        "ai": {
                            "properties": {
                                "processed": {"type": "boolean"},
                            }
                        }
                    }
                }
            }
        }
        result = client._detect_ai_field_type("test-index", "processed")
        assert result == "boolean"

    def test_detect_ai_field_type_not_found(self):
        client, mock_es = self._make_client()
        mock_es.indices.get_mapping.return_value = {
            "test-index": {"mappings": {"properties": {}}}
        }
        result = client._detect_ai_field_type("test-index", "processed")
        assert result is None

    def test_detect_ai_field_type_exception(self):
        client, mock_es = self._make_client()
        mock_es.indices.get_mapping.side_effect = Exception("connection error")
        result = client._detect_ai_field_type("test-index", "processed")
        assert result is None

    def test_health_check_ok(self):
        client, mock_es = self._make_client()
        mock_es.ping.return_value = True
        assert client.health_check() is True

    def test_health_check_fail(self):
        client, mock_es = self._make_client()
        mock_es.ping.return_value = False
        assert client.health_check() is False

    def test_health_check_exception(self):
        client, mock_es = self._make_client()
        mock_es.ping.side_effect = Exception("down")
        assert client.health_check() is False


class TestBuildUnprocessedBoolQuery:
    def _make_client(self):
        with patch("src.es_client.Elasticsearch") as MockES:
            from src.es_client import ESClient
            client = ESClient()
            client.es = MockES.return_value
            return client

    def test_query_structure(self):
        client = self._make_client()
        client._ai_processed_type = "boolean"
        q = client._build_unprocessed_bool_query()
        assert "should" in q
        assert q["minimum_should_match"] == 1


class TestEnsureAiMappingEscalation:
    """Verify that ensure_ai_mapping declares escalation fields."""

    def _make_client(self):
        with patch("src.es_client.Elasticsearch") as MockES:
            mock_es = MockES.return_value
            from src.es_client import ESClient
            client = ESClient()
            client.es = mock_es
            return client, mock_es

    def test_escalation_fields_in_mapping(self):
        client, mock_es = self._make_client()
        client._ai_processed_type = "boolean"
        client._ai_processed_at_type = "date"
        mock_es.indices.put_mapping.return_value = True

        client.ensure_ai_mapping("test-*")

        call_args = mock_es.indices.put_mapping.call_args
        body = call_args[1]["body"] if "body" in call_args[1] else call_args[0][0]
        ai_props = body["properties"]["ai"]["properties"]
        assert ai_props["escalated"] == {"type": "boolean"}
        assert ai_props["escalated_from"] == {"type": "keyword"}
        assert ai_props["escalated_model"] == {"type": "keyword"}


class TestBulkUpdateEscalationFields:
    """Verify that bulk_update_ai_advice passes escalation fields through."""

    def _make_client(self):
        with patch("src.es_client.Elasticsearch") as MockES:
            mock_es = MockES.return_value
            from src.es_client import ESClient
            client = ESClient()
            client.es = mock_es
            client._ai_processed_type = "boolean"
            client._ai_processed_at_type = "date"
            return client, mock_es

    def test_escalation_fields_written(self):
        client, mock_es = self._make_client()

        updates = [{
            "_index": "test-idx",
            "_id": "doc1",
            "ai_advice": "advice text",
            "ai_processed_at": 1700000000000,
            "ai_fields": {
                "summary": "test summary",
                "threat_level": "严重",
                "security_hint": "hint",
                "recommendation": "rec",
                "escalated": True,
                "escalated_from": "高",
                "escalated_model": "gpt-4.1-mini",
            },
        }]

        captured_actions = []

        def fake_streaming_bulk(es, actions, **kwargs):
            captured_actions.extend(actions)
            yield True, {"update": {"result": "updated", "status": 200}}

        from elasticsearch import helpers
        with patch.object(helpers, "streaming_bulk", side_effect=fake_streaming_bulk):
            client.bulk_update_ai_advice(updates)

        assert len(captured_actions) == 1
        ai_doc = captured_actions[0]["doc"]["ai"]
        assert ai_doc["escalated"] is True
        assert ai_doc["escalated_from"] == "高"
        assert ai_doc["escalated_model"] == "gpt-4.1-mini"

    def test_non_escalated_doc_has_no_escalation_fields(self):
        client, mock_es = self._make_client()

        updates = [{
            "_index": "test-idx",
            "_id": "doc2",
            "ai_advice": "normal advice",
            "ai_processed_at": 1700000000000,
            "ai_fields": {
                "summary": "normal summary",
                "threat_level": "低",
            },
        }]

        captured_actions = []

        def fake_streaming_bulk(es, actions, **kwargs):
            captured_actions.extend(actions)
            yield True, {"update": {"result": "updated", "status": 200}}

        from elasticsearch import helpers
        with patch.object(helpers, "streaming_bulk", side_effect=fake_streaming_bulk):
            client.bulk_update_ai_advice(updates)

        ai_doc = captured_actions[0]["doc"]["ai"]
        assert "escalated" not in ai_doc
        assert "escalated_from" not in ai_doc
