#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         es_client.py
Description:  Elasticsearch client for querying Suricata eve.json logs and writing results.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from elasticsearch import Elasticsearch, helpers
from typing import List, Dict, Generator, Optional
import logging

from .config import config
from .pre_process import build_unprocessed_bool_query

logger = logging.getLogger(__name__)

class ESClient:
    def __init__(self):
        self.es = Elasticsearch(
            hosts=[config.ES_HOST],
            basic_auth=(config.ES_USER, config.ES_PSWD),
            verify_certs=False,
            request_timeout=30,
        )
        self._ai_processed_type: Optional[str] = None
        self._ai_processed_at_type: Optional[str] = None

    def _detect_ai_field_type(self, index_pattern: str, field: str) -> Optional[str]:
        try:
            mappings = self.es.indices.get_mapping(index=index_pattern)
        except Exception as e:
            logger.debug("Failed to read mappings for %s: %s", index_pattern, e)
            return None

        for index_data in mappings.values():
            props = index_data.get("mappings", {}).get("properties", {})
            ai_props = props.get("ai", {}).get("properties", {})
            field_mapping = ai_props.get(field, {})
            if isinstance(field_mapping, dict) and "type" in field_mapping:
                return field_mapping["type"]

        return None

    def _get_processed_value(self, processed: bool) -> bool | str:
        if self._ai_processed_type is None:
            self._ai_processed_type = self._detect_ai_field_type(config.ES_INDEX_PATTERN, "processed")

        if self._ai_processed_type in (None, "boolean"):
            return processed

        return "true" if processed else "false"

    def _get_processed_at_value(self, processed_at: int | str) -> int | str:
        if self._ai_processed_at_type is None:
            self._ai_processed_at_type = self._detect_ai_field_type(config.ES_INDEX_PATTERN, "processed_at")

        if self._ai_processed_at_type in (None, "date"):
            return processed_at

        return str(processed_at)

    def _log_sample_doc(self, index: str, doc_id: str) -> None:
        if not logger.isEnabledFor(logging.DEBUG):
            return

        try:
            doc = self.es.get(index=index, id=doc_id, _source_includes=["ai"])
            logger.debug("Post-update sample doc %s/%s ai=%s", index, doc_id, doc.get("_source", {}).get("ai"))
        except Exception as e:
            logger.debug("Failed to fetch sample doc %s/%s: %s", index, doc_id, e)

    def ensure_ai_mapping(self, index_pattern: str = config.ES_INDEX_PATTERN) -> None:
        """
        Ensure ai.* fields are mapped for search and visibility in Kibana.
        """
        if self._ai_processed_type is None:
            self._ai_processed_type = self._detect_ai_field_type(index_pattern, "processed")
        if self._ai_processed_at_type is None:
            self._ai_processed_at_type = self._detect_ai_field_type(index_pattern, "processed_at")

        mapping = {
            "properties": {
                "ai": {
                    "properties": {
                        "advice": {
                            "type": "text",
                            "fields": {
                                "keyword": {
                                    "type": "keyword",
                                    "ignore_above": 256
                                }
                            }
                        }
                    }
                }
            }
        }

        if self._ai_processed_type in (None, "boolean"):
            mapping["properties"]["ai"]["properties"]["processed"] = {"type": "boolean"}
        else:
            logger.warning(
                "ai.processed is mapped as %s; keeping existing type and writing string values.",
                self._ai_processed_type
            )

        if self._ai_processed_at_type in (None, "date"):
            mapping["properties"]["ai"]["properties"]["processed_at"] = {"type": "date"}
        else:
            logger.warning(
                "ai.processed_at is mapped as %s; keeping existing type and writing string values.",
                self._ai_processed_at_type
            )

        # Escalation fields (always safe to declare — new fields)
        mapping["properties"]["ai"]["properties"]["escalated"] = {"type": "boolean"}
        mapping["properties"]["ai"]["properties"]["escalated_from"] = {"type": "keyword"}
        mapping["properties"]["ai"]["properties"]["escalated_model"] = {"type": "keyword"}

        try:
            self.es.indices.put_mapping(index=index_pattern, body=mapping)
            logger.info("Ensured ai.* mapping for index pattern: %s", index_pattern)
        except Exception as e:
            logger.warning("Failed to ensure ai.* mapping for %s: %s", index_pattern, e)


    def health_check(self) -> bool:
        """Check the health of the Elasticsearch cluster."""
        try:
            return self.es.ping()
        except Exception as e:
            logger.error(f"Elasticsearch health check failed: {e}")
            return False


    def get_unprocessed_docs(self, index: str, size: int) -> Generator[Dict, None, None]:
        """
        Fetch unprocessed documents from Elasticsearch.
        Use scroll API for efficient retrieval.
        """
        bool_query = self._build_unprocessed_bool_query()

        query = {
            "query": {
                "bool": bool_query
            },
            "sort": [{"@timestamp": {"order": "asc"}}],
            "size": size
        }

        try:
            response = self.es.search(index=index, body=query)
            for hit in response['hits']['hits']:
                yield {
                    '_index': hit['_index'],
                    '_id': hit['_id'],
                    '_source': hit['_source']
                }

        except Exception as e:
            logger.error(f"Error fetching unprocessed documents: {e}")
            raise


    def count_unprocessed_docs(self, index: str) -> int:
        """
        Count unprocessed documents from Elasticsearch using the same filters as get_unprocessed_docs.
        """
        bool_query = self._build_unprocessed_bool_query()
        query = {"query": {"bool": bool_query}}
        try:
            response = self.es.count(index=index, body=query)
            return int(response.get("count", 0))
        except Exception as e:
            logger.error("Error counting unprocessed documents: %s", e)
            raise


    def _build_unprocessed_bool_query(self) -> Dict:
        processed_value = self._get_processed_value(False)
        return build_unprocessed_bool_query(processed_value)


    def bulk_update_ai_advice(self, updates: List[Dict]) -> Dict:
        """
        Bulk update the ai.advice field for processed documents.
        
        updates format:
        [
            {
                '_index': 'suricata-eve-yyyy.mm.dd',
                '_id': 'document_id',
                'ai_advice': 'Some advice text',
                'ai_processed': True,
                'ai_processed_at': 1700000000000
            },
            ...
        ] 
        """
        actions = []
        processed_value = self._get_processed_value(True)
        for update in updates:
            processed_at = self._get_processed_at_value(update["ai_processed_at"])
            ai_doc = {
                "advice": update['ai_advice'],
                "processed": processed_value,
                "processed_at": processed_at
            }

            extra_fields = update.get("ai_fields")
            if isinstance(extra_fields, dict):
                for key in ("summary", "threat_level", "security_hint", "recommendation",
                            "escalated", "escalated_from", "escalated_model"):
                    value = extra_fields.get(key)
                    if isinstance(value, bool):
                        if value:  # only write True; omit False entirely
                            ai_doc[key] = value
                    elif value is not None and value != "":
                        ai_doc[key] = value

            action = {
                "_op_type": "update",
                "_index": update['_index'],
                "_id": update['_id'],
                "doc": {
                    "ai": ai_doc
                }
            }
            actions.append(action)

        # Debug: print first action
        if actions:
            logger.debug(f"Sample update action: index={actions[0]['_index']}, id={actions[0]['_id']}, advice_length={len(actions[0]['doc']['ai']['advice'])}")


        try:
            success = 0
            updated = 0
            noops = 0
            not_found = 0
            errors = []

            for ok, item in helpers.streaming_bulk(
                self.es,
                actions,
                raise_on_error=False,
                refresh="wait_for"
            ):
                action = next(iter(item))
                info = item.get(action, {})
                result = info.get("result")

                if not ok:
                    errors.append(item)
                    if info.get("status") == 404 or result == "not_found":
                        not_found += 1
                    continue

                success += 1
                if result == "updated":
                    updated += 1
                elif result == "noop":
                    noops += 1

            result = {
                "success": success,
                "failed": len(errors)
            }

            logger.info(
                "Bulk update summary: success=%s updated=%s noop=%s not_found=%s failed=%s",
                success,
                updated,
                noops,
                not_found,
                len(errors)
            )

            if errors:
                logger.error("Bulk update encountered %s errors. Sample: %s", len(errors), errors[:3])

            if actions:
                try:
                    doc = self.es.get(index=actions[0]["_index"], id=actions[0]["_id"], _source_includes=["ai"])
                    ai = doc.get("_source", {}).get("ai")
                    if not ai or not ai.get("advice"):
                        logger.warning(
                            "Post-update sample doc missing ai.advice. index=%s id=%s ai=%s",
                            actions[0]["_index"],
                            actions[0]["_id"],
                            ai
                        )
                    else:
                        logger.info(
                            "Post-update sample doc ai.processed=%s advice_length=%s",
                            ai.get("processed"),
                            len(ai.get("advice"))
                        )
                except Exception as e:
                    logger.warning(
                        "Failed to fetch sample doc after update. index=%s id=%s error=%s",
                        actions[0]["_index"],
                        actions[0]["_id"],
                        e
                    )

            return result

        except Exception as e:
            logger.error(f"Error during bulk update: {e}")
            raise

    
    def update_single_doc(self, index: str, doc_id: str, ai_advice: str, processed_at: int | str) -> bool:
        """
        Update a single document's ai.advice field.
        """
        try:
            processed_at_value = self._get_processed_at_value(processed_at)
            processed_value = self._get_processed_value(True)
            self.es.update(
                index=index,
                id=doc_id,
                body={
                    "doc": {
                        "ai": {
                            "advice": ai_advice,
                            "processed": processed_value,
                            "processed_at": processed_at_value
                        }
                    }
                }
            )
            return True
        except Exception as e:
            logger.error(f"Error updating document {doc_id} in index {index}: {e}")
            return False

    def try_connect_index(self, index: str) -> bool:
        """Try to connect to a target index for reading."""
        try:
            if not self.es.indices.exists(index=index):
                logger.warning("Target index does not exist: %s", index)
                return False
            self.es.search(index=index, body={"query": {"match_all": {}}, "size": 1})
            return True
        except Exception as e:
            logger.warning("Failed to connect to index %s: %s", index, e)
            return False
