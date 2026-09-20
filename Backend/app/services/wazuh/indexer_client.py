"""Bounded OpenSearch queries for the Wazuh Indexer on port 9200."""

import hashlib
import json
import re
import time
from datetime import UTC, datetime, timedelta
from threading import Lock
from typing import Any

from opensearchpy import OpenSearch

from app.config import settings
from app.core.observability.wazuh import observe_wazuh_call
from app.services.wazuh.analyst_evidence import compact_alert, compact_vulnerability, technique_id
from app.services.wazuh.exceptions import WazuhAPIError
from app.services.wazuh.models import (
    AlertEvidence,
    AlertIngestionDocument,
    AlertIngestionPage,
    AlertSearchResult,
    ArchivedLogSearchResult,
    RawAlertDocument,
)


RAW_ALERT_FIELDS = (
    "@timestamp",
    "timestamp",
    "agent",
    "rule",
    "data",
    "full_log",
    "predecoder",
    "decoder",
    "location",
    "manager",
    "input",
)


def _nested(source: dict[str, Any], *path: str) -> Any:
    value: Any = source
    for part in path:
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if item is not None]
    if value is None:
        return []
    return [str(value)]


def _first_value(source: dict[str, Any], *paths: tuple[str, ...]) -> Any:
    for path in paths:
        value = _nested(source, *path)
        if value not in (None, ""):
            return value
    return None


def _bounded_raw_value(value: Any, *, depth: int = 0) -> Any:
    if depth >= 5:
        return "[nested value omitted]"
    if isinstance(value, dict):
        return {
            str(key)[:128]: _bounded_raw_value(item, depth=depth + 1)
            for key, item in list(value.items())[:100]
        }
    if isinstance(value, list):
        return [_bounded_raw_value(item, depth=depth + 1) for item in value[:100]]
    if isinstance(value, str):
        return value[:8000]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:1000]


def _bounded_raw_source(source: dict[str, Any]) -> dict[str, Any]:
    return {
        field: _bounded_raw_value(source[field])
        for field in RAW_ALERT_FIELDS
        if field in source
    }


def _event_outcome(source: dict[str, Any]) -> str:
    groups = " ".join(_string_list(_nested(source, "rule", "groups"))).lower()
    description = str(_nested(source, "rule", "description") or "").lower()
    full_log = str(source.get("full_log") or "").lower()
    text = f"{groups} {description} {full_log}"
    if "authentication_failed" in text or "failed password" in text or "login failed" in text:
        return "failure"
    if "authentication_success" in text or "accepted password" in text or "login successful" in text:
        return "success"
    return "unknown"


def _archive_status(response: dict[str, Any], total: int) -> str:
    shards = response.get("_shards")
    if isinstance(shards, dict):
        try:
            total_shards = int(shards.get("total", 0))
            failed_shards = int(shards.get("failed", 0))
        except (TypeError, ValueError):
            return "available" if total > 0 else "unknown"
        if failed_shards > 0:
            return "partial"
        return "available" if total_shards > 0 else "unavailable"
    return "available" if total > 0 else "unknown"


class WazuhIndexerClient:
    """Owns all index names and OpenSearch DSL used by the application."""

    ALERT_INDEX = "wazuh-alerts-*"
    ARCHIVE_INDEX = settings.WAZUH_ARCHIVE_INDEX
    VULNERABILITY_INDEX = "wazuh-states-vulnerabilities-*"

    def __init__(self, client: OpenSearch | None = None) -> None:
        self._client = client or OpenSearch(
            hosts=[{"host": settings.WAZUH_INDEXER_HOST, "port": settings.WAZUH_INDEXER_PORT}],
            http_auth=(
                settings.WAZUH_INDEXER_USER,
                settings.WAZUH_INDEXER_PASSWORD.get_secret_value(),
            ),
            use_ssl=True,
            verify_certs=settings.WAZUH_VERIFY_SSL,
            ca_certs=settings.WAZUH_CA_CERT if settings.WAZUH_VERIFY_SSL else None,
            ssl_assert_hostname=False,
            ssl_show_warn=not settings.WAZUH_VERIFY_SSL,
            timeout=float(settings.WAZUH_TIMEOUT),
            max_retries=3,
            retry_on_timeout=True,
        )
        self._alert_cache: dict[tuple[Any, ...], tuple[float, AlertSearchResult]] = {}
        self._alert_cache_lock = Lock()

    def health(self) -> dict[str, Any]:
        with observe_wazuh_call(
            operation="cluster_health",
            component="indexer",
        ):
            return self._client.cluster.health()

    def _search(
        self,
        *,
        index: str,
        body: dict[str, Any],
        operation: str,
        **options: Any,
    ) -> dict[str, Any]:
        with observe_wazuh_call(
            operation=operation,
            component="indexer",
        ):
            return self._client.search(
                index=index,
                body=body,
                **options,
            )

    def search_alerts(
        self,
        *,
        min_level: int = 0,
        hours: int = 24,
        limit: int = 50,
        agent_id: str | None = None,
        rule_id: str | None = None,
        source_ip: str | None = None,
        target_user: str | None = None,
        text: str | None = None,
        authentication_only: bool = False,
        oldest_first: bool = False,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> AlertSearchResult:
        self._validate_window(hours, limit)
        if (start_time is None) != (end_time is None):
            raise ValueError("start_time and end_time must be provided together.")
        if start_time is not None and end_time is not None and start_time >= end_time:
            raise ValueError("start_time must be earlier than end_time.")
        cache_key = (
            "search_alerts",
            min_level,
            hours,
            limit,
            agent_id,
            rule_id,
            source_ip,
            target_user,
            text,
            authentication_only,
            oldest_first,
            start_time.isoformat() if start_time else None,
            end_time.isoformat() if end_time else None,
        )
        now = time.monotonic()
        with self._alert_cache_lock:
            cached = self._alert_cache.get(cache_key)
            if cached and cached[0] > now:
                return cached[1]
        query = self._alert_query(
            min_level=min_level,
            hours=hours,
            agent_id=agent_id,
            rule_id=rule_id,
            source_ip=source_ip,
            target_user=target_user,
            text=text,
            authentication_only=authentication_only,
            start_time=start_time,
            end_time=end_time,
        )

        response = self._search(index=self.ALERT_INDEX, operation="search_alerts", body={
            "size": limit,
            "sort": [{"@timestamp": "asc" if oldest_first else "desc"}],
            "track_total_hits": True,
            "query": query,
        })
        result = self._alert_result(response)
        with self._alert_cache_lock:
            if len(self._alert_cache) >= 256:
                oldest = min(self._alert_cache, key=lambda key: self._alert_cache[key][0])
                self._alert_cache.pop(oldest)
            self._alert_cache[cache_key] = (now + 10.0, result)
        return result

    @staticmethod
    def _alert_query(
        *,
        min_level: int = 0,
        hours: int = 24,
        agent_id: str | None = None,
        rule_id: str | None = None,
        source_ip: str | None = None,
        target_user: str | None = None,
        text: str | None = None,
        authentication_only: bool = False,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> dict[str, Any]:
        """Alert filter clause shared by document search and aggregation.

        Both have to select the same population, or an aggregation's total
        would not describe the rows a matching search returns.
        """

        timestamp_range = (
            {
                "gte": start_time.isoformat(),
                "lte": end_time.isoformat(),
            }
            if start_time is not None and end_time is not None
            else {"gte": f"now-{hours}h"}
        )
        must: list[dict[str, Any]] = [{"range": {"@timestamp": timestamp_range}}]
        if min_level:
            must.append({"range": {"rule.level": {"gte": min_level}}})
        if agent_id:
            must.append({"term": {"agent.id": agent_id}})
        if rule_id:
            must.append({"term": {"rule.id": rule_id}})
        if source_ip:
            must.append({
                "bool": {
                    "should": [
                        {"term": {"source_ip": source_ip}},
                        {"term": {"data.srcip": source_ip}},
                        {"term": {"data.src_ip": source_ip}},
                        {"term": {"data.source_ip": source_ip}},
                        {"term": {"data.remote_ip": source_ip}},
                    ],
                    "minimum_should_match": 1,
                }
            })
        if target_user:
            must.append({
                "bool": {
                    "should": [
                        {"term": {"target_user": target_user}},
                        {"term": {"data.dstuser": target_user}},
                        {"term": {"data.srcuser": target_user}},
                        {"term": {"data.user": target_user}},
                        {"term": {"data.username": target_user}},
                    ],
                    "minimum_should_match": 1,
                }
            })
        if text:
            must.append({
                "multi_match": {
                    "query": text,
                    "fields": ["full_log", "rule.description", "rule.groups", "agent.name"],
                }
            })

        query: dict[str, Any] = {"bool": {"must": must}}
        if authentication_only:
            query["bool"]["should"] = [
                {"terms": {"rule.groups": ["authentication_failed", "authentication_success", "sshd"]}},
                {"multi_match": {
                    "query": "authentication login password sshd",
                    "fields": ["full_log", "rule.description", "rule.groups"],
                }},
            ]
            query["bool"]["minimum_should_match"] = 1

        return query

    # Wazuh writes the attacker address and the account under the decoder's
    # own field names. These are the keyword fields the indexer can bucket on;
    # the aggregation reports which one it counted and how many of the
    # matching documents actually carry it, so a sparsely populated field can
    # never be mistaken for a complete ranking.
    SOURCE_IP_FIELD = "data.srcip"
    TARGET_USER_FIELD = "data.dstuser"

    def aggregate_alerts(
        self,
        *,
        min_level: int = 0,
        hours: int = 24,
        agent_id: str | None = None,
        rule_id: str | None = None,
        source_ip: str | None = None,
        target_user: str | None = None,
        text: str | None = None,
        authentication_only: bool = False,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        top: int = 10,
    ) -> dict[str, Any]:
        """Rank source IPs, rules, agents and accounts over EVERY match.

        `search_alerts` returns at most `limit` documents, so counting them
        answers "which IP dominates the sample I was handed", not "which IP
        dominates the 871 matching alerts". This runs the same filters with
        size=0 and lets the indexer do the counting, so the ranking describes
        the whole population and the coverage block can say so.
        """

        if not 1 <= top <= 50:
            raise ValueError("top must be between 1 and 50.")
        self._validate_window(hours, 1)
        query = self._alert_query(
            min_level=min_level,
            hours=hours,
            agent_id=agent_id,
            rule_id=rule_id,
            source_ip=source_ip,
            target_user=target_user,
            text=text,
            authentication_only=authentication_only,
            start_time=start_time,
            end_time=end_time,
        )
        response = self._search(
            index=self.ALERT_INDEX,
            operation="aggregate_alerts",
            body={
                "size": 0,
                "track_total_hits": True,
                "query": query,
                "aggs": {
                    "by_source_ip": {
                        "terms": {"field": self.SOURCE_IP_FIELD, "size": top}
                    },
                    "source_ip_present": {
                        "value_count": {"field": self.SOURCE_IP_FIELD}
                    },
                    "by_target_user": {
                        "terms": {"field": self.TARGET_USER_FIELD, "size": top}
                    },
                    "target_user_present": {
                        "value_count": {"field": self.TARGET_USER_FIELD}
                    },
                    "by_agent": {"terms": {"field": "agent.name", "size": top}},
                    "by_level": {"terms": {"field": "rule.level", "size": 20}},
                    "by_rule": {
                        "terms": {"field": "rule.id", "size": top},
                        # One document per rule carries the description, so the
                        # analyst does not need a second call to learn what a
                        # rule ID actually detects.
                        "aggs": {
                            "sample": {
                                "top_hits": {
                                    "size": 1,
                                    "_source": ["rule.description", "rule.level"],
                                }
                            }
                        },
                    },
                },
            },
        )
        aggregations = response.get("aggregations", {})
        total = self._total(response)

        def buckets(name: str) -> dict[str, int]:
            values = aggregations.get(name, {}).get("buckets", [])
            return {str(item["key"]): item["doc_count"] for item in values}

        def count(name: str) -> int:
            return int(aggregations.get(name, {}).get("value") or 0)

        rules = []
        for item in aggregations.get("by_rule", {}).get("buckets", []):
            hits = item.get("sample", {}).get("hits", {}).get("hits", [])
            rule = (hits[0].get("_source", {}) if hits else {}).get("rule", {})
            rules.append(
                {
                    "rule_id": str(item["key"]),
                    "count": item["doc_count"],
                    "description": rule.get("description"),
                    "level": rule.get("level"),
                }
            )

        return {
            "coverage": {
                "matched": total,
                "returned": total,
                "truncated": False,
                "status": "complete",
                "aggregation_scope": "full_population",
                "note": (
                    "Counts were computed by the indexer over every matching "
                    "document, not over a returned sample."
                ),
            },
            "window": {
                "hours": hours if start_time is None else None,
                "start": start_time.isoformat() if start_time else None,
                "end": end_time.isoformat() if end_time else None,
            },
            "filters": {
                "min_level": min_level,
                "agent_id": agent_id,
                "rule_id": rule_id,
                "source_ip": source_ip,
                "target_user": target_user,
                "text": text,
                "authentication_only": authentication_only,
            },
            "total_alerts": total,
            "by_rule": rules,
            "by_level": buckets("by_level"),
            "by_agent": buckets("by_agent"),
            "by_source_ip": buckets("by_source_ip"),
            "source_ip_field": self.SOURCE_IP_FIELD,
            "alerts_with_source_ip": count("source_ip_present"),
            "by_target_user": buckets("by_target_user"),
            "target_user_field": self.TARGET_USER_FIELD,
            "alerts_with_target_user": count("target_user_present"),
        }

    def get_alert_by_id(self, alert_id: str) -> AlertEvidence | None:
        response = self._search(index=self.ALERT_INDEX, operation="get_alert", body={
            "size": 1,
            "query": {"ids": {"values": [alert_id]}},
        })
        hits = response.get("hits", {}).get("hits", [])
        return self._normalize_alert(hits[0]) if hits else None

    def get_raw_alert_by_id(self, alert_id: str) -> RawAlertDocument | None:
        response = self._search(index=self.ALERT_INDEX, operation="get_raw_alert", body={
            "size": 1,
            "query": {"ids": {"values": [alert_id]}},
        })
        hits = response.get("hits", {}).get("hits", [])
        if not hits:
            return None
        hit = hits[0]
        source = hit.get("_source", {})
        if not isinstance(source, dict):
            source = {}
        raw_hash = hashlib.sha256(
            json.dumps(
                source,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            ).encode("utf-8")
        ).hexdigest()
        return RawAlertDocument(
            alert_id=str(hit.get("_id") or alert_id),
            normalized=self._normalize_alert(hit),
            raw_document=_bounded_raw_source(source),
            index_name=str(hit.get("_index") or self.ALERT_INDEX),
            raw_document_hash=raw_hash,
        )

    def search_alert_page(
        self,
        *,
        size: int = 500,
        since: datetime | None = None,
        search_after: list[Any] | None = None,
    ) -> AlertIngestionPage:
        """Read a stable ascending page for idempotent background ingestion."""

        if not 1 <= size <= 1000:
            raise ValueError("size must be between 1 and 1000.")
        timestamp_range = (
            {"gte": since.isoformat()} if since is not None else {"gte": "now-24h"}
        )
        body: dict[str, Any] = {
            "size": size,
            "sort": [
                {"@timestamp": {"order": "asc", "unmapped_type": "date"}},
                {"_index": {"order": "asc"}},
                {"_id": {"order": "asc"}},
            ],
            "track_total_hits": True,
            "query": {"range": {"@timestamp": timestamp_range}},
        }
        if search_after:
            body["search_after"] = search_after
        response = self._search(
            index=self.ALERT_INDEX,
            operation="ingest_alerts",
            body=body,
        )
        hits = response.get("hits", {}).get("hits", [])
        documents = []
        for hit in hits:
            source = hit.get("_source")
            if not isinstance(source, dict):
                source = {}
            documents.append(
                AlertIngestionDocument(
                    document_id=str(hit.get("_id") or ""),
                    index_name=str(hit.get("_index") or self.ALERT_INDEX),
                    sort_values=list(hit.get("sort") or []),
                    normalized=self._normalize_alert(hit),
                    raw_document=_bounded_raw_source(source),
                )
            )
        return AlertIngestionPage(
            documents=documents,
            search_after=(
                documents[-1].sort_values if documents else search_after
            ),
            total=self._total(response),
        )

    def search_archived_logs(
        self,
        *,
        text: str,
        hours: int = 24,
        limit: int = 50,
        agent_id: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> ArchivedLogSearchResult:
        self._validate_window(hours, limit)
        if not 2 <= len(text) <= 256:
            raise ValueError("text must be between 2 and 256 characters.")
        if (start_time is None) != (end_time is None):
            raise ValueError("start_time and end_time must be provided together.")

        timestamp_range = (
            {
                "gte": start_time.isoformat(),
                "lte": end_time.isoformat(),
            }
            if start_time is not None and end_time is not None
            else {"gte": f"now-{hours}h"}
        )
        must: list[dict[str, Any]] = [
            {
                "bool": {
                    "should": [
                        {"range": {"@timestamp": timestamp_range}},
                        {"range": {"timestamp": timestamp_range}},
                    ],
                    "minimum_should_match": 1,
                }
            },
            {
                "multi_match": {
                    "query": text,
                    "fields": [
                        "full_log",
                        "rule.description",
                        "rule.groups",
                        "data.*",
                        "decoder.name",
                        "location",
                        "agent.name",
                    ],
                }
            },
        ]
        if agent_id:
            must.append({"term": {"agent.id": agent_id}})

        response = self._search(
            index=self.ARCHIVE_INDEX,
            operation="search_archived_logs",
            body={
                "size": limit,
                "sort": [
                    {"@timestamp": {"order": "desc", "unmapped_type": "date"}},
                    {"timestamp": {"order": "desc", "unmapped_type": "date"}},
                ],
                "track_total_hits": True,
                "query": {"bool": {"must": must}},
            },
            ignore_unavailable=True,
            allow_no_indices=True,
        )
        hits = response.get("hits", {}).get("hits", [])
        events = [
            RawAlertDocument(
                alert_id=str(hit.get("_id") or ""),
                normalized=self._normalize_alert(hit),
                raw_document=_bounded_raw_source(
                    hit.get("_source", {})
                    if isinstance(hit.get("_source"), dict)
                    else {}
                ),
            )
            for hit in hits
        ]
        total = self._total(response)
        return ArchivedLogSearchResult(
            index_pattern=self.ARCHIVE_INDEX,
            archive_status=_archive_status(response, total),
            query_scope={
                "text": text,
                "hours": hours,
                "agent_id": agent_id,
                "start_time": start_time.isoformat() if start_time else None,
                "end_time": end_time.isoformat() if end_time else None,
                "limit": limit,
            },
            total=total,
            returned=len(events),
            truncated=total > len(events),
            events=events,
        )

    def archive_summary(self, hours: int = 24) -> dict[str, Any]:
        self._validate_window(hours, 1)
        response = self._search(
            index=self.ARCHIVE_INDEX,
            operation="archive_statistics",
            body={
                "size": 0,
                "track_total_hits": True,
                "query": {
                    "bool": {
                        "should": [
                            {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
                            {"range": {"timestamp": {"gte": f"now-{hours}h"}}},
                        ],
                        "minimum_should_match": 1,
                    }
                },
                "aggs": {
                    "earliest": {"min": {"field": "@timestamp"}},
                    "latest": {"max": {"field": "@timestamp"}},
                },
            },
            ignore_unavailable=True,
            allow_no_indices=True,
        )
        aggregations = response.get("aggregations", {})
        total = self._total(response)
        return {
            "index_pattern": self.ARCHIVE_INDEX,
            "archive_status": _archive_status(response, total),
            "hours": hours,
            "total_events": total,
            "earliest": aggregations.get("earliest", {}).get("value_as_string"),
            "latest": aggregations.get("latest", {}).get("value_as_string"),
        }

    def alert_summary(self, hours: int = 24) -> dict[str, Any]:
        self._validate_window(hours, 1)
        response = self._search(index=self.ALERT_INDEX, operation="rule_context", body={
            "size": 0,
            "track_total_hits": True,
            "query": {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
            "aggs": {
                "by_level": {"terms": {"field": "rule.level", "size": 20}},
                "by_agent": {"terms": {"field": "agent.name", "size": 10}},
                "by_group": {"terms": {"field": "rule.groups", "size": 10}},
            },
        })

        def buckets(name: str) -> dict[str, int]:
            values = response.get("aggregations", {}).get(name, {}).get("buckets", [])
            return {str(item["key"]): item["doc_count"] for item in values}

        return {
            "hours": hours,
            "total_alerts": self._total(response),
            "by_level": buckets("by_level"),
            "by_agent": buckets("by_agent"),
            "by_group": buckets("by_group"),
        }

    def search_vulnerabilities(
        self, *, severity: str | None = None, agent_id: str | None = None, limit: int = 20
    ) -> tuple[list[dict[str, Any]], int]:
        self._validate_window(1, limit)
        must: list[dict[str, Any]] = []
        if severity:
            must.append({"term": {"vulnerability.severity": severity}})
        if agent_id:
            must.append({"term": {"agent.id": agent_id}})
        response = self._search(index=self.VULNERABILITY_INDEX, operation="endpoint_vulnerabilities", body={
            "size": limit,
            "track_total_hits": True,
            "query": {"bool": {"must": must}} if must else {"match_all": {}},
        })
        hits = response.get("hits", {}).get("hits", [])
        return [item.get("_source", {}) for item in hits], self._total(response)

    @classmethod
    def _evidence_page(cls, response: dict[str, Any], *, offset: int, compact: Any,
                       records_key: str) -> dict[str, Any]:
        if response.get("timed_out") or (response.get("_shards") or {}).get("failed", 0):
            raise WazuhAPIError("Wazuh returned an incomplete search; absence of activity cannot be established.", status_code=503)
        total_info = response.get("hits", {}).get("total", {})
        if isinstance(total_info, dict) and total_info.get("relation", "eq") != "eq":
            raise WazuhAPIError("Wazuh did not return an exact matched-record count.", status_code=503)
        items = [compact(hit) for hit in response.get("hits", {}).get("hits", [])]
        total = cls._total(response)
        truncated = offset > 0 or total > len(items)
        return {
            "total": total, "returned": len(items), "truncated": truncated,
            "offset": offset,
            "next_offset": offset + len(items) if items and offset + len(items) < total and offset + len(items) <= 5000 else None,
            records_key: items,
            "coverage": {"matched": total, "returned": len(items), "truncated": truncated,
                         "status": "partial" if truncated else "complete"},
        }

    def threat_hunt(
        self, *, hours: int = 24, limit: int = 20, offset: int = 0,
        agent_id: str | None = None, technique: str | None = None,
        executable: str | None = None, source_ip: str | None = None,
        target_user: str | None = None, start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> dict[str, Any]:
        """Fixed alert-index hunt; model callers cannot supply paths or DSL."""
        self._validate_window(hours, limit)
        if not 0 <= offset <= 5000:
            raise ValueError("offset must be between 0 and 5000.")
        if (start_time is None) != (end_time is None):
            raise ValueError("start_time and end_time must be provided together.")
        if start_time is not None and end_time is not None:
            if start_time.tzinfo is None or end_time.tzinfo is None:
                raise ValueError("Hunt timestamps must include a timezone.")
            if not 0 < (end_time - start_time).total_seconds() <= 168 * 3600:
                raise ValueError("Hunt interval must be positive and no longer than seven days.")
        query = self._alert_query(hours=hours, agent_id=agent_id, source_ip=source_ip,
                                  target_user=target_user, start_time=start_time, end_time=end_time)
        if technique:
            query["bool"]["must"].append({"term": {"rule.mitre.id": technique_id(technique)}})
        if executable:
            if not 1 <= len(executable) <= 512:
                raise ValueError("executable must be between 1 and 512 characters.")
            query["bool"]["must"].append({"bool": {"should": [
                {"term": {"data.audit.exe": executable}},
                {"term": {"data.win.eventdata.image": executable}},
            ], "minimum_should_match": 1}})
        response = self._search(index=self.ALERT_INDEX, operation="threat_hunt", body={
            "size": limit, "from": offset, "track_total_hits": True,
            "sort": [{"@timestamp": "asc"}, {"_index": "asc"}, {"_id": "asc"}],
            "_source": list(RAW_ALERT_FIELDS), "query": query,
        })
        result = self._evidence_page(response, offset=offset, compact=compact_alert, records_key="alerts")
        result["scope"] = "wazuh_alerts_only; untagged activity will not match a MITRE filter"
        return result

    def vulnerability_evidence(
        self, *, severity: str | None = None, agent_id: str | None = None,
        cve_id: str | None = None, package_name: str | None = None,
        limit: int = 20, offset: int = 0,
    ) -> dict[str, Any]:
        self._validate_window(1, limit)
        if not 0 <= offset <= 5000:
            raise ValueError("offset must be between 0 and 5000.")
        must = []
        if severity:
            severity = severity.capitalize()
            if severity not in {"Critical", "High", "Medium", "Low"}:
                raise ValueError("severity must be critical, high, medium, or low.")
            must.append({"term": {"vulnerability.severity": severity}})
        if cve_id:
            cve_id = cve_id.strip().upper()
            if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
                raise ValueError("Use a CVE ID such as CVE-2025-4050.")
            must.append({"term": {"vulnerability.id": cve_id}})
        if agent_id:
            must.append({"term": {"agent.id": agent_id}})
        if package_name:
            if not 1 <= len(package_name) <= 256:
                raise ValueError("package_name must be between 1 and 256 characters.")
            must.append({"term": {"package.name": package_name}})
        response = self._search(index=self.VULNERABILITY_INDEX, operation="vulnerability_evidence", body={
            "size": limit, "from": offset, "track_total_hits": True,
            "sort": [{"vulnerability.detected_at": {"order": "desc", "unmapped_type": "date"}},
                     {"_index": "asc"}, {"_id": "asc"}],
            "_source": ["agent", "host.os", "package", "vulnerability"],
            "query": {"bool": {"must": must}} if must else {"match_all": {}},
        })
        result = self._evidence_page(response, offset=offset, compact=compact_vulnerability, records_key="items")
        result["scope"] = "current_vulnerability_inventory; not historical alerts or proof of exploitation"
        return result

    def alert_statistics(
        self, *, mode: str, hours: int = 24, baseline_hours: int = 144,
        interval_minutes: int = 60, agent_id: str | None = None,
        rule_id: str | None = None, min_level: int = 0,
    ) -> dict[str, Any]:
        """Fixed, bounded analytics: timeline, observed MITRE, or prior baseline."""
        self._validate_window(hours, 1)
        if mode not in {"timeline", "mitre", "baseline"}:
            raise ValueError("Unsupported analytics mode.")
        if not 0 <= min_level <= 15:
            raise ValueError("min_level must be between 0 and 15.")
        if mode == "baseline" and not 1 <= baseline_hours <= 168 - hours:
            raise ValueError("Current and baseline windows together must span at most seven days.")
        if mode == "timeline" and (not 1 <= interval_minutes <= 1440 or
                                    (hours * 60 + interval_minutes - 1) // interval_minutes + 1 > 168):
            raise ValueError("Timeline must have at most 168 buckets; increase interval_minutes.")
        now = datetime.now(UTC)
        start = now - timedelta(hours=hours)
        query = self._alert_query(hours=hours, agent_id=agent_id, rule_id=rule_id,
                                  min_level=min_level, start_time=start, end_time=now)
        # Pin the same clock for every view and keep comparison windows disjoint.
        query["bool"]["must"][0]["range"]["@timestamp"] = {
            "gte": start.isoformat(), "lt": now.isoformat(),
        }
        if mode == "timeline":
            aggs = {"timeline": {"date_histogram": {
                "field": "@timestamp", "fixed_interval": f"{interval_minutes}m",
                "min_doc_count": 0, "extended_bounds": {
                    "min": start.isoformat(), "max": (now - timedelta(milliseconds=1)).isoformat(),
                },
            }}}
        elif mode == "mitre":
            aggs = {
                "mapped": {"filter": {"exists": {"field": "rule.mitre.id"}}},
                "techniques": {"terms": {"field": "rule.mitre.id", "size": 15,
                                           "show_term_doc_count_error": True},
                               "aggs": {"agents": {"terms": {"field": "agent.id", "size": 5}}}},
                "tactics": {"terms": {"field": "rule.mitre.tactic", "size": 15}},
            }
        else:
            baseline_start = start - timedelta(hours=baseline_hours)
            query["bool"]["must"][0]["range"]["@timestamp"]["gte"] = baseline_start.isoformat()
            aggs = {
                "current": {"filter": {"range": {"@timestamp": {
                    "gte": start.isoformat(), "lt": now.isoformat(),
                }}}},
                "baseline": {"filter": {"range": {"@timestamp": {
                    "gte": baseline_start.isoformat(), "lt": start.isoformat(),
                }}}},
            }
        response = self._search(index=self.ALERT_INDEX, operation=f"alert_{mode}",
                                body={"size": 0, "track_total_hits": True, "query": query, "aggs": aggs})
        self._check_aggregation(response)
        total = self._total(response)
        values = response.get("aggregations", {})
        result = {"scope": "matching alert documents, not proof of compromise",
                  "window": {"start": start.isoformat(), "end": now.isoformat(), "hours": hours},
                  "filters": {"agent_id": agent_id, "rule_id": rule_id, "min_level": min_level},
                  "total_alerts": total, "aggregations": values}
        if mode == "baseline":
            current = int(values["current"]["doc_count"])
            baseline = int(values["baseline"]["doc_count"])
            current_rate, baseline_rate = current / hours, baseline / baseline_hours
            result["comparison"] = {
                "current_count": current, "baseline_count": baseline,
                "current_per_hour": current_rate, "baseline_per_hour": baseline_rate,
                "rate_ratio": current_rate / baseline_rate if baseline_rate else None,
                "baseline_zero": baseline == 0, "baseline_hours": baseline_hours,
                "baseline_start": baseline_start.isoformat(), "baseline_end": start.isoformat(),
                "note": "Zero in this baseline is not never seen historically; rates alone do not prove an attack.",
            }
        result["coverage"] = self._aggregation_coverage(values, total)
        if mode == "timeline":
            result.pop("aggregations")
            result["interval_minutes"] = interval_minutes
            result["series"] = [{"timestamp": bucket["key_as_string"], "count": bucket["doc_count"]}
                                for bucket in values["timeline"]["buckets"]]
        if mode == "mitre":
            result["mapped_alerts"] = values["mapped"]["doc_count"]
            result["unmapped_alerts"] = total - result["mapped_alerts"]
            result["note"] = "Observed MITRE mappings, not detection-gap proof. Multi-valued tags can count a document in several buckets."
        return result

    @staticmethod
    def _check_aggregation(response: dict[str, Any]) -> None:
        if response.get("timed_out") or response.get("_shards", {}).get("failed", 0):
            raise WazuhAPIError("Wazuh aggregation is incomplete.", status_code=503)
        if response.get("hits", {}).get("total", {}).get("relation", "eq") != "eq":
            raise WazuhAPIError("Wazuh aggregation total is not exact.", status_code=503)
        if not isinstance(response.get("aggregations"), dict):
            raise WazuhAPIError("Wazuh aggregation result is missing.", status_code=503)

    @staticmethod
    def _aggregation_coverage(values: dict[str, Any], total: int) -> dict[str, Any]:
        def partial(value: Any) -> bool:
            if isinstance(value, dict):
                if "buckets" in value and "sum_other_doc_count" in value:
                    error = value.get("doc_count_error_upper_bound")
                    if value["sum_other_doc_count"] or error is None or error != 0:
                        return True
                return any(partial(item) for item in value.values())
            return isinstance(value, list) and any(partial(item) for item in value)
        truncated = partial(values)
        return {"matched": total, "returned": total, "truncated": truncated,
                "status": "partial" if truncated else "complete", "aggregation_scope": "full_population",
                "note": "Indexer totals cover all matches; top buckets may omit values or have count errors, reported in aggregations."}

    def ioc_agent_summary(
        self, *, indicator: str, indicator_type: str, hours: int = 24,
        agent_id: str | None = None,
    ) -> dict[str, Any]:
        """Cross-host counts over the same alert population as local IOC search."""
        self._validate_window(hours, 1)
        if not 2 <= len(indicator) <= 256:
            raise ValueError("indicator must be between 2 and 256 characters.")
        # Keep the population identical to hunt_ioc_telemetry's alert query.
        query = self._alert_query(hours=hours, agent_id=agent_id, text=indicator)
        response = self._search(index=self.ALERT_INDEX, operation="ioc_agent_summary", body={
            "size": 0, "track_total_hits": True, "query": query,
            "aggs": {"agents": {"terms": {"field": "agent.id", "size": 20,
                                              "show_term_doc_count_error": True},
                                  "aggs": {"first_seen": {"min": {"field": "@timestamp"}},
                                           "last_seen": {"max": {"field": "@timestamp"}},
                                           "name": {"top_hits": {"size": 1, "_source": ["agent.name"]}}}}},
        })
        self._check_aggregation(response)
        total = self._total(response)
        values = response["aggregations"]
        agents = values["agents"]
        rows = []
        for bucket in agents["buckets"]:
            names = bucket.get("name", {}).get("hits", {}).get("hits", [])
            name = names[0].get("_source", {}).get("agent", {}).get("name") if names else None
            rows.append({"agent_id": bucket["key"], "hostname": name, "count": bucket["doc_count"],
                         "first_seen": bucket.get("first_seen", {}).get("value_as_string"),
                         "last_seen": bucket.get("last_seen", {}).get("value_as_string"),
                         "count_error": bucket.get("doc_count_error_upper_bound")})
        return {"indicator": indicator, "indicator_type": indicator_type,
                "scope": "alert text occurrences only; shared indicator is not proof of a campaign",
                "total_alerts": total, "agents": rows,
                "sum_other_doc_count": agents.get("sum_other_doc_count"),
                "doc_count_error_upper_bound": agents.get("doc_count_error_upper_bound"),
                "coverage": self._aggregation_coverage(values, total)}

    def vulnerability_summary(self) -> dict[str, Any]:
        response = self._search(index=self.VULNERABILITY_INDEX, operation="vulnerability_inventory", body={
            "size": 0,
            "track_total_hits": True,
            "aggs": {"by_severity": {"terms": {"field": "vulnerability.severity", "size": 10}}},
        })
        buckets = response.get("aggregations", {}).get("by_severity", {}).get("buckets", [])
        return {
            "total_vulnerabilities": self._total(response),
            "by_severity": {str(item["key"]): item["doc_count"] for item in buckets},
        }

    def close(self) -> None:
        self._alert_cache.clear()
        self._client.close()

    @staticmethod
    def _validate_window(hours: int, limit: int) -> None:
        if not 1 <= hours <= 168:
            raise ValueError("hours must be between 1 and 168.")
        if not 1 <= limit <= 200:
            raise ValueError("limit must be between 1 and 200.")

    @classmethod
    def _alert_result(cls, response: dict[str, Any]) -> AlertSearchResult:
        hits = response.get("hits", {}).get("hits", [])
        alerts = [cls._normalize_alert(hit) for hit in hits]
        total = cls._total(response)
        return AlertSearchResult(
            total=total,
            returned=len(alerts),
            truncated=total > len(alerts),
            alerts=alerts,
        )

    @staticmethod
    def _normalize_alert(hit: dict[str, Any]) -> AlertEvidence:
        source = hit.get("_source", {})
        rule = source.get("rule") if isinstance(source.get("rule"), dict) else {}
        agent = source.get("agent") if isinstance(source.get("agent"), dict) else {}
        data = source.get("data") if isinstance(source.get("data"), dict) else {}
        mitre = rule.get("mitre") if isinstance(rule.get("mitre"), dict) else {}
        return AlertEvidence(
            alert_id=str(hit.get("_id") or source.get("id") or source.get("alert_id") or ""),
            timestamp=source.get("@timestamp") or source.get("timestamp"),
            agent_id=str(agent["id"]) if agent.get("id") is not None else None,
            agent_name=agent.get("name"),
            rule_id=str(rule.get("id") or ""),
            rule_level=int(rule.get("level") or 0),
            description=str(rule.get("description") or ""),
            source_ip=_first_value(
                source,
                ("source_ip",),
                ("data", "srcip"),
                ("data", "src_ip"),
                ("data", "source_ip"),
                ("data", "remote_ip"),
            ),
            target_user=_first_value(
                source,
                ("target_user",),
                ("data", "dstuser"),
                ("data", "srcuser"),
                ("data", "user"),
                ("data", "username"),
            ),
            hostname=_first_value(
                source,
                ("predecoder", "hostname"),
                ("agent", "name"),
            ),
            decoder_name=_first_value(source, ("decoder", "name")),
            full_log=_first_value(source, ("full_log",)),
            rule_groups=_string_list(rule.get("groups")),
            mitre_ids=_string_list(mitre.get("id")),
            event_count=int(
                rule.get("firedtimes") or source.get("event_count") or 1
            ),
            event_outcome=_event_outcome(source),
        )

    @staticmethod
    def _total(response: dict[str, Any]) -> int:
        total = response.get("hits", {}).get("total", 0)
        if isinstance(total, dict):
            total = total.get("value", 0)
        return int(total or 0)
