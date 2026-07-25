"""Bounded OpenSearch queries for the Wazuh Indexer on port 9200."""

import time
from datetime import datetime
from threading import Lock
from typing import Any

from opensearchpy import OpenSearch

from app.config import settings
from app.core.observability.wazuh import observe_wazuh_call
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
        return RawAlertDocument(
            alert_id=str(hit.get("_id") or alert_id),
            normalized=self._normalize_alert(hit),
            raw_document=_bounded_raw_source(source),
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
            event_outcome=_event_outcome(source),
        )

    @staticmethod
    def _total(response: dict[str, Any]) -> int:
        total = response.get("hits", {}).get("total", 0)
        if isinstance(total, dict):
            total = total.get("value", 0)
        return int(total or 0)
