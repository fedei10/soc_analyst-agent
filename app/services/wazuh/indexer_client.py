"""Bounded OpenSearch queries for the Wazuh Indexer on port 9200."""

import time
from threading import Lock
from typing import Any

from opensearchpy import OpenSearch

from app.config import settings
from app.services.wazuh.models import AlertEvidence, AlertSearchResult


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


class WazuhIndexerClient:
    """Owns all index names and OpenSearch DSL used by the application."""

    ALERT_INDEX = "wazuh-alerts-*"
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
            timeout=15,
            max_retries=3,
            retry_on_timeout=True,
        )
        self._alert_cache: dict[tuple[Any, ...], tuple[float, AlertSearchResult]] = {}
        self._alert_cache_lock = Lock()

    def health(self) -> dict[str, Any]:
        return self._client.cluster.health()

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
    ) -> AlertSearchResult:
        self._validate_window(hours, limit)
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
        )
        now = time.monotonic()
        with self._alert_cache_lock:
            cached = self._alert_cache.get(cache_key)
            if cached and cached[0] > now:
                return cached[1]
        must: list[dict[str, Any]] = [{"range": {"@timestamp": {"gte": f"now-{hours}h"}}}]
        if min_level:
            must.append({"range": {"rule.level": {"gte": min_level}}})
        if agent_id:
            must.append({"term": {"agent.id": agent_id}})
        if rule_id:
            must.append({"term": {"rule.id": rule_id}})
        if source_ip:
            must.append({"term": {"data.srcip": source_ip}})
        if target_user:
            must.append({"term": {"data.dstuser": target_user}})
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

        response = self._client.search(index=self.ALERT_INDEX, body={
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
        response = self._client.search(index=self.ALERT_INDEX, body={
            "size": 1,
            "query": {"ids": {"values": [alert_id]}},
        })
        hits = response.get("hits", {}).get("hits", [])
        return self._normalize_alert(hits[0]) if hits else None

    def alert_summary(self, hours: int = 24) -> dict[str, Any]:
        self._validate_window(hours, 1)
        response = self._client.search(index=self.ALERT_INDEX, body={
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
        response = self._client.search(index=self.VULNERABILITY_INDEX, body={
            "size": limit,
            "track_total_hits": True,
            "query": {"bool": {"must": must}} if must else {"match_all": {}},
        })
        hits = response.get("hits", {}).get("hits", [])
        return [item.get("_source", {}) for item in hits], self._total(response)

    def vulnerability_summary(self) -> dict[str, Any]:
        response = self._client.search(index=self.VULNERABILITY_INDEX, body={
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
            source_ip=data.get("srcip") or data.get("src_ip"),
            target_user=data.get("dstuser") or data.get("srcuser") or data.get("user"),
            mitre_ids=_string_list(mitre.get("id")),
            event_outcome=_event_outcome(source),
        )

    @staticmethod
    def _total(response: dict[str, Any]) -> int:
        total = response.get("hits", {}).get("total", 0)
        if isinstance(total, dict):
            total = total.get("value", 0)
        return int(total or 0)
