"""Application-facing Wazuh operations used by API routes and SOC tools."""

from typing import Any

from app.services.wazuh.indexer_client import WazuhIndexerClient
from app.services.wazuh.models import (
    AgentSummary,
    AlertEvidence,
    AlertSearchResult,
    AuthenticationTimeline,
    DetectionEvidence,
    RuleMitreContext,
    SuccessfulLoginAnalysis,
)
from app.services.wazuh.server_client import WazuhServerClient


def _items(payload: dict[str, Any]) -> list[dict[str, Any]]:
    data = payload.get("data")
    if not isinstance(data, dict):
        return []
    items = data.get("affected_items")
    return items if isinstance(items, list) else []


def _total(payload: dict[str, Any]) -> int:
    data = payload.get("data")
    if not isinstance(data, dict):
        return 0
    value = data.get("total_affected_items", len(_items(payload)))
    try:
        return int(value)
    except (TypeError, ValueError):
        return len(_items(payload))


class WazuhGateway:
    """Deterministic, bounded operations; no arbitrary agent-supplied paths or DSL."""

    def __init__(
        self,
        server: WazuhServerClient | None = None,
        indexer: WazuhIndexerClient | None = None,
    ) -> None:
        self.server = server or WazuhServerClient()
        self.indexer = indexer or WazuhIndexerClient()

    # FastAPI's explicitly defined read routes use these internal adapters. They
    # are never registered as LLM tools.
    def server_get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        return self.server.get(path, params=params)

    def server_get_raw(self, path: str, params: dict[str, Any] | None = None) -> str:
        return self.server.get_raw(path, params=params)

    def indexer_health(self) -> dict[str, Any]:
        return self.indexer.health()

    def validate_server(self) -> dict[str, Any]:
        return self.server.get("/")

    def get_high_severity_alerts(
        self, *, min_level: int = 10, hours: int = 24, limit: int = 50
    ) -> AlertSearchResult:
        return self.indexer.search_alerts(min_level=min_level, hours=hours, limit=limit)

    def search_alerts(
        self,
        *,
        min_level: int = 0,
        hours: int = 24,
        limit: int = 50,
        agent_id: str | None = None,
        rule_id: str | None = None,
        text: str | None = None,
    ) -> AlertSearchResult:
        return self.indexer.search_alerts(
            min_level=min_level,
            hours=hours,
            limit=limit,
            agent_id=agent_id,
            rule_id=rule_id,
            text=text,
        )

    def get_alert_by_id(self, alert_id: str) -> AlertEvidence | None:
        return self.indexer.get_alert_by_id(alert_id)

    def get_agent_summary(self, agent_id: str) -> AgentSummary | None:
        payload = self.server.get(
            "/agents",
            params={
                "agents_list": agent_id,
                "select": "id,name,ip,status,version,os.name,lastKeepAlive",
                "limit": 1,
            },
        )
        items = _items(payload)
        if not items:
            return None
        item = items[0]
        os_data = item.get("os") if isinstance(item.get("os"), dict) else {}
        return AgentSummary(
            agent_id=str(item.get("id") or agent_id),
            name=item.get("name"),
            ip=item.get("ip"),
            status=item.get("status"),
            version=item.get("version"),
            os_name=os_data.get("name"),
            last_keep_alive=item.get("lastKeepAlive"),
        )

    def get_related_alerts(
        self, *, alert_id: str, hours: int = 24, limit: int = 100
    ) -> AlertSearchResult:
        alert = self.get_alert_by_id(alert_id)
        if alert is None:
            return AlertSearchResult(total=0, returned=0, truncated=False, alerts=[])
        result = self.indexer.search_alerts(
            hours=hours,
            limit=limit,
            agent_id=alert.agent_id,
            rule_id=None if alert.source_ip else alert.rule_id,
            source_ip=alert.source_ip,
        )
        result = result.model_copy(deep=True)
        result.alerts = [item for item in result.alerts if item.alert_id != alert_id]
        result.total = max(0, result.total - 1)
        result.returned = len(result.alerts)
        result.truncated = result.total > result.returned
        return result

    def build_authentication_timeline(
        self,
        *,
        source_ip: str,
        target_user: str | None = None,
        agent_id: str | None = None,
        hours: int = 24,
        limit: int = 100,
    ) -> AuthenticationTimeline:
        result = self.indexer.search_alerts(
            hours=hours,
            limit=limit,
            source_ip=source_ip,
            target_user=target_user,
            agent_id=agent_id,
            authentication_only=True,
            oldest_first=True,
        )
        return AuthenticationTimeline(
            total=result.total,
            returned=result.returned,
            truncated=result.truncated,
            events=result.alerts,
        )

    def check_successful_login_after_failures(
        self,
        *,
        source_ip: str,
        target_user: str | None = None,
        agent_id: str | None = None,
        hours: int = 24,
        limit: int = 200,
    ) -> SuccessfulLoginAnalysis:
        timeline = self.build_authentication_timeline(
            source_ip=source_ip,
            target_user=target_user,
            agent_id=agent_id,
            hours=hours,
            limit=limit,
        )
        failures = [event for event in timeline.events if event.event_outcome == "failure"]
        last_failure = failures[-1].timestamp if failures else None
        successes = [
            event
            for event in timeline.events
            if event.event_outcome == "success"
            and last_failure is not None
            and event.timestamp > last_failure
        ]
        success = successes[0] if successes else None
        evidence_ids = [event.alert_id for event in failures]
        if success:
            evidence_ids.append(success.alert_id)
        return SuccessfulLoginAnalysis(
            failed_attempt_count=len(failures),
            first_failure=failures[0].timestamp if failures else None,
            last_failure=last_failure,
            successful_login_found=success is not None,
            successful_login_timestamp=success.timestamp if success else None,
            evidence_alert_ids=evidence_ids,
            confidence=1.0 if timeline.events and not timeline.truncated else 0.5,
            truncated=timeline.truncated,
        )

    def get_rule_and_mitre_context(self, rule_id: str) -> RuleMitreContext | None:
        rule_payload = self.server.get("/rules", params={"rule_ids": rule_id, "limit": 1})
        rules = _items(rule_payload)
        if not rules:
            return None
        rule = rules[0]
        mitre = rule.get("mitre") if isinstance(rule.get("mitre"), dict) else {}
        mitre_ids = mitre.get("id") or []
        if not isinstance(mitre_ids, list):
            mitre_ids = [mitre_ids]
        techniques: list[dict[str, Any]] = []
        if mitre_ids:
            techniques = _items(self.server.get(
                "/mitre/techniques",
                params={"search": ",".join(str(item) for item in mitre_ids), "limit": 50},
            ))
        groups = rule.get("groups") or []
        if not isinstance(groups, list):
            groups = [groups]
        return RuleMitreContext(
            rule_id=str(rule.get("id") or rule_id),
            description=rule.get("description"),
            level=rule.get("level"),
            groups=[str(item) for item in groups],
            mitre_ids=[str(item) for item in mitre_ids],
            techniques=techniques,
        )

    def get_detection_evidence(self, *, agent_id: str, limit: int = 100) -> DetectionEvidence:
        fim = self.server.get("/syscheck/{agent_id}".format(agent_id=agent_id), params={"limit": limit})
        sca = self.server.get("/sca/{agent_id}".format(agent_id=agent_id), params={"limit": limit})
        fim_items = _items(fim)
        sca_items = _items(sca)
        fim_total = _total(fim)
        sca_total = _total(sca)
        return DetectionEvidence(
            agent_id=agent_id,
            fim_findings=fim_items,
            sca_findings=sca_items,
            fim_total=fim_total,
            sca_total=sca_total,
            truncated=fim_total > len(fim_items) or sca_total > len(sca_items),
        )

    def alert_summary(self, hours: int = 24) -> dict[str, Any]:
        return self.indexer.alert_summary(hours)

    def search_vulnerabilities(
        self, *, severity: str | None = None, agent_id: str | None = None, limit: int = 20
    ) -> tuple[list[dict[str, Any]], int]:
        return self.indexer.search_vulnerabilities(
            severity=severity, agent_id=agent_id, limit=limit
        )

    def vulnerability_summary(self) -> dict[str, Any]:
        return self.indexer.vulnerability_summary()

    def close(self) -> None:
        self.server.close()
        self.indexer.close()
