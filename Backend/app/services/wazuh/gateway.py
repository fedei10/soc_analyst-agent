"""Application-facing Wazuh operations used by API routes and SOC tools."""

from datetime import datetime, timedelta
import re
from typing import Any, Literal

from app.config import settings
from app.services.redis.ephemeral import EphemeralRedis
from app.services.wazuh.analyst_evidence import compact_mitre, technique_id
from app.services.wazuh.indexer_client import WazuhIndexerClient
from app.services.wazuh.models import (
    AgentConnectivitySummary,
    AgentSummary,
    AlertIngestionPage,
    AlertEvidence,
    AlertSearchResult,
    ArchivedLogSearchResult,
    AuthenticationTimeline,
    DetectionEvidence,
    EndpointInventory,
    EndpointForensics,
    IOCHuntResult,
    RawAlertDocument,
    RuleMitreContext,
    SuccessfulLoginAnalysis,
)
from app.services.wazuh.server_client import WazuhServerClient
from app.utils.helpers import gather


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
        cache: Any | None = None,
    ) -> None:
        self.server = server or WazuhServerClient()
        self.indexer = indexer or WazuhIndexerClient()
        self._cache = cache or EphemeralRedis()

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
        source_ip: str | None = None,
        target_user: str | None = None,
        text: str | None = None,
        authentication_only: bool = False,
        oldest_first: bool = False,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> AlertSearchResult:
        return self.indexer.search_alerts(
            min_level=min_level,
            hours=hours,
            limit=limit,
            agent_id=agent_id,
            rule_id=rule_id,
            source_ip=source_ip,
            target_user=target_user,
            text=text,
            authentication_only=authentication_only,
            oldest_first=oldest_first,
            start_time=start_time,
            end_time=end_time,
        )

    def get_alert_by_id(self, alert_id: str) -> AlertEvidence | None:
        return self.indexer.get_alert_by_id(alert_id)

    def get_raw_alert_by_id(self, alert_id: str) -> RawAlertDocument | None:
        return self.indexer.get_raw_alert_by_id(alert_id)

    def search_alert_page(
        self,
        *,
        size: int = 500,
        since: datetime | None = None,
        search_after: list[Any] | None = None,
    ) -> AlertIngestionPage:
        return self.indexer.search_alert_page(
            size=size,
            since=since,
            search_after=search_after,
        )

    def search_alerts_by_agent_and_time(
        self,
        *,
        agent_id: str,
        center_time: datetime,
        window_minutes: int = 30,
        limit: int = 100,
        authentication_only: bool = False,
    ) -> AlertSearchResult:
        if not 1 <= window_minutes <= 1440:
            raise ValueError("window_minutes must be between 1 and 1440.")
        window = timedelta(minutes=window_minutes)
        return self.indexer.search_alerts(
            agent_id=agent_id,
            hours=24,
            limit=limit,
            authentication_only=authentication_only,
            oldest_first=True,
            start_time=center_time - window,
            end_time=center_time + window,
        )

    def search_archived_logs(
        self,
        *,
        text: str,
        hours: int = 24,
        limit: int = 50,
        agent_id: str | None = None,
        center_time: datetime | None = None,
        window_minutes: int = 30,
    ) -> ArchivedLogSearchResult:
        start_time = None
        end_time = None
        if center_time is not None:
            if not 1 <= window_minutes <= 1440:
                raise ValueError("window_minutes must be between 1 and 1440.")
            window = timedelta(minutes=window_minutes)
            start_time = center_time - window
            end_time = center_time + window
        return self.indexer.search_archived_logs(
            text=text,
            hours=hours,
            limit=limit,
            agent_id=agent_id,
            start_time=start_time,
            end_time=end_time,
        )

    def get_log_statistics(self, *, hours: int = 24) -> dict[str, Any]:
        return {
            "alerts": self.indexer.alert_summary(hours),
            "archives": self.indexer.archive_summary(hours),
        }

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

    def get_agent_inventory(
        self,
        *,
        agent_id: str,
        component: Literal[
            "processes",
            "ports",
            "packages",
            "os",
            "network",
            "hotfixes",
            "hardware",
        ],
        limit: int = 50,
        text: str | None = None,
    ) -> EndpointInventory:
        """Return one allowlisted, bounded syscollector inventory component."""
        if not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100.")
        paths = {
            "processes": "processes",
            "ports": "ports",
            "packages": "packages",
            "os": "os",
            "network": "netiface",
            "hotfixes": "hotfixes",
            "hardware": "hardware",
        }
        syscollector_component = paths.get(component)
        if syscollector_component is None:
            raise ValueError("Unsupported endpoint inventory component.")
        params: dict[str, Any] = {"limit": limit}
        if text:
            params["search"] = text
        payload = self.server.get(
            f"/syscollector/{agent_id}/{syscollector_component}",
            params=params,
        )
        items = _items(payload)
        total = _total(payload)
        return EndpointInventory(
            agent_id=agent_id,
            component=component,
            total=total,
            returned=len(items),
            truncated=total > len(items),
            items=items,
        )

    def get_related_alerts(
        self,
        *,
        alert_id: str,
        hours: int = 24,
        limit: int = 100,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        authentication_only: bool = False,
    ) -> AlertSearchResult:
        if (start_time is None) != (end_time is None):
            raise ValueError("start_time and end_time must be provided together.")
        alert = self.get_alert_by_id(alert_id)
        if alert is None:
            return AlertSearchResult(total=0, returned=0, truncated=False, alerts=[])
        time_bounds: dict[str, datetime] = {}
        if start_time is not None and end_time is not None:
            time_bounds = {
                "start_time": start_time,
                "end_time": end_time,
            }
        elif alert.agent_id:
            time_bounds = {
                "start_time": alert.timestamp - timedelta(hours=hours),
                "end_time": alert.timestamp + timedelta(hours=hours),
            }
        if alert.agent_id:
            result = self.indexer.search_alerts(
                hours=hours,
                limit=limit,
                agent_id=alert.agent_id,
                source_ip=alert.source_ip,
                authentication_only=authentication_only,
                oldest_first=True,
                **time_bounds,
            )
        else:
            result = self.indexer.search_alerts(
                hours=hours,
                limit=limit,
                rule_id=alert.rule_id,
                authentication_only=authentication_only,
                oldest_first=start_time is not None,
                **time_bounds,
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
        source_ip: str | None = None,
        target_user: str | None = None,
        agent_id: str | None = None,
        hours: int = 24,
        limit: int = 100,
        center_time: datetime | None = None,
        window_minutes: int = 30,
    ) -> AuthenticationTimeline:
        if not source_ip and not agent_id:
            raise ValueError("source_ip or agent_id is required.")
        start_time = None
        end_time = None
        if center_time is not None:
            if not 1 <= window_minutes <= 1440:
                raise ValueError("window_minutes must be between 1 and 1440.")
            window = timedelta(minutes=window_minutes)
            start_time = center_time - window
            end_time = center_time + window
        result = self.indexer.search_alerts(
            hours=hours,
            limit=limit,
            source_ip=source_ip,
            target_user=target_user,
            agent_id=agent_id,
            authentication_only=True,
            oldest_first=True,
            start_time=start_time,
            end_time=end_time,
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
        source_ip: str | None = None,
        target_user: str | None = None,
        agent_id: str | None = None,
        hours: int = 24,
        limit: int = 200,
        center_time: datetime | None = None,
        window_minutes: int = 30,
    ) -> SuccessfulLoginAnalysis:
        timeline = self.build_authentication_timeline(
            source_ip=source_ip,
            target_user=target_user,
            agent_id=agent_id,
            hours=hours,
            limit=limit,
            center_time=center_time,
            window_minutes=window_minutes,
        )
        # The indexer normally applies these filters. Re-check them here so
        # correlation remains exact when an adapter returns a broader page,
        # and so a success for another account can never be called a
        # successful login after these failures.
        scoped: list[AlertEvidence] = []
        seen_ids: set[str] = set()
        for event in sorted(timeline.events, key=lambda item: item.timestamp):
            if event.alert_id in seen_ids:
                continue
            if source_ip and event.source_ip != source_ip:
                continue
            if target_user and event.target_user != target_user:
                continue
            if agent_id and event.agent_id != agent_id:
                continue
            seen_ids.add(event.alert_id)
            scoped.append(event)
        events = scoped
        failures = [
            event for event in events if event.event_outcome == "failure"
        ]
        first_failure = failures[0].timestamp if failures else None
        last_failure = failures[-1].timestamp if failures else None
        failure_keys = {
            (event.source_ip, event.target_user, event.agent_id)
            for event in failures
            if event.source_ip and event.target_user and event.agent_id
        }
        successes = [
            event
            for event in events
            if event.event_outcome == "success"
            and first_failure is not None
            and event.timestamp > first_failure
            and (event.source_ip, event.target_user, event.agent_id)
            in failure_keys
        ]
        success = successes[0] if successes else None
        if success:
            conclusion = "successful_login_observed"
        elif failures:
            conclusion = "no_success_in_returned_alerts"
        else:
            conclusion = "no_failures_in_returned_alerts"
        return SuccessfulLoginAnalysis(
            successful_login_search_completed=True,
            search_scope={
                "source": "wazuh-alerts-*",
                "source_ip": source_ip,
                "target_user": target_user,
                "agent_id": agent_id,
                "hours": hours,
                "center_time": (
                    center_time.isoformat() if center_time else None
                ),
                "window_minutes": window_minutes,
                "limit": limit,
            },
            returned_authentication_events=len(events),
            failed_attempt_count=len(failures),
            first_failure=first_failure,
            last_failure=last_failure,
            successful_login_found=success is not None,
            successful_login_observed=success is not None,
            successful_login_timestamp=success.timestamp if success else None,
            conclusion=conclusion,
            evidence_alert_ids=[event.alert_id for event in events],
            confidence=1.0 if timeline.events and not timeline.truncated else 0.5,
            truncated=timeline.truncated,
        )

    def get_rule_and_mitre_context(self, rule_id: str) -> RuleMitreContext | None:
        """Rule and MITRE reference data for a rule ID.

        Cached: rule definitions change when rules are deployed, not between
        two questions about the same alert, and this costs two round trips.
        Deliberately not applied to agent status or inventory - the verifier
        reads those to decide whether a response actually worked, and a stale
        answer there is a wrong security verdict, not a slow one.
        """

        cached = self._cache.get_json(
            namespace="wazuh-rule-context",
            organization_id=settings.WAZUH_INGESTION_ORGANIZATION_ID,
            cache_key=str(rule_id),
        )
        if cached is not None:
            return RuleMitreContext.model_validate(cached)
        context = self._load_rule_and_mitre_context(rule_id)
        if context is not None:
            self._cache.set_json(
                namespace="wazuh-rule-context",
                organization_id=settings.WAZUH_INGESTION_ORGANIZATION_ID,
                cache_key=str(rule_id),
                value=context.model_dump(mode="json"),
                ttl_seconds=settings.WAZUH_RULE_CONTEXT_TTL_SECONDS,
            )
        return context

    def _load_rule_and_mitre_context(
        self,
        rule_id: str,
    ) -> RuleMitreContext | None:
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
                params={"q": ",".join(f"external_id={technique_id(str(item))}" for item in mitre_ids), "limit": 50},
            ))
        groups = rule.get("groups") or []
        if not isinstance(groups, list):
            groups = [groups]
        mitre_source = "rule_definition" if mitre_ids else "none"
        if not mitre_ids:
            # The rule definition carries no mapping, but the alerts it fires
            # usually do. Aggregating them beats the tool whose whole job is
            # MITRE context returning nothing - and the source is labelled so
            # a caller can tell the two apart.
            derived = self._mitre_ids_from_alerts(rule_id)
            if derived:
                mitre_ids = derived
                mitre_source = "alert_documents"
                techniques = _items(
                    self.server.get(
                        "/mitre/techniques",
                        params={
                            "q": ",".join(f"external_id={technique_id(item)}" for item in mitre_ids),
                            "limit": 50,
                        },
                    )
                )
        return RuleMitreContext(
            rule_id=str(rule.get("id") or rule_id),
            description=rule.get("description"),
            level=rule.get("level"),
            groups=[str(item) for item in groups],
            mitre_ids=[str(item) for item in mitre_ids],
            techniques=techniques,
            mitre_source=mitre_source,
        )

    def get_mitre_technique_context(self, technique: str) -> dict[str, Any] | None:
        """Resolve ATT&CK external ID, then its actual mitigation relations.

        Wazuh's MITRE `id` is a STIX UUID; `external_id` is T1040/M1031.
        Reference data is not evidence that a technique occurred locally.
        """
        external_id = technique_id(technique)
        payload = self.server.get("/mitre/techniques", params={
            "q": f"external_id={external_id}", "limit": 1,
        })
        records = _items(payload)
        records = [record for record in records if record.get("external_id", record.get("id")) == external_id]
        if not records:
            return None
        item = records[0]
        mitigation_ids = item.get("mitigations") or []
        mitigations = []
        mitigation_total = 0
        if mitigation_ids:
            mitigation_payload = self.server.get("/mitre/mitigations", params={
                "mitigation_ids": ",".join(str(value) for value in mitigation_ids[:10]),
                "limit": 10,
            })
            mitigations = [compact_mitre(value) for value in _items(mitigation_payload)
                           if value.get("id") in mitigation_ids or value.get("external_id") in mitigation_ids]
            mitigation_total = _total(mitigation_payload)
        return {
            "technique_id": external_id,
            "evidence_ref": f"wazuh:mitre:{external_id}",
            "technique": compact_mitre(item), "mitigations": mitigations,
            "mitigation_total": max(len(mitigation_ids), mitigation_total),
            "truncated": len(mitigation_ids) > len(mitigations),
            "scope": "mitre_reference_catalog; not observed attack evidence",
            "source": "wazuh_server_api",
        }

    def threat_hunt(self, **filters: Any) -> dict[str, Any]:
        return self.indexer.threat_hunt(**filters)

    def alert_statistics(self, **filters: Any) -> dict[str, Any]:
        return self.indexer.alert_statistics(**filters)

    def ioc_agent_summary(self, **filters: Any) -> dict[str, Any]:
        return self.indexer.ioc_agent_summary(**filters)

    def get_sca_evidence(
        self, *, agent_id: str, policy_id: str | None = None,
        limit: int = 20, offset: int = 0,
    ) -> dict[str, Any]:
        """SCA policy scores or failed checks with native remediation guidance."""
        agent = self._agent_path_segment(agent_id)
        if not 1 <= limit <= 50 or not 0 <= offset <= 5000:
            raise ValueError("SCA limit must be 1-50 and offset 0-5000.")
        path = f"/sca/{agent}"
        params = {"limit": limit, "offset": offset}
        if policy_id is not None:
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", policy_id):
                raise ValueError("Invalid SCA policy ID.")
            path += f"/checks/{policy_id}"
            params["result"] = "failed"
        payload = self.server.get(path, params=params)
        fields = ("id", "title", "result", "rationale", "remediation", "compliance") if policy_id else (
            "policy_id", "name", "description", "score", "pass", "fail", "invalid", "total_checks", "end_scan",
        )
        items = [{key: value for key, value in item.items() if key in fields} for item in _items(payload)]
        for item in items:
            item["evidence_ref"] = f"wazuh:sca:{agent}:{policy_id or item.get('policy_id')}:{item.get('id', 'policy')}"
        total = _total(payload)
        partial = offset > 0 or total > len(items)
        next_offset = offset + len(items)
        return {"agent_id": agent, "policy_id": policy_id, "total": total, "returned": len(items),
                "offset": offset, "truncated": partial, "items": items,
                "next_offset": next_offset if items and next_offset < total and next_offset <= 5000 else None,
                "scope": "SCA scan results, not compromise evidence; remediation is proposed, not executed",
                "coverage": {"matched": total, "returned": len(items), "truncated": partial,
                             "status": "partial" if partial else "complete"}}

    def search_mitre_catalog(self, *, keyword: str, resource: str = "techniques", limit: int = 10) -> dict[str, Any]:
        if resource not in {"techniques", "tactics", "mitigations", "groups", "software"}:
            raise ValueError("Unsupported MITRE catalog resource.")
        if not 1 <= len(keyword.strip()) <= 128 or not 1 <= limit <= 20:
            raise ValueError("MITRE keyword must be 1-128 characters and limit 1-20.")
        payload = self.server.get(f"/mitre/{resource}", params={"search": keyword.strip(), "limit": limit})
        items = [compact_mitre(item) for item in _items(payload)]
        total = _total(payload)
        return {"resource": resource, "keyword": keyword, "total": total, "returned": len(items),
                "truncated": total > len(items), "items": items,
                "scope": "mitre_reference_catalog; not observed attack evidence"}

    def get_mitre_metadata(self) -> dict[str, Any]:
        payload = self.server.get("/mitre/metadata")
        return {"metadata": payload.get("data", {}), "scope": "mitre_reference_catalog",
                "source": "Wazuh server /mitre/metadata"}

    def vulnerability_evidence(self, **filters: Any) -> dict[str, Any]:
        return self.indexer.vulnerability_evidence(**filters)

    def _mitre_ids_from_alerts(self, rule_id: str) -> list[str]:
        """MITRE IDs observed on recent alerts for this rule. Never raises."""

        try:
            result = self.search_alerts(
                hours=168,
                min_level=0,
                limit=50,
                rule_id=str(rule_id),
            )
        except Exception:
            return []
        seen: list[str] = []
        for alert in result.alerts:
            for technique in getattr(alert, "mitre_techniques", []) or []:
                value = str(technique).strip()
                if value and value not in seen:
                    seen.append(value)
        return seen

    def get_detection_evidence(self, *, agent_id: str, limit: int = 100) -> DetectionEvidence:
        fim = self.server.get("/syscheck/{agent_id}".format(agent_id=agent_id), params={"limit": limit})
        sca = self.server.get("/sca/{agent_id}".format(agent_id=agent_id), params={"limit": limit})
        rootcheck = self.server.get(
            "/rootcheck/{agent_id}".format(agent_id=agent_id),
            params={"limit": limit},
        )
        fim_items = _items(fim)
        sca_items = _items(sca)
        rootcheck_items = _items(rootcheck)
        fim_total = _total(fim)
        sca_total = _total(sca)
        rootcheck_total = _total(rootcheck)
        return DetectionEvidence(
            agent_id=agent_id,
            fim_findings=fim_items,
            sca_findings=sca_items,
            rootcheck_findings=rootcheck_items,
            fim_total=fim_total,
            sca_total=sca_total,
            rootcheck_total=rootcheck_total,
            truncated=(
                fim_total > len(fim_items)
                or sca_total > len(sca_items)
                or rootcheck_total > len(rootcheck_items)
            ),
        )

    def get_endpoint_forensics(
        self,
        *,
        agent_id: str,
        limit: int = 20,
    ) -> EndpointForensics:
        """Collect a partial-safe, bounded endpoint evidence snapshot."""
        if not 1 <= limit <= 25:
            raise ValueError("limit must be between 1 and 25.")

        errors: list[dict[str, str]] = []
        agent = None
        inventories: dict[str, EndpointInventory] = {}
        detection_evidence = None
        vulnerabilities: list[dict[str, Any]] = []
        vulnerability_total = 0

        try:
            agent = self.get_agent_summary(agent_id)
        except Exception:
            errors.append({
                "source": "agent_summary",
                "code": "SOURCE_UNAVAILABLE",
            })

        for component in ("processes", "ports", "network"):
            try:
                inventories[component] = self.get_agent_inventory(
                    agent_id=agent_id,
                    component=component,
                    limit=limit,
                )
            except Exception:
                errors.append({
                    "source": f"inventory:{component}",
                    "code": "SOURCE_UNAVAILABLE",
                })

        try:
            detection_evidence = self.get_detection_evidence(
                agent_id=agent_id,
                limit=limit,
            )
        except Exception:
            errors.append({
                "source": "fim_sca_rootcheck",
                "code": "SOURCE_UNAVAILABLE",
            })

        try:
            vulnerabilities, vulnerability_total = self.search_vulnerabilities(
                agent_id=agent_id,
                limit=limit,
            )
        except Exception:
            errors.append({
                "source": "vulnerabilities",
                "code": "SOURCE_UNAVAILABLE",
            })

        return EndpointForensics(
            agent_id=agent_id,
            agent=agent,
            inventories=inventories,
            detection_evidence=detection_evidence,
            vulnerabilities=vulnerabilities,
            vulnerability_total=vulnerability_total,
            truncated=(
                any(item.truncated for item in inventories.values())
                or (
                    detection_evidence is not None
                    and detection_evidence.truncated
                )
                or vulnerability_total > len(vulnerabilities)
            ),
            source_errors=errors,
            telemetry_limitations=[
                "Endpoint memory capture is not available through this Wazuh integration.",
                (
                    "Process ancestry is limited to PID and parent-PID fields "
                    "returned by Wazuh syscollector."
                ),
                "Packet payload capture is not available through this tool.",
            ],
        )

    def hunt_ioc_telemetry(
        self,
        *,
        indicator: str,
        indicator_type: Literal[
            "ip",
            "domain",
            "hash",
            "process",
            "user",
            "path",
            "other",
        ],
        hours: int = 24,
        limit: int = 10,
        agent_id: str | None = None,
    ) -> IOCHuntResult:
        """Search bounded local Wazuh telemetry without claiming reputation."""
        if not 2 <= len(indicator) <= 256:
            raise ValueError("indicator must be between 2 and 256 characters.")
        if not 1 <= hours <= 168:
            raise ValueError("hours must be between 1 and 168.")
        if not 1 <= limit <= 20:
            raise ValueError("limit must be between 1 and 20.")

        alerts = None
        archived_logs = None
        errors: list[dict[str, str]] = []
        try:
            alerts = self.search_alerts(
                hours=hours,
                limit=limit,
                agent_id=agent_id,
                text=indicator,
            )
        except Exception:
            errors.append({
                "source": "wazuh_alerts",
                "code": "SOURCE_UNAVAILABLE",
            })
        try:
            archived_logs = self.search_archived_logs(
                text=indicator,
                hours=hours,
                limit=limit,
                agent_id=agent_id,
            )
        except Exception:
            errors.append({
                "source": "wazuh_archives",
                "code": "SOURCE_UNAVAILABLE",
            })

        return IOCHuntResult(
            indicator=indicator,
            indicator_type=indicator_type,
            alerts=alerts,
            archived_logs=archived_logs,
            source_errors=errors,
            intelligence_scope=[
                "local_wazuh_alerts",
                "local_wazuh_archives",
            ],
        )

    def alert_summary(self, hours: int = 24) -> dict[str, Any]:
        return self.indexer.alert_summary(hours)

    def aggregate_alerts(self, **filters: Any) -> dict[str, Any]:
        """Full-population counts for the same filters `search_alerts` takes."""
        return self.indexer.aggregate_alerts(**filters)

    @staticmethod
    def _agent_path_segment(agent_id: str) -> str:
        """Agent IDs are interpolated into a URL path, so bound them here."""
        segment = str(agent_id).strip()
        if not segment.isalnum() or len(segment) > 16:
            raise ValueError(f"agent_id must be alphanumeric, got {agent_id!r}.")
        return segment

    def telemetry_health(
        self,
        *,
        agent_id: str | None = None,
        error_log_limit: int = 20,
    ) -> dict[str, Any]:
        """Evidence about whether missing data is real or a pipeline failure.

        "No alerts matched" and "the pipeline dropped the events" look
        identical from the alert index. Wazuh does report the difference: the
        manager counts discarded agent messages and dropped analysis events,
        the agent counts per-file log drops, and a misconfigured agent simply
        never collects the source in the first place. Without those counters
        an analyst can only assume the silence is real.

        Returns observations only - no verdict about whether a gap is benign.
        """

        limit = max(1, min(int(error_log_limit), 100))

        def manager_stat(component: str):
            return lambda: self.server_get(f"/manager/stats/{component}")

        tasks: list[tuple[str, Any]] = [
            ("remoted", manager_stat("remoted")),
            ("analysisd", manager_stat("analysisd")),
            (
                "manager_errors",
                lambda: self.server_get(
                    "/manager/logs",
                    {"level": "error", "limit": limit},
                ),
            ),
        ]
        if agent_id:
            segment = self._agent_path_segment(agent_id)
            tasks.extend(
                [
                    (
                        "logcollector",
                        lambda: self.server_get(
                            f"/agents/{segment}/stats/logcollector"
                        ),
                    ),
                    (
                        "collected_files",
                        lambda: self.server_get(
                            f"/agents/{segment}/config/logcollector/localfile"
                        ),
                    ),
                    (
                        "file_integrity_config",
                        lambda: self.server_get(
                            f"/agents/{segment}/config/syscheck/syscheck"
                        ),
                    ),
                ]
            )

        raw = gather(tasks)

        def payload(label: str) -> dict[str, Any] | None:
            value = raw.get(label)
            if isinstance(value, Exception) or value is None:
                return None
            data = value.get("data") if isinstance(value, dict) else None
            return data if isinstance(data, dict) else None

        def unavailable(label: str) -> str | None:
            value = raw.get(label)
            return type(value).__name__ if isinstance(value, Exception) else None

        def affected(data: dict[str, Any] | None) -> dict[str, Any]:
            """Wazuh nests stats under data.affected_items[0] on 4.x."""
            items = (data or {}).get("affected_items")
            first = items[0] if isinstance(items, list) and items else None
            return first if isinstance(first, dict) else (data or {})

        remoted = affected(payload("remoted"))
        analysisd = affected(payload("analysisd"))

        def counter(source: dict[str, Any], *names: str) -> int | None:
            for name in names:
                value = source.get(name)
                if isinstance(value, (int, float)):
                    return int(value)
            return None

        discarded = counter(remoted, "discarded_count", "discarded")
        dropped_events = counter(
            analysisd,
            "events_dropped",
            "event_queue_usage",
            "syscheck_queue_usage",
        )

        # Per-file drops are the agent-side signal: the log existed, the agent
        # read it, and the target queue refused it.
        agent_drops = 0
        dropping_files: list[dict[str, Any]] = []
        logcollector = affected(payload("logcollector"))
        for period in ("global", "interval"):
            block = logcollector.get(period)
            if not isinstance(block, dict):
                continue
            for entry in block.get("files") or []:
                if not isinstance(entry, dict):
                    continue
                drops = sum(
                    int(target.get("drops") or 0)
                    for target in entry.get("targets") or []
                    if isinstance(target, dict)
                )
                if drops:
                    agent_drops += drops
                    dropping_files.append(
                        {
                            "location": entry.get("location"),
                            "drops": drops,
                            "period": period,
                        }
                    )

        errors_payload = payload("manager_errors") or {}
        manager_errors = [
            {
                "timestamp": item.get("timestamp"),
                "tag": item.get("tag"),
                "description": str(item.get("description") or "")[:500],
            }
            for item in (errors_payload.get("affected_items") or [])
            if isinstance(item, dict)
        ]

        collected = affected(payload("collected_files"))
        monitored_logs = [
            entry.get("location")
            for entry in (
                (collected.get("localfile") or [])
                if isinstance(collected.get("localfile"), list)
                else []
            )
            if isinstance(entry, dict) and entry.get("location")
        ]
        syscheck = affected(payload("file_integrity_config")).get("syscheck")
        file_integrity_enabled = (
            str((syscheck or {}).get("disabled", "")).lower() == "no"
            if isinstance(syscheck, dict)
            else None
        )

        degraded = bool(discarded) or bool(dropped_events) or bool(agent_drops)
        return {
            "agent_id": agent_id,
            "ingestion": {
                "manager_discarded_messages": discarded,
                "manager_dropped_events": dropped_events,
                "remoted_queue_size": counter(remoted, "queue_size"),
                "remoted_total_queue_size": counter(remoted, "total_queue_size"),
                "dequeued_after_close": counter(remoted, "dequeued_after_close"),
                "tcp_sessions": counter(remoted, "tcp_sessions"),
            },
            "agent_log_drops": agent_drops if agent_id else None,
            "dropping_files": dropping_files,
            "monitored_logs": monitored_logs if agent_id else None,
            "file_integrity_enabled": file_integrity_enabled,
            "manager_error_count": len(manager_errors),
            "manager_errors": manager_errors,
            "unavailable_checks": {
                label: reason
                for label in raw
                if (reason := unavailable(label)) is not None
            },
            "telemetry_complete": not degraded,
            "note": (
                "Drops or discards mean an absence of alerts may be a "
                "collection failure rather than an absence of activity."
                if degraded
                else "No drop or discard counters were raised by Wazuh."
            ),
        }

    def search_vulnerabilities(
        self, *, severity: str | None = None, agent_id: str | None = None, limit: int = 20
    ) -> tuple[list[dict[str, Any]], int]:
        return self.indexer.search_vulnerabilities(
            severity=severity, agent_id=agent_id, limit=limit
        )

    def vulnerability_summary(self) -> dict[str, Any]:
        return self.indexer.vulnerability_summary()

    def agent_connectivity_summary(self) -> AgentConnectivitySummary:
        """Agent counts by connection status (active/disconnected/pending/
        never_connected), for detecting telemetry gaps and Wazuh health."""
        payload = self.server.get("/agents/summary/status")
        data = payload.get("data") or {}
        # Response shape varies by Wazuh version: newer APIs nest counts
        # under "connection", older ones return them at the top level.
        source = data.get("connection") if isinstance(data.get("connection"), dict) else data
        counts = {
            str(key): int(value)
            for key, value in source.items()
            if isinstance(value, int) and key.lower() != "total"
        }
        total = source.get("total")
        return AgentConnectivitySummary(
            by_status=counts,
            total=int(total) if isinstance(total, int) else sum(counts.values()),
        )

    def close(self) -> None:
        self.server.close()
        self.indexer.close()
