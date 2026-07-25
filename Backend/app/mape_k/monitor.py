"""Deterministic Wazuh ingestion, normalization, deduplication and correlation."""

from __future__ import annotations

from typing import Any

from app.config import settings
from app.mape_k.schemas import (
    EvidenceReference,
    IncidentWorkflowState,
    WorkflowStage,
    WorkflowStatus,
)
from app.mape_k.utils import audit_event, content_hash, stable_id
from app.services.redis.ephemeral import EphemeralRedis
from app.services.wazuh.gateway import WazuhGateway
from app.services.wazuh.normalization import (
    aggregate_alerts,
    build_findings,
    normalize_alerts,
)


class WazuhMonitor:
    def __init__(
        self,
        gateway: WazuhGateway | None = None,
        cache: EphemeralRedis | None = None,
    ) -> None:
        self.gateway = gateway or WazuhGateway()
        self.cache = cache or EphemeralRedis()

    def run(self, state: IncidentWorkflowState) -> dict[str, Any]:
        primary = self.gateway.get_alert_by_id(state.alert_id)
        if primary is None:
            raise LookupError(f"Wazuh alert {state.alert_id!r} was not found.")

        related = self.gateway.get_related_alerts(
            alert_id=state.alert_id,
            hours=max(1, settings.MAPEK_CORRELATION_WINDOW_SECONDS // 3600 + 1),
            limit=100,
        )
        alerts_by_id = {primary.alert_id: primary}
        for alert in related.alerts:
            alerts_by_id.setdefault(alert.alert_id, alert)

        raw_alerts = [
            alert.model_dump(mode="json", exclude_none=True)
            for alert in alerts_by_id.values()
        ]
        envelopes = normalize_alerts(raw_alerts)
        groups = aggregate_alerts(envelopes)
        findings = build_findings(groups)
        normalized = [envelope.normalized for envelope in envelopes]

        evidence: list[EvidenceReference] = []
        evidence_records: list[dict[str, Any]] = []
        for alert in normalized:
            safe_payload = alert.model_dump(mode="json")
            evidence_id = stable_id("EV", "wazuh-alert", alert.alert_id, length=16)
            digest = content_hash(safe_payload)
            reference = EvidenceReference(
                evidence_id=evidence_id,
                source_type="wazuh_alert",
                source_ref=f"wazuh:alert:{alert.alert_id}",
                observed_at=alert.timestamp,
                summary=alert.summary[:1000],
                content_hash=digest,
            )
            evidence.append(reference)
            evidence_records.append(
                {
                    "evidence_id": evidence_id,
                    "source_type": "wazuh_alert",
                    "source_ref": reference.source_ref,
                    "timestamp": alert.timestamp.isoformat(),
                    "summary": reference.summary,
                    "content_hash": digest,
                    "payload": safe_payload,
                }
            )

        inventory: dict[str, Any] = {}
        inventory_errors: list[dict[str, str]] = []
        agent_id = state.agent_id or primary.agent_id
        if agent_id:
            for component in ("ports", "processes", "network", "os")[
                : settings.MAPEK_MAX_TOOL_CALLS_PER_STAGE
            ]:
                try:
                    result = self.gateway.get_agent_inventory(
                        agent_id=agent_id,
                        component=component,
                        limit=25,
                    )
                    inventory[component] = result.model_dump(mode="json")
                except Exception as exc:
                    inventory_errors.append(
                        {"component": component, "error": type(exc).__name__}
                    )

        fingerprint_material = [
            group.group_key for group in groups
        ] or [state.alert_id]
        fingerprint = stable_id(
            "FP",
            *sorted(fingerprint_material),
            length=32,
        )
        evidence_version = content_hash(
            sorted(item.content_hash for item in evidence)
        )
        self.cache.set_json(
            namespace="mapek-correlation",
            organization_id=state.organization_id,
            cache_key=fingerprint,
            value={
                "incident_id": state.incident_id,
                "evidence_version": evidence_version,
                "alert_ids": list(alerts_by_id),
            },
            ttl_seconds=settings.MAPEK_CORRELATION_WINDOW_SECONDS,
        )

        return {
            "stage": WorkflowStage.ANALYZE,
            "current_stage": WorkflowStage.ANALYZE,
            "status": WorkflowStatus.RUNNING,
            "agent_id": agent_id,
            "normalized_alerts": normalized,
            "evidence": evidence,
            "evidence_records": evidence_records,
            "findings": [
                finding.model_dump(mode="json") for finding in findings
            ],
            "incident_fingerprint": fingerprint,
            "evidence_version": evidence_version,
            "monitor_context": {
                "inventory": inventory,
                "inventory_errors": inventory_errors,
                "raw_alert_count": len(raw_alerts),
                "deduplicated_alert_count": len(normalized),
                "correlated_group_count": len(groups),
            },
            "audit_events": [
                audit_event(
                    "monitor_completed",
                    alert_count=len(normalized),
                    finding_count=len(findings),
                    inventory_errors=inventory_errors,
                )
            ],
        }

