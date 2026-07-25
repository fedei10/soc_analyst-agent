"""Deterministic Wazuh ingestion, normalization, deduplication and correlation."""

from __future__ import annotations

import ipaddress
from datetime import timedelta
from typing import Any

from app.config import settings
from app.mape_k.schemas import (
    AuthenticationEvidenceSummary,
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


SSH_EVENT_TYPES = {
    "ssh_login_failure",
    "ssh_invalid_user_attempt",
    "ssh_brute_force",
    "ssh_password_spraying",
    "ssh_login_success",
    "ssh_success_after_failures",
}


def _same_authentication_subject(failure: Any, success: Any) -> bool:
    if (
        failure.source_ip
        and success.source_ip
        and failure.source_ip != success.source_ip
    ):
        return False
    if (
        failure.target_user
        and success.target_user
        and failure.target_user != success.target_user
    ):
        return False
    failure_asset = failure.hostname or failure.agent_name or failure.agent_id
    success_asset = success.hostname or success.agent_name or success.agent_id
    return not (failure_asset and success_asset and failure_asset != success_asset)


def _uniform_boolean(values: list[bool]) -> bool | None:
    unique = set(values)
    return unique.pop() if len(unique) == 1 else None


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

        primary_envelope = normalize_alerts(
            [primary.model_dump(mode="json", exclude_none=True)]
        )[0]
        primary_is_ssh = primary_envelope.normalized.event_type in SSH_EVENT_TYPES
        window_seconds = max(1, settings.MAPEK_CORRELATION_WINDOW_SECONDS)
        correlation_start = primary.timestamp - timedelta(seconds=window_seconds)
        correlation_end = primary.timestamp + timedelta(seconds=window_seconds)
        related = self.gateway.get_related_alerts(
            alert_id=state.alert_id,
            hours=max(1, min(168, (window_seconds + 3599) // 3600)),
            limit=100,
            start_time=correlation_start,
            end_time=correlation_end,
            authentication_only=primary_is_ssh,
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

        authentication_evidence = None
        if primary_is_ssh:
            authentication_envelopes = [
                envelope
                for envelope in envelopes
                if envelope.normalized.event_type in SSH_EVENT_TYPES
            ]
            authentication_alerts = [
                envelope.normalized for envelope in authentication_envelopes
            ]
            failures = [
                alert
                for alert in authentication_alerts
                if alert.outcome == "failure"
            ]
            successes = [
                alert
                for alert in authentication_alerts
                if alert.outcome == "success"
            ]
            source_ips = list(
                dict.fromkeys(
                    alert.source_ip for alert in authentication_alerts
                    if alert.source_ip
                )
            )
            target_users = list(
                dict.fromkeys(
                    alert.target_user for alert in authentication_alerts
                    if alert.target_user
                )
            )
            affected_assets = list(
                dict.fromkeys(
                    alert.hostname or alert.agent_name or alert.agent_id
                    for alert in authentication_alerts
                    if alert.hostname or alert.agent_name or alert.agent_id
                )
            )
            successful_login_after_failures = None
            if failures:
                successful_login_after_failures = any(
                    failure.timestamp < success.timestamp
                    and (
                        success.timestamp - failure.timestamp
                    ).total_seconds()
                    <= settings.MAPEK_SSH_SUCCESS_AFTER_FAILURE_WINDOW_SECONDS
                    and _same_authentication_subject(failure, success)
                    for failure in failures
                    for success in successes
                )
                if related.truncated and not successful_login_after_failures:
                    successful_login_after_failures = None

            approved_admin_ips = {
                value.strip()
                for value in settings.MAPEK_APPROVED_ADMIN_IPS.split(",")
                if value.strip()
            }
            internal_flags = [
                ipaddress.ip_address(source_ip).is_private
                for source_ip in source_ips
            ]
            approved_flags = [
                source_ip in approved_admin_ips for source_ip in source_ips
            ]
            missing_evidence = []
            if not source_ips:
                missing_evidence.append("source_ip")
            if not target_users:
                missing_evidence.append("target_user")
            if not affected_assets:
                missing_evidence.append("affected_asset")
            if related.truncated:
                missing_evidence.append("authentication_search_truncated")
            missing_evidence.extend(
                ["source_asset_identity", "source_reputation"]
            )
            authentication_evidence = AuthenticationEvidenceSummary(
                first_seen=min(alert.timestamp for alert in authentication_alerts),
                last_seen=max(alert.timestamp for alert in authentication_alerts),
                failed_attempt_count=sum(
                    int(envelope.attack_details.get("attempt_count") or 1)
                    for envelope in authentication_envelopes
                    if envelope.normalized.outcome == "failure"
                ),
                successful_attempt_count=sum(
                    int(envelope.attack_details.get("attempt_count") or 1)
                    for envelope in authentication_envelopes
                    if envelope.normalized.outcome == "success"
                ),
                distinct_event_count=len(authentication_alerts),
                distinct_target_user_count=len(target_users),
                source_ips=source_ips,
                target_users=target_users,
                affected_assets=affected_assets,
                successful_login_after_failures=successful_login_after_failures,
                source_is_internal=(
                    _uniform_boolean(internal_flags) if internal_flags else None
                ),
                source_is_approved_admin=(
                    _uniform_boolean(approved_flags) if approved_flags else None
                ),
                source_asset_id=None,
                source_reputation=None,
                total_hits=max(len(authentication_alerts), related.total + 1),
                returned_hits=len(authentication_alerts),
                truncated=related.truncated,
                correlation_window_start=correlation_start,
                correlation_window_end=correlation_end,
                missing_evidence=missing_evidence,
            )

        evidence: list[EvidenceReference] = []
        evidence_records: list[dict[str, Any]] = []
        for envelope in envelopes:
            alert = envelope.normalized
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
                    "raw_source_type": "wazuh_opensearch",
                    "raw_source_index": settings.WAZUH_ARCHIVE_INDEX,
                    "raw_source_document_id": alert.alert_id,
                    "raw_document_hash": None,
                    "normalized_document_hash": digest,
                    "normalizer_name": envelope.normalizer_name,
                    "normalizer_version": envelope.normalizer_version,
                    "ingested_at": envelope.normalized_at.isoformat(),
                    "observed_at": alert.timestamp.isoformat(),
                    "organization_id": state.organization_id,
                    "summary": reference.summary,
                    "content_hash": digest,
                    "event_count": int(
                        envelope.attack_details.get("attempt_count") or 1
                    ),
                    "attack_details": envelope.attack_details,
                }
            )

        inventory: dict[str, Any] = {}
        inventory_errors: list[dict[str, str]] = []
        agent_id = state.agent_id or primary.agent_id
        if agent_id and not primary_is_ssh:
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
            "authentication_evidence": authentication_evidence,
            "findings": [
                finding.model_dump(mode="json") for finding in findings
            ],
            "incident_fingerprint": fingerprint,
            "evidence_version": evidence_version,
            "monitor_context": {
                "evidence_profile": (
                    "ssh_authentication" if primary_is_ssh else "generic_inventory"
                ),
                "inventory": inventory,
                "inventory_errors": inventory_errors,
                "raw_alert_count": len(raw_alerts),
                "deduplicated_alert_count": len(normalized),
                "correlated_group_count": len(groups),
                "correlation": {
                    "total_hits": max(len(alerts_by_id), related.total + 1),
                    "returned_hits": len(alerts_by_id),
                    "truncated": related.truncated,
                    "window_start": correlation_start.isoformat(),
                    "window_end": correlation_end.isoformat(),
                },
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
