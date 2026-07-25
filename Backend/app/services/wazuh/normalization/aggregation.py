"""Deterministic alert grouping and security-finding generation."""

from __future__ import annotations

import hashlib
import time
from collections import defaultdict
from datetime import datetime

import structlog

from app.config import settings
from app.services.wazuh.normalization.schemas import (
    AlertEnvelope,
    AlertGroup,
    SecurityFinding,
)


logger = structlog.get_logger("tsage.wazuh.normalization")

FINDING_TITLES = {
    "ssh_brute_force": "Repeated SSH authentication failures",
    "ssh_login_failure": "SSH authentication failure",
    "ssh_login_success": "Successful SSH login",
    "process_execution": "Process execution observed",
    "process_created": "Sysmon process creation",
    "network_connection": "Network activity observed",
    "vulnerable_package": "Vulnerable package detected",
    "compliance_control_failed": "Compliance control failed",
    "compliance_control_status": "Compliance control status changed",
    "package_installed": "Package installed",
    "package_removed": "Package removed",
    "package_state_changed": "Package state changed",
    "file_created": "File created",
    "file_modified": "File modified",
    "file_deleted": "File deleted",
    "registry_changed": "Registry activity observed",
    "generic_alert": "Wazuh alert",
}


def severity_for_level(level: int) -> str:
    if level >= 13:
        return "critical"
    if level >= 10:
        return "high"
    if level >= 7:
        return "medium"
    if level >= 4:
        return "low"
    return "informational"


def _window_seconds(envelope: AlertEnvelope) -> int:
    family = envelope.normalized.attack_family
    if family in {"credential_access", "initial_access"}:
        return settings.AUTH_AGGREGATION_WINDOW_SECONDS
    if family == "vulnerability_management":
        return settings.VULNERABILITY_AGGREGATION_WINDOW_SECONDS
    if family == "security_posture":
        return settings.COMPLIANCE_AGGREGATION_WINDOW_SECONDS
    return settings.ALERT_AGGREGATION_WINDOW_SECONDS


def _bucket(timestamp: datetime, seconds: int) -> int:
    return int(timestamp.timestamp()) // max(seconds, 1)


def _specific_parts(envelope: AlertEnvelope) -> tuple[str, ...]:
    alert = envelope.normalized
    details = envelope.attack_details
    family = alert.attack_family
    if family in {"credential_access", "initial_access"}:
        return (
            alert.event_type,
            alert.source_ip or "",
            alert.hostname or alert.agent_id or "",
            alert.target_user or "",
            str(details.get("protocol") or ""),
        )
    if family == "vulnerability_management":
        return (
            alert.agent_id or alert.hostname or "",
            alert.cve_id or "",
            alert.package_name or "",
        )
    if family == "security_posture":
        return (
            alert.agent_id or alert.hostname or "",
            str(details.get("benchmark") or ""),
            str(details.get("control_id") or ""),
        )
    if family == "software_change":
        return (
            alert.agent_id or alert.hostname or "",
            alert.package_name or "",
            str(details.get("operation") or ""),
        )
    if family == "file_change":
        return (
            alert.agent_id or alert.hostname or "",
            alert.file_path or "",
            str(details.get("operation") or ""),
        )
    return (
        alert.event_type,
        alert.source_ip or "",
        alert.hostname or alert.agent_id or "",
        alert.rule_id or "",
    )


def grouping_key(envelope: AlertEnvelope) -> str:
    alert = envelope.normalized
    parts = (
        alert.attack_family,
        *_specific_parts(envelope),
        str(_bucket(alert.timestamp, _window_seconds(envelope))),
    )
    return "|".join(parts)


def _correlation_key(envelope: AlertEnvelope) -> str:
    """Return the attack-specific key without a wall-clock bucket."""

    return "|".join(
        (
            envelope.normalized.attack_family,
            *_specific_parts(envelope),
        )
    )


def _windowed_groups(
    envelopes: list[AlertEnvelope],
) -> dict[str, list[AlertEnvelope]]:
    """Cluster events by elapsed time, avoiding fixed-bucket boundary splits."""

    candidates: dict[str, list[AlertEnvelope]] = defaultdict(list)
    for envelope in envelopes:
        candidates[_correlation_key(envelope)].append(envelope)

    grouped: dict[str, list[AlertEnvelope]] = {}
    for base_key, items in candidates.items():
        ordered = sorted(items, key=lambda item: item.normalized.timestamp)
        current: list[AlertEnvelope] = []
        window_start: datetime | None = None
        for envelope in ordered:
            timestamp = envelope.normalized.timestamp
            window_seconds = _window_seconds(envelope)
            if (
                current
                and window_start is not None
                and (timestamp - window_start).total_seconds() > window_seconds
            ):
                key = f"{base_key}|{window_start.isoformat()}"
                grouped[key] = current
                current = []
                window_start = None
            if window_start is None:
                window_start = timestamp
            current.append(envelope)
        if current and window_start is not None:
            key = f"{base_key}|{window_start.isoformat()}"
            grouped[key] = current
    return grouped


def _unique(values: list[str | None]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def aggregate_alerts(
    envelopes: list[AlertEnvelope],
    *,
    max_evidence_refs: int | None = None,
) -> list[AlertGroup]:
    started = time.perf_counter()
    limit = max_evidence_refs or settings.MAX_EVIDENCE_REFS_PER_FINDING
    grouped = _windowed_groups(envelopes)

    results = []
    for key, items in grouped.items():
        alerts = [item.normalized for item in items]
        evidence_refs = _unique(
            [ref for item in items for ref in item.evidence_refs]
        )
        event_counts = [
            int(
                item.attack_details.get("attempt_count")
                or item.attack_details.get("execution_count")
                or item.attack_details.get("connection_count")
                or 1
            )
            for item in items
        ]
        outcomes: dict[str, int] = defaultdict(int)
        for alert in alerts:
            outcomes[alert.outcome] += 1
        group_id = f"GRP-{hashlib.sha256(key.encode()).hexdigest()[:16].upper()}"
        representative = max(
            alerts,
            key=lambda item: (item.rule_level, item.timestamp),
        )
        results.append(
            AlertGroup(
                group_id=group_id,
                group_key=key,
                category=representative.category,
                attack_family=representative.attack_family,
                event_type=representative.event_type,
                first_seen=min(item.timestamp for item in alerts),
                last_seen=max(item.timestamp for item in alerts),
                alert_count=len(alerts),
                event_count=sum(event_counts),
                highest_severity=max(item.rule_level for item in alerts),
                source_ips=_unique([item.source_ip for item in alerts]),
                destination_ips=_unique(
                    [item.destination_ip for item in alerts]
                ),
                target_hosts=_unique(
                    [item.hostname or item.agent_name for item in alerts]
                ),
                target_users=_unique([item.target_user for item in alerts]),
                outcomes=dict(outcomes),
                mitre_techniques=_unique(
                    [
                        technique
                        for item in alerts
                        for technique in item.mitre_techniques
                    ]
                ),
                summary=(
                    f"{len(alerts)} {representative.event_type.replace('_', ' ')} "
                    f"alert(s) observed from {min(item.timestamp for item in alerts).isoformat()} "
                    f"to {max(item.timestamp for item in alerts).isoformat()}."
                ),
                evidence_refs=evidence_refs[:limit],
                representative_alert_id=representative.alert_id,
                truncated_evidence_refs=len(evidence_refs) > limit,
            )
        )
    results.sort(key=lambda item: (item.highest_severity, item.last_seen), reverse=True)
    raw_count = len(envelopes)
    logger.info(
        "alert_aggregation_completed",
        raw_alert_count=raw_count,
        group_count=len(results),
        deduplication_ratio=(
            round(1 - len(results) / raw_count, 4) if raw_count else 0
        ),
        duration_ms=round((time.perf_counter() - started) * 1000, 2),
    )
    return results


def build_findings(groups: list[AlertGroup]) -> list[SecurityFinding]:
    findings = []
    for group in groups:
        severity = severity_for_level(group.highest_severity)
        investigation_recommended = severity in {"high", "critical"}
        finding = SecurityFinding(
            finding_id=f"FND-{group.group_id.removeprefix('GRP-')}",
            title=FINDING_TITLES.get(
                group.event_type,
                group.event_type.replace("_", " ").title(),
            ),
            summary=group.summary,
            category=group.category,
            attack_family=group.attack_family,
            event_type=group.event_type,
            severity=severity,
            severity_score=group.highest_severity,
            confidence=0.9 if group.event_type != "generic_alert" else 0.6,
            first_seen=group.first_seen,
            last_seen=group.last_seen,
            affected_assets=group.target_hosts,
            source_ips=group.source_ips,
            target_users=group.target_users,
            mitre_techniques=group.mitre_techniques,
            alert_count=group.alert_count,
            representative_alert_id=group.representative_alert_id,
            evidence_refs=group.evidence_refs,
            investigation_recommended=investigation_recommended,
            recommendation_reason_code=(
                "HIGH_OR_CRITICAL_RULE_LEVEL"
                if investigation_recommended
                else None
            ),
        )
        logger.info(
            "finding_created",
            finding_id=finding.finding_id,
            attack_family=finding.attack_family,
            event_type=finding.event_type,
            alert_count=finding.alert_count,
            severity=finding.severity,
        )
        findings.append(finding)
    return findings
