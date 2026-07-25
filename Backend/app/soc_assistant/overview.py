"""Deterministic aggregation for the SOC operations overview."""

from datetime import UTC, datetime
from typing import Any

from app.api.v1.schemas.overview import (
    AlertReduction,
    OverviewMetric,
    PipelineStage,
    SOCOverview,
    SOCPlatform,
)


PIPELINE_STAGES = (
    "monitor",
    "analyze",
    "plan",
    "approval",
    "execute",
    "verify",
    "complete",
    "failed",
)
TERMINAL_STATUSES = {"completed", "failed", "rejected", "escalated"}


def _pipeline_stage(snapshot: dict[str, Any]) -> str:
    status = str(snapshot.get("status") or "").lower()
    stage = str(snapshot.get("current_stage") or snapshot.get("stage") or "").lower()
    if status in {"failed", "rejected", "escalated"} or stage in {
        "failed",
        "rejected",
        "escalated",
    }:
        return "failed"
    if status == "completed" or stage in {"complete", "completed", "final_report"}:
        return "complete"
    aliases = {
        "created": "monitor",
        "load_alert": "monitor",
        "monitor": "monitor",
        "l1": "analyze",
        "l2": "analyze",
        "l3": "analyze",
        "analyze": "analyze",
        "plan": "plan",
        "policy_gate": "plan",
        "human_approval": "approval",
        "waiting_approval": "approval",
        "awaiting_approval": "approval",
        "approved": "approval",
        "response_execution": "execute",
        "execute": "execute",
        "verification": "verify",
        "verify": "verify",
    }
    return aliases.get(stage, "monitor")


def _recent_investigation(snapshot: dict[str, Any]) -> dict[str, Any]:
    audit_events = snapshot.get("audit_events") or []
    timestamps = [
        str(item.get("timestamp"))
        for item in audit_events
        if isinstance(item, dict) and item.get("timestamp")
    ]
    return {
        "investigation_id": snapshot.get("investigation_id"),
        "alert_id": snapshot.get("alert_id"),
        "status": snapshot.get("status"),
        "current_stage": snapshot.get("current_stage"),
        "severity": snapshot.get("severity"),
        "confidence": snapshot.get("confidence"),
        "updated_at": timestamps[-1] if timestamps else None,
    }


def _recent_finding(finding: dict[str, Any]) -> dict[str, Any]:
    summary = finding.get("finding")
    verdict = finding.get("verdict")
    return {
        "finding_id": finding.get("finding_id"),
        "title": summary.get("title") if isinstance(summary, dict) else None,
        "severity": finding.get("severity"),
        "verdict": verdict.get("verdict") if isinstance(verdict, dict) else None,
        "confidence": (
            verdict.get("confidence") if isinstance(verdict, dict) else None
        ),
        "alert_count": finding.get("alert_count", 0),
        "last_seen": finding.get("last_seen"),
    }


def build_soc_overview(
    *,
    investigations: list[dict[str, Any]],
    investigation_total: int,
    findings: list[dict[str, Any]],
    alert_summary: dict[str, Any] | None,
    window_hours: int,
) -> SOCOverview:
    pipeline_counts = {stage: 0 for stage in PIPELINE_STAGES}
    severity_counts: dict[str, int] = {}
    pending_approvals = 0
    executed_actions = 0

    for snapshot in investigations:
        pipeline_counts[_pipeline_stage(snapshot)] += 1
        severity = str(snapshot.get("severity") or "").lower()
        if severity:
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        if (
            snapshot.get("status") == "awaiting_approval"
            or "human_approval" in (snapshot.get("pending_nodes") or [])
        ):
            pending_approvals += 1
        executed_actions += len(snapshot.get("executed_actions") or [])

    represented_alerts = sum(
        max(0, int(item.get("alert_count") or 0)) for item in findings
    )
    raw_alerts = None
    if alert_summary is not None:
        raw_alerts = max(0, int(alert_summary.get("total_alerts") or 0))
    reduction_percent = None
    if raw_alerts:
        reduction_percent = round(
            max(0.0, min(100.0, (1 - len(findings) / raw_alerts) * 100)),
            1,
        )

    active = sum(
        str(item.get("status") or "") not in TERMINAL_STATUSES
        for item in investigations
    )
    malicious = sum(
        isinstance(item.get("verdict"), dict)
        and item["verdict"].get("verdict") == "malicious"
        for item in findings
    )

    return SOCOverview(
        generated_at=datetime.now(UTC).isoformat(),
        window_hours=window_hours,
        wazuh_status="available" if alert_summary is not None else "unavailable",
        metrics={
            "active_investigations": OverviewMetric(value=active),
            "total_investigations": OverviewMetric(value=investigation_total),
            "security_findings": OverviewMetric(value=len(findings)),
            "malicious_findings": OverviewMetric(value=malicious),
            "pending_approvals": OverviewMetric(value=pending_approvals),
            "executed_actions": OverviewMetric(value=executed_actions),
            "wazuh_alerts": OverviewMetric(value=raw_alerts),
        },
        pipeline=[
            PipelineStage(stage=stage, count=pipeline_counts[stage])
            for stage in PIPELINE_STAGES
        ],
        severity_distribution=severity_counts,
        alert_reduction=AlertReduction(
            raw_alerts=raw_alerts,
            represented_alerts=represented_alerts,
            findings=len(findings),
            reduction_percent=reduction_percent,
        ),
        recent_investigations=[
            _recent_investigation(item) for item in investigations[:6]
        ],
        recent_findings=[_recent_finding(item) for item in findings[:6]],
    )


def build_soc_platform(
    *,
    investigations: list[dict[str, Any]],
    model_assignments: list[dict[str, Any]],
    response_policy: dict[str, bool | int | str],
    retention: dict[str, int | str],
) -> SOCPlatform:
    approvals: list[dict[str, Any]] = []
    actions: list[dict[str, Any]] = []
    audit_events: list[dict[str, Any]] = []

    for snapshot in investigations:
        investigation_id = str(snapshot.get("investigation_id") or "")
        approval = snapshot.get("approval_request")
        decision = snapshot.get("approval_decision")
        decision_value = (
            str(decision.get("decision") or "")
            if isinstance(decision, dict)
            else ""
        )
        if isinstance(approval, dict):
            approvals.append(
                {
                    "investigation_id": investigation_id,
                    "approval_id": approval.get("approval_id"),
                    "incident_id": approval.get("incident_id"),
                    "expires_at": approval.get("expires_at"),
                    "required_role": approval.get("required_role"),
                    "status": decision_value or "pending",
                    "proposed_actions": approval.get("proposed_actions") or [],
                }
            )

        executed = {
            str(item.get("action_id"))
            for item in snapshot.get("executed_actions") or []
            if isinstance(item, dict) and item.get("action_id")
        }
        proposed = (
            approval.get("proposed_actions") or []
            if isinstance(approval, dict)
            else snapshot.get("proposed_actions") or []
        )
        for action in proposed:
            if not isinstance(action, dict):
                continue
            action_id = str(action.get("action_id") or "")
            if action_id and action_id in executed:
                status = "executed"
            elif decision_value == "approve":
                status = "approved"
            elif decision_value == "reject":
                status = "rejected"
            elif snapshot.get("status") == "awaiting_approval":
                status = "awaiting_approval"
            else:
                status = "proposed"
            actions.append(
                {
                    "investigation_id": investigation_id,
                    "action_id": action_id or None,
                    "action_type": action.get("action_type"),
                    "target": action.get("target"),
                    "risk_level": action.get("risk_level"),
                    "status": status,
                    "evidence_refs": action.get("evidence_refs") or [],
                }
            )

        for event in snapshot.get("audit_events") or []:
            if isinstance(event, dict):
                audit_events.append(
                    {
                        "investigation_id": investigation_id,
                        **event,
                    }
                )

    approvals.sort(key=lambda item: str(item.get("expires_at") or ""), reverse=True)
    audit_events.sort(
        key=lambda item: str(item.get("timestamp") or ""),
        reverse=True,
    )
    return SOCPlatform(
        generated_at=datetime.now(UTC).isoformat(),
        pending_approvals=approvals[:50],
        response_actions=actions[:100],
        audit_events=audit_events[:200],
        model_assignments=model_assignments,
        response_policy=response_policy,
        retention=retention,
    )
