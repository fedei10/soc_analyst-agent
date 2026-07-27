"""Deterministic tier reports used for durable analyst handoff."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.orchestration.schemas import AgentTier, TierReport


def _generated_at(state: dict[str, Any], tier: AgentTier) -> datetime:
    for event in reversed(state.get("audit_events", [])):
        if (
            isinstance(event, dict)
            and event.get("stage") == tier
            and event.get("event") == "analysis_completed"
        ):
            try:
                value = datetime.fromisoformat(
                    str(event["timestamp"]).replace("Z", "+00:00")
                )
                return value if value.tzinfo else value.replace(tzinfo=UTC)
            except (KeyError, TypeError, ValueError):
                break
    return datetime.now(UTC)


def _activity(state: dict[str, Any], tier: AgentTier) -> list[dict[str, Any]]:
    result = []
    for run in state.get("specialist_runs", []):
        if not isinstance(run, dict) or run.get("tier") != tier:
            continue
        result.append(
            {
                "run_id": run.get("run_id"),
                "role": run.get("role"),
                "status": run.get("status"),
                "provider": run.get("provider"),
                "model": run.get("model"),
                "duration_ms": run.get("duration_ms"),
                "tools": [
                    {
                        "name": item.get("name"),
                        "status": item.get("status"),
                    }
                    for item in run.get("tool_activity", [])
                    if isinstance(item, dict)
                ],
                "error_code": run.get("error_code"),
            }
        )
    return result


def build_tier_report(
    state: dict[str, Any],
    tier: AgentTier,
) -> dict[str, Any]:
    raw_result = state.get(f"{tier}_result")
    if not isinstance(raw_result, dict):
        raise ValueError(f"{tier.upper()} result is required for its report.")

    alert = state.get("normalized_alert")
    if not isinstance(alert, dict):
        alert = {}
    evidence_refs = [
        str(item)
        for item in raw_result.get("evidence_refs", [])
        if item
    ]
    escalation_required = bool(
        raw_result.get("escalate")
        or raw_result.get("requires_l3")
        or (
            tier == "l1"
            and raw_result.get("severity") in {"medium", "high", "critical"}
        )
        or (
            tier == "l1"
            and float(raw_result.get("confidence") or 0) < 0.70
        )
        or (
            tier == "l2"
            and (
                raw_result.get("detection_gap")
                or raw_result.get("containment_recommendations")
                or raw_result.get("severity") in {"high", "critical"}
            )
        )
    )
    report = TierReport(
        report_id=f"RPT-{state['investigation_id']}-{tier.upper()}",
        investigation_id=str(state["investigation_id"]),
        tier=tier,
        status="completed",
        summary=str(raw_result.get("summary") or f"{tier.upper()} report"),
        generated_at=_generated_at(state, tier),
        alert_context={
            key: alert.get(key)
            for key in (
                "alert_id",
                "timestamp",
                "agent_id",
                "agent_name",
                "rule_id",
                "rule_level",
                "description",
                "source_ip",
                "target_user",
                "event_outcome",
            )
            if alert.get(key) is not None
        },
        triage={
            key: raw_result.get(key)
            for key in (
                "classification",
                "severity",
                "confidence",
                "false_positive",
                "false_positive_confirmed",
                "mitre_techniques",
            )
            if key in raw_result
        },
        initial_investigation={
            "affected_host": raw_result.get("affected_host"),
            "affected_user": raw_result.get("affected_user"),
            "source_ip": raw_result.get("source_ip"),
            "affected_assets": raw_result.get("affected_assets", []),
            "timeline": raw_result.get("timeline", []),
            "related_alert_ids": raw_result.get(
                "related_alert_ids",
                [],
            ),
            "evidence_count": len(state.get("evidence", [])),
            "documented_evidence": raw_result.get("evidence", []),
        },
        advanced_analysis={
            "incident_status": raw_result.get("incident_status"),
            "root_cause": raw_result.get("root_cause"),
            "scope_summary": raw_result.get("scope_summary"),
            "attack_chain": raw_result.get("attack_chain", []),
            "compromise_indicators": raw_result.get(
                "compromise_indicators",
                [],
            ),
            "threat_hunt_findings": raw_result.get(
                "threat_hunt_findings",
                [],
            ),
            "threat_assessment": raw_result.get("threat_assessment", {}),
            "ioc_assessments": raw_result.get("ioc_assessments", []),
            "ttp_analysis": raw_result.get("ttp_analysis", []),
            "forensic_assessment": raw_result.get(
                "forensic_assessment",
                {},
            ),
            "malware_analysis": raw_result.get("malware_analysis", {}),
            "systemic_weaknesses": raw_result.get(
                "systemic_weaknesses",
                [],
            ),
        },
        containment={
            "recommendations": raw_result.get(
                "containment_recommendations",
                raw_result.get("proposed_actions", []),
            ),
            "strategy": raw_result.get("containment_strategy", []),
            "incident_command_plan": raw_result.get(
                "incident_command_plan",
                {},
            ),
            "eradication_steps": raw_result.get("eradication_steps", []),
            "recovery_steps": raw_result.get("recovery_steps", []),
            "requires_human_approval": any(
                item.get("action_type") in {
                    "block_ip",
                    "restart_agent",
                    "restart_service",
                }
                for item in raw_result.get(
                    "containment_recommendations",
                    raw_result.get("proposed_actions", []),
                )
                if isinstance(item, dict)
            ),
        },
        detection_engineering={
            "recommendations": raw_result.get(
                "detection_tuning_recommendations",
                raw_result.get("rule_recommendations", []),
            ),
            "detection_gaps": raw_result.get("detection_gaps", []),
            "architecture_recommendations": raw_result.get(
                "architecture_recommendations",
                [],
            ),
            "playbook_recommendations": raw_result.get(
                "playbook_recommendations",
                [],
            ),
            "automation_opportunities": raw_result.get(
                "automation_opportunities",
                [],
            ),
        },
        post_incident_review=raw_result.get(
            "post_incident_review",
            {},
        ),
        escalation={
            "required": escalation_required,
            "reason": raw_result.get("escalation_reason"),
            "next_tier": (
                "l2"
                if tier == "l1" and escalation_required
                else "l3"
                if tier == "l2" and escalation_required
                else None
            ),
        },
        analyst_activity=_activity(state, tier),
        evidence_refs=evidence_refs,
        result=raw_result,
    )
    return report.model_dump(mode="json")
