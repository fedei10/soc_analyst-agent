"""Deterministic evidence-reference validation for model conclusions."""

from typing import Any

from app.coreAgents.orchestration.schemas import L1Result, L2Result, L3Result
from app.coreAgents.orchestration.state import InvestigationState


def _reference_from_item(item: dict[str, Any]) -> str | None:
    explicit = item.get("evidence_ref") or item.get("evidence_id")
    if explicit:
        return str(explicit)
    alert_id = item.get("alert_id")
    if alert_id:
        return f"alert:{alert_id}"
    return None


def available_evidence_refs(state: InvestigationState) -> set[str]:
    refs: set[str] = set()
    alert = state.get("normalized_alert")
    if isinstance(alert, dict) and alert.get("alert_id"):
        refs.add(f"alert:{alert['alert_id']}")
    for key in ("evidence", "timeline"):
        for item in state.get(key, []) or []:
            if isinstance(item, dict):
                ref = _reference_from_item(item)
                if ref:
                    refs.add(ref)
    l1 = state.get("l1_result") or {}
    for item in l1.get("evidence", []) if isinstance(l1, dict) else []:
        if isinstance(item, dict):
            ref = _reference_from_item(item)
            if ref:
                refs.add(ref)
    l2 = state.get("l2_result") or {}
    if isinstance(l2, dict):
        refs.update(
            f"alert:{alert_id}"
            for alert_id in l2.get("related_alert_ids", [])
            if alert_id
        )
    return refs


def validate_result_evidence(
    state: InvestigationState,
    result: L1Result | L2Result | L3Result,
) -> None:
    available = available_evidence_refs(state)
    refs = set(result.evidence_refs)
    if not refs:
        raise ValueError("Important conclusions require evidence references.")
    if not refs.issubset(available):
        raise ValueError("Conclusion references unavailable evidence.")
    if isinstance(result, L3Result):
        for action in result.proposed_actions:
            action_refs = set(action.evidence_refs)
            if not action_refs or not action_refs.issubset(available):
                raise ValueError(
                    "Every proposed action requires valid evidence references."
                )
