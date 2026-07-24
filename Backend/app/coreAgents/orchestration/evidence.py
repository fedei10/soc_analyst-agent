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


def _refs_from_value(value: Any, *, depth: int = 0) -> set[str]:
    if depth > 6:
        return set()
    if isinstance(value, dict):
        refs: set[str] = set()
        ref = _reference_from_item(value)
        if ref:
            refs.add(ref)
        for item in value.values():
            refs.update(_refs_from_value(item, depth=depth + 1))
        return refs
    if isinstance(value, list):
        refs: set[str] = set()
        for item in value[:200]:
            refs.update(_refs_from_value(item, depth=depth + 1))
        return refs
    return set()


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
        refs.update(_refs_from_value(l2.get("evidence", [])))
    l3 = state.get("l3_result") or {}
    if isinstance(l3, dict):
        refs.update(_refs_from_value(l3.get("evidence", [])))
    refs.update(_refs_from_value(state.get("specialist_findings", {})))
    return refs


def validate_result_evidence(
    state: InvestigationState,
    result: L1Result | L2Result | L3Result,
) -> None:
    available = available_evidence_refs(state)
    refs = set(result.evidence_refs)
    carried_refs = (
        _refs_from_value(result.evidence)
        if isinstance(result, (L2Result, L3Result))
        else set()
    )
    effective_available = available | carried_refs
    validation_available = (
        available
        if state.get("specialist_findings")
        else effective_available
    )
    if not refs:
        raise ValueError("Important conclusions require evidence references.")
    if not refs.issubset(validation_available):
        raise ValueError("Conclusion references unavailable evidence.")
    if isinstance(result, L2Result):
        durable_state = dict(state)
        durable_state.pop("specialist_findings", None)
        durable_refs = available_evidence_refs(durable_state)
        if not refs.issubset(durable_refs | carried_refs):
            raise ValueError(
                "New L2 evidence references must be carried in the result."
            )
        for action in result.containment_recommendations:
            action_refs = set(action.evidence_refs)
            if (
                not action_refs
                or not action_refs.issubset(validation_available)
                or not action_refs.issubset(durable_refs | carried_refs)
            ):
                raise ValueError(
                    "Every L2 containment proposal requires valid evidence "
                    "references."
                )
    if isinstance(result, L3Result):
        durable_state = dict(state)
        durable_state.pop("specialist_findings", None)
        durable_refs = available_evidence_refs(durable_state)
        if not refs.issubset(durable_refs | carried_refs):
            raise ValueError(
                "New L3 evidence references must be carried in the result."
            )
        for action in result.proposed_actions:
            action_refs = set(action.evidence_refs)
            if (
                not action_refs
                or not action_refs.issubset(validation_available)
                or not action_refs.issubset(durable_refs | carried_refs)
            ):
                raise ValueError(
                    "Every proposed action requires valid evidence references."
                )
