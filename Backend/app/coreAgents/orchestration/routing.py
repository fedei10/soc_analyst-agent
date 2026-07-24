"""Deterministic routing rules for SOC investigation state."""

from typing import Literal

from pydantic import ValidationError

from app.coreAgents.orchestration.schemas import (
    L1Result,
    L2Result,
    Severity,
    WRITE_ACTIONS,
)
from app.coreAgents.orchestration.state import InvestigationState


L1Route = Literal["l2_investigation", "final_report", "failed"]
L2Route = Literal["l3_analysis", "final_report", "failed"]
ActionPolicyRoute = Literal["awaiting_approval", "final_report", "failed"]
ApprovalRoute = Literal[
    "response_approved",
    "prepare_actions",
    "final_report",
    "failed",
]

L1_FALSE_POSITIVE_CONFIDENCE = 0.90
L1_LOW_RISK_CONFIDENCE = 0.85
L1_MINIMUM_CONFIDENCE = 0.70


def route_after_step(
    state: InvestigationState,
    *,
    success_node: str,
) -> str:
    if state.get("status") == "failed":
        return "failed"
    return success_node


def route_after_l1(state: InvestigationState) -> L1Route:
    raw_result = state.get("l1_result")
    if raw_result is None:
        return "failed"

    try:
        result = L1Result.model_validate(raw_result)
    except ValidationError:
        return "failed"

    if (
        result.false_positive
        and result.confidence >= L1_FALSE_POSITIVE_CONFIDENCE
    ):
        return "final_report"

    if (
        result.severity in {Severity.informational, Severity.low}
        and result.confidence >= L1_LOW_RISK_CONFIDENCE
        and not result.escalate
    ):
        return "final_report"

    if result.severity in {
        Severity.medium,
        Severity.high,
        Severity.critical,
    }:
        return "l2_investigation"

    if result.confidence < L1_MINIMUM_CONFIDENCE:
        return "l2_investigation"

    if result.escalate:
        return "l2_investigation"

    return "final_report"


def route_after_l2(state: InvestigationState) -> L2Route:
    raw_result = state.get("l2_result")
    if raw_result is None:
        return "failed"

    try:
        result = L2Result.model_validate(raw_result)
    except ValidationError:
        return "failed"

    if result.false_positive_confirmed:
        return "final_report"

    if result.detection_gap:
        return "l3_analysis"

    if result.severity in {Severity.high, Severity.critical}:
        return "l3_analysis"

    if result.requires_l3:
        return "l3_analysis"

    if result.containment_recommendations:
        return "l3_analysis"

    return "final_report"


def requires_approval(action: dict) -> bool:
    """Derive approval policy from trusted action types only."""
    return action.get("action_type") in WRITE_ACTIONS


def route_after_action_policy(
    state: InvestigationState,
) -> ActionPolicyRoute:
    if state.get("status") == "failed":
        return "failed"

    actions = state.get("proposed_actions", [])
    if not isinstance(actions, list):
        return "failed"

    if any(requires_approval(action) for action in actions):
        return "awaiting_approval"

    return "final_report"


def route_after_approval(state: InvestigationState) -> ApprovalRoute:
    if state.get("status") == "failed":
        return "failed"

    decision = state.get("approval_decision")
    if not isinstance(decision, dict):
        return "failed"

    choice = decision.get("decision")
    if choice == "approve":
        return "response_approved"
    if choice == "reject":
        return "final_report"
    if choice == "modify":
        return "prepare_actions"
    return "failed"
