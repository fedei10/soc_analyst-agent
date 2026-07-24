"""Executable nodes for the SOC investigation graph."""

import json
import uuid
from datetime import UTC, datetime, timedelta

from pydantic import BaseModel
from langgraph.types import interrupt

from app.coreAgents.orchestration.schemas import (
    ApprovalDecision,
    ApprovalRequest,
    ExecutionAuthorization,
    L1Result,
    L2Result,
    L3Result,
    ProposedAction,
)
from app.coreAgents.orchestration.routing import requires_approval
from app.coreAgents.orchestration.evidence import validate_result_evidence
from app.coreAgents.orchestration.state import InvestigationState
from app.coreAgents.orchestration.agent_runner import invoke_validated_agent


def audit_event(
    state: InvestigationState,
    *,
    stage: str,
    event: str,
) -> dict:
    return {
        "investigation_id": state.get("investigation_id", "unknown"),
        "stage": stage,
        "event": event,
        "timestamp": datetime.now(UTC).isoformat(),
    }


def failed_update(
    state: InvestigationState,
    *,
    stage: str,
    code: str,
) -> dict:
    return {
        "status": "failed",
        "current_stage": "failed",
        "errors": [
            {
                "stage": stage,
                "code": code,
                "message": f"{stage.upper()} analysis could not be completed.",
            }
        ],
        "audit_events": [
            audit_event(state, stage=stage, event="analysis_failed")
        ],
    }


def initialize_investigation(state: InvestigationState) -> dict:
    if not state.get("investigation_id") or not state.get("alert_id"):
        return failed_update(
            state,
            stage="initialize",
            code="INVALID_INVESTIGATION_INPUT",
        )

    return {
        "status": "running",
        "current_stage": "initialized",
        "audit_events": [
            audit_event(
                state,
                stage="initialize",
                event="investigation_initialized",
            )
        ],
    }


def load_wazuh_alert(state: InvestigationState, *, gateway=None) -> dict:
    if gateway is None:
        from app.services.wazuh.dependencies import get_wazuh_gateway

        gateway = get_wazuh_gateway()

    try:
        alert = gateway.get_alert_by_id(state["alert_id"])
    except Exception:
        return failed_update(
            state,
            stage="load_alert",
            code="WAZUH_ALERT_LOAD_FAILED",
        )

    if alert is None:
        return failed_update(
            state,
            stage="load_alert",
            code="WAZUH_ALERT_NOT_FOUND",
        )

    if isinstance(alert, BaseModel):
        source_alert = alert.model_dump(mode="json")
    elif isinstance(alert, dict):
        source_alert = alert
    else:
        return failed_update(
            state,
            stage="load_alert",
            code="INVALID_WAZUH_ALERT",
        )

    return {
        "current_stage": "alert_loaded",
        "source_alert": source_alert,
        "audit_events": [
            audit_event(state, stage="load_alert", event="alert_loaded")
        ],
    }


def normalize_alert(state: InvestigationState) -> dict:
    source = state.get("source_alert")
    if not isinstance(source, dict):
        return failed_update(
            state,
            stage="normalize_alert",
            code="SOURCE_ALERT_MISSING",
        )

    alert_id = str(source.get("alert_id") or state["alert_id"])
    if alert_id != state["alert_id"]:
        return failed_update(
            state,
            stage="normalize_alert",
            code="ALERT_ID_MISMATCH",
        )

    fields = (
        "timestamp",
        "agent_id",
        "agent_name",
        "rule_id",
        "rule_level",
        "description",
        "source_ip",
        "target_user",
        "mitre_ids",
        "event_outcome",
    )
    normalized = {"alert_id": alert_id}
    normalized.update(
        {
            field: source[field]
            for field in fields
            if source.get(field) is not None
        }
    )

    return {
        "current_stage": "alert_normalized",
        "normalized_alert": normalized,
        "audit_events": [
            audit_event(
                state,
                stage="normalize_alert",
                event="alert_normalized",
            )
        ],
    }


def invoke_structured_agent(
    agent,
    *,
    payload: dict,
    result_model: type[BaseModel],
    role: str,
) -> BaseModel:
    _, validated = invoke_validated_agent(
        agent,
        messages=[
            {
                "role": "user",
                "content": json.dumps(payload, default=str),
            }
        ],
        result_model=result_model,
        role=role,
    )
    return validated


def run_l1(state: InvestigationState, *, agent=None) -> dict:
    if agent is None:
        from app.coreAgents.Agents.soc_level1_agent import agent as l1_agent

        agent = l1_agent

    normalized_alert = state.get("normalized_alert")
    if normalized_alert is None:
        return failed_update(state, stage="l1", code="ALERT_NOT_NORMALIZED")

    try:
        result = invoke_structured_agent(
            agent,
            payload={
                "task": "Triage this normalized Wazuh alert.",
                "alert": normalized_alert,
                "evidence": state.get("evidence", []),
            },
            result_model=L1Result,
            role="l1",
        )
    except Exception:
        return failed_update(state, stage="l1", code="L1_AGENT_FAILED")

    validated = L1Result.model_validate(result)
    try:
        validate_result_evidence(state, validated)
    except ValueError:
        return failed_update(
            state,
            stage="l1",
            code="UNSUPPORTED_EVIDENCE_REFERENCE",
        )
    return {
        "status": "running",
        "current_stage": "l1_completed",
        "l1_result": validated.model_dump(mode="json"),
        "severity": validated.severity.value,
        "confidence": validated.confidence,
        "evidence": [*state.get("evidence", []), *validated.evidence],
        "audit_events": [
            audit_event(state, stage="l1", event="analysis_completed")
        ],
    }


def run_l2(state: InvestigationState, *, agent=None) -> dict:
    if agent is None:
        from app.coreAgents.Agents.soc_level2_agent import agent as l2_agent

        agent = l2_agent

    if state.get("l1_result") is None:
        return failed_update(state, stage="l2", code="L1_RESULT_MISSING")

    try:
        result = invoke_structured_agent(
            agent,
            payload={
                "task": "Investigate the alert using the L1 triage result.",
                "alert": state.get("normalized_alert", {}),
                "l1_result": state["l1_result"],
                "evidence": state.get("evidence", []),
            },
            result_model=L2Result,
            role="l2",
        )
    except Exception:
        return failed_update(state, stage="l2", code="L2_AGENT_FAILED")

    validated = L2Result.model_validate(result)
    try:
        validate_result_evidence(state, validated)
    except ValueError:
        return failed_update(
            state,
            stage="l2",
            code="UNSUPPORTED_EVIDENCE_REFERENCE",
        )
    return {
        "status": "running",
        "current_stage": "l2_completed",
        "l2_result": validated.model_dump(mode="json"),
        "severity": validated.severity.value,
        "confidence": validated.confidence,
        "timeline": validated.timeline,
        "affected_assets": validated.affected_assets,
        "audit_events": [
            audit_event(state, stage="l2", event="analysis_completed")
        ],
    }


def run_l3(state: InvestigationState, *, agent=None) -> dict:
    if agent is None:
        from app.coreAgents.Agents.soc_level3_agent import agent as l3_agent

        agent = l3_agent

    if state.get("l2_result") is None:
        return failed_update(state, stage="l3", code="L2_RESULT_MISSING")

    try:
        result = invoke_structured_agent(
            agent,
            payload={
                "task": "Perform advanced analysis and propose remediation.",
                "alert": state.get("normalized_alert", {}),
                "l1_result": state.get("l1_result"),
                "l2_result": state["l2_result"],
                "evidence": state.get("evidence", []),
                "timeline": state.get("timeline", []),
                "affected_assets": state.get("affected_assets", []),
            },
            result_model=L3Result,
            role="l3",
        )
    except Exception:
        return failed_update(state, stage="l3", code="L3_AGENT_FAILED")

    validated = L3Result.model_validate(result)
    try:
        validate_result_evidence(state, validated)
    except ValueError:
        return failed_update(
            state,
            stage="l3",
            code="UNSUPPORTED_EVIDENCE_REFERENCE",
        )
    return {
        "status": "running",
        "current_stage": "l3_completed",
        "l3_result": validated.model_dump(mode="json"),
        "proposed_actions": [
            action.model_dump(mode="json")
            for action in validated.proposed_actions
        ],
        "audit_events": [
            audit_event(state, stage="l3", event="analysis_completed")
        ],
    }


def prepare_actions(state: InvestigationState) -> dict:
    """Revalidate L3 proposals and discard any model-supplied policy value."""
    raw_actions = state.get("proposed_actions", [])
    if not isinstance(raw_actions, list):
        return failed_update(
            state,
            stage="policy_gate",
            code="INVALID_PROPOSED_ACTIONS",
        )

    validated_actions = []
    trusted_action_fields = {
        "action_type",
        "target",
        "reason",
        "risk_level",
        "operational_impact",
        "evidence_refs",
    }
    try:
        for raw_action in raw_actions:
            if not isinstance(raw_action, dict):
                raise ValueError("Proposed action must be an object.")
            trusted_fields = {
                key: value
                for key, value in raw_action.items()
                if key in trusted_action_fields
            }
            action = ProposedAction.model_validate(trusted_fields)
            validated_actions.append(action.model_dump(mode="json"))
    except (TypeError, ValueError):
        return failed_update(
            state,
            stage="policy_gate",
            code="INVALID_PROPOSED_ACTIONS",
        )

    return {
        "current_stage": "action_policy_completed",
        "proposed_actions": validated_actions,
        "audit_events": [
            audit_event(
                state,
                stage="policy_gate",
                event="actions_validated",
            )
        ],
    }


def mark_awaiting_approval(state: InvestigationState) -> dict:
    """Checkpoint write proposals for later human review without executing."""
    actions = [
        action
        for action in state.get("proposed_actions", [])
        if requires_approval(action)
    ]
    if not actions:
        return failed_update(
            state,
            stage="human_approval",
            code="APPROVAL_ACTIONS_MISSING",
        )

    approval_request = ApprovalRequest(
        investigation_id=state["investigation_id"],
        approval_id=f"APR-{uuid.uuid4().hex}",
        expires_at=datetime.now(UTC) + timedelta(minutes=15),
        proposed_actions=[
            {
                key: value
                for key, value in action.items()
                if key
                in {
                    "action_type",
                    "target",
                    "reason",
                    "risk_level",
                    "operational_impact",
                    "evidence_refs",
                }
            }
            for action in actions
        ],
    )

    return {
        "status": "awaiting_approval",
        "current_stage": "human_approval",
        "approval_request": approval_request.model_dump(mode="json"),
        "audit_events": [
            audit_event(
                state,
                stage="human_approval",
                event="approval_required",
            )
        ],
    }


def request_human_approval(state: InvestigationState) -> dict:
    """Pause once and validate the external analyst decision on resume."""
    approval_request = state.get("approval_request")
    if not isinstance(approval_request, dict):
        return failed_update(
            state,
            stage="human_approval",
            code="APPROVAL_REQUEST_MISSING",
        )

    raw_decision = interrupt(approval_request)
    try:
        decision = ApprovalDecision.model_validate(raw_decision)
    except (TypeError, ValueError):
        return failed_update(
            state,
            stage="human_approval",
            code="INVALID_APPROVAL_DECISION",
        )

    if decision.approval_id != approval_request.get("approval_id"):
        return failed_update(
            state,
            stage="human_approval",
            code="APPROVAL_ID_MISMATCH",
        )

    try:
        expires_at = datetime.fromisoformat(approval_request["expires_at"])
    except (KeyError, TypeError, ValueError):
        return failed_update(
            state,
            stage="human_approval",
            code="INVALID_APPROVAL_EXPIRY",
        )
    if expires_at <= datetime.now(UTC):
        return failed_update(
            state,
            stage="human_approval",
            code="APPROVAL_EXPIRED",
        )

    decision_data = decision.model_dump(mode="json")
    event = {
        **audit_event(
            state,
            stage="human_approval",
            event="approval_decision_received",
        ),
        "decision": decision.decision,
        "approved_by": decision.approved_by,
        "approval_id": decision.approval_id,
    }

    if decision.decision == "modify":
        return {
            "status": "running",
            "current_stage": "approval_modified",
            "approval_decision": decision_data,
            "proposed_actions": decision.modified_actions,
            "audit_events": [event],
        }

    return {
        "status": (
            "approved" if decision.decision == "approve" else "rejected"
        ),
        "current_stage": "approval_received",
        "approval_decision": decision_data,
        "audit_events": [event],
    }


def mark_response_approved(state: InvestigationState) -> dict:
    """Checkpoint approval for the separate response executor step."""
    decision = state.get("approval_decision") or {}
    if decision.get("decision") != "approve":
        return failed_update(
            state,
            stage="response_approved",
            code="VALID_APPROVAL_MISSING",
        )

    return {
        "status": "approved",
        "current_stage": "response_approved",
        "audit_events": [
            audit_event(
                state,
                stage="response_approved",
                event="response_execution_pending",
            )
        ],
    }


def request_execution_authorization(state: InvestigationState) -> dict:
    """Pause after approval so only the executor operation can continue."""
    request = state.get("approval_request") or {}
    decision = state.get("approval_decision") or {}
    if (
        decision.get("decision") != "approve"
        or decision.get("approval_id") != request.get("approval_id")
    ):
        return failed_update(
            state,
            stage="response_execution",
            code="VALID_APPROVAL_MISSING",
        )

    raw_authorization = interrupt({
        "type": "response_execution",
        "investigation_id": state["investigation_id"],
        "approval_id": request["approval_id"],
        "action_count": len(request.get("proposed_actions", [])),
    })
    try:
        authorization = ExecutionAuthorization.model_validate(
            raw_authorization
        )
    except (TypeError, ValueError):
        return failed_update(
            state,
            stage="response_execution",
            code="INVALID_EXECUTION_AUTHORIZATION",
        )
    if authorization.approval_id != request.get("approval_id"):
        return failed_update(
            state,
            stage="response_execution",
            code="APPROVAL_ID_MISMATCH",
        )
    if len(authorization.action_ids) != len(
        request.get("proposed_actions", [])
    ):
        return failed_update(
            state,
            stage="response_execution",
            code="ACTION_CLAIM_MISMATCH",
        )
    return {
        "status": "running",
        "current_stage": "response_execution_authorized",
        "execution_authorization": authorization.model_dump(mode="json"),
        "audit_events": [{
            **audit_event(
                state,
                stage="response_execution",
                event="response_execution_authorized",
            ),
            "execution_id": authorization.execution_id,
            "executed_by": authorization.executed_by,
        }],
    }


def create_final_report(state: InvestigationState) -> dict:
    l1 = state.get("l1_result") or {}
    l2 = state.get("l2_result") or {}
    l3 = state.get("l3_result") or {}

    summary = (
        l3.get("summary")
        or l2.get("summary")
        or l1.get("summary")
        or "Investigation completed without an agent summary."
    )
    recommendations = (
        l3.get("remediation_steps")
        or l2.get("recommended_next_steps")
        or []
    )
    approval_decision = state.get("approval_decision") or {}
    executed_actions = state.get("executed_actions", [])
    if approval_decision.get("decision") == "reject":
        response_status = "rejected"
    elif executed_actions and all(
        action.get("status") == "verified"
        for action in executed_actions
    ):
        response_status = "verified"
    elif any(
        action.get("status") == "verification_failed"
        for action in executed_actions
    ):
        response_status = "verification_failed"
    elif any(
        action.get("status") == "verification_pending"
        for action in executed_actions
    ):
        response_status = "verification_pending"
    elif executed_actions:
        response_status = "executed_unverified"
    else:
        response_status = "not_executed"
    report = {
        "investigation_id": state["investigation_id"],
        "status": "completed",
        "severity": state.get("severity", "informational"),
        "classification": l1.get("classification", "unknown"),
        "summary": summary,
        "timeline": state.get("timeline", []),
        "mitre_techniques": l1.get("mitre_techniques", []),
        "recommendations": recommendations,
        "response_status": response_status,
        "verification_results": state.get("verification_results", []),
    }

    return {
        "status": "completed",
        "current_stage": "final_report",
        "final_report": report,
        "audit_events": [
            audit_event(
                state,
                stage="final_report",
                event="investigation_completed",
            )
        ],
    }


def handle_failure(state: InvestigationState) -> dict:
    return {
        "status": "failed",
        "current_stage": "failed",
        "audit_events": [
            audit_event(state, stage="failed", event="investigation_failed")
        ],
    }
