"""Deterministic incident report construction for durable persistence."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.mape_k.schemas import IncidentWorkflowState


def build_final_report(state: IncidentWorkflowState) -> dict[str, Any]:
    diagnosis = (
        state.diagnosis.model_dump(mode="json") if state.diagnosis else None
    )
    plan = (
        state.remediation_plan.model_dump(mode="json")
        if state.remediation_plan
        else None
    )
    advisory_plan = (
        state.advisory_plan.model_dump(mode="json")
        if state.advisory_plan
        else None
    )
    return {
        "report_type": "mapek_incident_report",
        "incident_id": state.incident_id,
        "investigation_id": state.investigation_id,
        "alert_id": state.alert_id,
        "status": state.status,
        "stage": state.stage,
        "diagnosis": diagnosis,
        "remediation_plan": plan,
        "advisory_plan": advisory_plan,
        "policy_decision": (
            state.policy_decision.model_dump(mode="json")
            if state.policy_decision
            else None
        ),
        "approval": (
            state.approval_decision.model_dump(mode="json")
            if state.approval_decision
            else None
        ),
        "executions": [
            item.model_dump(mode="json") for item in state.execution_results
        ],
        "verification": (
            state.verification.model_dump(mode="json")
            if state.verification
            else None
        ),
        "rollback": (
            state.rollback.model_dump(mode="json") if state.rollback else None
        ),
        "evidence_ids": [item.evidence_id for item in state.evidence],
        "token_usage": {
            "compatibility_input": state.llm_input_tokens,
            "compatibility_output": state.llm_output_tokens,
            "estimated_input": state.estimated_input_tokens,
            "estimated_output": state.estimated_output_tokens,
            "actual_input": state.actual_input_tokens,
            "actual_output": state.actual_output_tokens,
            "cached_input": state.cached_input_tokens,
            "model_calls": state.model_calls,
            "retries": state.model_retries,
            "provider": state.model_provider,
            "model": state.model_name,
            "estimated_cost_usd": state.estimated_cost_usd,
            "actual_cost_usd": state.actual_cost_usd,
        },
        "generated_at": datetime.now(UTC).isoformat(),
    }
