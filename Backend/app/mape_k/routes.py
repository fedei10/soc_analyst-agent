"""Conditional-edge routing for the MAPE-K workflow graph."""

from __future__ import annotations

from app.mape_k.schemas import (
    IncidentWorkflowState,
    WorkflowStage,
    WorkflowStatus,
)


def after_monitor(state: IncidentWorkflowState) -> str:
    return "knowledge" if state.status == WorkflowStatus.FAILED else "analyze"


def after_analyze(state: IncidentWorkflowState) -> str:
    return "plan" if state.stage == WorkflowStage.PLAN else "knowledge"


def after_plan(state: IncidentWorkflowState) -> str:
    return (
        "policy_gate"
        if state.stage == WorkflowStage.POLICY_GATE
        else "knowledge"
    )


def after_policy_gate(state: IncidentWorkflowState) -> str:
    if state.status == WorkflowStatus.WAITING_APPROVAL:
        return "human_approval"
    if state.status == WorkflowStatus.APPROVED:
        return "execution_authorization"
    return "knowledge"


def after_human_approval(state: IncidentWorkflowState) -> str:
    return (
        "execution_authorization"
        if state.status == WorkflowStatus.APPROVED
        else "knowledge"
    )


def after_execution_authorization(state: IncidentWorkflowState) -> str:
    return (
        "execute"
        if state.stage == WorkflowStage.EXECUTE
        and state.execution_authorization is not None
        else "knowledge"
    )


def after_execute(state: IncidentWorkflowState) -> str:
    if state.status == WorkflowStatus.FAILED:
        return "rollback"
    if state.status == WorkflowStatus.WAITING_VERIFICATION:
        return "verification_wait"
    if state.stage == WorkflowStage.VERIFY:
        return "verify"
    return "knowledge"


def after_verification_wait(state: IncidentWorkflowState) -> str:
    if state.status == WorkflowStatus.WAITING_VERIFICATION:
        return "verification_wait"
    if (
        state.stage == WorkflowStage.VERIFY
        and state.status == WorkflowStatus.RUNNING
    ):
        return "verify"
    if state.stage == WorkflowStage.ROLLBACK:
        return "rollback"
    return "knowledge"


def after_verify(state: IncidentWorkflowState) -> str:
    return (
        "rollback"
        if state.stage == WorkflowStage.ROLLBACK
        or state.status == WorkflowStatus.FAILED
        else "knowledge"
    )
