"""Shared typed state for the LangGraph investigation workflow."""

import operator
from enum import Enum
from typing import Annotated, Any, NotRequired, Required, TypedDict

from app.coreAgents.orchestration.schemas import Severity


class InvestigationStatus(str, Enum):
    created = "created"
    running = "running"
    awaiting_approval = "awaiting_approval"
    approved = "approved"
    rejected = "rejected"
    completed = "completed"
    failed = "failed"


class InvestigationStage(str, Enum):
    created = "created"
    load_alert = "load_alert"
    l1 = "l1"
    l2 = "l2"
    l3 = "l3"
    policy_gate = "policy_gate"
    human_approval = "human_approval"
    response_execution = "response_execution"
    verification = "verification"
    final_report = "final_report"
    failed = "failed"


class InvestigationState(TypedDict, total=False):
    investigation_id: Required[str]
    status: Required[str]
    current_stage: Required[str]

    alert_id: Required[str]
    agent_id: NotRequired[str | None]
    organization_id: NotRequired[str | None]
    owner_user_id: NotRequired[str | None]
    initiated_by: NotRequired[str | None]
    initiation_reason: NotRequired[str | None]

    source_alert: NotRequired[dict[str, Any]]
    normalized_alert: NotRequired[dict[str, Any]]
    l1_result: NotRequired[dict[str, Any] | None]
    l2_result: NotRequired[dict[str, Any] | None]
    l3_result: NotRequired[dict[str, Any] | None]
    l1_report: NotRequired[dict[str, Any] | None]
    l2_report: NotRequired[dict[str, Any] | None]
    l3_report: NotRequired[dict[str, Any] | None]
    specialist_runs: Annotated[list[dict[str, Any]], operator.add]

    evidence: NotRequired[list[dict[str, Any]]]
    timeline: NotRequired[list[dict[str, Any]]]
    affected_assets: NotRequired[list[str]]

    severity: NotRequired[str]
    confidence: NotRequired[float]

    proposed_actions: NotRequired[list[dict[str, Any]]]
    approval_request: NotRequired[dict[str, Any] | None]
    approval_decision: NotRequired[dict[str, Any] | None]
    execution_authorization: NotRequired[dict[str, Any] | None]
    executed_actions: NotRequired[list[dict[str, Any]]]
    verification_results: NotRequired[list[dict[str, Any]]]

    final_report: NotRequired[dict[str, Any] | None]

    errors: Annotated[list[dict[str, Any]], operator.add]
    audit_events: Annotated[list[dict[str, Any]], operator.add]
