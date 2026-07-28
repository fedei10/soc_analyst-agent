"""Node implementations for the MAPE-K workflow graph.

Each node is a top-level function whose first argument is the service it
drives; graph.py binds services with functools.partial at wiring time.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from langgraph.types import interrupt
from pydantic import ValidationError

from app.config import settings
from app.mape_k.analyze import IncidentAnalyzer
from app.mape_k.executor import RestrictedExecutor
from app.mape_k.knowledge import build_final_report
from app.mape_k.monitor import WazuhMonitor
from app.mape_k.playbooks import PlaybookPlanner
from app.mape_k.policy import PolicyEngine, role_allows
from app.mape_k.schemas import (
    ApprovalDecision,
    ApprovalRequestRecord,
    ExecutionAuthorization,
    IncidentWorkflowState,
    RollbackResult,
    TrustedApprovalSubmission,
    VerificationResumeAuthorization,
    VerificationOutcome,
    WorkflowError,
    WorkflowStage,
    WorkflowStatus,
    compute_plan_hash,
)
from app.mape_k.utils import audit_event, stable_id
from app.mape_k.verify import (
    ResponseVerifier,
    verification_observation_ready_at,
)


def _failure(stage: WorkflowStage, exc: Exception) -> dict[str, Any]:
    error = WorkflowError(
        stage=stage,
        code=f"{stage.value.upper()}_FAILED",
        message=f"{stage.value} stage failed ({type(exc).__name__}).",
        retryable=False,
    )
    return {
        "stage": stage,
        "current_stage": stage,
        "status": WorkflowStatus.FAILED,
        "error": error,
        "errors": [error.model_dump(mode="json")],
        "audit_events": [
            audit_event(
                "workflow_stage_failed",
                stage=stage,
                error_code=error.code,
            )
        ],
    }


def _approval_escalation(
    *,
    code: str,
    message: str,
    reason: str,
    **payload: Any,
) -> dict[str, Any]:
    """Refuse an approval resume without escaping the graph."""

    return {
        "stage": WorkflowStage.POLICY_GATE,
        "current_stage": WorkflowStage.POLICY_GATE,
        "status": WorkflowStatus.ESCALATED,
        "error": WorkflowError(
            stage=WorkflowStage.POLICY_GATE,
            code=code,
            message=message,
        ),
        "audit_events": [
            audit_event("approval_invalidated", reason=reason, **payload)
        ],
    }


def _validate_approval_binding(
    state: IncidentWorkflowState,
    request: ApprovalRequestRecord,
) -> None:
    plan = state.remediation_plan
    if plan is None:
        raise ValueError("The approved remediation plan is unavailable.")
    expected_action_ids = [action.action_id for action in plan.actions]
    checks = {
        "incident": request.incident_id == state.incident_id,
        "investigation": request.investigation_id == state.investigation_id,
        "plan_id": request.plan_id == plan.plan_id,
        "plan_version": request.plan_version == plan.plan_version,
        "plan_hash": request.plan_hash == compute_plan_hash(plan),
        "evidence_version": (
            request.evidence_version == state.evidence_version
            and request.evidence_version == plan.evidence_version
        ),
        "policy_version": (
            request.policy_version == settings.MAPEK_POLICY_VERSION
            and request.policy_version == plan.policy_version
        ),
        "action_catalogue_version": (
            request.action_catalogue_version
            == settings.MAPEK_ACTION_CATALOGUE_VERSION
            and request.action_catalogue_version == plan.action_catalogue_version
        ),
        "actions": request.action_ids == expected_action_ids,
    }
    stale = [name for name, valid in checks.items() if not valid]
    if stale:
        raise ValueError(
            "Approval is stale or belongs to another workflow: "
            + ", ".join(stale)
        )
    now = datetime.now(UTC)
    if request.expires_at <= now or plan.expires_at <= now:
        raise ValueError("Approval or remediation plan has expired.")


def monitor_node(
    monitor: WazuhMonitor,
    state: IncidentWorkflowState,
) -> dict[str, Any]:
    try:
        return monitor.run(state)
    except Exception as exc:
        return _failure(WorkflowStage.MONITOR, exc)


def analyze_node(
    analyzer: IncidentAnalyzer,
    state: IncidentWorkflowState,
) -> dict[str, Any]:
    if state.analysis_attempts >= settings.MAPEK_MAX_ANALYSIS_ATTEMPTS:
        return {
            "stage": WorkflowStage.ANALYZE,
            "current_stage": WorkflowStage.ANALYZE,
            "status": WorkflowStatus.ESCALATED,
            "audit_events": [
                audit_event(
                    "analysis_escalated",
                    reason="analysis_attempt_limit_reached",
                )
            ],
        }
    try:
        diagnosis, usage = analyzer.run(state)
    except Exception as exc:
        return _failure(WorkflowStage.ANALYZE, exc)
    inconclusive = (
        diagnosis.confidence < settings.MAPEK_ANALYSIS_CONFIDENCE_THRESHOLD
        or diagnosis.needs_more_evidence
    )
    attempts = state.analysis_attempts + 1
    # Inconclusive with attempts left is not a dead end: go back to Monitor,
    # collect over a wider window, and diagnose again. Only the last attempt
    # escalates to a human.
    recollect = inconclusive and attempts < settings.MAPEK_MAX_ANALYSIS_ATTEMPTS
    escalated = inconclusive and not recollect
    if recollect:
        next_stage = WorkflowStage.MONITOR
    elif escalated:
        next_stage = WorkflowStage.ANALYZE
    else:
        next_stage = WorkflowStage.PLAN
    actual_input = usage.get("actual_input_tokens")
    actual_output = usage.get("actual_output_tokens")
    cached_input = usage.get("cached_input_tokens")
    return {
        "diagnosis": diagnosis,
        "analysis_attempts": attempts,
        "llm_input_tokens": state.llm_input_tokens + usage["input_tokens"],
        "llm_output_tokens": state.llm_output_tokens + usage["output_tokens"],
        "estimated_input_tokens": (
            state.estimated_input_tokens
            + int(usage.get("estimated_input_tokens") or 0)
        ),
        "estimated_output_tokens": (
            state.estimated_output_tokens
            + int(usage.get("estimated_output_tokens") or 0)
        ),
        "actual_input_tokens": (
            (state.actual_input_tokens or 0) + int(actual_input)
            if actual_input is not None
            else state.actual_input_tokens
        ),
        "actual_output_tokens": (
            (state.actual_output_tokens or 0) + int(actual_output)
            if actual_output is not None
            else state.actual_output_tokens
        ),
        "cached_input_tokens": (
            (state.cached_input_tokens or 0) + int(cached_input)
            if cached_input is not None
            else state.cached_input_tokens
        ),
        "model_calls": state.model_calls
        + int(usage.get("model_calls") or 0),
        "model_retries": state.model_retries
        + int(usage.get("retries") or 0),
        "model_provider": usage.get("provider") or state.model_provider,
        "model_name": usage.get("model") or state.model_name,
        "stage": next_stage,
        "current_stage": next_stage,
        "status": (
            WorkflowStatus.ESCALATED
            if escalated
            else WorkflowStatus.RUNNING
        ),
        "audit_events": [
            audit_event(
                "analysis_completed",
                deterministic=diagnosis.deterministic,
                confidence=diagnosis.confidence,
                evidence_ids=diagnosis.evidence_ids,
                provider=usage.get("provider"),
                model=usage.get("model"),
                model_calls=usage.get("model_calls", 0),
            ),
            *(
                [
                    audit_event(
                        "analysis_recollect_requested",
                        attempt=attempts,
                        max_attempts=settings.MAPEK_MAX_ANALYSIS_ATTEMPTS,
                        reason=(
                            "needs_more_evidence"
                            if diagnosis.needs_more_evidence
                            else "low_confidence"
                        ),
                        confidence=diagnosis.confidence,
                    )
                ]
                if recollect
                else []
            ),
        ],
    }


def _planning_usage_update(
    state: IncidentWorkflowState,
    usage: dict[str, Any],
) -> dict[str, Any]:
    actual_input = usage.get("actual_input_tokens")
    actual_output = usage.get("actual_output_tokens")
    cached_input = usage.get("cached_input_tokens")
    return {
        "llm_input_tokens": (
            state.llm_input_tokens + int(usage.get("input_tokens") or 0)
        ),
        "llm_output_tokens": (
            state.llm_output_tokens + int(usage.get("output_tokens") or 0)
        ),
        "estimated_input_tokens": (
            state.estimated_input_tokens
            + int(usage.get("estimated_input_tokens") or 0)
        ),
        "estimated_output_tokens": (
            state.estimated_output_tokens
            + int(usage.get("estimated_output_tokens") or 0)
        ),
        "actual_input_tokens": (
            (state.actual_input_tokens or 0) + int(actual_input)
            if actual_input is not None
            else state.actual_input_tokens
        ),
        "actual_output_tokens": (
            (state.actual_output_tokens or 0) + int(actual_output)
            if actual_output is not None
            else state.actual_output_tokens
        ),
        "cached_input_tokens": (
            (state.cached_input_tokens or 0) + int(cached_input)
            if cached_input is not None
            else state.cached_input_tokens
        ),
        "model_calls": state.model_calls
        + int(usage.get("model_calls") or 0),
        "model_retries": state.model_retries
        + int(usage.get("retries") or 0),
        "model_provider": usage.get("provider") or state.model_provider,
        "model_name": usage.get("model") or state.model_name,
    }


def plan_node(
    planner: PlaybookPlanner,
    state: IncidentWorkflowState,
) -> dict[str, Any]:
    if state.planning_attempts > settings.MAPEK_MAX_PLANNING_RETRIES:
        return {
            "stage": WorkflowStage.PLAN,
            "current_stage": WorkflowStage.PLAN,
            "status": WorkflowStatus.ESCALATED,
            "audit_events": [
                audit_event(
                    "planning_escalated",
                    reason="planning_retry_limit_reached",
                )
            ],
        }
    try:
        selection = planner.plan(state)
    except Exception as exc:
        return {
            "stage": WorkflowStage.PLAN,
            "current_stage": WorkflowStage.PLAN,
            "status": WorkflowStatus.ESCALATED,
            "error": WorkflowError(
                stage=WorkflowStage.PLAN,
                code="PLANNING_FAILED",
                message=str(exc)[:1000],
            ),
            "audit_events": [
                audit_event("planning_escalated", reason="planning_failed")
            ],
        }
    plan = selection.plan
    if plan is None:
        advisory = selection.advisory_plan
        if advisory is None:
            return _failure(
                WorkflowStage.PLAN,
                ValueError(
                    "Planner returned neither an executable nor advisory plan."
                ),
            )
        return {
            "remediation_plan": None,
            "advisory_plan": advisory,
            "planning_attempts": state.planning_attempts + 1,
            "stage": WorkflowStage.UPDATE_KNOWLEDGE,
            "current_stage": WorkflowStage.UPDATE_KNOWLEDGE,
            "status": WorkflowStatus.ESCALATED,
            **_planning_usage_update(state, selection.usage),
            "audit_events": [
                audit_event(
                    "advisory_plan_created",
                    diagnosis_type=advisory.diagnosis_type,
                    evidence_ids=advisory.evidence_ids,
                    executable=False,
                    selected_by=selection.selected_by,
                    rationale=(selection.rationale or "")[:600],
                )
            ],
        }
    update: dict[str, Any] = {
        "remediation_plan": plan,
        "advisory_plan": None,
        "planning_attempts": state.planning_attempts + 1,
        "stage": WorkflowStage.POLICY_GATE,
        "current_stage": WorkflowStage.POLICY_GATE,
        **_planning_usage_update(state, selection.usage),
        "audit_events": [
            audit_event(
                "plan_selected",
                playbook_id=plan.playbook_id,
                playbook_version=plan.playbook_version,
                selected_by=selection.selected_by,
                incident_type=selection.canonical_incident_type,
            )
        ],
    }
    if (
        selection.selected_by == "model"
        and state.diagnosis is not None
        and selection.canonical_incident_type != state.diagnosis.incident_type
    ):
        # Rewrite the diagnosis onto the playbook's published incident type
        # so the policy engine keeps re-validating deterministically, and
        # record the original label the model mapped from.
        original = state.diagnosis.incident_type
        entities = {
            **state.diagnosis.affected_entities,
            "original_incident_type": original,
        }
        update["diagnosis"] = state.diagnosis.model_copy(
            update={
                "incident_type": selection.canonical_incident_type,
                "affected_entities": entities,
            }
        )
        update["audit_events"].append(
            audit_event(
                "plan_incident_type_canonicalized",
                original_incident_type=original,
                canonical_incident_type=selection.canonical_incident_type,
                rationale=(selection.rationale or "")[:600],
            )
        )
    return update


def policy_node(
    policy: PolicyEngine,
    state: IncidentWorkflowState,
) -> dict[str, Any]:
    decision = policy.evaluate(state)
    if not decision.allowed:
        return {
            "policy_decision": decision,
            "stage": WorkflowStage.POLICY_GATE,
            "current_stage": WorkflowStage.POLICY_GATE,
            "status": WorkflowStatus.ESCALATED,
            "audit_events": [
                audit_event(
                    "policy_denied",
                    reason_codes=decision.reason_codes,
                )
            ],
        }
    if decision.approval_required:
        plan = state.remediation_plan
        if plan is None or not plan.plan_id or not plan.plan_hash:
            return _failure(
                WorkflowStage.POLICY_GATE,
                ValueError("The remediation plan is not approval-bindable."),
            )
        if not decision.required_role:
            return _failure(
                WorkflowStage.POLICY_GATE,
                ValueError("A mutating plan requires an approval role."),
            )
        now = datetime.now(UTC)
        approval_id = stable_id(
            "APR",
            state.incident_id,
            plan.plan_id,
            plan.plan_hash,
            state.evidence_version,
            length=32,
        )
        request = ApprovalRequestRecord(
            approval_id=approval_id,
            investigation_id=state.investigation_id,
            incident_id=state.incident_id,
            plan_id=plan.plan_id,
            plan_version=plan.plan_version,
            plan_hash=plan.plan_hash,
            evidence_version=state.evidence_version or "",
            policy_version=plan.policy_version,
            action_catalogue_version=plan.action_catalogue_version,
            action_ids=[action.action_id for action in plan.actions],
            required_role=decision.required_role,
            requested_at=now,
            expires_at=min(
                plan.expires_at,
                now + timedelta(seconds=settings.MAPEK_APPROVAL_TTL_SECONDS),
            ),
        )
        return {
            "policy_decision": decision,
            "approval_request": request,
            "stage": WorkflowStage.POLICY_GATE,
            "current_stage": WorkflowStage.POLICY_GATE,
            "status": WorkflowStatus.WAITING_APPROVAL,
            "audit_events": [
                audit_event(
                    "approval_requested",
                    approval_id=approval_id,
                    required_role=decision.required_role,
                )
            ],
        }
    return {
        "policy_decision": decision,
        "stage": WorkflowStage.POLICY_GATE,
        "current_stage": WorkflowStage.POLICY_GATE,
        "status": WorkflowStatus.APPROVED,
    }


def approval_node(state: IncidentWorkflowState) -> dict[str, Any]:
    request = state.approval_request
    if request is None:
        return _failure(
            WorkflowStage.POLICY_GATE,
            ValueError("The durable approval request is unavailable."),
        )
    payload = interrupt(
        {
            "kind": "human_approval",
            "approval_id": request.approval_id,
            "required_role": request.required_role,
            "plan_id": request.plan_id,
            "plan_version": request.plan_version,
            "plan_hash": request.plan_hash,
            "evidence_version": request.evidence_version,
            "action_ids": request.action_ids,
            "expires_at": request.expires_at.isoformat(),
        }
    )
    # A malformed or mismatched resume must land as an audited escalation,
    # exactly like execution_authorization_node handles the same case. Raising
    # here escaped graph.invoke() and surfaced as an unexplained 500 with no
    # audit trail and the workflow stuck mid-interrupt.
    try:
        submission = TrustedApprovalSubmission.model_validate(payload)
    except ValidationError:
        return _approval_escalation(
            code="APPROVAL_PAYLOAD_INVALID",
            message="The approval submission is not a valid payload.",
            reason="invalid_payload",
        )
    if submission.approval_id != request.approval_id:
        return _approval_escalation(
            code="APPROVAL_ID_MISMATCH",
            message="Approval ID does not match this incident.",
            reason="approval_id_mismatch",
            approval_id=submission.approval_id,
        )
    try:
        _validate_approval_binding(state, request)
    except ValueError as exc:
        return {
            "stage": WorkflowStage.POLICY_GATE,
            "current_stage": WorkflowStage.POLICY_GATE,
            "status": WorkflowStatus.ESCALATED,
            "error": WorkflowError(
                stage=WorkflowStage.POLICY_GATE,
                code="APPROVAL_STALE",
                message=str(exc),
            ),
            "audit_events": [
                audit_event(
                    "approval_invalidated",
                    approval_id=submission.approval_id,
                    reason="stale_or_expired",
                )
            ],
        }
    decision = ApprovalDecision(
        approval_id=submission.approval_id,
        decision=submission.decision,
        actor_user_id=submission.actor_user_id,
        actor_roles=submission.actor_roles,
        plan_id=request.plan_id,
        plan_version=request.plan_version,
        plan_hash=request.plan_hash,
        evidence_version=request.evidence_version,
        policy_version=request.policy_version,
        action_catalogue_version=request.action_catalogue_version,
        comment=submission.comment,
    )
    if decision.decision == "approve" and not role_allows(
        decision.actor_roles,
        request.required_role,
    ):
        return {
            "approval_decision": decision,
            "stage": WorkflowStage.POLICY_GATE,
            "current_stage": WorkflowStage.POLICY_GATE,
            "status": WorkflowStatus.ESCALATED,
            "audit_events": [
                audit_event(
                    "approval_denied_by_policy",
                    approval_id=decision.approval_id,
                    reason="insufficient_role",
                )
            ],
        }
    if decision.decision == "reject":
        return {
            "approval_decision": decision,
            "stage": WorkflowStage.POLICY_GATE,
            "current_stage": WorkflowStage.POLICY_GATE,
            "status": WorkflowStatus.REJECTED,
            "audit_events": [
                audit_event(
                    "approval_rejected",
                    approval_id=decision.approval_id,
                )
            ],
        }
    return {
        "approval_decision": decision,
        "stage": WorkflowStage.POLICY_GATE,
        "current_stage": WorkflowStage.POLICY_GATE,
        "status": WorkflowStatus.APPROVED,
        "audit_events": [
            audit_event(
                "approval_granted",
                approval_id=decision.approval_id,
            )
        ],
    }


def execution_authorization_node(
    policy: PolicyEngine,
    state: IncidentWorkflowState,
) -> dict[str, Any]:
    request = state.approval_request
    decision = state.approval_decision
    if request is None or decision is None or decision.decision != "approve":
        return _failure(
            WorkflowStage.POLICY_GATE,
            ValueError("A valid durable approval is required for execution."),
        )
    payload = interrupt(
        {
            "kind": "execution_authorization",
            "approval_id": decision.approval_id,
            "plan_id": decision.plan_id,
            "plan_hash": decision.plan_hash,
            "action_ids": request.action_ids,
        }
    )
    try:
        authorization = ExecutionAuthorization.model_validate(payload)
    except ValidationError:
        return {
            "stage": WorkflowStage.POLICY_GATE,
            "current_stage": WorkflowStage.POLICY_GATE,
            "status": WorkflowStatus.ESCALATED,
            "error": WorkflowError(
                stage=WorkflowStage.POLICY_GATE,
                code="EXECUTION_AUTHORIZATION_INVALID",
                message="The execution authorization is not a valid payload.",
            ),
            "audit_events": [
                audit_event(
                    "execution_authorization_denied",
                    reason="invalid_payload",
                )
            ],
        }
    if authorization.approval_id != decision.approval_id:
        return {
            "stage": WorkflowStage.POLICY_GATE,
            "current_stage": WorkflowStage.POLICY_GATE,
            "status": WorkflowStatus.ESCALATED,
            "error": WorkflowError(
                stage=WorkflowStage.POLICY_GATE,
                code="EXECUTION_AUTHORIZATION_DENIED",
                message="Execution authorization has the wrong approval ID.",
            ),
            "audit_events": [
                audit_event(
                    "execution_authorization_denied",
                    reason="approval_id_mismatch",
                )
            ],
        }
    try:
        _validate_approval_binding(state, request)
    except ValueError as exc:
        return {
            "stage": WorkflowStage.POLICY_GATE,
            "current_stage": WorkflowStage.POLICY_GATE,
            "status": WorkflowStatus.ESCALATED,
            "error": WorkflowError(
                stage=WorkflowStage.POLICY_GATE,
                code="APPROVAL_STALE",
                message=str(exc),
            ),
            "audit_events": [
                audit_event(
                    "approval_invalidated",
                    approval_id=decision.approval_id,
                    reason="stale_or_expired",
                )
            ],
        }
    expected_action_ids = [
        action.action_id
        for action in (
            state.remediation_plan.actions if state.remediation_plan else []
        )
    ]
    if authorization.action_ids != expected_action_ids:
        return {
            "stage": WorkflowStage.POLICY_GATE,
            "current_stage": WorkflowStage.POLICY_GATE,
            "status": WorkflowStatus.ESCALATED,
            "error": WorkflowError(
                stage=WorkflowStage.POLICY_GATE,
                code="EXECUTION_ACTION_SET_MISMATCH",
                message=(
                    "Execution action IDs do not exactly match the "
                    "approved plan."
                ),
            ),
            "audit_events": [
                audit_event(
                    "execution_authorization_denied",
                    reason="action_set_mismatch",
                )
            ],
        }
    if not role_allows(authorization.actor_roles, request.required_role):
        return {
            "stage": WorkflowStage.POLICY_GATE,
            "current_stage": WorkflowStage.POLICY_GATE,
            "status": WorkflowStatus.ESCALATED,
            "error": WorkflowError(
                stage=WorkflowStage.POLICY_GATE,
                code="EXECUTOR_ROLE_DENIED",
                message="The current executor role cannot execute this plan.",
            ),
            "audit_events": [
                audit_event(
                    "execution_authorization_denied",
                    reason="insufficient_current_role",
                )
            ],
        }
    fresh_policy = policy.evaluate(state)
    if not fresh_policy.allowed:
        return {
            "stage": WorkflowStage.POLICY_GATE,
            "current_stage": WorkflowStage.POLICY_GATE,
            "status": WorkflowStatus.ESCALATED,
            "error": WorkflowError(
                stage=WorkflowStage.POLICY_GATE,
                code="POLICY_RECHECK_DENIED",
                message="Policy no longer allows the approved plan.",
            ),
            "audit_events": [
                audit_event(
                    "execution_authorization_denied",
                    reason_codes=fresh_policy.reason_codes,
                )
            ],
        }
    return {
        "execution_authorization": authorization,
        "stage": WorkflowStage.EXECUTE,
        "current_stage": WorkflowStage.EXECUTE,
        "audit_events": [
            audit_event(
                "execution_authorized",
                execution_id=authorization.execution_id,
                actor_user_id=authorization.actor_user_id,
                approval_id=authorization.approval_id,
                plan_hash_prefix=decision.plan_hash[:12],
            )
        ],
    }


def execute_node(
    executor: RestrictedExecutor,
    state: IncidentWorkflowState,
) -> dict[str, Any]:
    try:
        results = executor.run(state)
    except Exception as exc:
        return _failure(WorkflowStage.EXECUTE, exc)
    verification_not_before = verification_observation_ready_at(
        list(results),
        observation_seconds=int(
            settings.MAPEK_VERIFICATION_OBSERVATION_SECONDS
        ),
    )
    real_execution_accepted = verification_not_before is not None
    return {
        "execution_results": results,
        "verification_not_before": verification_not_before,
        "stage": WorkflowStage.VERIFY,
        "current_stage": WorkflowStage.VERIFY,
        "status": (
            WorkflowStatus.WAITING_VERIFICATION
            if real_execution_accepted
            else WorkflowStatus.RUNNING
        ),
        "audit_events": [
            audit_event(
                "execution_completed",
                statuses=[item.status for item in results],
                dry_run=settings.MAPEK_DRY_RUN,
            )
        ],
    }


def verification_wait_node(state: IncidentWorkflowState) -> dict[str, Any]:
    ready_at = state.verification_not_before
    if ready_at is None:
        return {
            "stage": WorkflowStage.ROLLBACK,
            "current_stage": WorkflowStage.ROLLBACK,
            "status": WorkflowStatus.ESCALATED,
            "error": WorkflowError(
                stage=WorkflowStage.VERIFY,
                code="VERIFICATION_WINDOW_UNAVAILABLE",
                message=(
                    "No successful execution timestamp is available for "
                    "post-action verification."
                ),
            ),
            "audit_events": [
                audit_event(
                    "verification_wait_failed",
                    reason="successful_execution_timestamp_unavailable",
                )
            ],
        }
    payload = interrupt(
        {
            "kind": "verification_wait",
            "investigation_id": state.investigation_id,
            "incident_id": state.incident_id,
            "observation_ready_at": ready_at.isoformat(),
        }
    )
    try:
        authorization = VerificationResumeAuthorization.model_validate(
            payload
        )
    except Exception:
        return {
            "stage": WorkflowStage.VERIFY,
            "current_stage": WorkflowStage.VERIFY,
            "status": WorkflowStatus.WAITING_VERIFICATION,
            "audit_events": [
                audit_event(
                    "verification_resume_rejected",
                    reason="untrusted_resume_payload",
                )
            ],
        }
    if authorization.investigation_id != state.investigation_id:
        return {
            "stage": WorkflowStage.VERIFY,
            "current_stage": WorkflowStage.VERIFY,
            "status": WorkflowStatus.WAITING_VERIFICATION,
            "audit_events": [
                audit_event(
                    "verification_resume_rejected",
                    reason="investigation_mismatch",
                )
            ],
        }
    now = datetime.now(UTC)
    if now < ready_at:
        return {
            "stage": WorkflowStage.VERIFY,
            "current_stage": WorkflowStage.VERIFY,
            "status": WorkflowStatus.WAITING_VERIFICATION,
            "audit_events": [
                audit_event(
                    "verification_resume_rejected",
                    reason="observation_window_incomplete",
                    observation_ready_at=ready_at,
                )
            ],
        }
    return {
        "stage": WorkflowStage.VERIFY,
        "current_stage": WorkflowStage.VERIFY,
        "status": WorkflowStatus.RUNNING,
        "audit_events": [
            audit_event(
                "verification_resumed",
                actor_user_id=authorization.actor_user_id,
                observation_ready_at=ready_at,
            )
        ],
    }


def verify_node(
    verifier: ResponseVerifier,
    state: IncidentWorkflowState,
) -> dict[str, Any]:
    try:
        result = verifier.run(state)
    except Exception as exc:
        failure = _failure(WorkflowStage.VERIFY, exc)
        failure["status"] = WorkflowStatus.ESCALATED
        failure["stage"] = WorkflowStage.ROLLBACK
        failure["current_stage"] = WorkflowStage.ROLLBACK
        return failure
    passed = result.passed
    requires_rollback = result.outcome in {
        VerificationOutcome.FAILED,
        VerificationOutcome.PARTIAL,
    }
    return {
        "verification": result,
        "stage": (
            WorkflowStage.UPDATE_KNOWLEDGE
            if passed
            else (
                WorkflowStage.ROLLBACK
                if requires_rollback
                else WorkflowStage.VERIFY
            )
        ),
        "current_stage": (
            WorkflowStage.UPDATE_KNOWLEDGE
            if passed
            else (
                WorkflowStage.ROLLBACK
                if requires_rollback
                else WorkflowStage.VERIFY
            )
        ),
        "status": (
            WorkflowStatus.RUNNING if passed else WorkflowStatus.ESCALATED
        ),
        "audit_events": [
            audit_event(
                "verification_completed",
                passed=passed,
                outcome=result.outcome,
                dry_run=result.dry_run,
            )
        ],
    }


def rollback_node(
    executor: RestrictedExecutor,
    state: IncidentWorkflowState,
) -> dict[str, Any]:
    try:
        results = executor.rollback(state)
    except Exception as exc:
        failure = _failure(WorkflowStage.ROLLBACK, exc)
        failure["status"] = WorkflowStatus.ESCALATED
        failure["rollback"] = RollbackResult(
            attempted=True,
            successful=False,
            results=[],
        )
        return failure
    successful = all(
        item["status"] in {"executed", "dry_run", "not_required"}
        for item in results
    )
    return {
        "rollback": RollbackResult(
            attempted=True,
            successful=successful,
            results=results,
        ),
        "stage": WorkflowStage.ROLLBACK,
        "current_stage": WorkflowStage.ROLLBACK,
        "status": WorkflowStatus.ESCALATED,
        "audit_events": [
            audit_event("rollback_completed", successful=successful)
        ],
    }


def knowledge_node(state: IncidentWorkflowState) -> dict[str, Any]:
    terminal_status = state.status
    terminal_stage = state.stage
    if (
        state.stage == WorkflowStage.UPDATE_KNOWLEDGE
        and state.status == WorkflowStatus.RUNNING
    ):
        terminal_status = WorkflowStatus.COMPLETED
    update = {
        "status": terminal_status,
        "stage": terminal_stage,
        "current_stage": terminal_stage,
    }
    report_state = state.model_copy(update=update)
    update["final_report"] = build_final_report(report_state)
    update["audit_events"] = [
        audit_event(
            "knowledge_updated",
            final_status=terminal_status,
        )
    ]
    return update
