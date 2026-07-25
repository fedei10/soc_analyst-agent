"""Single controlled MAPE-K LangGraph state machine."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Any, Callable

import structlog
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

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
from app.mape_k.serde import create_checkpoint_serializer
from app.mape_k.utils import audit_event, stable_id
from app.mape_k.verify import (
    ResponseVerifier,
    verification_observation_ready_at,
)


logger = structlog.get_logger("tsage.mapek")


def _safe_transition_metadata(
    state: IncidentWorkflowState,
    update: dict[str, Any] | None = None,
) -> dict[str, Any]:
    update = update or {}
    plan = update.get("remediation_plan") or state.remediation_plan
    error = update.get("error")
    if hasattr(error, "code"):
        error_code = error.code
    elif isinstance(error, dict):
        error_code = error.get("code")
    else:
        error_code = None
    return {
        "incident_id": state.incident_id,
        "investigation_id": state.investigation_id,
        "organization_id": state.organization_id,
        "stage": str(update.get("stage") or state.stage),
        "status": str(update.get("status") or state.status),
        "evidence_count": len(state.evidence),
        "finding_count": len(state.findings),
        "action_count": len(plan.actions) if plan is not None else 0,
        "plan_id": getattr(plan, "plan_id", None),
        "plan_hash_prefix": (
            str(getattr(plan, "plan_hash", ""))[:12] or None
            if plan is not None
            else None
        ),
        "evidence_version_prefix": (
            str(state.evidence_version)[:12]
            if state.evidence_version
            else None
        ),
        "error_code": error_code,
        "provider": update.get("model_provider") or state.model_provider,
        "model": update.get("model_name") or state.model_name,
    }


def _observed_node(
    node_name: str,
    function: Callable[[IncidentWorkflowState], dict[str, Any]],
) -> Callable[[IncidentWorkflowState], dict[str, Any]]:
    start_events = {
        "monitor": ("workflow_started", "evidence_collection_started"),
        "analyze": ("diagnosis_started",),
        "plan": ("planning_started",),
        "policy_gate": ("policy_evaluation_started",),
        "human_approval": ("approval_review_started",),
        "execution_authorization": ("execution_claim_started",),
        "execute": ("execution_started",),
        "verification_wait": ("verification_wait_started",),
        "verify": ("verification_started",),
        "rollback": ("rollback_started",),
        "knowledge": ("knowledge_update_started",),
    }
    completed_events = {
        "monitor": "evidence_collection_completed",
        "analyze": "diagnosis_completed",
        "plan": "plan_created",
        "policy_gate": "policy_evaluated",
        "human_approval": "approval_review_completed",
        "execution_authorization": "execution_claim_completed",
        "execute": "execution_completed",
        "verification_wait": "verification_wait_completed",
        "verify": "verification_completed",
        "rollback": "rollback_completed",
        "knowledge": "workflow_completed",
    }

    def wrapper(state: IncidentWorkflowState) -> dict[str, Any]:
        metadata = _safe_transition_metadata(state)
        for event_name in start_events.get(node_name, ()):
            logger.info(event_name, **metadata)
        started = time.perf_counter()
        update = function(state)
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        completed_event = completed_events.get(
            node_name,
            "workflow_transition",
        )
        result_metadata = _safe_transition_metadata(state, update)
        result_status = result_metadata["status"]
        if node_name == "analyze" and result_status == WorkflowStatus.ESCALATED:
            completed_event = "diagnosis_escalated"
        elif node_name == "execute" and result_status == WorkflowStatus.FAILED:
            completed_event = "execution_failed"
        elif node_name == "human_approval":
            if result_status == WorkflowStatus.APPROVED:
                completed_event = "approval_granted"
            elif result_status == WorkflowStatus.REJECTED:
                completed_event = "approval_rejected"
        elif node_name == "knowledge":
            completed_event = (
                "workflow_completed"
                if result_status == WorkflowStatus.COMPLETED
                else "workflow_escalated"
            )
        logger.info(
            completed_event,
            **result_metadata,
            duration_ms=duration_ms,
        )
        if (
            node_name == "policy_gate"
            and result_status == WorkflowStatus.WAITING_APPROVAL
        ):
            logger.info(
                "approval_requested",
                **result_metadata,
                duration_ms=duration_ms,
            )
        logger.info(
            "workflow_transition",
            **result_metadata,
            source_stage=str(state.stage),
            node=node_name,
            duration_ms=duration_ms,
        )
        if completed_event != "workflow_escalated" and result_status in {
            WorkflowStatus.ESCALATED,
            WorkflowStatus.FAILED,
        }:
            logger.warning(
                "workflow_escalated",
                **result_metadata,
                node=node_name,
            )
        return update

    return wrapper


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


def create_mape_k_graph(
    *,
    monitor: WazuhMonitor | None = None,
    analyzer: IncidentAnalyzer | None = None,
    planner: PlaybookPlanner | None = None,
    policy: PolicyEngine | None = None,
    executor: RestrictedExecutor | None = None,
    verifier: ResponseVerifier | None = None,
    checkpointer=None,
):
    monitor = monitor or WazuhMonitor()
    analyzer = analyzer or IncidentAnalyzer()
    planner = planner or PlaybookPlanner()
    policy = policy or PolicyEngine()
    executor = executor or RestrictedExecutor()
    verifier = verifier or ResponseVerifier()

    def monitor_node(state: IncidentWorkflowState) -> dict[str, Any]:
        try:
            return monitor.run(state)
        except Exception as exc:
            return _failure(WorkflowStage.MONITOR, exc)

    def analyze_node(state: IncidentWorkflowState) -> dict[str, Any]:
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
        escalated = (
            diagnosis.confidence < settings.MAPEK_ANALYSIS_CONFIDENCE_THRESHOLD
            or diagnosis.needs_more_evidence
        )
        actual_input = usage.get("actual_input_tokens")
        actual_output = usage.get("actual_output_tokens")
        cached_input = usage.get("cached_input_tokens")
        return {
            "diagnosis": diagnosis,
            "analysis_attempts": state.analysis_attempts + 1,
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
            "stage": (
                WorkflowStage.ANALYZE if escalated else WorkflowStage.PLAN
            ),
            "current_stage": (
                WorkflowStage.ANALYZE if escalated else WorkflowStage.PLAN
            ),
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
                )
            ],
        }

    def plan_node(state: IncidentWorkflowState) -> dict[str, Any]:
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
            plan = planner.run(state)
        except Exception as exc:
            return {
                "stage": WorkflowStage.PLAN,
                "current_stage": WorkflowStage.PLAN,
                "status": WorkflowStatus.ESCALATED,
                "error": WorkflowError(
                    stage=WorkflowStage.PLAN,
                    code="NO_APPROVED_PLAYBOOK",
                    message=str(exc)[:1000],
                ),
                "audit_events": [
                    audit_event("planning_escalated", reason="no_approved_playbook")
                ],
            }
        return {
            "remediation_plan": plan,
            "planning_attempts": state.planning_attempts + 1,
            "stage": WorkflowStage.POLICY_GATE,
            "current_stage": WorkflowStage.POLICY_GATE,
            "audit_events": [
                audit_event(
                    "plan_selected",
                    playbook_id=plan.playbook_id,
                    playbook_version=plan.playbook_version,
                )
            ],
        }

    def policy_node(state: IncidentWorkflowState) -> dict[str, Any]:
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
        submission = TrustedApprovalSubmission.model_validate(payload)
        if submission.approval_id != request.approval_id:
            raise ValueError("Approval ID does not match this incident.")
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
        authorization = ExecutionAuthorization.model_validate(payload)
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

    def execute_node(state: IncidentWorkflowState) -> dict[str, Any]:
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

    def verification_wait_node(
        state: IncidentWorkflowState,
    ) -> dict[str, Any]:
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

    def verify_node(state: IncidentWorkflowState) -> dict[str, Any]:
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

    def rollback_node(state: IncidentWorkflowState) -> dict[str, Any]:
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

    builder = StateGraph(IncidentWorkflowState)
    builder.add_node("monitor", _observed_node("monitor", monitor_node))
    builder.add_node("analyze", _observed_node("analyze", analyze_node))
    builder.add_node("plan", _observed_node("plan", plan_node))
    builder.add_node(
        "policy_gate",
        _observed_node("policy_gate", policy_node),
    )
    builder.add_node(
        "human_approval",
        _observed_node("human_approval", approval_node),
    )
    builder.add_node(
        "execution_authorization",
        _observed_node(
            "execution_authorization",
            execution_authorization_node,
        ),
    )
    builder.add_node("execute", _observed_node("execute", execute_node))
    builder.add_node(
        "verification_wait",
        _observed_node("verification_wait", verification_wait_node),
    )
    builder.add_node("verify", _observed_node("verify", verify_node))
    builder.add_node("rollback", _observed_node("rollback", rollback_node))
    builder.add_node("knowledge", _observed_node("knowledge", knowledge_node))

    builder.add_edge(START, "monitor")
    builder.add_conditional_edges(
        "monitor",
        lambda state: "knowledge" if state.status == WorkflowStatus.FAILED else "analyze",
        {"analyze": "analyze", "knowledge": "knowledge"},
    )
    builder.add_conditional_edges(
        "analyze",
        lambda state: "plan" if state.stage == WorkflowStage.PLAN else "knowledge",
        {"plan": "plan", "knowledge": "knowledge"},
    )
    builder.add_conditional_edges(
        "plan",
        lambda state: (
            "policy_gate"
            if state.stage == WorkflowStage.POLICY_GATE
            else "knowledge"
        ),
        {"policy_gate": "policy_gate", "knowledge": "knowledge"},
    )
    builder.add_conditional_edges(
        "policy_gate",
        lambda state: (
            "human_approval"
            if state.status == WorkflowStatus.WAITING_APPROVAL
            else (
                "execution_authorization"
                if state.status == WorkflowStatus.APPROVED
                else "knowledge"
            )
        ),
        {
            "human_approval": "human_approval",
            "execution_authorization": "execution_authorization",
            "knowledge": "knowledge",
        },
    )
    builder.add_conditional_edges(
        "human_approval",
        lambda state: (
            "execution_authorization"
            if state.status == WorkflowStatus.APPROVED
            else "knowledge"
        ),
        {
            "execution_authorization": "execution_authorization",
            "knowledge": "knowledge",
        },
    )
    builder.add_conditional_edges(
        "execution_authorization",
        lambda state: (
            "execute"
            if state.stage == WorkflowStage.EXECUTE
            and state.execution_authorization is not None
            else "knowledge"
        ),
        {"execute": "execute", "knowledge": "knowledge"},
    )
    builder.add_conditional_edges(
        "execute",
        lambda state: (
            "rollback"
            if state.status == WorkflowStatus.FAILED
            else "verification_wait"
            if state.status == WorkflowStatus.WAITING_VERIFICATION
            else "verify"
            if state.stage == WorkflowStage.VERIFY
            else "knowledge"
        ),
        {
            "verification_wait": "verification_wait",
            "verify": "verify",
            "rollback": "rollback",
            "knowledge": "knowledge",
        },
    )
    builder.add_conditional_edges(
        "verification_wait",
        lambda state: (
            "verification_wait"
            if state.status == WorkflowStatus.WAITING_VERIFICATION
            else "verify"
            if state.stage == WorkflowStage.VERIFY
            and state.status == WorkflowStatus.RUNNING
            else "rollback"
            if state.stage == WorkflowStage.ROLLBACK
            else "knowledge"
        ),
        {
            "verification_wait": "verification_wait",
            "verify": "verify",
            "rollback": "rollback",
            "knowledge": "knowledge",
        },
    )
    builder.add_conditional_edges(
        "verify",
        lambda state: (
            "rollback"
            if state.stage == WorkflowStage.ROLLBACK
            or state.status == WorkflowStatus.FAILED
            else "knowledge"
        ),
        {"rollback": "rollback", "knowledge": "knowledge"},
    )
    builder.add_edge("rollback", "knowledge")
    builder.add_edge("knowledge", END)
    return builder.compile(
        checkpointer=(
            checkpointer
            if checkpointer is not None
            else InMemorySaver(serde=create_checkpoint_serializer())
        )
    )


def investigation_config(investigation_id: str) -> dict[str, Any]:
    if not investigation_id:
        raise ValueError("investigation_id is required.")
    return {
        "configurable": {"thread_id": investigation_id},
        "run_name": "mapek-security-investigation",
        "metadata": {"investigation_id": investigation_id, "workflow": "mape-k"},
    }
