"""Single controlled MAPE-K LangGraph state machine."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Callable

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
    IncidentWorkflowState,
    RollbackResult,
    WorkflowError,
    WorkflowStage,
    WorkflowStatus,
)
from app.mape_k.serde import create_checkpoint_serializer
from app.mape_k.utils import audit_event, stable_id
from app.mape_k.verify import ResponseVerifier


def _failure(stage: WorkflowStage, exc: Exception) -> dict[str, Any]:
    error = WorkflowError(
        stage=stage,
        code=f"{stage.value.upper()}_FAILED",
        message=str(exc)[:1000],
        retryable=False,
    )
    return {
        "stage": WorkflowStage.FAILED,
        "current_stage": WorkflowStage.FAILED,
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
                "stage": WorkflowStage.ESCALATED,
                "current_stage": WorkflowStage.ESCALATED,
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
        return {
            "diagnosis": diagnosis,
            "analysis_attempts": state.analysis_attempts + 1,
            "llm_input_tokens": state.llm_input_tokens + usage["input_tokens"],
            "llm_output_tokens": state.llm_output_tokens + usage["output_tokens"],
            "stage": (
                WorkflowStage.ESCALATED if escalated else WorkflowStage.PLAN
            ),
            "current_stage": (
                WorkflowStage.ESCALATED if escalated else WorkflowStage.PLAN
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
                )
            ],
        }

    def plan_node(state: IncidentWorkflowState) -> dict[str, Any]:
        if state.planning_attempts > settings.MAPEK_MAX_PLANNING_RETRIES:
            return {
                "stage": WorkflowStage.ESCALATED,
                "current_stage": WorkflowStage.ESCALATED,
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
                "stage": WorkflowStage.ESCALATED,
                "current_stage": WorkflowStage.ESCALATED,
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
            "proposed_actions": [
                action.model_dump(mode="json") for action in plan.actions
            ],
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
                "stage": WorkflowStage.ESCALATED,
                "current_stage": WorkflowStage.ESCALATED,
                "status": WorkflowStatus.ESCALATED,
                "audit_events": [
                    audit_event(
                        "policy_denied",
                        reason_codes=decision.reason_codes,
                    )
                ],
            }
        if decision.approval_required:
            approval_id = stable_id(
                "APR", state.incident_id, state.evidence_version, length=32
            )
            request = {
                "approval_id": approval_id,
                "investigation_id": state.investigation_id,
                "incident_id": state.incident_id,
                "required_role": decision.required_role,
                "proposed_actions": state.proposed_actions,
                "expires_at": (
                    datetime.now(UTC) + timedelta(minutes=30)
                ).isoformat(),
            }
            return {
                "policy_decision": decision,
                "approval_request": request,
                "stage": WorkflowStage.WAITING_APPROVAL,
                "current_stage": WorkflowStage.WAITING_APPROVAL,
                "status": WorkflowStatus.AWAITING_APPROVAL,
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
            "stage": WorkflowStage.APPROVED,
            "current_stage": WorkflowStage.APPROVED,
            "status": WorkflowStatus.APPROVED,
        }

    def approval_node(state: IncidentWorkflowState) -> dict[str, Any]:
        request = state.approval_request or {}
        payload = interrupt(
            {
                "kind": "human_approval",
                "approval_id": request.get("approval_id"),
                "required_role": request.get("required_role"),
                "proposed_actions": request.get("proposed_actions", []),
            }
        )
        decision = ApprovalDecision.model_validate(payload)
        if decision.approval_id != request.get("approval_id"):
            raise ValueError("Approval ID does not match this incident.")
        expires_at = datetime.fromisoformat(str(request.get("expires_at")))
        if expires_at.tzinfo is None or expires_at <= datetime.now(UTC):
            return {
                "approval_decision": decision,
                "stage": WorkflowStage.ESCALATED,
                "current_stage": WorkflowStage.ESCALATED,
                "status": WorkflowStatus.ESCALATED,
                "audit_events": [
                    audit_event(
                        "approval_expired",
                        approval_id=decision.approval_id,
                    )
                ],
            }
        if decision.decision == "approve" and not role_allows(
            decision.approver_roles,
            str(request.get("required_role") or "") or None,
        ):
            return {
                "approval_decision": decision,
                "stage": WorkflowStage.ESCALATED,
                "current_stage": WorkflowStage.ESCALATED,
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
                "stage": WorkflowStage.REJECTED,
                "current_stage": WorkflowStage.REJECTED,
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
            "stage": WorkflowStage.APPROVED,
            "current_stage": WorkflowStage.APPROVED,
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
        payload = interrupt(
            {
                "kind": "execution_authorization",
                "approval_id": (
                    state.approval_decision.approval_id
                    if state.approval_decision
                    else None
                ),
            }
        )
        if payload.get("approval_id") != (
            state.approval_decision.approval_id
            if state.approval_decision
            else None
        ):
            raise ValueError("Execution authorization has the wrong approval ID.")
        action_ids = payload.get("action_ids")
        expected_actions = (
            len(state.remediation_plan.actions)
            if state.remediation_plan
            else 0
        )
        if (
            not payload.get("execution_id")
            or not payload.get("executed_by")
            or not isinstance(action_ids, list)
            or len(action_ids) != expected_actions
        ):
            raise ValueError("Execution authorization claim is incomplete.")
        return {
            "execution_authorization": payload,
            "stage": WorkflowStage.EXECUTE,
            "current_stage": WorkflowStage.EXECUTE,
            "audit_events": [
                audit_event(
                    "execution_authorized",
                    execution_id=payload.get("execution_id"),
                    executed_by=payload.get("executed_by"),
                )
            ],
        }

    def execute_node(state: IncidentWorkflowState) -> dict[str, Any]:
        try:
            results = executor.run(state)
        except Exception as exc:
            return _failure(WorkflowStage.EXECUTE, exc)
        authorization = getattr(state, "execution_authorization", {}) or {}
        executed_actions = [
            {
                **result.model_dump(mode="json"),
                "status": result.status,
                "execution_id": authorization.get(
                    "execution_id", result.execution_id
                ),
                "executed_by": authorization.get("executed_by"),
                "approval_id": (
                    state.approval_decision.approval_id
                    if state.approval_decision
                    else None
                ),
            }
            for result in results
        ]
        return {
            "execution_results": results,
            "executed_actions": executed_actions,
            "stage": WorkflowStage.VERIFY,
            "current_stage": WorkflowStage.VERIFY,
            "status": WorkflowStatus.RUNNING,
            "audit_events": [
                audit_event(
                    "execution_completed",
                    statuses=[item.status for item in results],
                    dry_run=settings.MAPEK_DRY_RUN,
                )
            ],
        }

    def verify_node(state: IncidentWorkflowState) -> dict[str, Any]:
        try:
            result = verifier.run(state)
        except Exception as exc:
            return _failure(WorkflowStage.VERIFY, exc)
        passed = result.passed
        return {
            "verification": result,
            "stage": (
                WorkflowStage.UPDATE_KNOWLEDGE
                if passed
                else WorkflowStage.ROLLBACK
            ),
            "current_stage": (
                WorkflowStage.UPDATE_KNOWLEDGE
                if passed
                else WorkflowStage.ROLLBACK
            ),
            "status": (
                WorkflowStatus.RUNNING if passed else WorkflowStatus.ESCALATED
            ),
            "audit_events": [
                audit_event(
                    "verification_completed",
                    passed=passed,
                    dry_run=result.dry_run,
                )
            ],
        }

    def rollback_node(state: IncidentWorkflowState) -> dict[str, Any]:
        results = executor.rollback(state)
        successful = all(item["status"] in {"executed", "dry_run"} for item in results)
        return {
            "rollback": RollbackResult(
                attempted=True,
                successful=successful,
                results=results,
            ),
            "stage": WorkflowStage.ESCALATED,
            "current_stage": WorkflowStage.ESCALATED,
            "status": WorkflowStatus.ESCALATED,
            "audit_events": [
                audit_event("rollback_completed", successful=successful)
            ],
        }

    def knowledge_node(state: IncidentWorkflowState) -> dict[str, Any]:
        terminal_status = state.status
        terminal_stage = state.stage
        if state.stage == WorkflowStage.UPDATE_KNOWLEDGE:
            terminal_status = WorkflowStatus.COMPLETED
            terminal_stage = WorkflowStage.COMPLETED
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
    builder.add_node("monitor", monitor_node)
    builder.add_node("analyze", analyze_node)
    builder.add_node("plan", plan_node)
    builder.add_node("policy_gate", policy_node)
    builder.add_node("human_approval", approval_node)
    builder.add_node("execution_authorization", execution_authorization_node)
    builder.add_node("execute", execute_node)
    builder.add_node("verify", verify_node)
    builder.add_node("rollback", rollback_node)
    builder.add_node("knowledge", knowledge_node)

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
            if state.stage == WorkflowStage.WAITING_APPROVAL
            else (
                "execution_authorization"
                if state.stage == WorkflowStage.APPROVED
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
            if state.stage == WorkflowStage.APPROVED
            else "knowledge"
        ),
        {
            "execution_authorization": "execution_authorization",
            "knowledge": "knowledge",
        },
    )
    builder.add_edge("execution_authorization", "execute")
    builder.add_conditional_edges(
        "execute",
        lambda state: "verify" if state.stage == WorkflowStage.VERIFY else "knowledge",
        {"verify": "verify", "knowledge": "knowledge"},
    )
    builder.add_conditional_edges(
        "verify",
        lambda state: (
            "rollback" if state.stage == WorkflowStage.ROLLBACK else "knowledge"
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
