"""Wiring for the single controlled MAPE-K LangGraph state machine.

Node implementations live in nodes.py, routing in routes.py.
"""

from __future__ import annotations

import time
from functools import partial
from typing import Any, Callable

import structlog
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph

from app.mape_k import nodes, routes
from app.mape_k.analyze import IncidentAnalyzer
from app.mape_k.executor import RestrictedExecutor
from app.mape_k.monitor import WazuhMonitor
from app.mape_k.playbooks import PlaybookPlanner
from app.mape_k.policy import PolicyEngine
from app.mape_k.schemas import (
    IncidentWorkflowState,
    WorkflowStatus,
)
from app.mape_k.serde import create_checkpoint_serializer
from app.mape_k.verify import ResponseVerifier


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

    node_functions: dict[
        str,
        Callable[[IncidentWorkflowState], dict[str, Any]],
    ] = {
        "monitor": partial(nodes.monitor_node, monitor),
        "analyze": partial(nodes.analyze_node, analyzer),
        "plan": partial(nodes.plan_node, planner),
        "policy_gate": partial(nodes.policy_node, policy),
        "human_approval": nodes.approval_node,
        "execution_authorization": partial(
            nodes.execution_authorization_node,
            policy,
        ),
        "execute": partial(nodes.execute_node, executor),
        "verification_wait": nodes.verification_wait_node,
        "verify": partial(nodes.verify_node, verifier),
        "rollback": partial(nodes.rollback_node, executor),
        "knowledge": nodes.knowledge_node,
    }

    builder = StateGraph(IncidentWorkflowState)
    for name, function in node_functions.items():
        builder.add_node(name, _observed_node(name, function))

    builder.add_edge(START, "monitor")
    builder.add_conditional_edges(
        "monitor",
        routes.after_monitor,
        {"analyze": "analyze", "knowledge": "knowledge"},
    )
    builder.add_conditional_edges(
        "analyze",
        routes.after_analyze,
        {"plan": "plan", "knowledge": "knowledge"},
    )
    builder.add_conditional_edges(
        "plan",
        routes.after_plan,
        {"policy_gate": "policy_gate", "knowledge": "knowledge"},
    )
    builder.add_conditional_edges(
        "policy_gate",
        routes.after_policy_gate,
        {
            "human_approval": "human_approval",
            "execution_authorization": "execution_authorization",
            "knowledge": "knowledge",
        },
    )
    builder.add_conditional_edges(
        "human_approval",
        routes.after_human_approval,
        {
            "execution_authorization": "execution_authorization",
            "knowledge": "knowledge",
        },
    )
    builder.add_conditional_edges(
        "execution_authorization",
        routes.after_execution_authorization,
        {"execute": "execute", "knowledge": "knowledge"},
    )
    builder.add_conditional_edges(
        "execute",
        routes.after_execute,
        {
            "verification_wait": "verification_wait",
            "verify": "verify",
            "rollback": "rollback",
            "knowledge": "knowledge",
        },
    )
    builder.add_conditional_edges(
        "verification_wait",
        routes.after_verification_wait,
        {
            "verification_wait": "verification_wait",
            "verify": "verify",
            "rollback": "rollback",
            "knowledge": "knowledge",
        },
    )
    builder.add_conditional_edges(
        "verify",
        routes.after_verify,
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
