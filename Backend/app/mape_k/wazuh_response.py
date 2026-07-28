"""Wazuh-specific state capture and rollback adapters.

These adapters stay outside the model-facing tool layer. They only operate on
registered actions after the workflow's approval and authorization gates.
"""

from __future__ import annotations

from typing import Any

from app.db.repositories.investigations import InvestigationRepository
from app.mape_k.executor import ACTIVE_RESPONSE_COMMANDS
from app.mape_k.registries import ACTION_REGISTRY
from app.mape_k.schemas import IncidentWorkflowState, RemediationAction
from app.mape_k.temporary_actions import (
    RollbackAttemptResult,
    TemporaryActionRollbackTask,
)
from app.services.wazuh.dependencies import (
    get_wazuh_gateway,
    get_wazuh_responder,
)


_ACTIVE_ACTION_STATUSES = {
    "accepted",
    "applied",
    "executed",
    "outcome_unknown",
    "rollback_failed_retryable",
}
_CONNECTED_AGENT_STATUSES = {"active", "connected"}


def _forward_effect_type(action_type):
    registration = ACTION_REGISTRY.require(action_type)
    if registration.rollback_action_type is not None:
        return action_type
    return ACTION_REGISTRY.forward_action_for(action_type) or action_type


class WazuhBeforeStateProvider:
    """Capture the app-owned action state plus current agent connectivity."""

    def __init__(
        self,
        *,
        repository: InvestigationRepository,
        gateway: Any | None = None,
    ) -> None:
        self.repository = repository
        self.gateway = gateway

    def __call__(
        self,
        *,
        action: RemediationAction,
        state: IncidentWorkflowState,
    ) -> dict[str, Any]:
        gateway = self.gateway or get_wazuh_gateway()
        agent_id = str(state.agent_id or "")
        if not agent_id.isdigit():
            raise RuntimeError("A numeric Wazuh agent ID is required for state capture.")
        agent = gateway.get_agent_summary(agent_id)
        if agent is None:
            raise RuntimeError("The Wazuh agent is unavailable for state capture.")
        status = str(agent.status or "unknown").lower()
        effect_type = _forward_effect_type(action.action_type)
        records = self.repository.list_response_actions(
            state.investigation_id,
            organization_id=state.organization_id,
        )
        action_present = any(
            str(item.get("action_type")) == effect_type.value
            and str(item.get("target")) == action.target
            and str(item.get("status")) in _ACTIVE_ACTION_STATUSES
            for item in records
        )
        return {
            "target": action.target,
            "action_present": action_present,
            "wazuh_agent_status": status,
            "management_connectivity": status in _CONNECTED_AGENT_STATUSES,
            "snapshot_source": "wazuh_agent_and_tsage_action_ledger",
        }


class WazuhTemporaryActionRollbackAdapter:
    """Send a registered inverse action and verify manager/agent acceptance."""

    def __init__(
        self,
        *,
        repository: InvestigationRepository,
        gateway: Any | None = None,
        responder: Any | None = None,
    ) -> None:
        self.repository = repository
        self.gateway = gateway
        self.responder = responder

    def rollback(
        self,
        task: TemporaryActionRollbackTask,
    ) -> RollbackAttemptResult:
        snapshot = self.repository.get_snapshot(
            task.investigation_id,
            organization_id=task.organization_id,
        )
        agent_id = str((snapshot or {}).get("agent_id") or "")
        if not agent_id.isdigit():
            return RollbackAttemptResult(
                success=False,
                retryable=False,
                details={"error": "numeric_wazuh_agent_id_required"},
            )
        registration = ACTION_REGISTRY.require(task.rollback_action_type)
        command = ACTIVE_RESPONSE_COMMANDS.get(registration.executor_key)
        if command is None:
            return RollbackAttemptResult(
                success=False,
                retryable=False,
                details={"error": "rollback_adapter_not_registered"},
            )
        responder = self.responder or get_wazuh_responder()
        response = responder.run_active_response(
            agent_id=agent_id,
            command=command,
            arguments=[task.target],
        )
        gateway = self.gateway or get_wazuh_gateway()
        agent = gateway.get_agent_summary(agent_id)
        status = str(getattr(agent, "status", "") or "").lower()
        manager_accepted = isinstance(response, dict)
        verified = manager_accepted and status in _CONNECTED_AGENT_STATUSES
        return RollbackAttemptResult(
            success=verified,
            verified=verified,
            retryable=not verified,
            details={
                "manager_accepted": manager_accepted,
                "wazuh_agent_status": status or "unknown",
                "verification_scope": "manager_acceptance_and_agent_connectivity",
                "rollback_idempotency_key": task.rollback_idempotency_key,
            },
        )
