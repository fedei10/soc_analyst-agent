"""Versioned allowlisted playbooks and deterministic selection."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.config import settings
from app.mape_k.registries import PLAYBOOK_REGISTRY
from app.mape_k.schemas import (
    ActionType,
    IncidentWorkflowState,
    RemediationAction,
    RemediationPlan,
)
from app.mape_k.utils import stable_id


class PlaybookPlanner:
    def run(self, state: IncidentWorkflowState) -> RemediationPlan:
        diagnosis = state.diagnosis
        if diagnosis is None or diagnosis.incident_type != "ssh_brute_force":
            raise LookupError("No approved playbook matches this diagnosis.")
        source_ip = str(diagnosis.affected_entities.get("source_ip") or "")
        block_id = stable_id("ACT", state.incident_id, "block_ip", source_ip)
        unblock_id = stable_id("ACT", state.incident_id, "unblock_ip", source_ip)
        created_at = datetime.now(UTC)
        plan = RemediationPlan(
            plan_version=1,
            playbook_id="ssh-bruteforce-v1",
            playbook_version="1.0",
            incident_id=state.incident_id,
            evidence_version=str(state.evidence_version or ""),
            policy_version=settings.MAPEK_POLICY_VERSION,
            action_catalogue_version=settings.MAPEK_ACTION_CATALOGUE_VERSION,
            created_at=created_at,
            expires_at=created_at
            + timedelta(seconds=settings.MAPEK_APPROVAL_TTL_SECONDS),
            risk_level=1,
            actions=[
                RemediationAction(
                    action_id=block_id,
                    action_type=ActionType.BLOCK_IP,
                    target=source_ip,
                    parameters={"scope": "wazuh_active_response"},
                    ttl_seconds=settings.MAPEK_TEMPORARY_BLOCK_TTL_SECONDS,
                    risk_level=1,
                    evidence_refs=diagnosis.evidence_ids,
                )
            ],
            preconditions=[
                "source_ip_not_protected",
                "source_ip_not_approved_admin",
                "wazuh_agent_connected",
                "rollback_available",
            ],
            expected_effects=["Failed SSH attempts from the source stop."],
            security_checks=["ssh_attempts_stopped", "no_new_critical_alerts"],
            health_checks=[
                "wazuh_agent_connected",
                "ssh_port_listening",
                "management_ssh_reachable",
            ],
            rollback_actions=[
                RemediationAction(
                    action_id=unblock_id,
                    action_type=ActionType.UNBLOCK_IP,
                    target=source_ip,
                    parameters={"reverts_action_id": block_id},
                    risk_level=0,
                    evidence_refs=diagnosis.evidence_ids,
                )
            ],
            approval_required=True,
            required_role="soc_l2",
            reason=(
                "Temporarily contain the correlated SSH password-guessing source "
                "with automatic expiry and an explicit rollback."
            ),
        )
        PLAYBOOK_REGISTRY.validate_plan(
            plan,
            diagnosis_type=diagnosis.incident_type,
        )
        return plan
