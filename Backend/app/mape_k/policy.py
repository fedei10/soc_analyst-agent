"""Deterministic safety and RBAC policy for approved playbooks."""

from __future__ import annotations

from app.config import settings
from app.mape_k.schemas import (
    ActionType,
    IncidentWorkflowState,
    PolicyDecision,
)
from app.mape_k.utils import csv_set


ROLE_LEVEL = {
    "soc_l1": 1,
    "soc_l2": 2,
    "soc_l3": 3,
    "security_admin": 4,
}


def role_allows(roles: list[str], required_role: str | None) -> bool:
    if required_role is None:
        return True
    required = ROLE_LEVEL.get(required_role, 99)
    return any(ROLE_LEVEL.get(role, 0) >= required for role in roles)


class PolicyEngine:
    def evaluate(self, state: IncidentWorkflowState) -> PolicyDecision:
        diagnosis = state.diagnosis
        plan = state.remediation_plan
        reasons: list[str] = []
        if diagnosis is None or plan is None:
            return PolicyDecision(
                allowed=False,
                approval_required=False,
                reason_codes=["MISSING_DIAGNOSIS_OR_PLAN"],
            )
        if diagnosis.confidence < settings.MAPEK_ANALYSIS_CONFIDENCE_THRESHOLD:
            reasons.append("LOW_CONFIDENCE")
        known_evidence = {item.evidence_id for item in state.evidence}
        if not diagnosis.evidence_ids or not set(diagnosis.evidence_ids) <= known_evidence:
            reasons.append("INVALID_EVIDENCE_REFERENCES")
        if plan.actions and not plan.rollback_actions:
            reasons.append("ROLLBACK_UNAVAILABLE")

        protected_ips = csv_set(settings.MAPEK_PROTECTED_IPS)
        approved_admin_ips = csv_set(settings.MAPEK_APPROVED_ADMIN_IPS)
        protected_accounts = csv_set(settings.MAPEK_PROTECTED_ACCOUNTS)
        protected_processes = csv_set(settings.MAPEK_PROTECTED_PROCESSES)
        for action in plan.actions:
            if action.action_type == ActionType.BLOCK_IP:
                if action.target in protected_ips:
                    reasons.append("PROTECTED_IP")
                if action.target in approved_admin_ips:
                    reasons.append("APPROVED_ADMIN_IP")
                if action.ttl_seconds is None:
                    reasons.append("BLOCK_TTL_REQUIRED")
            if action.action_type == ActionType.DISABLE_USER and action.target in protected_accounts:
                reasons.append("PROTECTED_ACCOUNT")
            if (
                action.action_type in {ActionType.STOP_SERVICE, ActionType.RESTART_SERVICE}
                and action.target in protected_processes
            ):
                reasons.append("PROTECTED_PROCESS")

        return PolicyDecision(
            allowed=not reasons,
            approval_required=plan.approval_required,
            required_role=plan.required_role,
            reason_codes=list(dict.fromkeys(reasons or ["POLICY_PASSED"])),
        )

