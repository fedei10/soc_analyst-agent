"""Deterministic safety and RBAC policy for approved playbooks."""

from __future__ import annotations

from datetime import UTC, datetime

from app.config import settings
from app.mape_k.registries import (
    ACTION_REGISTRY,
    PLAYBOOK_REGISTRY,
    ROLE_LEVEL,
    VERIFICATION_CHECK_REGISTRY,
)
from app.mape_k.schemas import (
    ActionType,
    IncidentWorkflowState,
    PolicyDecision,
    compute_plan_hash,
)
from app.mape_k.utils import canonical_ip, csv_set


APPROVAL_ROLE_LEVEL = {
    "soc_l1": 1,
    **ROLE_LEVEL,
}


def role_allows(roles: list[str], required_role: str | None) -> bool:
    if required_role is None:
        return True
    required = APPROVAL_ROLE_LEVEL.get(required_role, 99)
    return any(APPROVAL_ROLE_LEVEL.get(role, 0) >= required for role in roles)


def _higher_role(
    first: str | None,
    second: str | None,
) -> str | None:
    candidates = [role for role in (first, second) if role]
    if not candidates:
        return None
    return max(candidates, key=lambda role: APPROVAL_ROLE_LEVEL.get(role, 99))


def _canonical_ip_set(value: str) -> set[str]:
    result: set[str] = set()
    for item in csv_set(value):
        try:
            result.add(canonical_ip(item))
        except ValueError:
            continue
    return result


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
        if plan.incident_id != state.incident_id:
            reasons.append("PLAN_INCIDENT_MISMATCH")
        if plan.evidence_version != str(state.evidence_version or ""):
            reasons.append("PLAN_EVIDENCE_VERSION_MISMATCH")
        if plan.policy_version != settings.MAPEK_POLICY_VERSION:
            reasons.append("PLAN_POLICY_VERSION_MISMATCH")
        if (
            plan.action_catalogue_version
            != settings.MAPEK_ACTION_CATALOGUE_VERSION
            or plan.action_catalogue_version != ACTION_REGISTRY.version
        ):
            reasons.append("ACTION_CATALOGUE_VERSION_MISMATCH")
        if plan.expires_at <= datetime.now(UTC):
            reasons.append("PLAN_EXPIRED")
        if not plan.plan_hash or plan.plan_hash != compute_plan_hash(plan):
            reasons.append("PLAN_HASH_MISMATCH")

        try:
            PLAYBOOK_REGISTRY.validate_plan(
                plan,
                diagnosis_type=diagnosis.incident_type,
            )
        except (LookupError, ValueError):
            reasons.append("INVALID_PLAYBOOK_REGISTRATION")

        if plan.actions and not plan.rollback_actions:
            reasons.append("ROLLBACK_UNAVAILABLE")

        protected_ips = _canonical_ip_set(settings.MAPEK_PROTECTED_IPS)
        approved_admin_ips = _canonical_ip_set(
            settings.MAPEK_APPROVED_ADMIN_IPS
        )
        protected_accounts = csv_set(settings.MAPEK_PROTECTED_ACCOUNTS)
        protected_processes = csv_set(settings.MAPEK_PROTECTED_PROCESSES)
        protected_services = csv_set(settings.MAPEK_PROTECTED_SERVICES)
        registered_roles: list[str] = []
        for action in plan.actions:
            registration = ACTION_REGISTRY.get(action.action_type)
            if registration is None:
                reasons.append("UNREGISTERED_ACTION")
            else:
                registered_roles.append(registration.minimum_role)
            if (
                not action.evidence_refs
                or not set(action.evidence_refs) <= known_evidence
            ):
                reasons.append("INVALID_ACTION_EVIDENCE_REFERENCES")
            if action.action_type == ActionType.BLOCK_IP:
                diagnosed_source_ip = str(
                    diagnosis.affected_entities.get("source_ip") or ""
                )
                try:
                    diagnosed_source_ip = canonical_ip(diagnosed_source_ip)
                except ValueError:
                    diagnosed_source_ip = ""
                if not diagnosed_source_ip or action.target != diagnosed_source_ip:
                    reasons.append("ACTION_TARGET_NOT_EVIDENCE_BOUND")
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
            if (
                action.action_type
                in {
                    ActionType.START_SERVICE,
                    ActionType.STOP_SERVICE,
                    ActionType.RESTART_SERVICE,
                }
                and action.target in protected_services
            ):
                reasons.append("PROTECTED_SERVICE")

        for action in plan.rollback_actions:
            if ACTION_REGISTRY.get(action.action_type) is None:
                reasons.append("UNREGISTERED_ROLLBACK_ACTION")
            if (
                not action.evidence_refs
                or not set(action.evidence_refs) <= known_evidence
            ):
                reasons.append("INVALID_ROLLBACK_EVIDENCE_REFERENCES")

        for check_name in [*plan.security_checks, *plan.health_checks]:
            if VERIFICATION_CHECK_REGISTRY.get(check_name) is None:
                reasons.append("UNREGISTERED_VERIFICATION_CHECK")

        maximum_action_risk = max(
            (action.risk_level for action in plan.actions),
            default=0,
        )
        if plan.risk_level < maximum_action_risk:
            reasons.append("PLAN_RISK_TOO_LOW")

        policy_role = (
            max(
                registered_roles,
                key=lambda role: APPROVAL_ROLE_LEVEL.get(role, 99),
            )
            if registered_roles
            else None
        )
        effective_role = _higher_role(plan.required_role, policy_role)
        approval_required = bool(
            plan.approval_required
            or any(
                registration.mutating
                for action in plan.actions
                if (registration := ACTION_REGISTRY.get(action.action_type))
            )
        )

        return PolicyDecision(
            allowed=not reasons,
            approval_required=approval_required,
            required_role=effective_role,
            reason_codes=list(dict.fromkeys(reasons or ["POLICY_PASSED"])),
        )
