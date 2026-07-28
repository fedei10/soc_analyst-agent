"""Versioned allowlisted playbooks and their selection.

Selection is catalogue-first: a diagnosed incident type that a registered
playbook publishes picks that playbook with no model involved. The model is
consulted only when the diagnosis names something the catalogue does not
recognise, and then only to *choose* among already-published playbooks - it
never authors actions, targets, TTLs or checks. Whatever it picks is
canonicalised back onto that playbook's own incident type so the policy
engine keeps validating deterministically, and the mapping it proposed is
written to the audit trail.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.config import settings
from app.mape_k.llm import LLMProvider, LLMTier, get_llm_provider
from app.mape_k.registries import PLAYBOOK_REGISTRY, PlaybookRegistration
from app.mape_k.schemas import (
    ActionType,
    Diagnosis,
    IncidentWorkflowState,
    RemediationAction,
    RemediationPlan,
)
from app.mape_k.utils import stable_id


class PlaybookSelection(BaseModel):
    """The model's constrained answer when the catalogue has no exact match."""

    applies: bool = Field(
        description=(
            "True only when one published playbook genuinely addresses the "
            "diagnosed incident. False escalates to a human."
        )
    )
    playbook_id: str = Field(
        default="",
        description="Exact playbook_id from the supplied list, or empty.",
    )
    canonical_incident_type: str = Field(
        default="",
        description=(
            "Which of that playbook's published incident types the diagnosis "
            "corresponds to. Must come from the supplied list."
        ),
    )
    rationale: str = Field(default="", max_length=600)


@dataclass(frozen=True)
class PlanSelection:
    plan: RemediationPlan
    canonical_incident_type: str
    selected_by: Literal["catalogue", "model"]
    rationale: str | None = None


def _plan_envelope(
    state: IncidentWorkflowState,
    *,
    playbook_id: str,
    risk_level: int,
    actions: list[RemediationAction],
    rollback_actions: list[RemediationAction],
    preconditions: list[str],
    expected_effects: list[str],
    security_checks: list[str],
    health_checks: list[str],
    required_role: str,
    reason: str,
) -> RemediationPlan:
    created_at = datetime.now(UTC)
    return RemediationPlan(
        plan_version=1,
        playbook_id=playbook_id,
        playbook_version="1.0",
        incident_id=state.incident_id,
        evidence_version=str(state.evidence_version or ""),
        policy_version=settings.MAPEK_POLICY_VERSION,
        action_catalogue_version=settings.MAPEK_ACTION_CATALOGUE_VERSION,
        created_at=created_at,
        expires_at=created_at
        + timedelta(seconds=settings.MAPEK_APPROVAL_TTL_SECONDS),
        risk_level=risk_level,
        actions=actions,
        preconditions=preconditions,
        expected_effects=expected_effects,
        security_checks=security_checks,
        health_checks=health_checks,
        rollback_actions=rollback_actions,
        approval_required=True,
        required_role=required_role,
        reason=reason,
    )


def _block_source_ip_plan(
    state: IncidentWorkflowState,
    diagnosis: Diagnosis,
    *,
    playbook_id: str,
    reason: str,
) -> RemediationPlan:
    source_ip = str(diagnosis.affected_entities.get("source_ip") or "")
    if not source_ip:
        raise LookupError(
            "The diagnosis names no source IP to contain."
        )
    block_id = stable_id("ACT", state.incident_id, "block_ip", source_ip)
    unblock_id = stable_id("ACT", state.incident_id, "unblock_ip", source_ip)
    return _plan_envelope(
        state,
        playbook_id=playbook_id,
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
        required_role="soc_l2",
        reason=reason,
    )


def _disable_user_plan(
    state: IncidentWorkflowState,
    diagnosis: Diagnosis,
    *,
    playbook_id: str,
    reason: str,
) -> RemediationPlan:
    users = [
        str(user)
        for user in (diagnosis.affected_entities.get("users") or [])
        if user
    ]
    if len(users) != 1:
        # One account per plan: the published playbook declares exactly one
        # action, and containing several accounts at once deserves its own
        # approval each rather than being bundled behind one click.
        raise LookupError(
            "Account containment needs exactly one compromised account; the "
            f"diagnosis names {len(users)}."
        )
    account = users[0]
    disable_id = stable_id("ACT", state.incident_id, "disable_user", account)
    enable_id = stable_id("ACT", state.incident_id, "enable_user", account)
    return _plan_envelope(
        state,
        playbook_id=playbook_id,
        risk_level=2,
        actions=[
            RemediationAction(
                action_id=disable_id,
                action_type=ActionType.DISABLE_USER,
                target=account,
                parameters={"scope": "wazuh_active_response"},
                risk_level=2,
                evidence_refs=diagnosis.evidence_ids,
            )
        ],
        rollback_actions=[
            RemediationAction(
                action_id=enable_id,
                action_type=ActionType.ENABLE_USER,
                target=account,
                parameters={"reverts_action_id": disable_id},
                risk_level=1,
                evidence_refs=diagnosis.evidence_ids,
            )
        ],
        preconditions=[
            "account_not_protected",
            "source_not_approved_admin",
            "wazuh_agent_connected",
            "rollback_available",
        ],
        expected_effects=[
            "The account cannot authenticate until an analyst re-enables it."
        ],
        security_checks=[
            "no_new_auth_success_for_user",
            "no_new_critical_alerts",
        ],
        health_checks=["wazuh_agent_connected", "management_ssh_reachable"],
        required_role="soc_l3",
        reason=reason,
    )


# playbook_id -> builder. A playbook is only reachable when it is both
# registered (published shape) and buildable (code that fills that shape).
PLAN_BUILDERS = {
    "ssh-bruteforce-v1": lambda state, diagnosis: _block_source_ip_plan(
        state,
        diagnosis,
        playbook_id="ssh-bruteforce-v1",
        reason=(
            "Temporarily contain the correlated SSH password-guessing source "
            "with automatic expiry and an explicit rollback."
        ),
    ),
    "ssh-password-spray-v1": lambda state, diagnosis: _block_source_ip_plan(
        state,
        diagnosis,
        playbook_id="ssh-password-spray-v1",
        reason=(
            "Temporarily contain the source spraying passwords across "
            "multiple accounts, with automatic expiry and an explicit "
            "rollback."
        ),
    ),
    "credential-compromise-v1": lambda state, diagnosis: _disable_user_plan(
        state,
        diagnosis,
        playbook_id="credential-compromise-v1",
        reason=(
            "Suspend the account that authenticated successfully after "
            "repeated failures, pending analyst confirmation. Blocking the "
            "source alone would leave working credentials in play."
        ),
    ),
}


SELECTION_SYSTEM_PROMPT = (
    "You map a security diagnosis onto one already-approved response "
    "playbook. You do not design a response: the actions, targets, expiry "
    "and verification of each playbook are fixed in code and a human must "
    "still approve them.\n"
    "Choose a playbook only when it genuinely addresses the diagnosed "
    "incident on the evidence given. Set applies=false whenever you are "
    "unsure, the diagnosis is a different kind of problem, or the required "
    "entity (a source IP, an account) is missing - escalating to a human is "
    "the correct answer, never a failure. Never choose a containment "
    "playbook to 'do something' about an incident it does not fit."
)


class PlaybookPlanner:
    def __init__(self, llm: LLMProvider | None = None) -> None:
        self._llm = llm

    @property
    def llm(self) -> LLMProvider:
        if self._llm is None:
            self._llm = get_llm_provider(LLMTier.ROUTER)
        return self._llm

    @staticmethod
    def _buildable(registrations: list[PlaybookRegistration]):
        return sorted(
            (item for item in registrations if item.playbook_id in PLAN_BUILDERS),
            key=lambda item: item.playbook_id,
        )

    @staticmethod
    def _catalogue_summary() -> list[dict[str, Any]]:
        """Every buildable playbook, described only as far as the model needs."""

        summary: list[dict[str, Any]] = []
        for playbook_id in sorted(PLAN_BUILDERS):
            registration = PLAYBOOK_REGISTRY.get(playbook_id, "1.0")
            if registration is None:
                continue
            summary.append(
                {
                    "playbook_id": registration.playbook_id,
                    "incident_types": sorted(registration.incident_types),
                    "actions": sorted(
                        str(value) for value in registration.action_types
                    ),
                    "requires": (
                        "a source IP in affected_entities.source_ip"
                        if ActionType.BLOCK_IP in registration.action_types
                        else "exactly one account in affected_entities.users"
                    ),
                }
            )
        return summary

    def _model_selection(
        self,
        state: IncidentWorkflowState,
        diagnosis: Diagnosis,
    ) -> tuple[PlaybookRegistration, str, str]:
        """Ask the model to map an unrecognised diagnosis onto a playbook."""

        catalogue = self._catalogue_summary()
        payload = {
            "diagnosis": {
                "incident_type": diagnosis.incident_type,
                "summary": diagnosis.summary,
                "root_cause": diagnosis.root_cause,
                "attack_techniques": diagnosis.attack_techniques,
                "affected_entities": diagnosis.affected_entities,
                "affected_assets": diagnosis.affected_assets,
                "confidence": diagnosis.confidence,
                "needs_more_evidence": diagnosis.needs_more_evidence,
            },
            "playbooks": catalogue,
        }
        selection, _usage = self.llm.invoke_structured(
            PlaybookSelection,
            [
                {"role": "system", "content": SELECTION_SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": json.dumps(
                        payload,
                        sort_keys=True,
                        separators=(",", ":"),
                        default=str,
                    ),
                },
            ],
        )
        selection = PlaybookSelection.model_validate(selection)
        if not selection.applies:
            raise LookupError(
                "No approved playbook addresses this diagnosis "
                f"({selection.rationale or 'model declined to map it'})."
            )
        registration = PLAYBOOK_REGISTRY.get(selection.playbook_id, "1.0")
        if registration is None or registration.playbook_id not in PLAN_BUILDERS:
            raise LookupError(
                "The selected playbook is not a registered, buildable playbook."
            )
        canonical = selection.canonical_incident_type
        if canonical not in registration.incident_types:
            # The model must land on a type this playbook actually publishes;
            # otherwise fall back to the playbook's own single type when it
            # has exactly one, and refuse when it is genuinely ambiguous.
            if len(registration.incident_types) != 1:
                raise LookupError(
                    "The selected playbook does not publish the proposed "
                    "incident type."
                )
            canonical = next(iter(registration.incident_types))
        return registration, canonical, selection.rationale

    def plan(self, state: IncidentWorkflowState) -> PlanSelection:
        diagnosis = state.diagnosis
        if diagnosis is None:
            raise LookupError("A diagnosis is required before planning.")

        matches = self._buildable(
            PLAYBOOK_REGISTRY.for_incident_type(diagnosis.incident_type)
        )
        if matches:
            registration = matches[0]
            canonical = diagnosis.incident_type
            selected_by: Literal["catalogue", "model"] = "catalogue"
            rationale = None
        else:
            registration, canonical, rationale = self._model_selection(
                state,
                diagnosis,
            )
            selected_by = "model"

        plan = PLAN_BUILDERS[registration.playbook_id](state, diagnosis)
        # The same validation the policy engine will independently repeat.
        # A model-selected plan is checked against the canonical type, so
        # nothing reaches approval on the strength of the model's mapping
        # alone.
        PLAYBOOK_REGISTRY.validate_plan(plan, diagnosis_type=canonical)
        return PlanSelection(
            plan=plan,
            canonical_incident_type=canonical,
            selected_by=selected_by,
            rationale=rationale,
        )

    def run(self, state: IncidentWorkflowState) -> RemediationPlan:
        """Backwards-compatible entry point returning only the plan."""

        return self.plan(state).plan
