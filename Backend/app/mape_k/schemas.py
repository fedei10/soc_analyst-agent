"""Typed MAPE-K state and allowlisted security-response contracts."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.services.wazuh.normalization.schemas import NormalizedAlert


MAX_CHECKPOINT_AUDIT_EVENTS = 64

ACCOUNT_TARGET_PATTERN = re.compile(r"[A-Za-z0-9._@-]{1,64}")


def merge_bounded_audit_events(
    current: list[dict[str, Any]],
    incoming: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Retain a compact recent window; PostgreSQL stores durable history."""

    return [*current, *incoming][-MAX_CHECKPOINT_AUDIT_EVENTS:]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class WorkflowStage(StrEnum):
    MONITOR = "monitor"
    ANALYZE = "analyze"
    PLAN = "plan"
    POLICY_GATE = "policy_gate"
    EXECUTE = "execute"
    VERIFY = "verify"
    UPDATE_KNOWLEDGE = "update_knowledge"
    ROLLBACK = "rollback"


class WorkflowStatus(StrEnum):
    CREATED = "created"
    QUEUED = "queued"
    RUNNING = "running"
    WAITING_APPROVAL = "waiting_approval"
    # Compatibility alias for snapshots created before the status split.
    AWAITING_APPROVAL = "waiting_approval"
    WAITING_VERIFICATION = "waiting_verification"
    APPROVED = "approved"
    COMPLETED = "completed"
    REJECTED = "rejected"
    ESCALATED = "escalated"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ActionType(StrEnum):
    BLOCK_IP = "block_ip"
    UNBLOCK_IP = "unblock_ip"
    ISOLATE_HOST = "isolate_host"
    RESTORE_NETWORK_ACCESS = "restore_network_access"
    DISABLE_USER = "disable_user"
    ENABLE_USER = "enable_user"
    STOP_SERVICE = "stop_service"
    START_SERVICE = "start_service"
    RESTART_SERVICE = "restart_service"
    QUARANTINE_FILE = "quarantine_file"
    RESTORE_FILE = "restore_file"
    APPLY_APPROVED_PATCH = "apply_approved_patch"
    RESTORE_CONFIGURATION = "restore_configuration"
    INCREASE_MONITORING = "increase_monitoring"


class EvidenceReference(StrictModel):
    evidence_id: str = Field(pattern=r"^EV-[A-F0-9]{12,64}$")
    source_type: str
    source_ref: str
    observed_at: datetime | None = None
    summary: str
    content_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class SSHDetectionPolicy(StrictModel):
    brute_force_min_failures: int = Field(default=5, ge=2, le=10_000)
    brute_force_min_events: int = Field(default=3, ge=2, le=10_000)
    brute_force_window_seconds: int = Field(default=300, ge=10, le=86_400)
    password_spray_min_users: int = Field(default=5, ge=2, le=10_000)
    password_spray_min_failures: int = Field(default=10, ge=2, le=100_000)
    password_spray_window_seconds: int = Field(default=300, ge=10, le=86_400)
    success_after_failure_window_seconds: int = Field(
        default=900,
        ge=10,
        le=86_400,
    )


class AuthenticationEvidenceSummary(StrictModel):
    first_seen: datetime
    last_seen: datetime
    failed_attempt_count: int = Field(ge=0)
    successful_attempt_count: int = Field(ge=0)
    distinct_event_count: int = Field(ge=0)
    distinct_target_user_count: int = Field(ge=0)
    source_ips: list[str] = Field(default_factory=list)
    target_users: list[str] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)
    successful_login_after_failures: bool | None = None
    source_is_internal: bool | None = None
    source_is_approved_admin: bool | None = None
    source_asset_id: str | None = None
    source_reputation: str | None = None
    total_hits: int = Field(default=0, ge=0)
    returned_hits: int = Field(default=0, ge=0)
    truncated: bool = False
    correlation_window_start: datetime | None = None
    correlation_window_end: datetime | None = None
    missing_evidence: list[str] = Field(default_factory=list)


class Diagnosis(StrictModel):
    incident_type: str
    summary: str
    root_cause: str
    attack_techniques: list[str] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)
    affected_entities: dict[str, Any] = Field(default_factory=dict)
    evidence_ids: list[str] = Field(min_length=1)
    confidence: float = Field(ge=0, le=1)
    needs_more_evidence: bool = False
    deterministic: bool = False


class RemediationAction(StrictModel):
    action_id: str
    action_type: ActionType
    target: str = Field(min_length=1, max_length=512)
    parameters: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = Field(default=15, ge=1, le=300)
    ttl_seconds: int | None = Field(default=None, ge=60, le=86400)
    risk_level: int = Field(ge=0, le=5)
    evidence_refs: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_action_parameters(self):
        if self.action_type in {ActionType.BLOCK_IP, ActionType.UNBLOCK_IP}:
            try:
                parsed_target = ipaddress.ip_address(self.target)
            except ValueError as exc:
                raise ValueError("IP actions require a valid IP target.") from exc
            self.target = str(parsed_target)
        if self.action_type in {ActionType.DISABLE_USER, ActionType.ENABLE_USER}:
            # The target is passed to a Wazuh Active Response script as an
            # argument, so it is a trust boundary: constrain it to an account
            # name shape rather than forwarding arbitrary text.
            if not ACCOUNT_TARGET_PATTERN.fullmatch(self.target):
                raise ValueError(
                    "Account actions require a plain account name target."
                )
        if self.action_type == ActionType.BLOCK_IP and self.ttl_seconds is None:
            raise ValueError("Temporary IP blocks require ttl_seconds.")
        if any(key in self.parameters for key in ("command", "shell", "argv")):
            raise ValueError("Arbitrary command parameters are prohibited.")
        return self


class RemediationPlan(StrictModel):
    plan_id: str | None = None
    plan_version: int = Field(default=1, ge=1)
    plan_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    playbook_id: str
    playbook_version: str = "1.0"
    incident_id: str
    evidence_version: str = ""
    policy_version: str = "1.0"
    action_catalogue_version: str = "1.0"
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC) + timedelta(minutes=30)
    )
    risk_level: int = Field(ge=0, le=5)
    actions: list[RemediationAction] = Field(default_factory=list)
    preconditions: list[str] = Field(default_factory=list)
    expected_effects: list[str] = Field(default_factory=list)
    health_checks: list[str] = Field(default_factory=list)
    security_checks: list[str] = Field(default_factory=list)
    rollback_actions: list[RemediationAction] = Field(default_factory=list)
    approval_required: bool
    required_role: Literal["soc_l2", "soc_l3", "security_admin"] | None = None
    reason: str

    @model_validator(mode="after")
    def bind_identity_and_hash(self):
        if self.expires_at <= self.created_at:
            raise ValueError("Remediation plan expiry must follow creation.")
        canonical_hash = compute_plan_hash(self)
        if self.plan_hash is not None and self.plan_hash != canonical_hash:
            raise ValueError("Remediation plan hash does not match its contents.")
        self.plan_hash = canonical_hash
        if self.plan_id is None:
            digest = hashlib.sha256(
                (
                    f"{self.incident_id}|{self.playbook_id}|"
                    f"{self.plan_version}|{canonical_hash}"
                ).encode("utf-8")
            ).hexdigest()[:24].upper()
            self.plan_id = f"PLAN-{digest}"
        return self


class PolicyDecision(StrictModel):
    allowed: bool
    approval_required: bool
    required_role: Literal["soc_l2", "soc_l3", "security_admin"] | None = None
    reason_codes: list[str] = Field(default_factory=list)


class ApprovalSubmission(StrictModel):
    approval_id: str
    decision: Literal["approve", "reject"]
    comment: str | None = Field(default=None, max_length=2000)


class TrustedApprovalSubmission(ApprovalSubmission):
    actor_user_id: str
    actor_roles: list[str] = Field(default_factory=list)


class ApprovalRequestRecord(StrictModel):
    approval_id: str
    investigation_id: str
    incident_id: str
    plan_id: str
    plan_version: int = Field(ge=1)
    plan_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    evidence_version: str
    policy_version: str
    action_catalogue_version: str
    action_ids: list[str] = Field(min_length=1)
    required_role: Literal["soc_l2", "soc_l3", "security_admin"]
    requested_at: datetime
    expires_at: datetime


class ApprovalDecision(StrictModel):
    approval_id: str
    decision: Literal["approve", "reject"]
    actor_user_id: str
    actor_roles: list[str] = Field(default_factory=list)
    plan_id: str
    plan_version: int = Field(ge=1)
    plan_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    evidence_version: str
    policy_version: str
    action_catalogue_version: str
    comment: str | None = Field(default=None, max_length=2000)
    decided_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ExecutionAuthorization(StrictModel):
    approval_id: str
    execution_id: str
    action_ids: list[str] = Field(min_length=1)
    actor_user_id: str
    actor_roles: list[str] = Field(default_factory=list)
    authorized_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("action_ids")
    @classmethod
    def action_ids_are_unique(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("Execution action IDs must be unique.")
        return value


class VerificationResumeAuthorization(StrictModel):
    kind: Literal["server_verification_resume"] = "server_verification_resume"
    investigation_id: str
    actor_user_id: str
    actor_roles: list[str] = Field(default_factory=list)
    authorized_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ExecutionResult(StrictModel):
    execution_id: str
    action_id: str
    incident_id: str
    idempotency_key: str
    action_type: ActionType
    target: str
    status: Literal[
        "dry_run",
        "accepted",
        "applied",
        "executed",
        "failed_retryable",
        "failed_terminal",
        "duplicate",
        "timed_out",
        "outcome_unknown",
        "no_op",
        "rolled_back",
        "cancelled",
    ]
    before_state: dict[str, Any] = Field(default_factory=dict)
    result: dict[str, Any] = Field(default_factory=dict)
    rollback_action_id: str | None = None
    started_at: datetime
    completed_at: datetime


class VerificationOutcome(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    PARTIAL = "partial"
    SIMULATED = "simulated"
    NOT_VERIFIED = "not_verified"


class VerificationResult(StrictModel):
    outcome: VerificationOutcome
    security_checks_passed: bool
    health_checks_passed: bool
    checks: list[dict[str, Any]] = Field(default_factory=list)
    verified_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    dry_run: bool = False

    @property
    def passed(self) -> bool:
        return (
            self.outcome == VerificationOutcome.PASSED
            and self.security_checks_passed
            and self.health_checks_passed
        )


class RollbackResult(StrictModel):
    attempted: bool
    successful: bool
    results: list[dict[str, Any]] = Field(default_factory=list)
    completed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class WorkflowError(StrictModel):
    stage: WorkflowStage
    code: str
    message: str
    retryable: bool = False


class IncidentWorkflowState(BaseModel):
    model_config = ConfigDict(extra="allow")

    incident_id: str
    investigation_id: str
    alert_id: str
    finding_id: str | None = None
    organization_id: str = "local"
    owner_user_id: str | None = None
    initiated_by: str | None = None
    initiation_reason: str | None = None
    agent_id: str | None = None
    status: WorkflowStatus = WorkflowStatus.CREATED
    stage: WorkflowStage = WorkflowStage.MONITOR
    current_stage: str = WorkflowStage.MONITOR
    normalized_alerts: list[NormalizedAlert] = Field(default_factory=list)
    evidence: list[EvidenceReference] = Field(default_factory=list)
    evidence_records: list[dict[str, Any]] = Field(default_factory=list)
    authentication_evidence: AuthenticationEvidenceSummary | None = None
    findings: list[dict[str, Any]] = Field(default_factory=list)
    incident_fingerprint: str | None = None
    evidence_version: str | None = None
    diagnosis: Diagnosis | None = None
    remediation_plan: RemediationPlan | None = None
    policy_decision: PolicyDecision | None = None
    approval_request: ApprovalRequestRecord | None = None
    approval_decision: ApprovalDecision | None = None
    execution_authorization: ExecutionAuthorization | None = None
    proposed_actions: list[dict[str, Any]] = Field(default_factory=list)
    execution_results: list[ExecutionResult] = Field(default_factory=list)
    executed_actions: list[dict[str, Any]] = Field(default_factory=list)
    verification_not_before: datetime | None = None
    verification: VerificationResult | None = None
    rollback: RollbackResult | None = None
    retry_count: int = Field(default=0, ge=0)
    analysis_attempts: int = Field(default=0, ge=0)
    planning_attempts: int = Field(default=0, ge=0)
    llm_input_tokens: int = Field(default=0, ge=0)
    llm_output_tokens: int = Field(default=0, ge=0)
    estimated_input_tokens: int = Field(default=0, ge=0)
    estimated_output_tokens: int = Field(default=0, ge=0)
    actual_input_tokens: int | None = Field(default=None, ge=0)
    actual_output_tokens: int | None = Field(default=None, ge=0)
    cached_input_tokens: int | None = Field(default=None, ge=0)
    model_calls: int = Field(default=0, ge=0)
    model_retries: int = Field(default=0, ge=0)
    model_provider: str | None = None
    model_name: str | None = None
    estimated_cost_usd: float = Field(default=0, ge=0)
    actual_cost_usd: float | None = Field(default=None, ge=0)
    error: WorkflowError | None = None
    errors: list[dict[str, Any]] = Field(default_factory=list)
    audit_events: Annotated[
        list[dict[str, Any]],
        merge_bounded_audit_events,
    ] = Field(
        default_factory=list
    )
    final_report: dict[str, Any] | None = None

    @field_validator("incident_id")
    @classmethod
    def incident_id_is_valid(cls, value: str) -> str:
        if not value.startswith("INC-"):
            raise ValueError("incident_id must start with INC-.")
        return value


def canonical_plan_payload(plan: RemediationPlan) -> dict[str, Any]:
    return {
        "actions": [
            action.model_dump(mode="json", exclude_none=False)
            for action in plan.actions
        ],
        "target": [action.target for action in plan.actions],
        "ttl": [action.ttl_seconds for action in plan.actions],
        "risk": plan.risk_level,
        "preconditions": plan.preconditions,
        "health_checks": plan.health_checks,
        "security_checks": plan.security_checks,
        "rollback_actions": [
            action.model_dump(mode="json", exclude_none=False)
            for action in plan.rollback_actions
        ],
        "required_role": plan.required_role,
        "playbook_id": plan.playbook_id,
        "playbook_version": plan.playbook_version,
        "incident_id": plan.incident_id,
        "plan_version": plan.plan_version,
        "evidence_version": plan.evidence_version,
        "policy_version": plan.policy_version,
        "action_catalogue_version": plan.action_catalogue_version,
    }


def compute_plan_hash(plan: RemediationPlan) -> str:
    rendered = json.dumps(
        canonical_plan_payload(plan),
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def state_dict(state: IncidentWorkflowState | dict[str, Any]) -> dict[str, Any]:
    if isinstance(state, IncidentWorkflowState):
        return state.model_dump(mode="json")
    return state
