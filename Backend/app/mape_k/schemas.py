"""Typed MAPE-K state and allowlisted security-response contracts."""

from __future__ import annotations

import ipaddress
import operator
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.services.wazuh.normalization.schemas import NormalizedAlert


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class WorkflowStage(StrEnum):
    CREATED = "created"
    MONITOR = "monitor"
    ANALYZE = "analyze"
    PLAN = "plan"
    POLICY_GATE = "policy_gate"
    WAITING_APPROVAL = "waiting_approval"
    APPROVED = "approved"
    EXECUTE = "execute"
    VERIFY = "verify"
    UPDATE_KNOWLEDGE = "update_knowledge"
    ROLLBACK = "rollback"
    COMPLETED = "completed"
    REJECTED = "rejected"
    ESCALATED = "escalated"
    FAILED = "failed"


class WorkflowStatus(StrEnum):
    CREATED = "created"
    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    COMPLETED = "completed"
    REJECTED = "rejected"
    ESCALATED = "escalated"
    FAILED = "failed"


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
                ipaddress.ip_address(self.target)
            except ValueError as exc:
                raise ValueError("IP actions require a valid IP target.") from exc
        if self.action_type == ActionType.BLOCK_IP and self.ttl_seconds is None:
            raise ValueError("Temporary IP blocks require ttl_seconds.")
        if any(key in self.parameters for key in ("command", "shell", "argv")):
            raise ValueError("Arbitrary command parameters are prohibited.")
        return self


class RemediationPlan(StrictModel):
    playbook_id: str
    playbook_version: str = "1.0"
    incident_id: str
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


class PolicyDecision(StrictModel):
    allowed: bool
    approval_required: bool
    required_role: Literal["soc_l2", "soc_l3", "security_admin"] | None = None
    reason_codes: list[str] = Field(default_factory=list)


class ApprovalDecision(StrictModel):
    approval_id: str
    decision: Literal["approve", "reject"]
    approved_by: str
    approver_roles: list[str] = Field(default_factory=list)
    decided_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ExecutionResult(StrictModel):
    execution_id: str
    action_id: str
    incident_id: str
    idempotency_key: str
    action_type: ActionType
    target: str
    status: Literal["dry_run", "executed", "failed", "duplicate", "timed_out"]
    before_state: dict[str, Any] = Field(default_factory=dict)
    result: dict[str, Any] = Field(default_factory=dict)
    rollback_action_id: str | None = None
    started_at: datetime
    completed_at: datetime


class VerificationResult(StrictModel):
    security_checks_passed: bool
    health_checks_passed: bool
    checks: list[dict[str, Any]] = Field(default_factory=list)
    verified_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    dry_run: bool = False

    @property
    def passed(self) -> bool:
        return self.security_checks_passed and self.health_checks_passed


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
    organization_id: str = "local"
    owner_user_id: str | None = None
    initiated_by: str | None = None
    initiation_reason: str | None = None
    agent_id: str | None = None
    status: WorkflowStatus = WorkflowStatus.CREATED
    stage: WorkflowStage = WorkflowStage.CREATED
    current_stage: str = WorkflowStage.CREATED
    normalized_alerts: list[NormalizedAlert] = Field(default_factory=list)
    evidence: list[EvidenceReference] = Field(default_factory=list)
    evidence_records: list[dict[str, Any]] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    incident_fingerprint: str | None = None
    evidence_version: str | None = None
    diagnosis: Diagnosis | None = None
    remediation_plan: RemediationPlan | None = None
    policy_decision: PolicyDecision | None = None
    approval_request: dict[str, Any] | None = None
    approval_decision: ApprovalDecision | None = None
    proposed_actions: list[dict[str, Any]] = Field(default_factory=list)
    execution_results: list[ExecutionResult] = Field(default_factory=list)
    executed_actions: list[dict[str, Any]] = Field(default_factory=list)
    verification: VerificationResult | None = None
    rollback: RollbackResult | None = None
    retry_count: int = Field(default=0, ge=0)
    analysis_attempts: int = Field(default=0, ge=0)
    planning_attempts: int = Field(default=0, ge=0)
    llm_input_tokens: int = Field(default=0, ge=0)
    llm_output_tokens: int = Field(default=0, ge=0)
    estimated_cost_usd: float = Field(default=0, ge=0)
    error: WorkflowError | None = None
    errors: list[dict[str, Any]] = Field(default_factory=list)
    audit_events: Annotated[list[dict[str, Any]], operator.add] = Field(
        default_factory=list
    )
    final_report: dict[str, Any] | None = None

    @field_validator("incident_id")
    @classmethod
    def incident_id_is_valid(cls, value: str) -> str:
        if not value.startswith("INC-"):
            raise ValueError("incident_id must start with INC-.")
        return value


def state_dict(state: IncidentWorkflowState | dict[str, Any]) -> dict[str, Any]:
    if isinstance(state, IncidentWorkflowState):
        return state.model_dump(mode="json")
    return state
