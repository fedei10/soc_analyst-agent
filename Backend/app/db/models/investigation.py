"""Durable user-scoped SOC records."""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


JSON_VALUE = JSON().with_variant(JSONB(), "postgresql")


def utc_now() -> datetime:
    return datetime.now(UTC)


class UserRecord(Base):
    __tablename__ = "soc_users"

    user_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    email: Mapped[str | None] = mapped_column(String(320), index=True)
    display_name: Mapped[str | None] = mapped_column(String(256))
    active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
    )


class InvestigationRecord(Base):
    __tablename__ = "soc_investigations"

    investigation_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    organization_id: Mapped[str] = mapped_column(
        String(128),
        index=True,
        default="legacy",
    )
    owner_user_id: Mapped[str | None] = mapped_column(String(128), index=True)
    alert_id: Mapped[str] = mapped_column(String(256), index=True)
    primary_alert_id: Mapped[int | None] = mapped_column(
        ForeignKey("soc_wazuh_alerts.id", ondelete="SET NULL"),
        index=True,
    )
    finding_id: Mapped[str | None] = mapped_column(
        ForeignKey("soc_findings.finding_id", ondelete="SET NULL"),
        index=True,
    )
    agent_id: Mapped[str | None] = mapped_column(String(32), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    current_stage: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str | None] = mapped_column(String(32), index=True)
    confidence: Mapped[float | None] = mapped_column(Float)
    initiated_by: Mapped[str | None] = mapped_column(String(128))
    initiated_by_user_id: Mapped[str | None] = mapped_column(
        String(128),
        index=True,
    )
    initiation_reason: Mapped[str | None] = mapped_column(Text)
    failure_code: Mapped[str | None] = mapped_column(String(128), index=True)
    failure_reason: Mapped[str | None] = mapped_column(Text)
    last_successful_stage: Mapped[str | None] = mapped_column(String(64))
    state_version: Mapped[int] = mapped_column(
        Integer,
        default=1,
        server_default="1",
    )
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        index=True,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )

    __table_args__ = (
        Index(
            "ix_soc_investigations_org_status_updated",
            "organization_id",
            "status",
            "updated_at",
        ),
    )


class InvestigationResourceLeaseRecord(Base):
    __tablename__ = "soc_investigation_resource_leases"

    lock_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(128), index=True)
    resource_type: Mapped[str] = mapped_column(String(64), index=True)
    resource_id: Mapped[str] = mapped_column(String(256), index=True)
    lease_token: Mapped[str] = mapped_column(String(64))
    owner_id: Mapped[str] = mapped_column(String(128), index=True)
    acquired_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
    )

    __table_args__ = (
        UniqueConstraint(
            "lease_token",
            name="uq_soc_investigation_resource_leases_token",
        ),
        UniqueConstraint(
            "organization_id",
            "resource_type",
            "resource_id",
            name="uq_soc_investigation_resource_leases_resource",
        ),
        Index(
            "ix_soc_investigation_resource_leases_org_expiry",
            "organization_id",
            "expires_at",
        ),
    )


class AgentRunRecord(Base):
    __tablename__ = "soc_agent_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    parent_run_id: Mapped[str | None] = mapped_column(
        ForeignKey("soc_agent_runs.run_id", ondelete="SET NULL"),
        index=True,
    )
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("soc_investigations.investigation_id", ondelete="CASCADE"),
        index=True,
    )
    organization_id: Mapped[str] = mapped_column(String(128), index=True)
    tier: Mapped[str] = mapped_column(String(8), index=True)
    role: Mapped[str] = mapped_column(String(64), index=True)
    attempt: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(32), index=True)
    provider: Mapped[str | None] = mapped_column(String(64))
    model_name: Mapped[str | None] = mapped_column(String(128))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    tool_activity: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON_VALUE,
        default=list,
    )
    error_code: Mapped[str | None] = mapped_column(String(64), index=True)
    error_summary: Mapped[str | None] = mapped_column(Text)
    result: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
    )

    __table_args__ = (
        Index(
            "ix_soc_agent_runs_org_investigation",
            "organization_id",
            "investigation_id",
        ),
    )


class ToolExecutionRecord(Base):
    __tablename__ = "soc_tool_executions"

    execution_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(
        ForeignKey("soc_agent_runs.run_id", ondelete="CASCADE"),
        index=True,
    )
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("soc_investigations.investigation_id", ondelete="CASCADE"),
        index=True,
    )
    organization_id: Mapped[str] = mapped_column(String(128), index=True)
    tool_name: Mapped[str] = mapped_column(String(128), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    attempt: Mapped[int] = mapped_column(Integer, default=1)
    input_summary: Mapped[dict[str, Any]] = mapped_column(
        JSON_VALUE,
        default=dict,
    )
    output_summary: Mapped[dict[str, Any]] = mapped_column(
        JSON_VALUE,
        default=dict,
    )
    error_code: Mapped[str | None] = mapped_column(String(64))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )


class EvidenceRecord(Base):
    __tablename__ = "soc_evidence_records"

    evidence_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("soc_investigations.investigation_id", ondelete="CASCADE"),
        index=True,
    )
    organization_id: Mapped[str] = mapped_column(String(128), index=True)
    source_type: Mapped[str] = mapped_column(String(64), index=True)
    source_ref: Mapped[str] = mapped_column(String(512), index=True)
    content_hash: Mapped[str] = mapped_column(String(64), index=True)
    excerpt: Mapped[str | None] = mapped_column(Text)
    evidence_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSON_VALUE,
        default=dict,
    )
    observed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
    )

    __table_args__ = (
        UniqueConstraint(
            "investigation_id",
            "content_hash",
            name="uq_soc_evidence_investigation_hash",
        ),
    )


class InvestigationReportRecord(Base):
    __tablename__ = "soc_investigation_reports"

    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("soc_investigations.investigation_id", ondelete="CASCADE"),
        primary_key=True,
    )
    organization_id: Mapped[str] = mapped_column(String(128), index=True)
    report: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE)
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
    )


class TierReportRecord(Base):
    __tablename__ = "soc_tier_reports"

    report_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("soc_investigations.investigation_id", ondelete="CASCADE"),
        index=True,
    )
    organization_id: Mapped[str] = mapped_column(String(128), index=True)
    tier: Mapped[str] = mapped_column(String(8), index=True)
    report: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE)
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
    )

    __table_args__ = (
        UniqueConstraint(
            "investigation_id",
            "tier",
            name="uq_soc_tier_report_investigation_tier",
        ),
        Index(
            "ix_soc_tier_reports_org_investigation",
            "organization_id",
            "investigation_id",
        ),
    )


class AuditEventRecord(Base):
    __tablename__ = "soc_audit_events"

    event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("soc_investigations.investigation_id", ondelete="CASCADE"),
        index=True,
    )
    organization_id: Mapped[str] = mapped_column(String(128), index=True)
    actor_user_id: Mapped[str | None] = mapped_column(String(128), index=True)
    actor_type: Mapped[str | None] = mapped_column(String(32), index=True)
    actor_id: Mapped[str | None] = mapped_column(String(128), index=True)
    request_id: Mapped[str | None] = mapped_column(String(128), index=True)
    trace_id: Mapped[str | None] = mapped_column(String(32), index=True)
    conversation_id: Mapped[str | None] = mapped_column(
        String(128),
        index=True,
    )
    target_type: Mapped[str | None] = mapped_column(String(64), index=True)
    target_id: Mapped[str | None] = mapped_column(String(256), index=True)
    outcome: Mapped[str | None] = mapped_column(String(32), index=True)
    reason_code: Mapped[str | None] = mapped_column(String(128), index=True)
    stage: Mapped[str] = mapped_column(String(64), index=True)
    event: Mapped[str] = mapped_column(String(128), index=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
    )
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        JSON_VALUE,
        default=dict,
    )
    previous_hash: Mapped[str | None] = mapped_column(String(64))
    event_hash: Mapped[str | None] = mapped_column(
        String(64),
        unique=True,
        index=True,
    )
    payload: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE)


class ApprovalRecord(Base):
    __tablename__ = "soc_approvals"

    approval_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("soc_investigations.investigation_id", ondelete="CASCADE"),
        index=True,
    )
    organization_id: Mapped[str] = mapped_column(String(128), index=True)
    incident_id: Mapped[str] = mapped_column(String(64), index=True)
    plan_id: Mapped[str] = mapped_column(String(64), index=True)
    plan_version: Mapped[int] = mapped_column(Integer)
    plan_hash: Mapped[str] = mapped_column(String(64), index=True)
    evidence_version: Mapped[str] = mapped_column(String(64), index=True)
    policy_version: Mapped[str] = mapped_column(String(64))
    action_catalogue_version: Mapped[str] = mapped_column(String(64))
    required_role: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(32), index=True)
    proposed_actions: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON_VALUE,
        default=list,
    )
    decision: Mapped[dict[str, Any] | None] = mapped_column(JSON_VALUE)
    decided_by_user_id: Mapped[str | None] = mapped_column(
        String(128),
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        index=True,
    )
    decided_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        index=True,
    )
    invalidated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        index=True,
    )
    invalidation_reason: Mapped[str | None] = mapped_column(String(128))


class ResponseActionRecord(Base):
    __tablename__ = "soc_response_actions"

    action_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("soc_investigations.investigation_id", ondelete="CASCADE"),
        index=True,
    )
    organization_id: Mapped[str] = mapped_column(String(128), index=True)
    action_type: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str] = mapped_column(String(256))
    risk_level: Mapped[str | None] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(32), index=True)
    plan_id: Mapped[str | None] = mapped_column(String(64), index=True)
    plan_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    evidence_version: Mapped[str | None] = mapped_column(String(64), index=True)
    approval_id: Mapped[str | None] = mapped_column(String(100), index=True)
    approved_by: Mapped[str | None] = mapped_column(String(100))
    approved_by_user_id: Mapped[str | None] = mapped_column(
        String(128),
        index=True,
    )
    execution_id: Mapped[str | None] = mapped_column(
        String(100),
        index=True,
    )
    executor_user_id: Mapped[str | None] = mapped_column(
        String(128),
        index=True,
    )
    claimed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        index=True,
    )
    executed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        index=True,
    )
    rollback_action_id: Mapped[str | None] = mapped_column(
        String(64),
        index=True,
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        index=True,
    )
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    rollback_claim_id: Mapped[str | None] = mapped_column(
        String(100),
        index=True,
    )
    rollback_retry_count: Mapped[int] = mapped_column(Integer, default=0)
    last_rollback_attempt: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
    )
    rollback_completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        index=True,
    )
    details: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
    )


class ConversationRecord(Base):
    __tablename__ = "soc_conversations"

    conversation_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(128), index=True)
    owner_user_id: Mapped[str] = mapped_column(String(128), index=True)
    title: Mapped[str | None] = mapped_column(String(256))
    status: Mapped[str] = mapped_column(String(32), default="active", index=True)
    conversation_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSON_VALUE,
        default=dict,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        index=True,
    )
    last_message_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        index=True,
    )

    __table_args__ = (
        Index(
            "ix_soc_conversations_org_updated",
            "organization_id",
            "updated_at",
        ),
    )


class ConversationMessageRecord(Base):
    __tablename__ = "soc_conversation_messages"

    message_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    conversation_id: Mapped[str] = mapped_column(
        ForeignKey("soc_conversations.conversation_id", ondelete="CASCADE"),
        index=True,
    )
    organization_id: Mapped[str] = mapped_column(String(128), index=True)
    sender_user_id: Mapped[str | None] = mapped_column(String(128), index=True)
    role: Mapped[str] = mapped_column(String(32), index=True)
    content: Mapped[str] = mapped_column(Text)
    content_hash: Mapped[str] = mapped_column(String(64), index=True)
    message_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSON_VALUE,
        default=dict,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        index=True,
    )
    retention_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        index=True,
    )


class ConversationSummaryRecord(Base):
    __tablename__ = "soc_conversation_summaries"

    summary_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    conversation_id: Mapped[str] = mapped_column(
        ForeignKey("soc_conversations.conversation_id", ondelete="CASCADE"),
        index=True,
    )
    organization_id: Mapped[str] = mapped_column(String(128), index=True)
    content: Mapped[str] = mapped_column(Text)
    message_count: Mapped[int] = mapped_column(Integer)
    through_message_id: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        index=True,
    )


class CuratedMemoryRecord(Base):
    __tablename__ = "soc_curated_memories"

    memory_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(128), index=True)
    user_id: Mapped[str | None] = mapped_column(String(128), index=True)
    namespace: Mapped[str] = mapped_column(String(256), index=True)
    memory_key: Mapped[str] = mapped_column(String(256))
    asset_id: Mapped[str | None] = mapped_column(String(256), index=True)
    investigation_id: Mapped[str | None] = mapped_column(
        ForeignKey("soc_investigations.investigation_id", ondelete="SET NULL"),
        index=True,
    )
    value: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE)
    content_hash: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        index=True,
    )

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "namespace",
            "memory_key",
            name="uq_soc_memory_org_namespace_key",
        ),
    )
