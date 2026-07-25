"""Durable alert ingestion, analyst cursor, and conversation reference records."""

from datetime import datetime
from typing import Any

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.models.investigation import JSON_VALUE, utc_now


class WazuhAlertRecord(Base):
    __tablename__ = "soc_wazuh_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    wazuh_document_id: Mapped[str] = mapped_column(String(256), index=True)
    wazuh_index: Mapped[str] = mapped_column(String(256))
    event_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
    )
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
    )
    agent_id: Mapped[str | None] = mapped_column(String(32), index=True)
    agent_name: Mapped[str | None] = mapped_column(String(256))
    rule_id: Mapped[str | None] = mapped_column(String(64), index=True)
    rule_level: Mapped[int] = mapped_column(Integer, default=0)
    source_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64))
    target_user: Mapped[str | None] = mapped_column(String(256), index=True)
    event_type: Mapped[str | None] = mapped_column(String(64), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    raw_alert: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE)
    normalized_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        index=True,
    )
    correlation_status: Mapped[str] = mapped_column(
        String(32),
        default="pending",
        index=True,
    )

    __table_args__ = (
        UniqueConstraint(
            "wazuh_index",
            "wazuh_document_id",
            name="uq_soc_wazuh_alert_document",
        ),
        Index(
            "ix_soc_wazuh_alerts_agent_timestamp",
            "agent_id",
            "event_timestamp",
        ),
    )


class NormalizedEventRecord(Base):
    __tablename__ = "soc_normalized_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[int] = mapped_column(
        ForeignKey("soc_wazuh_alerts.id", ondelete="CASCADE"),
        unique=True,
        index=True,
    )
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    category: Mapped[str] = mapped_column(String(64), index=True)
    attack_family: Mapped[str] = mapped_column(String(64), index=True)
    severity_score: Mapped[int] = mapped_column(Integer)
    confidence: Mapped[float] = mapped_column(Float)
    asset_id: Mapped[str | None] = mapped_column(String(256), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64))
    target_user: Mapped[str | None] = mapped_column(String(256), index=True)
    process_name: Mapped[str | None] = mapped_column(String(256))
    command_line: Mapped[str | None] = mapped_column(Text)
    mitre_techniques: Mapped[list[str]] = mapped_column(JSON_VALUE, default=list)
    normalized_data: Mapped[dict[str, Any]] = mapped_column(
        JSON_VALUE,
        default=dict,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
    )


class IngestionCheckpointRecord(Base):
    __tablename__ = "soc_ingestion_checkpoints"

    source_name: Mapped[str] = mapped_column(String(128), primary_key=True)
    last_event_timestamp: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    last_document_id: Mapped[str | None] = mapped_column(String(256))
    search_after: Mapped[list[Any] | None] = mapped_column(JSON_VALUE)
    last_run_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    last_run_completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    last_alert_count: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(32), default="idle", index=True)
    error_message: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
    )


class FindingAlertRecord(Base):
    __tablename__ = "soc_finding_alerts"

    finding_id: Mapped[str] = mapped_column(
        ForeignKey("soc_findings.finding_id", ondelete="CASCADE"),
        primary_key=True,
    )
    alert_id: Mapped[int] = mapped_column(
        ForeignKey("soc_wazuh_alerts.id", ondelete="CASCADE"),
        primary_key=True,
    )
    relationship: Mapped[str] = mapped_column(
        String(32),
        default="supporting",
    )
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
    )


class UserAlertCursorRecord(Base):
    __tablename__ = "soc_user_alert_cursors"

    user_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    last_checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_finding_version: Mapped[int | None] = mapped_column(Integer)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
    )


class ConversationReferenceRecord(Base):
    __tablename__ = "soc_conversation_references"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    conversation_id: Mapped[str] = mapped_column(
        ForeignKey("soc_conversations.conversation_id", ondelete="CASCADE"),
        index=True,
    )
    message_id: Mapped[str] = mapped_column(String(64), index=True)
    organization_id: Mapped[str] = mapped_column(String(128), index=True)
    reference_type: Mapped[str] = mapped_column(String(32), index=True)
    reference_value: Mapped[str] = mapped_column(String(256), index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        index=True,
    )

    __table_args__ = (
        Index(
            "ix_soc_conversation_references_latest",
            "conversation_id",
            "created_at",
        ),
    )


class InvestigationStepRecord(Base):
    __tablename__ = "soc_investigation_steps"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("soc_investigations.investigation_id", ondelete="CASCADE"),
        index=True,
    )
    stage: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    input_data: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict)
    output_data: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict)
    error_code: Mapped[str | None] = mapped_column(String(128), index=True)
    error_message: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
