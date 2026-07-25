"""Add durable Wazuh alert memory, cursors, references, and stage history."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260725_09"
down_revision = "20260725_08"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "soc_wazuh_alerts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("wazuh_document_id", sa.String(256), nullable=False),
        sa.Column("wazuh_index", sa.String(256), nullable=False),
        sa.Column("event_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("agent_id", sa.String(32)),
        sa.Column("agent_name", sa.String(256)),
        sa.Column("rule_id", sa.String(64)),
        sa.Column("rule_level", sa.Integer(), nullable=False),
        sa.Column("source_ip", sa.String(64)),
        sa.Column("destination_ip", sa.String(64)),
        sa.Column("target_user", sa.String(256)),
        sa.Column("event_type", sa.String(64)),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("raw_alert", postgresql.JSONB(), nullable=False),
        sa.Column("normalized_at", sa.DateTime(timezone=True)),
        sa.Column(
            "correlation_status",
            sa.String(32),
            nullable=False,
            server_default="pending",
        ),
        sa.UniqueConstraint(
            "wazuh_index",
            "wazuh_document_id",
            name="uq_soc_wazuh_alert_document",
        ),
    )
    for name, columns in (
        ("ix_soc_wazuh_alerts_wazuh_document_id", ["wazuh_document_id"]),
        ("ix_soc_wazuh_alerts_event_timestamp", ["event_timestamp"]),
        ("ix_soc_wazuh_alerts_agent_id", ["agent_id"]),
        ("ix_soc_wazuh_alerts_rule_id", ["rule_id"]),
        ("ix_soc_wazuh_alerts_source_ip", ["source_ip"]),
        ("ix_soc_wazuh_alerts_target_user", ["target_user"]),
        ("ix_soc_wazuh_alerts_event_type", ["event_type"]),
        ("ix_soc_wazuh_alerts_fingerprint", ["fingerprint"]),
        ("ix_soc_wazuh_alerts_normalized_at", ["normalized_at"]),
        (
            "ix_soc_wazuh_alerts_correlation_status",
            ["correlation_status"],
        ),
        (
            "ix_soc_wazuh_alerts_agent_timestamp",
            ["agent_id", "event_timestamp"],
        ),
    ):
        op.create_index(name, "soc_wazuh_alerts", columns)

    op.create_table(
        "soc_normalized_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "alert_id",
            sa.Integer(),
            sa.ForeignKey("soc_wazuh_alerts.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("attack_family", sa.String(64), nullable=False),
        sa.Column("severity_score", sa.Integer(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("asset_id", sa.String(256)),
        sa.Column("source_ip", sa.String(64)),
        sa.Column("destination_ip", sa.String(64)),
        sa.Column("target_user", sa.String(256)),
        sa.Column("process_name", sa.String(256)),
        sa.Column("command_line", sa.Text()),
        sa.Column("mitre_techniques", postgresql.JSONB(), nullable=False),
        sa.Column("normalized_data", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    for name, column in (
        ("ix_soc_normalized_events_alert_id", "alert_id"),
        ("ix_soc_normalized_events_event_type", "event_type"),
        ("ix_soc_normalized_events_category", "category"),
        ("ix_soc_normalized_events_attack_family", "attack_family"),
        ("ix_soc_normalized_events_asset_id", "asset_id"),
        ("ix_soc_normalized_events_source_ip", "source_ip"),
        ("ix_soc_normalized_events_target_user", "target_user"),
    ):
        op.create_index(name, "soc_normalized_events", [column])

    op.create_table(
        "soc_ingestion_checkpoints",
        sa.Column("source_name", sa.String(128), primary_key=True),
        sa.Column("last_event_timestamp", sa.DateTime(timezone=True)),
        sa.Column("last_document_id", sa.String(256)),
        sa.Column("search_after", postgresql.JSONB()),
        sa.Column("last_run_started_at", sa.DateTime(timezone=True)),
        sa.Column("last_run_completed_at", sa.DateTime(timezone=True)),
        sa.Column(
            "last_alert_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "status",
            sa.String(32),
            nullable=False,
            server_default="idle",
        ),
        sa.Column("error_message", sa.Text()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_soc_ingestion_checkpoints_status",
        "soc_ingestion_checkpoints",
        ["status"],
    )

    op.create_table(
        "soc_finding_alerts",
        sa.Column(
            "finding_id",
            sa.String(64),
            sa.ForeignKey("soc_findings.finding_id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "alert_id",
            sa.Integer(),
            sa.ForeignKey("soc_wazuh_alerts.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "relationship",
            sa.String(32),
            nullable=False,
            server_default="supporting",
        ),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "soc_user_alert_cursors",
        sa.Column("user_id", sa.String(128), primary_key=True),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_finding_version", sa.Integer()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "soc_conversation_references",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "conversation_id",
            sa.String(128),
            sa.ForeignKey("soc_conversations.conversation_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("message_id", sa.String(64), nullable=False),
        sa.Column("organization_id", sa.String(128), nullable=False),
        sa.Column("reference_type", sa.String(32), nullable=False),
        sa.Column("reference_value", sa.String(256), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    for name, columns in (
        ("ix_soc_conversation_references_conversation_id", ["conversation_id"]),
        ("ix_soc_conversation_references_message_id", ["message_id"]),
        ("ix_soc_conversation_references_organization_id", ["organization_id"]),
        ("ix_soc_conversation_references_reference_type", ["reference_type"]),
        ("ix_soc_conversation_references_reference_value", ["reference_value"]),
        ("ix_soc_conversation_references_created_at", ["created_at"]),
        (
            "ix_soc_conversation_references_latest",
            ["conversation_id", "created_at"],
        ),
    ):
        op.create_index(name, "soc_conversation_references", columns)

    op.create_table(
        "soc_investigation_steps",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "investigation_id",
            sa.String(64),
            sa.ForeignKey(
                "soc_investigations.investigation_id",
                ondelete="CASCADE",
            ),
            nullable=False,
        ),
        sa.Column("stage", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("input_data", postgresql.JSONB(), nullable=False),
        sa.Column("output_data", postgresql.JSONB(), nullable=False),
        sa.Column("error_code", sa.String(128)),
        sa.Column("error_message", sa.Text()),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
    )
    for name, column in (
        ("ix_soc_investigation_steps_investigation_id", "investigation_id"),
        ("ix_soc_investigation_steps_stage", "stage"),
        ("ix_soc_investigation_steps_status", "status"),
        ("ix_soc_investigation_steps_error_code", "error_code"),
    ):
        op.create_index(name, "soc_investigation_steps", [column])

    op.add_column(
        "soc_investigations",
        sa.Column(
            "primary_alert_id",
            sa.Integer(),
            sa.ForeignKey("soc_wazuh_alerts.id", ondelete="SET NULL"),
        ),
    )
    op.add_column(
        "soc_investigations",
        sa.Column(
            "finding_id",
            sa.String(64),
            sa.ForeignKey("soc_findings.finding_id", ondelete="SET NULL"),
        ),
    )
    op.add_column(
        "soc_investigations",
        sa.Column("failure_code", sa.String(128)),
    )
    op.add_column(
        "soc_investigations",
        sa.Column("failure_reason", sa.Text()),
    )
    op.add_column(
        "soc_investigations",
        sa.Column("last_successful_stage", sa.String(64)),
    )
    op.create_index(
        "ix_soc_investigations_primary_alert_id",
        "soc_investigations",
        ["primary_alert_id"],
    )
    op.create_index(
        "ix_soc_investigations_finding_id",
        "soc_investigations",
        ["finding_id"],
    )
    op.create_index(
        "ix_soc_investigations_failure_code",
        "soc_investigations",
        ["failure_code"],
    )
    op.create_index(
        "uq_soc_active_investigation_per_alert",
        "soc_investigations",
        ["organization_id", "alert_id"],
        unique=True,
        postgresql_where=sa.text(
            "status IN ('created', 'queued', 'running', 'awaiting_approval')"
        ),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_soc_active_investigation_per_alert",
        table_name="soc_investigations",
    )
    for name in (
        "ix_soc_investigations_failure_code",
        "ix_soc_investigations_finding_id",
        "ix_soc_investigations_primary_alert_id",
    ):
        op.drop_index(name, table_name="soc_investigations")
    for column in (
        "last_successful_stage",
        "failure_reason",
        "failure_code",
        "finding_id",
        "primary_alert_id",
    ):
        op.drop_column("soc_investigations", column)
    op.drop_table("soc_investigation_steps")
    op.drop_table("soc_conversation_references")
    op.drop_table("soc_user_alert_cursors")
    op.drop_table("soc_finding_alerts")
    op.drop_table("soc_ingestion_checkpoints")
    op.drop_table("soc_normalized_events")
    op.drop_table("soc_wazuh_alerts")
