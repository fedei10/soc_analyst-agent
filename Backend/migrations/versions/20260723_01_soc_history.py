"""Create durable SOC investigation history tables."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260723_01"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "soc_investigations",
        sa.Column("investigation_id", sa.String(64), primary_key=True),
        sa.Column("alert_id", sa.String(256), nullable=False),
        sa.Column("agent_id", sa.String(32)),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("current_stage", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(32)),
        sa.Column("confidence", sa.Float()),
        sa.Column("initiated_by", sa.String(128)),
        sa.Column("initiation_reason", sa.Text()),
        sa.Column("snapshot", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
    )
    op.create_index(
        "ix_soc_investigations_alert_id",
        "soc_investigations",
        ["alert_id"],
    )
    op.create_index(
        "ix_soc_investigations_agent_id",
        "soc_investigations",
        ["agent_id"],
    )
    op.create_index(
        "ix_soc_investigations_status_updated",
        "soc_investigations",
        ["status", "updated_at"],
    )
    op.create_index(
        "ix_soc_investigations_status",
        "soc_investigations",
        ["status"],
    )
    op.create_index(
        "ix_soc_investigations_current_stage",
        "soc_investigations",
        ["current_stage"],
    )
    op.create_index(
        "ix_soc_investigations_severity",
        "soc_investigations",
        ["severity"],
    )
    op.create_index(
        "ix_soc_investigations_updated_at",
        "soc_investigations",
        ["updated_at"],
    )

    op.create_table(
        "soc_agent_runs",
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
        sa.Column("tier", sa.String(8), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("result", postgresql.JSONB(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "investigation_id",
            "tier",
            name="uq_soc_agent_run_investigation_tier",
        ),
    )
    op.create_index(
        "ix_soc_agent_runs_investigation_id",
        "soc_agent_runs",
        ["investigation_id"],
    )
    op.create_index("ix_soc_agent_runs_tier", "soc_agent_runs", ["tier"])

    op.create_table(
        "soc_investigation_reports",
        sa.Column(
            "investigation_id",
            sa.String(64),
            sa.ForeignKey(
                "soc_investigations.investigation_id",
                ondelete="CASCADE",
            ),
            primary_key=True,
        ),
        sa.Column("report", postgresql.JSONB(), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "soc_audit_events",
        sa.Column("event_id", sa.String(64), primary_key=True),
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
        sa.Column("event", sa.String(128), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
    )
    op.create_index(
        "ix_soc_audit_events_investigation_id",
        "soc_audit_events",
        ["investigation_id"],
    )
    op.create_index(
        "ix_soc_audit_events_occurred_at",
        "soc_audit_events",
        ["occurred_at"],
    )
    op.create_index(
        "ix_soc_audit_events_stage",
        "soc_audit_events",
        ["stage"],
    )
    op.create_index(
        "ix_soc_audit_events_event",
        "soc_audit_events",
        ["event"],
    )

    op.create_table(
        "soc_response_actions",
        sa.Column("action_id", sa.String(64), primary_key=True),
        sa.Column(
            "investigation_id",
            sa.String(64),
            sa.ForeignKey(
                "soc_investigations.investigation_id",
                ondelete="CASCADE",
            ),
            nullable=False,
        ),
        sa.Column("action_type", sa.String(64), nullable=False),
        sa.Column("target", sa.String(256), nullable=False),
        sa.Column("risk_level", sa.String(32)),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("approval_id", sa.String(100)),
        sa.Column("approved_by", sa.String(100)),
        sa.Column("details", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_soc_response_actions_investigation_id",
        "soc_response_actions",
        ["investigation_id"],
    )
    op.create_index(
        "ix_soc_response_actions_status",
        "soc_response_actions",
        ["status"],
    )
    op.create_index(
        "ix_soc_response_actions_action_type",
        "soc_response_actions",
        ["action_type"],
    )
    op.create_index(
        "ix_soc_response_actions_approval_id",
        "soc_response_actions",
        ["approval_id"],
    )


def downgrade() -> None:
    op.drop_table("soc_response_actions")
    op.drop_table("soc_audit_events")
    op.drop_table("soc_investigation_reports")
    op.drop_table("soc_agent_runs")
    op.drop_table("soc_investigations")
