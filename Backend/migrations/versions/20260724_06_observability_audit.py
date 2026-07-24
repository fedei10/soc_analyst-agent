"""Add correlation and integrity fields to SOC audit events."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260724_06"
down_revision = "20260724_05"
branch_labels = None
depends_on = None


def upgrade() -> None:
    columns = (
        sa.Column("actor_type", sa.String(32)),
        sa.Column("actor_id", sa.String(128)),
        sa.Column("request_id", sa.String(128)),
        sa.Column("trace_id", sa.String(32)),
        sa.Column("conversation_id", sa.String(128)),
        sa.Column("target_type", sa.String(64)),
        sa.Column("target_id", sa.String(256)),
        sa.Column("outcome", sa.String(32)),
        sa.Column("reason_code", sa.String(128)),
        sa.Column(
            "metadata_json",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("previous_hash", sa.String(64)),
        sa.Column("event_hash", sa.String(64)),
    )
    for column in columns:
        op.add_column("soc_audit_events", column)

    op.execute(
        """
        UPDATE soc_audit_events
        SET actor_type = CASE
                WHEN actor_user_id IS NULL THEN 'system'
                ELSE 'user'
            END,
            actor_id = actor_user_id
        """
    )
    for column in (
        "actor_type",
        "actor_id",
        "request_id",
        "trace_id",
        "conversation_id",
        "target_type",
        "target_id",
        "outcome",
        "reason_code",
        "event_hash",
    ):
        op.create_index(
            f"ix_soc_audit_events_{column}",
            "soc_audit_events",
            [column],
            unique=column == "event_hash",
        )
    op.alter_column(
        "soc_audit_events",
        "metadata_json",
        server_default=None,
    )


def downgrade() -> None:
    for column in (
        "event_hash",
        "reason_code",
        "outcome",
        "target_id",
        "target_type",
        "conversation_id",
        "trace_id",
        "request_id",
        "actor_id",
        "actor_type",
    ):
        op.drop_index(
            f"ix_soc_audit_events_{column}",
            table_name="soc_audit_events",
        )
    for column in (
        "event_hash",
        "previous_hash",
        "metadata_json",
        "reason_code",
        "outcome",
        "target_id",
        "target_type",
        "conversation_id",
        "trace_id",
        "request_id",
        "actor_id",
        "actor_type",
    ):
        op.drop_column("soc_audit_events", column)
