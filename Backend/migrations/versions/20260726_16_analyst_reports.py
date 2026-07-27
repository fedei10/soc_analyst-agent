"""Persist chat-generated analyst reports."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260726_16"
down_revision = "20260726_15"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "soc_reports",
        sa.Column("report_id", sa.String(64), primary_key=True),
        sa.Column("organization_id", sa.String(128), nullable=False),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("body_markdown", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(32), nullable=True),
        sa.Column("source", sa.String(32), nullable=False, server_default="chat"),
        sa.Column("created_by", sa.String(128), nullable=False),
        sa.Column("conversation_id", sa.String(64), nullable=True),
        sa.Column("related_alert_ids", postgresql.JSONB(), nullable=False),
        sa.Column("related_finding_ids", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_soc_reports_organization_id",
        "soc_reports",
        ["organization_id"],
    )
    op.create_index(
        "ix_soc_reports_severity",
        "soc_reports",
        ["severity"],
    )
    op.create_index(
        "ix_soc_reports_source",
        "soc_reports",
        ["source"],
    )
    op.create_index(
        "ix_soc_reports_created_by",
        "soc_reports",
        ["created_by"],
    )
    op.create_index(
        "ix_soc_reports_conversation_id",
        "soc_reports",
        ["conversation_id"],
    )
    op.create_index(
        "ix_soc_reports_created_at",
        "soc_reports",
        ["created_at"],
    )
    op.create_index(
        "ix_soc_reports_org_created",
        "soc_reports",
        ["organization_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_soc_reports_org_created", table_name="soc_reports")
    op.drop_index("ix_soc_reports_created_at", table_name="soc_reports")
    op.drop_index("ix_soc_reports_conversation_id", table_name="soc_reports")
    op.drop_index("ix_soc_reports_created_by", table_name="soc_reports")
    op.drop_index("ix_soc_reports_source", table_name="soc_reports")
    op.drop_index("ix_soc_reports_severity", table_name="soc_reports")
    op.drop_index("ix_soc_reports_organization_id", table_name="soc_reports")
    op.drop_table("soc_reports")
