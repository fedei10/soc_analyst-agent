"""Persist triage findings, verdicts, and analyst feedback."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260725_08"
down_revision = "20260724_07"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "soc_findings",
        sa.Column("finding_id", sa.String(64), primary_key=True),
        sa.Column("organization_id", sa.String(128), nullable=False),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("attack_family", sa.String(64), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("severity_score", sa.Integer(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("alert_count", sa.Integer(), nullable=False),
        sa.Column("representative_alert_id", sa.String(256), nullable=False),
        sa.Column("evidence_refs", postgresql.JSONB(), nullable=False),
        sa.Column("finding", postgresql.JSONB(), nullable=False),
        sa.Column("verdict", postgresql.JSONB(), nullable=False),
        sa.Column("verdict_label", sa.String(32), nullable=False),
        sa.Column("verdict_confidence", sa.Float(), nullable=False),
        sa.Column("enrichment", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_soc_findings_organization_id",
        "soc_findings",
        ["organization_id"],
    )
    op.create_index(
        "ix_soc_findings_category",
        "soc_findings",
        ["category"],
    )
    op.create_index(
        "ix_soc_findings_attack_family",
        "soc_findings",
        ["attack_family"],
    )
    op.create_index(
        "ix_soc_findings_event_type",
        "soc_findings",
        ["event_type"],
    )
    op.create_index(
        "ix_soc_findings_severity",
        "soc_findings",
        ["severity"],
    )
    op.create_index(
        "ix_soc_findings_updated_at",
        "soc_findings",
        ["updated_at"],
    )
    op.create_index(
        "ix_soc_findings_verdict_label",
        "soc_findings",
        ["verdict_label"],
    )
    op.create_index(
        "ix_soc_findings_org_severity_updated",
        "soc_findings",
        ["organization_id", "severity", "updated_at"],
    )

    op.create_table(
        "soc_finding_feedback",
        sa.Column("feedback_id", sa.String(64), primary_key=True),
        sa.Column(
            "finding_id",
            sa.String(64),
            sa.ForeignKey("soc_findings.finding_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("organization_id", sa.String(128), nullable=False),
        sa.Column("reviewer_user_id", sa.String(128), nullable=False),
        sa.Column("disposition", sa.String(64), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_soc_finding_feedback_finding_id",
        "soc_finding_feedback",
        ["finding_id"],
    )
    op.create_index(
        "ix_soc_finding_feedback_organization_id",
        "soc_finding_feedback",
        ["organization_id"],
    )
    op.create_index(
        "ix_soc_finding_feedback_reviewer_user_id",
        "soc_finding_feedback",
        ["reviewer_user_id"],
    )
    op.create_index(
        "ix_soc_finding_feedback_disposition",
        "soc_finding_feedback",
        ["disposition"],
    )
    op.create_index(
        "ix_soc_finding_feedback_created_at",
        "soc_finding_feedback",
        ["created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_soc_finding_feedback_created_at", table_name="soc_finding_feedback")
    op.drop_index("ix_soc_finding_feedback_disposition", table_name="soc_finding_feedback")
    op.drop_index("ix_soc_finding_feedback_reviewer_user_id", table_name="soc_finding_feedback")
    op.drop_index("ix_soc_finding_feedback_organization_id", table_name="soc_finding_feedback")
    op.drop_index("ix_soc_finding_feedback_finding_id", table_name="soc_finding_feedback")
    op.drop_table("soc_finding_feedback")

    op.drop_index("ix_soc_findings_org_severity_updated", table_name="soc_findings")
    op.drop_index("ix_soc_findings_verdict_label", table_name="soc_findings")
    op.drop_index("ix_soc_findings_updated_at", table_name="soc_findings")
    op.drop_index("ix_soc_findings_severity", table_name="soc_findings")
    op.drop_index("ix_soc_findings_event_type", table_name="soc_findings")
    op.drop_index("ix_soc_findings_attack_family", table_name="soc_findings")
    op.drop_index("ix_soc_findings_category", table_name="soc_findings")
    op.drop_index("ix_soc_findings_organization_id", table_name="soc_findings")
    op.drop_table("soc_findings")
