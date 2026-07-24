"""Persist L1, L2, and L3 analyst handoff reports."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260724_07"
down_revision = "20260724_06"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "soc_tier_reports",
        sa.Column("report_id", sa.String(100), primary_key=True),
        sa.Column(
            "investigation_id",
            sa.String(64),
            sa.ForeignKey(
                "soc_investigations.investigation_id",
                ondelete="CASCADE",
            ),
            nullable=False,
        ),
        sa.Column("organization_id", sa.String(128), nullable=False),
        sa.Column("tier", sa.String(8), nullable=False),
        sa.Column("report", postgresql.JSONB(), nullable=False),
        sa.Column(
            "generated_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "investigation_id",
            "tier",
            name="uq_soc_tier_report_investigation_tier",
        ),
    )
    op.create_index(
        "ix_soc_tier_reports_investigation_id",
        "soc_tier_reports",
        ["investigation_id"],
    )
    op.create_index(
        "ix_soc_tier_reports_organization_id",
        "soc_tier_reports",
        ["organization_id"],
    )
    op.create_index(
        "ix_soc_tier_reports_tier",
        "soc_tier_reports",
        ["tier"],
    )
    op.create_index(
        "ix_soc_tier_reports_generated_at",
        "soc_tier_reports",
        ["generated_at"],
    )
    op.create_index(
        "ix_soc_tier_reports_org_investigation",
        "soc_tier_reports",
        ["organization_id", "investigation_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_soc_tier_reports_org_investigation",
        table_name="soc_tier_reports",
    )
    op.drop_index(
        "ix_soc_tier_reports_generated_at",
        table_name="soc_tier_reports",
    )
    op.drop_index(
        "ix_soc_tier_reports_tier",
        table_name="soc_tier_reports",
    )
    op.drop_index(
        "ix_soc_tier_reports_organization_id",
        table_name="soc_tier_reports",
    )
    op.drop_index(
        "ix_soc_tier_reports_investigation_id",
        table_name="soc_tier_reports",
    )
    op.drop_table("soc_tier_reports")
