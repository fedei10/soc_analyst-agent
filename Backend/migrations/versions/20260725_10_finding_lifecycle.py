"""Add finding correlation and lifecycle metadata."""

from alembic import op
import sqlalchemy as sa


revision = "20260725_10"
down_revision = "20260725_09"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "soc_findings",
        sa.Column("correlation_key", sa.String(256)),
    )
    op.add_column(
        "soc_findings",
        sa.Column(
            "status",
            sa.String(32),
            nullable=False,
            server_default="open",
        ),
    )
    op.add_column(
        "soc_findings",
        sa.Column(
            "version",
            sa.Integer(),
            nullable=False,
            server_default="1",
        ),
    )
    op.execute(
        "UPDATE soc_findings SET correlation_key = finding_id "
        "WHERE correlation_key IS NULL"
    )
    op.alter_column(
        "soc_findings",
        "correlation_key",
        nullable=False,
    )
    op.create_index(
        "ix_soc_findings_correlation_key",
        "soc_findings",
        ["correlation_key"],
    )
    op.create_index(
        "ix_soc_findings_status",
        "soc_findings",
        ["status"],
    )
    op.create_index(
        "ix_soc_findings_org_status_updated",
        "soc_findings",
        ["organization_id", "status", "updated_at"],
    )
    op.create_check_constraint(
        "ck_soc_findings_status",
        "soc_findings",
        "status IN ('open', 'investigating', 'contained', 'resolved', "
        "'false_positive')",
    )
def downgrade() -> None:
    op.drop_constraint(
        "ck_soc_findings_status",
        "soc_findings",
        type_="check",
    )
    for name in (
        "ix_soc_findings_org_status_updated",
        "ix_soc_findings_status",
        "ix_soc_findings_correlation_key",
    ):
        op.drop_index(name, table_name="soc_findings")
    for column in ("version", "status", "correlation_key"):
        op.drop_column("soc_findings", column)
