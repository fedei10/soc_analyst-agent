"""Add durable rollback claim state for temporary response actions."""

from alembic import op
import sqlalchemy as sa


revision = "20260725_14"
down_revision = "20260725_13"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "soc_response_actions",
        sa.Column("rollback_claim_id", sa.String(100)),
    )
    op.add_column(
        "soc_response_actions",
        sa.Column(
            "rollback_retry_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )
    op.add_column(
        "soc_response_actions",
        sa.Column("rollback_completed_at", sa.DateTime(timezone=True)),
    )
    op.create_index(
        "ix_soc_response_actions_rollback_claim_id",
        "soc_response_actions",
        ["rollback_claim_id"],
    )
    op.create_index(
        "ix_soc_response_actions_rollback_completed_at",
        "soc_response_actions",
        ["rollback_completed_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_soc_response_actions_rollback_completed_at",
        table_name="soc_response_actions",
    )
    op.drop_index(
        "ix_soc_response_actions_rollback_claim_id",
        table_name="soc_response_actions",
    )
    op.drop_column("soc_response_actions", "rollback_completed_at")
    op.drop_column("soc_response_actions", "rollback_retry_count")
    op.drop_column("soc_response_actions", "rollback_claim_id")
