"""Add durable response execution claims."""

from alembic import op
import sqlalchemy as sa


revision = "20260724_05"
down_revision = "20260724_04"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "soc_response_actions",
        sa.Column("execution_id", sa.String(100)),
    )
    op.add_column(
        "soc_response_actions",
        sa.Column("executor_user_id", sa.String(128)),
    )
    op.add_column(
        "soc_response_actions",
        sa.Column("claimed_at", sa.DateTime(timezone=True)),
    )
    op.add_column(
        "soc_response_actions",
        sa.Column("executed_at", sa.DateTime(timezone=True)),
    )
    op.create_index(
        "ix_soc_response_actions_execution_id",
        "soc_response_actions",
        ["execution_id"],
    )
    op.create_index(
        "ix_soc_response_actions_executor_user_id",
        "soc_response_actions",
        ["executor_user_id"],
    )
    op.create_index(
        "ix_soc_response_actions_claimed_at",
        "soc_response_actions",
        ["claimed_at"],
    )
    op.create_index(
        "ix_soc_response_actions_executed_at",
        "soc_response_actions",
        ["executed_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_soc_response_actions_executed_at",
        table_name="soc_response_actions",
    )
    op.drop_index(
        "ix_soc_response_actions_claimed_at",
        table_name="soc_response_actions",
    )
    op.drop_index(
        "ix_soc_response_actions_executor_user_id",
        table_name="soc_response_actions",
    )
    op.drop_index(
        "ix_soc_response_actions_execution_id",
        table_name="soc_response_actions",
    )
    op.drop_column("soc_response_actions", "executed_at")
    op.drop_column("soc_response_actions", "claimed_at")
    op.drop_column("soc_response_actions", "executor_user_id")
    op.drop_column("soc_response_actions", "execution_id")
