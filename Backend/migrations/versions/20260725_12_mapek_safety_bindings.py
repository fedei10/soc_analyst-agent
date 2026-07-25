"""Bind approvals and response actions to immutable MAPE-K plans."""

from alembic import op
import sqlalchemy as sa


revision = "20260725_12"
down_revision = "20260725_11"
branch_labels = None
depends_on = None


def upgrade() -> None:
    approval_columns = (
        sa.Column("incident_id", sa.String(64)),
        sa.Column("plan_id", sa.String(64)),
        sa.Column("plan_version", sa.Integer()),
        sa.Column("plan_hash", sa.String(64)),
        sa.Column("evidence_version", sa.String(64)),
        sa.Column("policy_version", sa.String(64)),
        sa.Column("action_catalogue_version", sa.String(64)),
        sa.Column("required_role", sa.String(32)),
        sa.Column("invalidated_at", sa.DateTime(timezone=True)),
        sa.Column("invalidation_reason", sa.String(128)),
    )
    for column in approval_columns:
        op.add_column("soc_approvals", column)
    for name in (
        "incident_id",
        "plan_id",
        "plan_hash",
        "evidence_version",
        "invalidated_at",
    ):
        op.create_index(
            f"ix_soc_approvals_{name}",
            "soc_approvals",
            [name],
        )

    action_columns = (
        sa.Column("plan_id", sa.String(64)),
        sa.Column("plan_hash", sa.String(64)),
        sa.Column("evidence_version", sa.String(64)),
        sa.Column("rollback_action_id", sa.String(64)),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("retry_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_rollback_attempt", sa.DateTime(timezone=True)),
    )
    for column in action_columns:
        op.add_column("soc_response_actions", column)
    for name in (
        "plan_id",
        "plan_hash",
        "evidence_version",
        "rollback_action_id",
        "expires_at",
    ):
        op.create_index(
            f"ix_soc_response_actions_{name}",
            "soc_response_actions",
            [name],
        )


def downgrade() -> None:
    for name in reversed(
        (
            "plan_id",
            "plan_hash",
            "evidence_version",
            "rollback_action_id",
            "expires_at",
        )
    ):
        op.drop_index(
            f"ix_soc_response_actions_{name}",
            table_name="soc_response_actions",
        )
    for name in (
        "last_rollback_attempt",
        "retry_count",
        "expires_at",
        "rollback_action_id",
        "evidence_version",
        "plan_hash",
        "plan_id",
    ):
        op.drop_column("soc_response_actions", name)

    for name in reversed(
        (
            "incident_id",
            "plan_id",
            "plan_hash",
            "evidence_version",
            "invalidated_at",
        )
    ):
        op.drop_index(
            f"ix_soc_approvals_{name}",
            table_name="soc_approvals",
        )
    for name in (
        "invalidation_reason",
        "invalidated_at",
        "required_role",
        "action_catalogue_version",
        "policy_version",
        "evidence_version",
        "plan_hash",
        "plan_version",
        "plan_id",
        "incident_id",
    ):
        op.drop_column("soc_approvals", name)
