"""Harden Wazuh ingestion cursors, metrics, and worker leases."""

from alembic import op
import sqlalchemy as sa


revision = "20260726_15"
down_revision = "20260725_14"
branch_labels = None
depends_on = None


def upgrade() -> None:
    table = "soc_ingestion_checkpoints"
    columns = (
        sa.Column(
            "connection_profile_id",
            sa.String(128),
            nullable=False,
            server_default="default",
        ),
        sa.Column(
            "index_pattern",
            sa.String(256),
            nullable=False,
            server_default="wazuh-alerts-*",
        ),
        sa.Column(
            "cursor_version",
            sa.Integer(),
            nullable=False,
            server_default="1",
        ),
        sa.Column("last_index_name", sa.String(256)),
        sa.Column(
            "previous_run_completed_at",
            sa.DateTime(timezone=True),
        ),
        sa.Column(
            "last_duplicate_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "last_finding_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "last_updated_finding_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "last_incident_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column("highest_new_rule_level", sa.Integer()),
        sa.Column(
            "last_cursor_advanced",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "last_truncated",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("lease_token", sa.String(100)),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
    )
    for column in columns:
        op.add_column(table, column)

    op.create_unique_constraint(
        "uq_soc_ingestion_cursor_scope",
        table,
        ["source_name", "connection_profile_id", "index_pattern"],
    )
    op.create_index(
        "ix_soc_ingestion_checkpoints_lease_token",
        table,
        ["lease_token"],
    )
    op.create_index(
        "ix_soc_ingestion_checkpoints_lease_expires_at",
        table,
        ["lease_expires_at"],
    )


def downgrade() -> None:
    table = "soc_ingestion_checkpoints"
    op.drop_index(
        "ix_soc_ingestion_checkpoints_lease_expires_at",
        table_name=table,
    )
    op.drop_index(
        "ix_soc_ingestion_checkpoints_lease_token",
        table_name=table,
    )
    op.drop_constraint(
        "uq_soc_ingestion_cursor_scope",
        table,
        type_="unique",
    )
    for column in (
        "lease_expires_at",
        "lease_token",
        "last_truncated",
        "last_cursor_advanced",
        "highest_new_rule_level",
        "last_incident_count",
        "last_updated_finding_count",
        "last_finding_count",
        "last_duplicate_count",
        "previous_run_completed_at",
        "last_index_name",
        "cursor_version",
        "index_pattern",
        "connection_profile_id",
    ):
        op.drop_column(table, column)
