"""Add investigation snapshot CAS versions and durable resource leases."""

from alembic import op
import sqlalchemy as sa


revision = "20260725_13"
down_revision = "20260725_12"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "soc_investigations",
        sa.Column(
            "state_version",
            sa.Integer(),
            nullable=False,
            server_default="1",
        ),
    )

    op.create_table(
        "soc_investigation_resource_leases",
        sa.Column("lock_key", sa.String(64), nullable=False),
        sa.Column("organization_id", sa.String(128), nullable=False),
        sa.Column("resource_type", sa.String(64), nullable=False),
        sa.Column("resource_id", sa.String(256), nullable=False),
        sa.Column("lease_token", sa.String(64), nullable=False),
        sa.Column("owner_id", sa.String(128), nullable=False),
        sa.Column(
            "acquired_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("lock_key"),
        sa.UniqueConstraint(
            "lease_token",
            name="uq_soc_investigation_resource_leases_token",
        ),
        sa.UniqueConstraint(
            "organization_id",
            "resource_type",
            "resource_id",
            name="uq_soc_investigation_resource_leases_resource",
        ),
    )
    for column in (
        "organization_id",
        "resource_type",
        "resource_id",
        "owner_id",
        "expires_at",
    ):
        op.create_index(
            f"ix_soc_investigation_resource_leases_{column}",
            "soc_investigation_resource_leases",
            [column],
        )
    op.create_index(
        "ix_soc_investigation_resource_leases_org_expiry",
        "soc_investigation_resource_leases",
        ["organization_id", "expires_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_soc_investigation_resource_leases_org_expiry",
        table_name="soc_investigation_resource_leases",
    )
    for column in reversed(
        (
            "organization_id",
            "resource_type",
            "resource_id",
            "owner_id",
            "expires_at",
        )
    ):
        op.drop_index(
            f"ix_soc_investigation_resource_leases_{column}",
            table_name="soc_investigation_resource_leases",
        )
    op.drop_table("soc_investigation_resource_leases")
    op.drop_column("soc_investigations", "state_version")
