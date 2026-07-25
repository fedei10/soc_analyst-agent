"""Add PostgreSQL indexes for pending and raw Wazuh alert queries."""

from alembic import op
import sqlalchemy as sa


revision = "20260725_11"
down_revision = "20260725_10"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_soc_wazuh_alerts_pending",
        "soc_wazuh_alerts",
        ["correlation_status"],
        postgresql_where=sa.text("correlation_status = 'pending'"),
    )
    op.create_index(
        "ix_soc_wazuh_alerts_raw_gin",
        "soc_wazuh_alerts",
        ["raw_alert"],
        postgresql_using="gin",
    )


def downgrade() -> None:
    op.drop_index(
        "ix_soc_wazuh_alerts_raw_gin",
        table_name="soc_wazuh_alerts",
    )
    op.drop_index(
        "ix_soc_wazuh_alerts_pending",
        table_name="soc_wazuh_alerts",
    )
