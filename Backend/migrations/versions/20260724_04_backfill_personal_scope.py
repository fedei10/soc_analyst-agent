"""Assign unowned legacy records in single-user installations."""

from alembic import op


revision = "20260724_04"
down_revision = "20260724_03"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TEMP TABLE tsage_single_user_scope
        ON COMMIT DROP
        AS
        SELECT min(user_id) AS user_id
        FROM soc_users
        HAVING count(*) = 1
        """
    )
    op.execute(
        """
        UPDATE soc_investigations AS investigations
        SET organization_id = scopes.user_id,
            owner_user_id = scopes.user_id,
            initiated_by_user_id = COALESCE(
                investigations.initiated_by_user_id,
                scopes.user_id
            ),
            snapshot = jsonb_set(
                investigations.snapshot,
                '{organization_id}',
                to_jsonb(scopes.user_id),
                true
            )
        FROM tsage_single_user_scope AS scopes
        WHERE investigations.owner_user_id IS NULL
        """
    )
    for table_name in (
        "soc_agent_runs",
        "soc_tool_executions",
        "soc_evidence_records",
        "soc_investigation_reports",
        "soc_audit_events",
        "soc_approvals",
        "soc_response_actions",
    ):
        op.execute(
            f"""
            UPDATE {table_name} AS records
            SET organization_id = investigations.organization_id
            FROM soc_investigations AS investigations
            WHERE records.investigation_id = investigations.investigation_id
            """
        )
    op.execute(
        """
        UPDATE soc_curated_memories AS memories
        SET organization_id = scopes.user_id,
            user_id = scopes.user_id
        FROM tsage_single_user_scope AS scopes
        WHERE memories.user_id IS NULL
        """
    )


def downgrade() -> None:
    pass
