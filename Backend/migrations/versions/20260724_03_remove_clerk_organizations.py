"""Remove Clerk organization membership persistence."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260724_03"
down_revision = "20260723_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TEMP TABLE tsage_personal_scope_map
        ON COMMIT DROP
        AS
        SELECT organization_id, min(user_id) AS user_id
        FROM soc_organization_memberships
        WHERE active IS TRUE
        GROUP BY organization_id
        HAVING count(*) = 1
        """
    )
    op.execute(
        """
        UPDATE soc_investigations
        SET organization_id = COALESCE(
                owner_user_id,
                initiated_by_user_id,
                organization_id
            ),
            owner_user_id = COALESCE(
                owner_user_id,
                initiated_by_user_id
            ),
            snapshot = jsonb_set(
                snapshot,
                '{organization_id}',
                to_jsonb(COALESCE(
                    owner_user_id,
                    initiated_by_user_id,
                    organization_id
                )),
                true
            )
        WHERE owner_user_id IS NOT NULL
           OR initiated_by_user_id IS NOT NULL
        """
    )
    op.execute(
        """
        UPDATE soc_investigations AS investigations
        SET organization_id = scopes.user_id,
            owner_user_id = COALESCE(
                investigations.owner_user_id,
                scopes.user_id
            ),
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
        FROM tsage_personal_scope_map AS scopes
        WHERE investigations.organization_id = scopes.organization_id
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
        UPDATE soc_conversations
        SET organization_id = owner_user_id
        """
    )
    for table_name in (
        "soc_conversation_messages",
        "soc_conversation_summaries",
    ):
        op.execute(
            f"""
            UPDATE {table_name} AS records
            SET organization_id = conversations.organization_id
            FROM soc_conversations AS conversations
            WHERE records.conversation_id = conversations.conversation_id
            """
        )
    op.execute(
        """
        UPDATE soc_curated_memories
        SET organization_id = user_id
        WHERE user_id IS NOT NULL
        """
    )
    op.execute(
        """
        UPDATE soc_curated_memories AS memories
        SET organization_id = scopes.user_id
        FROM tsage_personal_scope_map AS scopes
        WHERE memories.user_id IS NULL
          AND memories.organization_id = scopes.organization_id
        """
    )
    op.drop_table("soc_organization_memberships")


def downgrade() -> None:
    op.create_table(
        "soc_organization_memberships",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("organization_id", sa.String(128), nullable=False),
        sa.Column(
            "user_id",
            sa.String(128),
            sa.ForeignKey("soc_users.user_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("role", sa.String(64), nullable=False),
        sa.Column(
            "permissions",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "organization_id",
            "user_id",
            name="uq_soc_membership_organization_user",
        ),
    )
    op.create_index(
        "ix_soc_organization_memberships_organization_id",
        "soc_organization_memberships",
        ["organization_id"],
    )
    op.create_index(
        "ix_soc_organization_memberships_user_id",
        "soc_organization_memberships",
        ["user_id"],
    )
    op.create_index(
        "ix_soc_organization_memberships_role",
        "soc_organization_memberships",
        ["role"],
    )
