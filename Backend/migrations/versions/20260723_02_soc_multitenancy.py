"""Add organization scoping, conversations, and specialist run history."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260723_02"
down_revision = "20260723_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "soc_users",
        sa.Column("user_id", sa.String(128), primary_key=True),
        sa.Column("email", sa.String(320)),
        sa.Column("display_name", sa.String(256)),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_soc_users_email", "soc_users", ["email"])

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

    op.add_column(
        "soc_investigations",
        sa.Column(
            "organization_id",
            sa.String(128),
            nullable=False,
            server_default="legacy",
        ),
    )
    op.add_column(
        "soc_investigations",
        sa.Column("owner_user_id", sa.String(128)),
    )
    op.add_column(
        "soc_investigations",
        sa.Column("initiated_by_user_id", sa.String(128)),
    )
    op.execute(
        """
        UPDATE soc_investigations
        SET snapshot = snapshot || '{"organization_id": "legacy"}'::jsonb
        WHERE NOT (snapshot ? 'organization_id')
        """
    )
    op.alter_column(
        "soc_investigations",
        "organization_id",
        server_default=None,
    )
    op.create_index(
        "ix_soc_investigations_organization_id",
        "soc_investigations",
        ["organization_id"],
    )
    op.create_index(
        "ix_soc_investigations_owner_user_id",
        "soc_investigations",
        ["owner_user_id"],
    )
    op.create_index(
        "ix_soc_investigations_initiated_by_user_id",
        "soc_investigations",
        ["initiated_by_user_id"],
    )
    op.drop_index(
        "ix_soc_investigations_status_updated",
        table_name="soc_investigations",
    )
    op.create_index(
        "ix_soc_investigations_org_status_updated",
        "soc_investigations",
        ["organization_id", "status", "updated_at"],
    )

    op.drop_constraint(
        "uq_soc_agent_run_investigation_tier",
        "soc_agent_runs",
        type_="unique",
    )
    op.add_column(
        "soc_agent_runs",
        sa.Column("run_id", sa.String(64)),
    )
    op.add_column(
        "soc_agent_runs",
        sa.Column("parent_run_id", sa.String(64)),
    )
    op.add_column(
        "soc_agent_runs",
        sa.Column("organization_id", sa.String(128)),
    )
    op.add_column(
        "soc_agent_runs",
        sa.Column(
            "role",
            sa.String(64),
            nullable=False,
            server_default="supervisor",
        ),
    )
    op.add_column(
        "soc_agent_runs",
        sa.Column(
            "attempt",
            sa.Integer(),
            nullable=False,
            server_default="1",
        ),
    )
    op.add_column(
        "soc_agent_runs",
        sa.Column("provider", sa.String(64)),
    )
    op.add_column(
        "soc_agent_runs",
        sa.Column("model_name", sa.String(128)),
    )
    op.add_column(
        "soc_agent_runs",
        sa.Column("duration_ms", sa.Integer()),
    )
    op.add_column(
        "soc_agent_runs",
        sa.Column(
            "tool_activity",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )
    op.add_column(
        "soc_agent_runs",
        sa.Column("error_code", sa.String(64)),
    )
    op.add_column(
        "soc_agent_runs",
        sa.Column("error_summary", sa.Text()),
    )
    op.add_column(
        "soc_agent_runs",
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.execute(
        """
        UPDATE soc_agent_runs AS runs
        SET run_id = 'legacy-' || runs.id::text,
            organization_id = investigations.organization_id
        FROM soc_investigations AS investigations
        WHERE investigations.investigation_id = runs.investigation_id
        """
    )
    op.alter_column("soc_agent_runs", "run_id", nullable=False)
    op.alter_column("soc_agent_runs", "organization_id", nullable=False)
    op.alter_column("soc_agent_runs", "completed_at", nullable=True)
    op.alter_column("soc_agent_runs", "role", server_default=None)
    op.alter_column("soc_agent_runs", "attempt", server_default=None)
    op.alter_column("soc_agent_runs", "tool_activity", server_default=None)
    op.alter_column("soc_agent_runs", "created_at", server_default=None)
    op.create_index(
        "ix_soc_agent_runs_run_id",
        "soc_agent_runs",
        ["run_id"],
        unique=True,
    )
    op.create_index(
        "ix_soc_agent_runs_parent_run_id",
        "soc_agent_runs",
        ["parent_run_id"],
    )
    op.create_index(
        "ix_soc_agent_runs_organization_id",
        "soc_agent_runs",
        ["organization_id"],
    )
    op.create_index("ix_soc_agent_runs_role", "soc_agent_runs", ["role"])
    op.create_index("ix_soc_agent_runs_status", "soc_agent_runs", ["status"])
    op.create_index(
        "ix_soc_agent_runs_error_code",
        "soc_agent_runs",
        ["error_code"],
    )
    op.create_index(
        "ix_soc_agent_runs_org_investigation",
        "soc_agent_runs",
        ["organization_id", "investigation_id"],
    )
    op.create_foreign_key(
        "fk_soc_agent_runs_parent_run_id",
        "soc_agent_runs",
        "soc_agent_runs",
        ["parent_run_id"],
        ["run_id"],
        ondelete="SET NULL",
    )

    for table_name in (
        "soc_investigation_reports",
        "soc_audit_events",
        "soc_response_actions",
    ):
        op.add_column(
            table_name,
            sa.Column("organization_id", sa.String(128)),
        )
        op.execute(
            f"""
            UPDATE {table_name} AS child
            SET organization_id = investigations.organization_id
            FROM soc_investigations AS investigations
            WHERE investigations.investigation_id = child.investigation_id
            """
        )
        op.alter_column(table_name, "organization_id", nullable=False)
        op.create_index(
            f"ix_{table_name}_organization_id",
            table_name,
            ["organization_id"],
        )

    op.add_column(
        "soc_audit_events",
        sa.Column("actor_user_id", sa.String(128)),
    )
    op.create_index(
        "ix_soc_audit_events_actor_user_id",
        "soc_audit_events",
        ["actor_user_id"],
    )
    op.add_column(
        "soc_response_actions",
        sa.Column("approved_by_user_id", sa.String(128)),
    )
    op.create_index(
        "ix_soc_response_actions_approved_by_user_id",
        "soc_response_actions",
        ["approved_by_user_id"],
    )

    op.create_table(
        "soc_tool_executions",
        sa.Column("execution_id", sa.String(64), primary_key=True),
        sa.Column(
            "run_id",
            sa.String(64),
            sa.ForeignKey("soc_agent_runs.run_id", ondelete="CASCADE"),
            nullable=False,
        ),
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
        sa.Column("tool_name", sa.String(128), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column(
            "input_summary",
            postgresql.JSONB(),
            nullable=False,
        ),
        sa.Column(
            "output_summary",
            postgresql.JSONB(),
            nullable=False,
        ),
        sa.Column("error_code", sa.String(64)),
        sa.Column("duration_ms", sa.Integer()),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
    )
    for column in (
        "run_id",
        "investigation_id",
        "organization_id",
        "tool_name",
        "status",
    ):
        op.create_index(
            f"ix_soc_tool_executions_{column}",
            "soc_tool_executions",
            [column],
        )

    op.create_table(
        "soc_approvals",
        sa.Column("approval_id", sa.String(100), primary_key=True),
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
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column(
            "proposed_actions",
            postgresql.JSONB(),
            nullable=False,
        ),
        sa.Column("decision", postgresql.JSONB()),
        sa.Column("decided_by_user_id", sa.String(128)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("decided_at", sa.DateTime(timezone=True)),
    )
    for column in (
        "investigation_id",
        "organization_id",
        "status",
        "decided_by_user_id",
        "expires_at",
        "decided_at",
    ):
        op.create_index(
            f"ix_soc_approvals_{column}",
            "soc_approvals",
            [column],
        )

    op.create_table(
        "soc_evidence_records",
        sa.Column("evidence_id", sa.String(64), primary_key=True),
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
        sa.Column("source_type", sa.String(64), nullable=False),
        sa.Column("source_ref", sa.String(512), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("excerpt", sa.Text()),
        sa.Column("metadata", postgresql.JSONB(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "investigation_id",
            "content_hash",
            name="uq_soc_evidence_investigation_hash",
        ),
    )
    for column in (
        "investigation_id",
        "organization_id",
        "source_type",
        "source_ref",
        "content_hash",
        "observed_at",
    ):
        op.create_index(
            f"ix_soc_evidence_records_{column}",
            "soc_evidence_records",
            [column],
        )

    op.create_table(
        "soc_conversations",
        sa.Column("conversation_id", sa.String(128), primary_key=True),
        sa.Column("organization_id", sa.String(128), nullable=False),
        sa.Column("owner_user_id", sa.String(128), nullable=False),
        sa.Column("title", sa.String(256)),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("metadata", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_message_at", sa.DateTime(timezone=True)),
    )
    op.create_index(
        "ix_soc_conversations_organization_id",
        "soc_conversations",
        ["organization_id"],
    )
    op.create_index(
        "ix_soc_conversations_owner_user_id",
        "soc_conversations",
        ["owner_user_id"],
    )
    op.create_index(
        "ix_soc_conversations_status",
        "soc_conversations",
        ["status"],
    )
    op.create_index(
        "ix_soc_conversations_updated_at",
        "soc_conversations",
        ["updated_at"],
    )
    op.create_index(
        "ix_soc_conversations_last_message_at",
        "soc_conversations",
        ["last_message_at"],
    )
    op.create_index(
        "ix_soc_conversations_org_updated",
        "soc_conversations",
        ["organization_id", "updated_at"],
    )

    op.create_table(
        "soc_conversation_messages",
        sa.Column("message_id", sa.String(64), primary_key=True),
        sa.Column(
            "conversation_id",
            sa.String(128),
            sa.ForeignKey(
                "soc_conversations.conversation_id",
                ondelete="CASCADE",
            ),
            nullable=False,
        ),
        sa.Column("organization_id", sa.String(128), nullable=False),
        sa.Column("sender_user_id", sa.String(128)),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("metadata", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("retention_until", sa.DateTime(timezone=True)),
    )
    for column in (
        "conversation_id",
        "organization_id",
        "sender_user_id",
        "role",
        "content_hash",
        "created_at",
        "retention_until",
    ):
        op.create_index(
            f"ix_soc_conversation_messages_{column}",
            "soc_conversation_messages",
            [column],
        )

    op.create_table(
        "soc_conversation_summaries",
        sa.Column("summary_id", sa.String(64), primary_key=True),
        sa.Column(
            "conversation_id",
            sa.String(128),
            sa.ForeignKey(
                "soc_conversations.conversation_id",
                ondelete="CASCADE",
            ),
            nullable=False,
        ),
        sa.Column("organization_id", sa.String(128), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("message_count", sa.Integer(), nullable=False),
        sa.Column("through_message_id", sa.String(64)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    for column in ("conversation_id", "organization_id", "created_at"):
        op.create_index(
            f"ix_soc_conversation_summaries_{column}",
            "soc_conversation_summaries",
            [column],
        )

    op.create_table(
        "soc_curated_memories",
        sa.Column("memory_id", sa.String(64), primary_key=True),
        sa.Column("organization_id", sa.String(128), nullable=False),
        sa.Column("user_id", sa.String(128)),
        sa.Column("namespace", sa.String(256), nullable=False),
        sa.Column("memory_key", sa.String(256), nullable=False),
        sa.Column("asset_id", sa.String(256)),
        sa.Column(
            "investigation_id",
            sa.String(64),
            sa.ForeignKey(
                "soc_investigations.investigation_id",
                ondelete="SET NULL",
            ),
        ),
        sa.Column("value", postgresql.JSONB(), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint(
            "organization_id",
            "namespace",
            "memory_key",
            name="uq_soc_memory_org_namespace_key",
        ),
    )
    for column in (
        "organization_id",
        "user_id",
        "namespace",
        "asset_id",
        "investigation_id",
        "content_hash",
        "expires_at",
    ):
        op.create_index(
            f"ix_soc_curated_memories_{column}",
            "soc_curated_memories",
            [column],
        )


def downgrade() -> None:
    op.drop_table("soc_curated_memories")
    op.drop_table("soc_conversation_summaries")
    op.drop_table("soc_conversation_messages")
    op.drop_table("soc_conversations")
    op.drop_table("soc_evidence_records")
    op.drop_table("soc_approvals")
    op.drop_table("soc_tool_executions")

    op.drop_index(
        "ix_soc_response_actions_approved_by_user_id",
        table_name="soc_response_actions",
    )
    op.drop_column("soc_response_actions", "approved_by_user_id")
    op.drop_index(
        "ix_soc_audit_events_actor_user_id",
        table_name="soc_audit_events",
    )
    op.drop_column("soc_audit_events", "actor_user_id")
    for table_name in (
        "soc_response_actions",
        "soc_audit_events",
        "soc_investigation_reports",
    ):
        op.drop_index(
            f"ix_{table_name}_organization_id",
            table_name=table_name,
        )
        op.drop_column(table_name, "organization_id")

    op.execute(
        """
        DELETE FROM soc_agent_runs AS duplicate
        USING soc_agent_runs AS keeper
        WHERE duplicate.investigation_id = keeper.investigation_id
          AND duplicate.tier = keeper.tier
          AND duplicate.id > keeper.id
        """
    )
    op.drop_constraint(
        "fk_soc_agent_runs_parent_run_id",
        "soc_agent_runs",
        type_="foreignkey",
    )
    for index_name in (
        "ix_soc_agent_runs_org_investigation",
        "ix_soc_agent_runs_error_code",
        "ix_soc_agent_runs_status",
        "ix_soc_agent_runs_role",
        "ix_soc_agent_runs_organization_id",
        "ix_soc_agent_runs_parent_run_id",
        "ix_soc_agent_runs_run_id",
    ):
        op.drop_index(index_name, table_name="soc_agent_runs")
    op.alter_column("soc_agent_runs", "completed_at", nullable=False)
    for column in (
        "created_at",
        "error_summary",
        "error_code",
        "tool_activity",
        "duration_ms",
        "model_name",
        "provider",
        "attempt",
        "role",
        "organization_id",
        "parent_run_id",
        "run_id",
    ):
        op.drop_column("soc_agent_runs", column)
    op.create_unique_constraint(
        "uq_soc_agent_run_investigation_tier",
        "soc_agent_runs",
        ["investigation_id", "tier"],
    )

    op.drop_index(
        "ix_soc_investigations_org_status_updated",
        table_name="soc_investigations",
    )
    op.create_index(
        "ix_soc_investigations_status_updated",
        "soc_investigations",
        ["status", "updated_at"],
    )
    op.drop_index(
        "ix_soc_investigations_initiated_by_user_id",
        table_name="soc_investigations",
    )
    op.drop_index(
        "ix_soc_investigations_owner_user_id",
        table_name="soc_investigations",
    )
    op.drop_index(
        "ix_soc_investigations_organization_id",
        table_name="soc_investigations",
    )
    op.drop_column("soc_investigations", "initiated_by_user_id")
    op.drop_column("soc_investigations", "owner_user_id")
    op.drop_column("soc_investigations", "organization_id")

    op.drop_table("soc_organization_memberships")
    op.drop_table("soc_users")
