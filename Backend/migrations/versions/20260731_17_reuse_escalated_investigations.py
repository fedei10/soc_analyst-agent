"""Prevent new duplicate investigations while preserving historical rows."""

from alembic import op


revision = "20260731_17"
down_revision = "20260726_16"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Some development databases already contain several escalated rows for
    # one alert. A wider unique index would either fail or require rewriting
    # that history. Keep the existing index and reject only future inserts;
    # the application alert lease remains the concurrency boundary.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION reject_duplicate_reusable_investigation()
        RETURNS trigger AS $$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM soc_investigations AS existing
                WHERE existing.organization_id = NEW.organization_id
                  AND existing.alert_id = NEW.alert_id
                  AND existing.status IN (
                      'created', 'queued', 'running', 'awaiting_approval',
                      'waiting_approval', 'waiting_verification', 'approved',
                      'escalated'
                  )
            ) THEN
                RAISE EXCEPTION
                    'A reusable investigation already exists for this alert.'
                    USING ERRCODE = 'unique_violation';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER prevent_duplicate_reusable_investigation
        BEFORE INSERT ON soc_investigations
        FOR EACH ROW
        WHEN (NEW.status IN (
            'created', 'queued', 'running', 'awaiting_approval',
            'waiting_approval', 'waiting_verification', 'approved', 'escalated'
        ))
        EXECUTE FUNCTION reject_duplicate_reusable_investigation();
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP TRIGGER IF EXISTS prevent_duplicate_reusable_investigation
        ON soc_investigations;
        """
    )
    op.execute(
        "DROP FUNCTION IF EXISTS reject_duplicate_reusable_investigation();"
    )
