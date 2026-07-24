from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.repositories.conversations import ConversationRepository
from app.db.repositories.identity import IdentityRepository


def repositories():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    return ConversationRepository(factory), IdentityRepository(factory)


def test_identity_and_conversation_history_are_organization_scoped():
    conversations, identities = repositories()
    identities.upsert_user(
        user_id="user-1",
        email="analyst@example.com",
        display_name="Analyst",
    )
    membership = identities.upsert_membership(
        organization_id="org-1",
        user_id="user-1",
        role="analyst",
        permissions=["org:soc:read", "authorization-token"],
    )
    conversations.create_conversation(
        conversation_id="conversation-1",
        organization_id="org-1",
        owner_user_id="user-1",
        metadata={"active_asset": "host-1", "api_key": "not-stored"},
    )
    message = conversations.append_message(
        conversation_id="conversation-1",
        organization_id="org-1",
        sender_user_id="user-1",
        role="user",
        content="Investigate host-1",
        metadata={"token": "not-stored", "source": "chat"},
    )

    assert membership["role"] == "analyst"
    assert conversations.get_conversation(
        "conversation-1",
        organization_id="org-2",
    ) is None
    assert message["metadata"] == {"source": "chat"}
    assert conversations.list_messages(
        "conversation-1",
        organization_id="org-1",
    )[0]["content"] == "Investigate host-1"


def test_summaries_memories_and_retention_cleanup():
    conversations, _ = repositories()
    conversations.create_conversation(
        conversation_id="conversation-1",
        organization_id="org-1",
        owner_user_id="user-1",
    )
    conversations.append_message(
        conversation_id="conversation-1",
        organization_id="org-1",
        role="assistant",
        content="Finding",
        retention_days=1,
    )
    summary = conversations.save_summary(
        conversation_id="conversation-1",
        organization_id="org-1",
        content="A bounded case summary",
        message_count=1,
    )
    memory = conversations.upsert_memory(
        organization_id="org-1",
        namespace="asset/host-1",
        memory_key="last-severity",
        value={"severity": "high", "reasoning": "not-stored"},
        asset_id="host-1",
    )

    assert conversations.latest_summary(
        "conversation-1",
        organization_id="org-1",
    )["summary_id"] == summary["summary_id"]
    assert memory["value"] == {"severity": "high"}
    assert len(conversations.list_memories(
        organization_id="org-1",
        namespace="asset/host-1",
    )) == 1
    deleted = conversations.delete_expired_messages(
        organization_id="org-1",
        now=datetime.now(UTC) + timedelta(days=2),
    )
    assert deleted == 1
