"""Organization-scoped conversation, summary, and curated memory persistence."""

from __future__ import annotations

import hashlib
import json
import uuid
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session, sessionmaker

from app.db.models.investigation import (
    ConversationMessageRecord,
    ConversationRecord,
    ConversationSummaryRecord,
    CuratedMemoryRecord,
)
from app.db.sanitization import bounded_excerpt, sanitize_for_storage
from app.db.session import get_session_factory


DEFAULT_MESSAGE_RETENTION_DAYS = 90


def _hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ConversationRepository:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def create_conversation(
        self,
        *,
        conversation_id: str,
        organization_id: str,
        owner_user_id: str,
        title: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not conversation_id or not organization_id or not owner_user_id:
            raise ValueError(
                "conversation_id, organization_id, and owner_user_id are "
                "required."
            )
        with self._session_factory.begin() as session:
            record = session.get(ConversationRecord, conversation_id)
            if record is not None:
                if record.organization_id != organization_id:
                    raise PermissionError(
                        "Conversation belongs to another organization."
                    )
                return self._serialize_conversation(record)
            record = ConversationRecord(
                conversation_id=conversation_id,
                organization_id=organization_id,
                owner_user_id=owner_user_id,
                title=(
                    bounded_excerpt(title, max_length=256)
                    if title
                    else None
                ),
                status="active",
                conversation_metadata=sanitize_for_storage(metadata or {}),
            )
            session.add(record)
            session.flush()
            return self._serialize_conversation(record)

    def get_conversation(
        self,
        conversation_id: str,
        *,
        organization_id: str,
    ) -> dict[str, Any] | None:
        with self._session_factory() as session:
            record = session.scalar(
                select(ConversationRecord).where(
                    ConversationRecord.conversation_id == conversation_id,
                    ConversationRecord.organization_id == organization_id,
                )
            )
            return (
                self._serialize_conversation(record)
                if record is not None
                else None
            )

    def list_conversations(
        self,
        *,
        organization_id: str,
        owner_user_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        statement = select(ConversationRecord).where(
            ConversationRecord.organization_id == organization_id
        )
        if owner_user_id:
            statement = statement.where(
                ConversationRecord.owner_user_id == owner_user_id
            )
        statement = (
            statement.order_by(ConversationRecord.updated_at.desc())
            .offset(offset)
            .limit(min(max(limit, 1), 100))
        )
        with self._session_factory() as session:
            return [
                self._serialize_conversation(record)
                for record in session.scalars(statement).all()
            ]

    def append_message(
        self,
        *,
        conversation_id: str,
        organization_id: str,
        role: str,
        content: str,
        sender_user_id: str | None = None,
        message_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        retention_days: int = DEFAULT_MESSAGE_RETENTION_DAYS,
    ) -> dict[str, Any]:
        if role not in {"user", "assistant", "system", "tool"}:
            raise ValueError("Unsupported conversation role.")
        now = datetime.now(UTC)
        bounded_content = bounded_excerpt(content, max_length=8000)
        with self._session_factory.begin() as session:
            conversation = session.scalar(
                select(ConversationRecord).where(
                    ConversationRecord.conversation_id == conversation_id,
                    ConversationRecord.organization_id == organization_id,
                )
            )
            if conversation is None:
                raise LookupError("Conversation not found.")
            record = ConversationMessageRecord(
                message_id=message_id or uuid.uuid4().hex,
                conversation_id=conversation_id,
                organization_id=organization_id,
                sender_user_id=sender_user_id,
                role=role,
                content=bounded_content,
                content_hash=_hash({
                    "role": role,
                    "content": bounded_content,
                }),
                message_metadata=sanitize_for_storage(metadata or {}),
                created_at=now,
                retention_until=now + timedelta(days=max(retention_days, 1)),
            )
            session.add(record)
            conversation.last_message_at = now
            conversation.updated_at = now
            session.flush()
            return self._serialize_message(record)

    def list_messages(
        self,
        conversation_id: str,
        *,
        organization_id: str,
        limit: int = 100,
        before: datetime | None = None,
    ) -> list[dict[str, Any]]:
        statement = select(ConversationMessageRecord).where(
            ConversationMessageRecord.conversation_id == conversation_id,
            ConversationMessageRecord.organization_id == organization_id,
        )
        if before is not None:
            statement = statement.where(
                ConversationMessageRecord.created_at < before
            )
        statement = statement.order_by(
            ConversationMessageRecord.created_at.asc()
        ).limit(min(max(limit, 1), 200))
        with self._session_factory() as session:
            return [
                self._serialize_message(record)
                for record in session.scalars(statement).all()
            ]

    def save_summary(
        self,
        *,
        conversation_id: str,
        organization_id: str,
        content: str,
        message_count: int,
        through_message_id: str | None = None,
        summary_id: str | None = None,
    ) -> dict[str, Any]:
        with self._session_factory.begin() as session:
            exists = session.scalar(
                select(ConversationRecord.conversation_id).where(
                    ConversationRecord.conversation_id == conversation_id,
                    ConversationRecord.organization_id == organization_id,
                )
            )
            if exists is None:
                raise LookupError("Conversation not found.")
            record = ConversationSummaryRecord(
                summary_id=summary_id or uuid.uuid4().hex,
                conversation_id=conversation_id,
                organization_id=organization_id,
                content=bounded_excerpt(content, max_length=8000),
                message_count=max(message_count, 0),
                through_message_id=through_message_id,
            )
            session.add(record)
            session.flush()
            return self._serialize_summary(record)

    def latest_summary(
        self,
        conversation_id: str,
        *,
        organization_id: str,
    ) -> dict[str, Any] | None:
        with self._session_factory() as session:
            record = session.scalar(
                select(ConversationSummaryRecord)
                .where(
                    ConversationSummaryRecord.conversation_id
                    == conversation_id,
                    ConversationSummaryRecord.organization_id
                    == organization_id,
                )
                .order_by(ConversationSummaryRecord.created_at.desc())
                .limit(1)
            )
            return (
                self._serialize_summary(record)
                if record is not None
                else None
            )

    def upsert_memory(
        self,
        *,
        organization_id: str,
        namespace: str,
        memory_key: str,
        value: dict[str, Any],
        user_id: str | None = None,
        asset_id: str | None = None,
        investigation_id: str | None = None,
        expires_at: datetime | None = None,
    ) -> dict[str, Any]:
        safe_value = sanitize_for_storage(value)
        with self._session_factory.begin() as session:
            record = session.scalar(
                select(CuratedMemoryRecord).where(
                    CuratedMemoryRecord.organization_id == organization_id,
                    CuratedMemoryRecord.namespace == namespace,
                    CuratedMemoryRecord.memory_key == memory_key,
                )
            )
            if record is None:
                record = CuratedMemoryRecord(
                    memory_id=uuid.uuid4().hex,
                    organization_id=organization_id,
                    user_id=user_id,
                    namespace=namespace[:256],
                    memory_key=memory_key[:256],
                    asset_id=asset_id,
                    investigation_id=investigation_id,
                    value=safe_value,
                    content_hash=_hash(safe_value),
                    expires_at=expires_at,
                )
                session.add(record)
            else:
                record.user_id = user_id
                record.asset_id = asset_id
                record.investigation_id = investigation_id
                record.value = safe_value
                record.content_hash = _hash(safe_value)
                record.expires_at = expires_at
            session.flush()
            return self._serialize_memory(record)

    def list_memories(
        self,
        *,
        organization_id: str,
        namespace: str,
        user_id: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        now = datetime.now(UTC)
        statement = select(CuratedMemoryRecord).where(
            CuratedMemoryRecord.organization_id == organization_id,
            CuratedMemoryRecord.namespace == namespace,
            (
                CuratedMemoryRecord.expires_at.is_(None)
                | (CuratedMemoryRecord.expires_at > now)
            ),
        )
        if user_id is not None:
            statement = statement.where(
                CuratedMemoryRecord.user_id == user_id
            )
        statement = statement.order_by(
            CuratedMemoryRecord.updated_at.desc()
        ).limit(min(max(limit, 1), 100))
        with self._session_factory() as session:
            return [
                self._serialize_memory(record)
                for record in session.scalars(statement).all()
            ]

    def delete_expired_messages(
        self,
        *,
        organization_id: str,
        now: datetime | None = None,
    ) -> int:
        cutoff = now or datetime.now(UTC)
        with self._session_factory.begin() as session:
            result = session.execute(
                delete(ConversationMessageRecord).where(
                    ConversationMessageRecord.organization_id
                    == organization_id,
                    ConversationMessageRecord.retention_until.is_not(None),
                    ConversationMessageRecord.retention_until <= cutoff,
                )
            )
            return int(result.rowcount or 0)

    @staticmethod
    def _serialize_conversation(
        record: ConversationRecord,
    ) -> dict[str, Any]:
        return {
            "conversation_id": record.conversation_id,
            "organization_id": record.organization_id,
            "owner_user_id": record.owner_user_id,
            "title": record.title,
            "status": record.status,
            "metadata": deepcopy(record.conversation_metadata),
            "created_at": record.created_at,
            "updated_at": record.updated_at,
            "last_message_at": record.last_message_at,
        }

    @staticmethod
    def _serialize_message(
        record: ConversationMessageRecord,
    ) -> dict[str, Any]:
        return {
            "message_id": record.message_id,
            "conversation_id": record.conversation_id,
            "organization_id": record.organization_id,
            "sender_user_id": record.sender_user_id,
            "role": record.role,
            "content": record.content,
            "content_hash": record.content_hash,
            "metadata": deepcopy(record.message_metadata),
            "created_at": record.created_at,
            "retention_until": record.retention_until,
        }

    @staticmethod
    def _serialize_summary(
        record: ConversationSummaryRecord,
    ) -> dict[str, Any]:
        return {
            "summary_id": record.summary_id,
            "conversation_id": record.conversation_id,
            "organization_id": record.organization_id,
            "content": record.content,
            "message_count": record.message_count,
            "through_message_id": record.through_message_id,
            "created_at": record.created_at,
        }

    @staticmethod
    def _serialize_memory(record: CuratedMemoryRecord) -> dict[str, Any]:
        return {
            "memory_id": record.memory_id,
            "organization_id": record.organization_id,
            "user_id": record.user_id,
            "namespace": record.namespace,
            "memory_key": record.memory_key,
            "asset_id": record.asset_id,
            "investigation_id": record.investigation_id,
            "value": deepcopy(record.value),
            "content_hash": record.content_hash,
            "created_at": record.created_at,
            "updated_at": record.updated_at,
            "expires_at": record.expires_at,
        }


def get_conversation_repository() -> ConversationRepository:
    return ConversationRepository(get_session_factory())
