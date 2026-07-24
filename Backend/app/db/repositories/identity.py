"""Clerk user projection used for durable attribution."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from app.db.models.investigation import UserRecord
from app.db.session import get_session_factory


class IdentityRepository:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def upsert_user(
        self,
        *,
        user_id: str,
        email: str | None = None,
        display_name: str | None = None,
        active: bool = True,
    ) -> dict[str, Any]:
        if not user_id.strip():
            raise ValueError("user_id is required.")
        with self._session_factory.begin() as session:
            record = session.get(UserRecord, user_id)
            if record is None:
                record = UserRecord(
                    user_id=user_id,
                    email=email,
                    display_name=display_name,
                    active=active,
                )
                session.add(record)
            else:
                record.email = email or record.email
                record.display_name = display_name or record.display_name
                record.active = active
            session.flush()
            return self._serialize_user(record)

    @staticmethod
    def _serialize_user(record: UserRecord) -> dict[str, Any]:
        return {
            "user_id": record.user_id,
            "email": record.email,
            "display_name": record.display_name,
            "active": record.active,
            "created_at": record.created_at,
            "updated_at": record.updated_at,
        }

def get_identity_repository() -> IdentityRepository:
    return IdentityRepository(get_session_factory())
