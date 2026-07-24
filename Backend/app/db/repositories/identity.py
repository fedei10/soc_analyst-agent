"""Clerk identity projection used for durable attribution and tenant scoping."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.db.models.investigation import (
    OrganizationMembershipRecord,
    UserRecord,
)
from app.db.sanitization import sanitize_for_storage
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

    def upsert_membership(
        self,
        *,
        organization_id: str,
        user_id: str,
        role: str,
        permissions: list[str],
        active: bool = True,
    ) -> dict[str, Any]:
        if not organization_id.strip() or not user_id.strip():
            raise ValueError("organization_id and user_id are required.")
        normalized_permissions = sorted({
            str(permission)
            for permission in sanitize_for_storage(permissions)
            if str(permission)
        })
        with self._session_factory.begin() as session:
            if session.get(UserRecord, user_id) is None:
                session.add(UserRecord(user_id=user_id))
                session.flush()
            record = session.scalar(
                select(OrganizationMembershipRecord).where(
                    OrganizationMembershipRecord.organization_id
                    == organization_id,
                    OrganizationMembershipRecord.user_id == user_id,
                )
            )
            if record is None:
                record = OrganizationMembershipRecord(
                    organization_id=organization_id,
                    user_id=user_id,
                    role=role,
                    permissions=normalized_permissions,
                    active=active,
                )
                session.add(record)
            else:
                record.role = role
                record.permissions = normalized_permissions
                record.active = active
            session.flush()
            return self._serialize_membership(record)

    def get_membership(
        self,
        *,
        organization_id: str,
        user_id: str,
    ) -> dict[str, Any] | None:
        with self._session_factory() as session:
            record = session.scalar(
                select(OrganizationMembershipRecord).where(
                    OrganizationMembershipRecord.organization_id
                    == organization_id,
                    OrganizationMembershipRecord.user_id == user_id,
                    OrganizationMembershipRecord.active.is_(True),
                )
            )
            return (
                self._serialize_membership(record)
                if record is not None
                else None
            )

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

    @staticmethod
    def _serialize_membership(
        record: OrganizationMembershipRecord,
    ) -> dict[str, Any]:
        return {
            "organization_id": record.organization_id,
            "user_id": record.user_id,
            "role": record.role,
            "permissions": deepcopy(record.permissions),
            "active": record.active,
            "created_at": record.created_at,
            "updated_at": record.updated_at,
        }


def get_identity_repository() -> IdentityRepository:
    return IdentityRepository(get_session_factory())
