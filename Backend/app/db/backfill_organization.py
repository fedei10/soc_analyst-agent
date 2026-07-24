"""Assign pre-authentication SOC records to a Clerk organization."""

from __future__ import annotations

import argparse
import re

from sqlalchemy import select, update

from app.db.models.investigation import (
    AgentRunRecord,
    ApprovalRecord,
    AuditEventRecord,
    InvestigationRecord,
    InvestigationReportRecord,
    OrganizationMembershipRecord,
    ResponseActionRecord,
    ToolExecutionRecord,
    UserRecord,
)
from app.db.session import get_session_factory


IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


def _identifier(value: str, label: str) -> str:
    if not IDENTIFIER_PATTERN.fullmatch(value):
        raise ValueError(f"{label} contains unsupported characters.")
    return value


def assign_legacy_records(
    *,
    organization_id: str,
    from_organization_id: str = "legacy",
    owner_user_id: str | None = None,
) -> dict[str, int]:
    target = _identifier(organization_id, "organization_id")
    source = _identifier(from_organization_id, "from_organization_id")
    owner = (
        _identifier(owner_user_id, "owner_user_id")
        if owner_user_id
        else None
    )
    counts: dict[str, int] = {}

    with get_session_factory().begin() as session:
        if owner:
            if session.get(UserRecord, owner) is None:
                session.add(UserRecord(user_id=owner))
                session.flush()
            membership = session.scalar(
                select(OrganizationMembershipRecord).where(
                    OrganizationMembershipRecord.organization_id == target,
                    OrganizationMembershipRecord.user_id == owner,
                )
            )
            if membership is None:
                session.add(OrganizationMembershipRecord(
                    organization_id=target,
                    user_id=owner,
                    role="admin",
                    permissions=[
                        "org:soc:read",
                        "org:investigations:create",
                        "org:responses:approve",
                        "org:responses:execute",
                    ],
                ))

        investigations = session.scalars(
            select(InvestigationRecord).where(
                InvestigationRecord.organization_id == source
            )
        ).all()
        for record in investigations:
            snapshot = dict(record.snapshot)
            snapshot["organization_id"] = target
            if owner:
                snapshot["owner_user_id"] = owner
                snapshot["initiated_by_user_id"] = owner
                record.owner_user_id = owner
                record.initiated_by_user_id = owner
            record.organization_id = target
            record.snapshot = snapshot
        counts["soc_investigations"] = len(investigations)

        updates = (
            AgentRunRecord,
            ApprovalRecord,
            InvestigationReportRecord,
            AuditEventRecord,
            ResponseActionRecord,
            ToolExecutionRecord,
        )
        for model in updates:
            result = session.execute(
                update(model)
                .where(model.organization_id == source)
                .values(organization_id=target)
            )
            counts[model.__tablename__] = int(result.rowcount or 0)

        if owner:
            session.execute(
                update(AuditEventRecord)
                .where(
                    AuditEventRecord.organization_id == target,
                    AuditEventRecord.actor_user_id.is_(None),
                )
                .values(actor_user_id=owner)
            )
            session.execute(
                update(ResponseActionRecord)
                .where(
                    ResponseActionRecord.organization_id == target,
                    ResponseActionRecord.approved_by_user_id.is_(None),
                )
                .values(approved_by_user_id=owner)
            )

    return counts


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Assign legacy TSAGE records to a Clerk organization."
    )
    parser.add_argument("--organization-id", required=True)
    parser.add_argument("--from-organization-id", default="legacy")
    parser.add_argument("--owner-user-id")
    args = parser.parse_args()
    counts = assign_legacy_records(
        organization_id=args.organization_id,
        from_organization_id=args.from_organization_id,
        owner_user_id=args.owner_user_id,
    )
    print(
        "Organization backfill complete: "
        + ", ".join(f"{table}={count}" for table, count in counts.items())
    )


if __name__ == "__main__":
    main()
