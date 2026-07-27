"""Checks for the in-memory analyst report repository."""

from app.db.repositories.reports import InMemoryReportRepository


def test_create_and_get_round_trip():
    repo = InMemoryReportRepository()
    record = repo.create(
        organization_id="user_1",
        title="SSH brute force on servervb",
        summary="Repeated failed logins from a single source.",
        body_markdown="## Summary\nBrute force detected.\n## Recommendations\n- Block the IP",
        created_by="user_1",
        conversation_id="conv-1",
        severity="high",
        related_alert_ids=["ssh-1", "ssh-2"],
    )
    assert record["report_id"].startswith("RPT-")

    fetched = repo.get(record["report_id"], organization_id="user_1")
    assert fetched is not None
    assert fetched["title"] == "SSH brute force on servervb"
    assert fetched["related_alert_ids"] == ["ssh-1", "ssh-2"]


def test_get_is_scoped_by_organization():
    repo = InMemoryReportRepository()
    record = repo.create(
        organization_id="user_1",
        title="T",
        summary="S",
        body_markdown="B",
        created_by="user_1",
    )
    assert repo.get(record["report_id"], organization_id="user_2") is None


def test_list_is_scoped_and_newest_first():
    repo = InMemoryReportRepository()
    first = repo.create(
        organization_id="user_1",
        title="First",
        summary="S",
        body_markdown="B",
        created_by="user_1",
    )
    second = repo.create(
        organization_id="user_1",
        title="Second",
        summary="S",
        body_markdown="B",
        created_by="user_1",
    )
    repo.create(
        organization_id="user_2",
        title="Other org",
        summary="S",
        body_markdown="B",
        created_by="user_2",
    )

    items = repo.list(organization_id="user_1", limit=10)

    assert [item["report_id"] for item in items] == [
        second["report_id"],
        first["report_id"],
    ]
