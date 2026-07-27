"""Checks for the analyst-report read endpoints and organization scoping."""

import pytest
from fastapi import HTTPException

from app.api.auth.deps import AuthPrincipal
from app.api.v1.endpoints import reports
from app.db.repositories.reports import InMemoryReportRepository

PRINCIPAL = AuthPrincipal(
    user_id="user_1",
    session_id="sess_1",
    scope_id="user_1",
)
OTHER_PRINCIPAL = AuthPrincipal(
    user_id="user_2",
    session_id="sess_2",
    scope_id="user_2",
)


def _seeded_repo() -> InMemoryReportRepository:
    repo = InMemoryReportRepository()
    repo.create(
        organization_id="user_1",
        title="SSH brute force write-up",
        summary="Repeated failed logins.",
        body_markdown="## Summary\nBrute force.",
        created_by="user_1",
        severity="high",
    )
    return repo


def test_list_reports_is_scoped_to_the_caller():
    repo = _seeded_repo()

    mine = reports.list_reports(PRINCIPAL, repo, limit=20, offset=0)
    assert mine["data"]["count"] == 1
    assert "organization_id" not in mine["data"]["items"][0]

    others = reports.list_reports(OTHER_PRINCIPAL, repo, limit=20, offset=0)
    assert others["data"]["count"] == 0


def test_get_report_hides_it_from_other_scopes():
    repo = _seeded_repo()
    report_id = repo.list(organization_id="user_1", limit=10)[0]["report_id"]

    body = reports.get_report(report_id, PRINCIPAL, repo)
    assert body["data"]["report_id"] == report_id

    with pytest.raises(HTTPException) as error:
        reports.get_report(report_id, OTHER_PRINCIPAL, repo)
    assert error.value.status_code == 404


def test_get_report_pdf_returns_a_pdf_response():
    repo = _seeded_repo()
    report_id = repo.list(organization_id="user_1", limit=10)[0]["report_id"]

    response = reports.get_report_pdf(report_id, PRINCIPAL, repo)
    assert response.media_type == "application/pdf"
    assert response.body.startswith(b"%PDF")
