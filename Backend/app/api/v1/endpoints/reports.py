"""Read-only access to analyst reports saved from the SOC chat."""

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response

from app.api.auth.deps import AuthPrincipal, require_read
from app.db.repositories.reports import ReportRepository, get_report_repository
from app.orchestration.report_pdf import build_analyst_report_pdf

read = APIRouter(dependencies=[Depends(require_read)])
ReadPrincipal = Annotated[AuthPrincipal, Depends(require_read)]
Repository = Annotated[ReportRepository, Depends(get_report_repository)]


def _public_data(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _public_data(item)
            for key, item in value.items()
            if key != "organization_id"
        }
    if isinstance(value, list):
        return [_public_data(item) for item in value]
    return value


@read.get("/reports", tags=["reports"])
def list_reports(
    principal: ReadPrincipal,
    repository: Repository,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
):
    items = repository.list(
        organization_id=principal.scope_id,
        limit=limit,
        offset=offset,
    )
    return {"data": {"items": _public_data(items), "count": len(items)}}


def _report(
    report_id: str,
    repository: ReportRepository,
    principal: AuthPrincipal,
) -> dict[str, Any]:
    record = repository.get(report_id, organization_id=principal.scope_id)
    if record is None:
        raise HTTPException(404, f"Report {report_id} not found.")
    return record


@read.get("/reports/{report_id}", tags=["reports"])
def get_report(
    report_id: str,
    principal: ReadPrincipal,
    repository: Repository,
):
    record = _report(report_id, repository, principal)
    return {"data": _public_data(record)}


@read.get("/reports/{report_id}.pdf", tags=["reports"])
def get_report_pdf(
    report_id: str,
    principal: ReadPrincipal,
    repository: Repository,
):
    record = _report(report_id, repository, principal)
    return Response(
        content=build_analyst_report_pdf(record),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'inline; filename="{report_id}.pdf"'
        },
    )
