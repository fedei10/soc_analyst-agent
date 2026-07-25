"""Read-only triage findings, verdicts, enrichment, and analyst feedback."""

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.auth.deps import AuthPrincipal, require_investigate, require_read
from app.api.v1.schemas.finding import FindingFeedbackInput
from app.config import settings
from app.db.repositories.findings import (
    FindingOwnershipError,
    FindingRepository,
    get_finding_repository,
)
from app.services.wazuh.dependencies import get_wazuh_gateway
from app.services.wazuh.gateway import WazuhGateway
from app.services.wazuh.triage.report import build_finding_report
from app.services.wazuh.triage.service import run_triage


read = APIRouter(dependencies=[Depends(require_read)])
write = APIRouter(dependencies=[Depends(require_investigate)])
ReadPrincipal = Annotated[AuthPrincipal, Depends(require_read)]
InvestigatorPrincipal = Annotated[AuthPrincipal, Depends(require_investigate)]
Gateway = Annotated[WazuhGateway, Depends(get_wazuh_gateway)]
Repository = Annotated[FindingRepository, Depends(get_finding_repository)]


def _finding_scope() -> str:
    return settings.WAZUH_INGESTION_ORGANIZATION_ID


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


@read.get("/findings", tags=["findings"])
def list_findings(
    principal: ReadPrincipal,
    gateway: Gateway,
    repository: Repository,
    hours: int = Query(default=24, ge=1, le=168),
    min_level: int = Query(default=0, ge=0, le=16),
    limit: int = Query(default=50, ge=1, le=200),
    severity: str | None = Query(
        default=None,
        pattern="^(informational|low|medium|high|critical)$",
    ),
    verdict: str | None = Query(
        default=None,
        pattern="^(benign|suspicious|malicious|inconclusive)$",
    ),
):
    try:
        run_triage(
            gateway=gateway,
            hours=hours,
            min_level=min_level,
            limit=limit,
            organization_id=_finding_scope(),
            repository=repository,
        )
    except FindingOwnershipError as exc:
        raise HTTPException(403, str(exc))
    items = repository.list(
        organization_id=_finding_scope(),
        limit=limit,
        severity=severity,
        verdict=verdict,
    )
    return {"data": {"items": _public_data(items), "count": len(items)}}


def _finding(
    finding_id: str,
    repository: FindingRepository,
    principal: AuthPrincipal,
) -> dict[str, Any]:
    record = repository.get(
        finding_id,
        organization_id=_finding_scope(),
    )
    if record is None:
        raise HTTPException(404, f"Finding {finding_id} not found.")
    return record


@read.get("/findings/{finding_id}", tags=["findings"])
def get_finding(
    finding_id: str,
    principal: ReadPrincipal,
    repository: Repository,
):
    record = _finding(finding_id, repository, principal)
    report = build_finding_report(record)
    return {"data": _public_data({**record, "report": report})}


@write.post("/findings/{finding_id}/feedback", status_code=201, tags=["findings"])
def submit_finding_feedback(
    finding_id: str,
    request: FindingFeedbackInput,
    principal: InvestigatorPrincipal,
    repository: Repository,
):
    try:
        entry = repository.add_feedback(
            finding_id=finding_id,
            organization_id=_finding_scope(),
            reviewer_user_id=principal.user_id,
            disposition=request.disposition,
            notes=request.notes,
        )
    except LookupError:
        raise HTTPException(404, f"Finding {finding_id} not found.")
    return {"data": _public_data(entry)}
