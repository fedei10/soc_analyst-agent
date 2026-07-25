"""Deterministic resolution and validation of SOC investigation references."""

from __future__ import annotations

from dataclasses import dataclass

from app.config import settings
from app.coreAgents.orchestration.investigation_service import (
    InvestigationNotFoundError,
    InvestigationService,
)
from app.db.repositories.alert_memory import get_alert_memory_repository
from app.db.repositories.findings import get_finding_repository
from app.services.wazuh.gateway import WazuhGateway
from app.services.wazuh.models import AlertIngestionDocument


PLACEHOLDER_IDS = {
    "ALERT-ID",
    "ALERT_ID",
    "<ALERT-ID>",
    "<ALERT_ID>",
    "EXAMPLE",
    "TEST",
}


class InvestigationReferenceError(ValueError):
    code = "INVALID_ALERT_ID"

    def __init__(self, message: str, *, suggested_command: str | None = None):
        super().__init__(message)
        self.suggested_command = suggested_command

    def payload(self) -> dict[str, str]:
        result = {"error": self.code, "message": str(self)}
        if self.suggested_command:
            result["suggested_command"] = self.suggested_command
        return result


class AlertNotFoundError(InvestigationReferenceError):
    code = "ALERT_NOT_FOUND"


class AlertAgentMismatchError(InvestigationReferenceError):
    code = "ALERT_AGENT_MISMATCH"


@dataclass(frozen=True)
class ResolvedInvestigationReference:
    reference_type: str
    alert_id: str
    agent_id: str | None
    finding_id: str | None = None
    existing_investigation: dict | None = None


def resolve_reference_type(value: str) -> str:
    normalized = value.strip()
    if normalized.lower().startswith("wazuh:alert:"):
        return "wazuh_alert"
    if normalized.upper().startswith("FND-"):
        return "finding"
    if normalized.upper().startswith("INV-"):
        return "investigation"
    return "wazuh_document_id"


def resolve_investigation_reference(
    value: str,
    *,
    agent_id: str | None,
    organization_id: str,
    gateway: WazuhGateway,
    investigations: InvestigationService,
    suggested_alert_id: str | None = None,
) -> ResolvedInvestigationReference:
    clean = value.strip()
    if clean.upper() in PLACEHOLDER_IDS:
        suggestion = (
            f"/investigate {suggested_alert_id}"
            + (f" --agent {agent_id}" if agent_id else "")
            if suggested_alert_id
            else None
        )
        raise InvestigationReferenceError(
            f"'{clean}' is an example placeholder, not a real Wazuh document ID.",
            suggested_command=suggestion,
        )

    reference_type = resolve_reference_type(clean)
    if reference_type == "investigation":
        investigation_id = clean.upper()
        try:
            existing = investigations.snapshot(
                investigation_id,
                organization_id=organization_id,
            )
        except InvestigationNotFoundError as exc:
            raise AlertNotFoundError(
                f"Investigation '{investigation_id}' does not exist."
            ) from exc
        return ResolvedInvestigationReference(
            reference_type=reference_type,
            alert_id=str(existing["alert_id"]),
            agent_id=existing.get("agent_id"),
            existing_investigation=existing,
        )

    finding_id = None
    if reference_type == "finding":
        finding_id = clean.upper()
        repository = get_finding_repository()
        finding = repository.get(
            finding_id,
            organization_id=organization_id,
        )
        if finding is None:
            finding = repository.get(
                finding_id,
                organization_id=settings.WAZUH_INGESTION_ORGANIZATION_ID,
            )
        if finding is None:
            raise AlertNotFoundError(
                f"Finding '{finding_id}' does not exist."
            )
        clean = str(finding["representative_alert_id"])
    elif reference_type == "wazuh_alert":
        clean = clean.split(":", 2)[-1]

    memory = get_alert_memory_repository()
    stored = memory.get_alert_by_document_id(clean)
    alert_agent_id = stored.get("agent_id") if stored else None
    if stored is None:
        raw = gateway.get_raw_alert_by_id(clean)
        if raw is None:
            raise AlertNotFoundError(
                f"Wazuh alert '{clean}' does not exist."
            )
        alert_agent_id = raw.normalized.agent_id
        memory.remember_alert_document(
            AlertIngestionDocument(
                document_id=raw.alert_id,
                index_name="wazuh-alerts-*",
                normalized=raw.normalized,
                raw_document=raw.raw_document,
            )
        )

    if agent_id and alert_agent_id and agent_id != alert_agent_id:
        raise AlertAgentMismatchError(
            f"Alert belongs to agent {alert_agent_id}, not {agent_id}."
        )

    existing = investigations.active_for_alert(
        clean,
        organization_id=organization_id,
    )
    return ResolvedInvestigationReference(
        reference_type=reference_type,
        alert_id=clean,
        agent_id=alert_agent_id or agent_id,
        finding_id=finding_id,
        existing_investigation=existing,
    )
