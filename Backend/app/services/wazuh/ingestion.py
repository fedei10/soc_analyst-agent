"""Checkpointed Wazuh ingestion and correlation over durable PostgreSQL data."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog

from app.config import settings
from app.db.repositories.alert_memory import (
    SQLAlchemyAlertMemoryRepository,
    get_alert_memory_repository,
)
from app.db.repositories.findings import (
    FindingRepository,
    get_finding_repository,
)
from app.services.wazuh.gateway import WazuhGateway
from app.services.wazuh.normalization.aggregation import (
    aggregate_alerts,
    build_findings,
)
from app.services.wazuh.normalization.schemas import AlertEnvelope
from app.services.wazuh.triage.analyzer import TriageAnalyzer
from app.services.wazuh.triage.enrichment import InternalAssetAdapter
from app.services.wazuh.triage.service import _enrich_finding


logger = structlog.get_logger("tsage.wazuh.ingestion")
SOURCE_NAME = "wazuh-indexer"


class AlertIngestionService:
    def __init__(
        self,
        *,
        gateway: WazuhGateway | None = None,
        alert_repository: SQLAlchemyAlertMemoryRepository | None = None,
        finding_repository: FindingRepository | None = None,
        analyzer: TriageAnalyzer | None = None,
    ) -> None:
        repository = alert_repository or get_alert_memory_repository()
        if not getattr(repository, "durable", False):
            raise RuntimeError("PostgreSQL is required for alert ingestion.")
        self.gateway = gateway or WazuhGateway()
        self.alert_repository = repository
        self.finding_repository = (
            finding_repository or get_finding_repository()
        )
        self.analyzer = analyzer or TriageAnalyzer()
        self.internal_adapter = InternalAssetAdapter()

    def ingest(self) -> dict[str, Any]:
        checkpoint = self.alert_repository.checkpoint(SOURCE_NAME) or {}
        since = checkpoint.get("last_event_timestamp")
        search_after = checkpoint.get("search_after")
        inserted_total = 0
        pages = 0
        self.alert_repository.mark_ingestion_started(SOURCE_NAME)
        try:
            while pages < settings.WAZUH_INGESTION_MAX_PAGES_PER_RUN:
                page = self.gateway.search_alert_page(
                    size=settings.WAZUH_INGESTION_PAGE_SIZE,
                    since=since,
                    search_after=search_after,
                )
                inserted_total += self.alert_repository.ingest_page(
                    source_name=SOURCE_NAME,
                    documents=page.documents,
                    search_after=page.search_after,
                )
                pages += 1
                search_after = page.search_after
                if len(page.documents) < settings.WAZUH_INGESTION_PAGE_SIZE:
                    break
            correlated = self.correlate()
            self.alert_repository.mark_ingestion_completed(
                SOURCE_NAME,
                alert_count=inserted_total,
            )
        except Exception as exc:
            self.alert_repository.mark_ingestion_failed(SOURCE_NAME, exc)
            logger.exception(
                "alert_ingestion_failed",
                error_type=type(exc).__name__,
            )
            raise
        result = {
            "source": SOURCE_NAME,
            "inserted_alerts": inserted_total,
            "correlated_alerts": correlated["correlated_alerts"],
            "findings_created_or_updated": correlated["finding_count"],
            "pages": pages,
            "completed_at": datetime.now(UTC).isoformat(),
        }
        logger.info("alert_ingestion_completed", **result)
        return result

    def correlate(self, *, limit: int = 500) -> dict[str, int]:
        pending = self.alert_repository.pending_normalized_events(limit=limit)
        if not pending:
            return {"correlated_alerts": 0, "finding_count": 0}
        envelopes = [
            AlertEnvelope.model_validate(data)
            for _, data in pending
        ]
        ids_by_reference = {
            envelope.normalized.evidence_ref: alert_id
            for (alert_id, _), envelope in zip(pending, envelopes, strict=True)
        }
        findings = build_findings(aggregate_alerts(envelopes))
        correlated: set[int] = set()
        for finding in findings:
            enrichment = _enrich_finding(finding, self.internal_adapter)
            verdict = self.analyzer.run(finding, enrichment)
            self.finding_repository.upsert(
                organization_id=settings.WAZUH_INGESTION_ORGANIZATION_ID,
                finding=finding,
                verdict=verdict,
                enrichment=enrichment,
            )
            alert_ids = [
                ids_by_reference[reference]
                for reference in finding.evidence_refs
                if reference in ids_by_reference
            ]
            self.alert_repository.attach_finding(
                finding_id=finding.finding_id,
                alert_ids=alert_ids,
            )
            correlated.update(alert_ids)
        return {
            "correlated_alerts": len(correlated),
            "finding_count": len(findings),
        }
