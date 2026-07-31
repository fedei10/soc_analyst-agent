"""Checkpointed Wazuh ingestion and correlation over durable PostgreSQL data."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
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
from app.services.wazuh.models import NewAlertCheckResult
from app.services.wazuh.normalization.aggregation import (
    aggregate_alerts_with_memberships,
    build_findings,
)
from app.services.wazuh.normalization.schemas import AlertEnvelope
from app.services.wazuh.triage.analyzer import TriageAnalyzer
from app.services.wazuh.triage.enrichment import InternalAssetAdapter
from app.services.wazuh.triage.service import _enrich_finding
from app.services.redis.ephemeral import EphemeralRedis


logger = structlog.get_logger("tsage.wazuh.ingestion")
SOURCE_NAME = "wazuh-indexer"


class IngestionAlreadyRunningError(RuntimeError):
    """Another worker owns the durable ingestion cursor lease."""


def ingestion_source_name(
    connection_profile_id: str,
    index_pattern: str,
) -> str:
    if connection_profile_id == "default" and index_pattern == "wazuh-alerts-*":
        return SOURCE_NAME
    digest = hashlib.sha256(
        f"{connection_profile_id}|{index_pattern}".encode()
    ).hexdigest()[:16]
    return f"{SOURCE_NAME}:{digest}"


def default_ingestion_source_name() -> str:
    return ingestion_source_name(
        settings.WAZUH_CONNECTION_PROFILE_ID,
        "wazuh-alerts-*",
    )


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class AlertIngestionService:
    def __init__(
        self,
        *,
        gateway: WazuhGateway | None = None,
        alert_repository: SQLAlchemyAlertMemoryRepository | None = None,
        finding_repository: FindingRepository | None = None,
        analyzer: TriageAnalyzer | None = None,
        cache: EphemeralRedis | None = None,
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
        self.cache = cache or EphemeralRedis()
        self.connection_profile_id = settings.WAZUH_CONNECTION_PROFILE_ID
        self.index_pattern = str(
            getattr(
                getattr(self.gateway, "indexer", None),
                "ALERT_INDEX",
                "wazuh-alerts-*",
            )
        )
        self.source_name = ingestion_source_name(
            self.connection_profile_id,
            self.index_pattern,
        )

    def ingest(self) -> NewAlertCheckResult:
        lock_resource = f"ingestion:{self.source_name}"
        redis_lease = self.cache.acquire_lock(
            organization_id=settings.WAZUH_INGESTION_ORGANIZATION_ID,
            resource=lock_resource,
            ttl_seconds=settings.WAZUH_INGESTION_LEASE_TTL_SECONDS,
        )
        if not redis_lease.acquired:
            raise IngestionAlreadyRunningError(
                "Another Wazuh ingestion cycle is already running."
            )
        checkpoint = self.alert_repository.checkpoint(
            self.source_name,
            connection_profile_id=self.connection_profile_id,
            index_pattern=self.index_pattern,
        ) or {}
        lease_token = self.alert_repository.claim_ingestion(
            self.source_name,
            connection_profile_id=self.connection_profile_id,
            index_pattern=self.index_pattern,
            lease_ttl_seconds=settings.WAZUH_INGESTION_LEASE_TTL_SECONDS,
        )
        if lease_token is None:
            self.cache.release_lock(
                organization_id=settings.WAZUH_INGESTION_ORGANIZATION_ID,
                resource=lock_resource,
                lease=redis_lease,
            )
            raise IngestionAlreadyRunningError(
                "Another Wazuh ingestion cycle owns the durable cursor lease."
            )
        previous_check_at = _as_utc(checkpoint.get("last_run_completed_at"))
        high_water = _as_utc(checkpoint.get("last_event_timestamp"))
        since = (
            high_water
            - timedelta(seconds=settings.WAZUH_INGESTION_OVERLAP_SECONDS)
            if high_water is not None
            else None
        )
        search_after = (
            checkpoint.get("search_after")
            if checkpoint.get("last_truncated")
            else None
        )
        inserted_total = 0
        duplicate_total = 0
        highest_new_rule_level: int | None = None
        cursor_advanced = False
        pages = 0
        last_page_size = 0
        try:
            while pages < settings.WAZUH_INGESTION_MAX_PAGES_PER_RUN:
                page = self.gateway.search_alert_page(
                    size=settings.WAZUH_INGESTION_PAGE_SIZE,
                    since=since,
                    search_after=search_after,
                )
                persisted = self.alert_repository.ingest_page_result(
                    source_name=self.source_name,
                    documents=page.documents,
                    search_after=page.search_after,
                    connection_profile_id=self.connection_profile_id,
                    index_pattern=self.index_pattern,
                )
                inserted_total += persisted.inserted_count
                duplicate_total += persisted.duplicate_count
                cursor_advanced = cursor_advanced or persisted.cursor_advanced
                if persisted.highest_new_rule_level is not None:
                    highest_new_rule_level = max(
                        highest_new_rule_level or 0,
                        persisted.highest_new_rule_level,
                )
                pages += 1
                last_page_size = len(page.documents)
                search_after = page.search_after
                if not self.alert_repository.renew_ingestion_claim(
                    self.source_name,
                    lease_token=lease_token,
                    lease_ttl_seconds=settings.WAZUH_INGESTION_LEASE_TTL_SECONDS,
                ):
                    raise IngestionAlreadyRunningError(
                        "The durable ingestion cursor lease was lost."
                    )
                if len(page.documents) < settings.WAZUH_INGESTION_PAGE_SIZE:
                    break
            truncated = bool(
                pages >= settings.WAZUH_INGESTION_MAX_PAGES_PER_RUN
                and last_page_size >= settings.WAZUH_INGESTION_PAGE_SIZE
            )
            if not self.alert_repository.renew_ingestion_claim(
                self.source_name,
                lease_token=lease_token,
                lease_ttl_seconds=settings.WAZUH_INGESTION_LEASE_TTL_SECONDS,
            ):
                raise IngestionAlreadyRunningError(
                    "The durable ingestion cursor lease was lost."
                )
            correlated = self.correlate(
                limit=(
                    settings.WAZUH_INGESTION_PAGE_SIZE
                    * settings.WAZUH_INGESTION_MAX_PAGES_PER_RUN
                )
            )
            self.alert_repository.mark_ingestion_completed(
                self.source_name,
                alert_count=inserted_total,
                duplicate_count=duplicate_total,
                finding_count=correlated["new_finding_count"],
                updated_finding_count=correlated["updated_finding_count"],
                incident_count=correlated["new_incident_count"],
                highest_new_rule_level=highest_new_rule_level,
                cursor_advanced=cursor_advanced,
                truncated=truncated,
            )
        except Exception as exc:
            self.alert_repository.mark_ingestion_failed(self.source_name, exc)
            logger.exception(
                "alert_ingestion_failed",
                error_type=type(exc).__name__,
            )
            raise
        finally:
            self.alert_repository.release_ingestion_claim(
                self.source_name,
                lease_token=lease_token,
            )
            self.cache.release_lock(
                organization_id=settings.WAZUH_INGESTION_ORGANIZATION_ID,
                resource=lock_resource,
                lease=redis_lease,
            )
        result = NewAlertCheckResult(
            source=self.source_name,
            connection_profile_id=self.connection_profile_id,
            index_pattern=self.index_pattern,
            checked_at=datetime.now(UTC),
            previous_check_at=previous_check_at,
            new_alert_count=inserted_total,
            duplicate_alert_count=duplicate_total,
            new_finding_count=correlated["new_finding_count"],
            updated_finding_count=correlated["updated_finding_count"],
            new_incident_count=correlated["new_incident_count"],
            highest_new_rule_level=highest_new_rule_level,
            has_new_alerts=inserted_total > 0,
            cursor_advanced=cursor_advanced,
            truncated=truncated,
            pages=pages,
        )
        logger.info("alert_ingestion_completed", **result.model_dump(mode="json"))
        return result

    def correlate(self, *, limit: int = 500) -> dict[str, int]:
        pending = self.alert_repository.pending_normalized_events(limit=limit)
        if not pending:
            return {
                "correlated_alerts": 0,
                "new_finding_count": 0,
                "updated_finding_count": 0,
                "new_incident_count": 0,
            }
        envelopes = [
            AlertEnvelope.model_validate(data)
            for _, data in pending
        ]
        ids_by_reference = {
            envelope.normalized.evidence_ref: alert_id
            for (alert_id, _), envelope in zip(pending, envelopes, strict=True)
        }
        groups, group_memberships = aggregate_alerts_with_memberships(
            envelopes
        )
        findings = build_findings(groups)
        correlated: set[int] = set()
        auto_candidates: list[Any] = []
        new_findings = 0
        updated_findings = 0
        finding_scope = settings.WAZUH_INGESTION_ORGANIZATION_ID
        for finding in findings:
            enrichment = _enrich_finding(finding, self.internal_adapter)
            # Monitor remains deterministic and provider-independent. Explicit
            # analyst triage may still use the model fallback.
            verdict = self.analyzer.run(
                finding,
                enrichment,
                allow_model=False,
            )
            previous = self.finding_repository.get(
                finding.finding_id,
                organization_id=finding_scope,
            )
            persisted = self.finding_repository.upsert(
                organization_id=finding_scope,
                finding=finding,
                verdict=verdict,
                enrichment=enrichment,
            )
            if previous is None:
                new_findings += 1
            elif int(persisted.get("version") or 0) > int(
                previous.get("version") or 0
            ):
                updated_findings += 1
            group_id = finding.finding_id.replace("FND-", "GRP-", 1)
            alert_ids = [
                ids_by_reference[reference]
                for reference in group_memberships.get(group_id, [])
                if reference in ids_by_reference
            ]
            self.alert_repository.attach_finding(
                finding_id=finding.finding_id,
                alert_ids=alert_ids,
            )
            correlated.update(alert_ids)
            if self._should_auto_investigate(finding, verdict):
                auto_candidates.append(finding)
        return {
            "correlated_alerts": len(correlated),
            "new_finding_count": new_findings,
            "updated_finding_count": updated_findings,
            "new_incident_count": self._open_auto_investigations(
                auto_candidates,
                organization_id=finding_scope,
            ),
        }

    @staticmethod
    def _should_auto_investigate(finding: Any, verdict: Any) -> bool:
        """Incident-creation policy: only clear, severe, confident findings."""

        if not settings.MAPEK_AUTO_INVESTIGATE_ENABLED:
            return False
        return bool(
            getattr(finding, "investigation_recommended", False)
            and getattr(verdict, "verdict", "") in {"malicious", "suspicious"}
            and float(getattr(verdict, "confidence", 0))
            >= float(settings.MAPEK_AUTO_INVESTIGATE_MIN_CONFIDENCE)
        )

    def _open_auto_investigations(
        self,
        findings: list[Any],
        *,
        organization_id: str,
    ) -> int:
        """Queue investigations for policy-selected findings.

        enqueue() already returns the existing investigation when one is
        active for the alert, so repeated ingestion cycles converge instead
        of piling up duplicates.
        """

        if not findings:
            return 0
        from app.orchestration.investigation_service import (
            get_investigation_service,
        )

        limit = max(0, int(settings.MAPEK_AUTO_INVESTIGATE_MAX_PER_CYCLE))
        service = get_investigation_service()
        opened = 0
        for finding in sorted(
            findings,
            key=lambda item: -int(getattr(item, "severity_score", 0)),
        )[:limit]:
            try:
                snapshot = service.enqueue(
                    alert_id=finding.representative_alert_id,
                    finding_id=finding.finding_id,
                    initiated_by="auto-triage",
                    initiation_reason=(
                        f"Auto-opened for {finding.severity} "
                        f"{finding.event_type} finding {finding.finding_id}."
                    ),
                    organization_id=organization_id,
                )
            except Exception:
                logger.warning(
                    "auto_investigation_failed",
                    finding_id=getattr(finding, "finding_id", None),
                    exc_info=True,
                )
                continue
            if str(snapshot.get("status") or "") == "queued":
                opened += 1
                logger.info(
                    "auto_investigation_opened",
                    finding_id=finding.finding_id,
                    investigation_id=snapshot.get("investigation_id"),
                    severity=finding.severity,
                )
        return opened


def check_for_new_wazuh_alerts() -> NewAlertCheckResult:
    """Run one deterministic, checkpointed Monitor cycle."""

    return AlertIngestionService().ingest()
