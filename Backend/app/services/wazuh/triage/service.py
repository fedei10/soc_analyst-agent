"""On-demand triage: search -> normalize -> group -> enrich -> verdict -> persist."""

from __future__ import annotations

from app.db.repositories.findings import FindingRepository, get_finding_repository
from app.services.wazuh.gateway import WazuhGateway
from app.services.wazuh.normalization.aggregation import aggregate_alerts, build_findings
from app.services.wazuh.normalization.registry import normalize_alerts
from app.services.wazuh.normalization.schemas import SecurityFinding
from app.services.wazuh.triage.analyzer import TriageAnalyzer
from app.services.wazuh.triage.enrichment import InternalAssetAdapter, VENDOR_ADAPTERS
from app.services.wazuh.triage.schemas import EnrichmentResult, TriagedFinding

MAX_ENRICHED_IPS_PER_FINDING = 5


def _enrich_finding(
    finding: SecurityFinding,
    internal_adapter: InternalAssetAdapter,
) -> list[EnrichmentResult]:
    results: list[EnrichmentResult] = []
    for source_ip in finding.source_ips[:MAX_ENRICHED_IPS_PER_FINDING]:
        internal = internal_adapter.enrich(source_ip, "ip")
        results.append(internal)
        if not internal.is_internal:
            results.extend(
                adapter.enrich(source_ip, "ip") for adapter in VENDOR_ADAPTERS.values()
            )
    return results


def run_triage(
    *,
    gateway: WazuhGateway,
    hours: int = 24,
    min_level: int = 0,
    limit: int = 50,
    organization_id: str,
    repository: FindingRepository | None = None,
    analyzer: TriageAnalyzer | None = None,
    internal_adapter: InternalAssetAdapter | None = None,
) -> list[TriagedFinding]:
    if not 1 <= hours <= 168:
        raise ValueError("hours must be between 1 and 168.")
    if not 1 <= limit <= 200:
        raise ValueError("limit must be between 1 and 200.")

    repository = repository or get_finding_repository()
    analyzer = analyzer or TriageAnalyzer()
    internal_adapter = internal_adapter or InternalAssetAdapter()

    result = gateway.search_alerts(min_level=min_level, hours=hours, limit=limit)
    raw_alerts = [alert.model_dump(mode="json") for alert in result.alerts]
    envelopes = normalize_alerts(raw_alerts)
    groups = aggregate_alerts(envelopes)
    findings = build_findings(groups)

    triaged: list[TriagedFinding] = []
    for finding in findings:
        enrichment = _enrich_finding(finding, internal_adapter)
        verdict = analyzer.run(finding, enrichment)
        repository.upsert(
            organization_id=organization_id,
            finding=finding,
            verdict=verdict,
            enrichment=enrichment,
        )
        triaged.append(TriagedFinding(finding=finding, verdict=verdict, enrichment=enrichment))
    return triaged
