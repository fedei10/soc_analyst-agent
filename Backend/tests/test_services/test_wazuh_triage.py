from datetime import UTC, datetime, timedelta

import pytest

from app.services.wazuh.models import AlertEvidence, AlertSearchResult
from app.services.wazuh.normalization.aggregation import aggregate_alerts, build_findings
from app.services.wazuh.normalization.registry import normalize_alert
from app.db.repositories.findings import (
    FindingOwnershipError,
    InMemoryFindingRepository,
)
from app.mape_k.llm import LLMConfigurationError
from app.services.wazuh.triage.analyzer import TriageAnalyzer
from app.services.wazuh.triage.enrichment import (
    ExternalNotConfiguredAdapter,
    InternalAssetAdapter,
)
from app.services.wazuh.triage.schemas import EnrichmentResult, TriageVerdict
from app.services.wazuh.triage.service import run_triage


BASE_TIME = datetime(2026, 7, 24, 19, 0, tzinfo=UTC)


def raw_alert(
    alert_id: str,
    *,
    timestamp: str = "2026-07-24T19:00:00Z",
    decoder: str = "json",
    groups: list[str] | None = None,
    description: str = "Synthetic alert",
    level: int = 7,
    data: dict | None = None,
    full_log: str = "synthetic log",
) -> dict:
    return {
        "_id": alert_id,
        "_source": {
            "@timestamp": timestamp,
            "agent": {"id": "001", "name": "servervb"},
            "rule": {
                "id": "100001",
                "level": level,
                "description": description,
                "groups": groups or [],
            },
            "decoder": {"name": decoder},
            "data": data or {},
            "full_log": full_log,
        },
    }


def auth_raw(alert_id: str, *, offset: int = 0) -> dict:
    raw = raw_alert(
        alert_id,
        timestamp=(BASE_TIME + timedelta(seconds=offset)).isoformat(),
        decoder="sshd",
        groups=["sshd", "authentication_failures"],
        description="sshd: brute force trying to get access to the system",
        level=10,
        data={"srcip": "192.168.100.9", "srcuser": "lab"},
        full_log="Failed password for lab from 192.168.100.9 port 4422 ssh2",
    )
    raw["_source"]["rule"]["id"] = "5712"
    raw["_source"]["rule"]["mitre"] = {"id": ["T1110"]}
    return raw


def ssh_brute_force_finding(count: int = 2):
    envelopes = [normalize_alert(auth_raw(f"ssh-{i}", offset=i)) for i in range(count)]
    groups = aggregate_alerts(envelopes)
    return build_findings(groups)[0]


def generic_finding():
    envelope = normalize_alert(raw_alert("generic-1"))
    groups = aggregate_alerts([envelope])
    return build_findings(groups)[0]


class FailingLLM:
    def invoke_structured(self, schema, messages):
        raise RuntimeError("provider unavailable")


class UnconfiguredLLM:
    def invoke_structured(self, schema, messages):
        raise LLMConfigurationError("provider not configured")


def test_ssh_brute_force_verdict_is_deterministic_and_malicious():
    finding = ssh_brute_force_finding()
    assert finding.event_type == "ssh_brute_force"
    verdict = TriageAnalyzer(llm=FailingLLM()).run(finding, enrichment=[])
    assert verdict.deterministic is True
    assert verdict.verdict == "malicious"
    assert verdict.escalation_recommended is True
    assert set(verdict.evidence_refs) <= set(finding.evidence_refs)


def test_allowlisted_source_overrides_verdict_to_benign():
    finding = ssh_brute_force_finding()
    enrichment = [
        EnrichmentResult(
            indicator="192.168.100.9",
            indicator_type="ip",
            is_internal=True,
            allowlisted=True,
            source="internal_asset_inventory",
        )
    ]
    verdict = TriageAnalyzer(llm=FailingLLM()).run(finding, enrichment)
    assert verdict.verdict == "benign"
    assert verdict.false_positive_indicators


def test_generic_alert_is_inconclusive_with_missing_evidence():
    finding = generic_finding()
    assert finding.event_type == "generic_alert"
    verdict = TriageAnalyzer(llm=FailingLLM()).run(finding, enrichment=[])
    assert verdict.verdict == "inconclusive"
    assert verdict.deterministic is True
    assert verdict.missing_evidence


def test_evidence_hallucination_is_rejected():
    finding = ssh_brute_force_finding()
    bad_verdict = TriageVerdict(
        verdict="malicious",
        confidence=0.9,
        severity=finding.severity,
        summary="fabricated",
        evidence_refs=["wazuh:alert:not-real"],
        escalation_recommended=True,
    )
    with pytest.raises(ValueError):
        TriageAnalyzer._validate_evidence(bad_verdict, finding)


def test_llm_fallback_used_for_unmapped_event_type(monkeypatch):
    finding = ssh_brute_force_finding()
    finding = finding.model_copy(update={"event_type": "network_connection"})

    class RoutedLLM:
        def invoke_structured(self, schema, messages):
            return (
                TriageVerdict(
                    verdict="suspicious",
                    confidence=0.5,
                    severity=finding.severity,
                    summary="LLM triage",
                    evidence_refs=finding.evidence_refs,
                    escalation_recommended=False,
                ),
                {"input_tokens": 10, "output_tokens": 4},
            )

    verdict = TriageAnalyzer(llm=RoutedLLM()).run(finding, enrichment=[])
    assert verdict.deterministic is False
    assert verdict.verdict == "suspicious"


def test_llm_unavailable_falls_back_to_inconclusive():
    finding = ssh_brute_force_finding()
    finding = finding.model_copy(update={"event_type": "network_connection"})
    verdict = TriageAnalyzer(llm=UnconfiguredLLM()).run(finding, enrichment=[])
    assert verdict.verdict == "inconclusive"
    assert verdict.reason_code == "LLM_UNAVAILABLE"


def test_internal_asset_adapter_flags_private_ip_as_internal():
    result = InternalAssetAdapter().enrich("192.168.100.9", "ip")
    assert result.is_internal is True
    assert result.known_asset is True
    assert result.allowlisted is False


def test_internal_asset_adapter_honors_approved_admin_allowlist(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "MAPEK_APPROVED_ADMIN_IPS", "192.168.100.9")
    result = InternalAssetAdapter().enrich("192.168.100.9", "ip")
    assert result.allowlisted is True
    assert result.reputation == "clean"


def test_external_adapter_is_not_configured():
    result = ExternalNotConfiguredAdapter("virustotal").enrich("8.8.8.8", "ip")
    assert result.source == "virustotal:not_configured"
    assert result.reputation == "unknown"


def test_finding_repository_upsert_is_idempotent():
    finding = ssh_brute_force_finding()
    verdict = TriageAnalyzer(llm=FailingLLM()).run(finding, enrichment=[])
    repo = InMemoryFindingRepository()
    first = repo.upsert(organization_id="org-1", finding=finding, verdict=verdict, enrichment=[])
    second = repo.upsert(organization_id="org-1", finding=finding, verdict=verdict, enrichment=[])
    assert first["created_at"] == second["created_at"]
    assert first["updated_at"] == second["updated_at"]
    assert first["version"] == second["version"] == 1
    assert second["status"] == "open"
    assert second["alert_count"] == finding.alert_count
    listed = repo.list(organization_id="org-1", limit=10)
    assert [item["finding_id"] for item in listed] == [finding.finding_id]


def test_finding_repository_rejects_cross_organization_upsert():
    finding = ssh_brute_force_finding()
    verdict = TriageAnalyzer(llm=FailingLLM()).run(finding, enrichment=[])
    repo = InMemoryFindingRepository()
    repo.upsert(organization_id="org-1", finding=finding, verdict=verdict, enrichment=[])
    with pytest.raises(FindingOwnershipError):
        repo.upsert(organization_id="org-2", finding=finding, verdict=verdict, enrichment=[])


def test_finding_repository_feedback_round_trip():
    finding = ssh_brute_force_finding()
    verdict = TriageAnalyzer(llm=FailingLLM()).run(finding, enrichment=[])
    repo = InMemoryFindingRepository()
    repo.upsert(organization_id="org-1", finding=finding, verdict=verdict, enrichment=[])
    repo.add_feedback(
        finding_id=finding.finding_id,
        organization_id="org-1",
        reviewer_user_id="analyst-1",
        disposition="confirmed_malicious",
        notes="Matches known scanner.",
    )
    feedback = repo.list_feedback(finding.finding_id, organization_id="org-1")
    assert len(feedback) == 1
    assert feedback[0]["disposition"] == "confirmed_malicious"
    record = repo.get(finding.finding_id, organization_id="org-1")
    assert record["feedback"] == feedback
    assert record["status"] == "investigating"
    assert record["version"] == 2


def test_finding_repository_feedback_requires_existing_finding():
    repo = InMemoryFindingRepository()
    with pytest.raises(LookupError):
        repo.add_feedback(
            finding_id="FND-MISSING",
            organization_id="org-1",
            reviewer_user_id="analyst-1",
            disposition="confirmed_benign",
            notes=None,
        )


class FakeGateway:
    def search_alerts(self, **kwargs):
        return AlertSearchResult(
            total=2,
            returned=2,
            truncated=False,
            alerts=[
                AlertEvidence(
                    alert_id=f"ssh-{i}",
                    timestamp=BASE_TIME + timedelta(seconds=i),
                    agent_id="001",
                    agent_name="servervb",
                    rule_id="5712",
                    rule_level=10,
                    description="sshd: brute force trying to get access to the system",
                    source_ip="192.168.100.9",
                    target_user="lab",
                    decoder_name="sshd",
                    full_log="Failed password for lab",
                    rule_groups=["sshd", "authentication_failures"],
                    mitre_ids=["T1110"],
                    event_outcome="failure",
                )
                for i in range(2)
            ],
        )


def test_run_triage_persists_and_returns_evidence_backed_verdicts():
    repo = InMemoryFindingRepository()
    triaged = run_triage(
        gateway=FakeGateway(),
        hours=24,
        min_level=0,
        limit=50,
        organization_id="org-1",
        repository=repo,
        analyzer=TriageAnalyzer(llm=FailingLLM()),
    )
    assert len(triaged) == 1
    item = triaged[0]
    assert item.verdict.verdict == "malicious"
    stored = repo.get(item.finding.finding_id, organization_id="org-1")
    assert stored is not None
    assert stored["verdict"]["verdict"] == "malicious"


def test_run_triage_rejects_out_of_range_hours():
    with pytest.raises(ValueError):
        run_triage(
            gateway=FakeGateway(),
            hours=0,
            organization_id="org-1",
            repository=InMemoryFindingRepository(),
        )
