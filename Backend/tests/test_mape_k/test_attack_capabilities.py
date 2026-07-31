import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.mape_k.capabilities import (
    capability_for_alert,
    diagnose_with_capabilities,
)
from app.mape_k.schemas import (
    EvidenceCollectionResult,
    EvidenceReference,
    IncidentWorkflowState,
)
from app.services.wazuh.normalization.schemas import NormalizedAlert


CASES = json.loads(
    (
        Path(__file__).parents[1]
        / "evaluation"
        / "attack_matrix.json"
    ).read_text()
)


def _state(case, *, rule_level=12):
    alert = NormalizedAlert(
        alert_id="alert-1",
        timestamp=datetime(2026, 7, 28, tzinfo=UTC),
        agent_id="001",
        hostname="lab-host",
        rule_id="100001",
        rule_level=rule_level,
        category="security",
        attack_family=case["attack_family"],
        event_type=case["event_type"],
        mitre_techniques=case["mitre"],
        process_name=case.get("process_name"),
        file_path=case.get("file_path"),
        package_name=case.get("package_name"),
        cve_id=case.get("cve_id"),
        destination_ip=case.get("destination_ip"),
        summary=case["name"],
        evidence_ref="wazuh:alert:alert-1",
        normalization_quality="complete",
    )
    evidence = EvidenceReference(
        evidence_id="EV-AAAAAAAAAAAA",
        source_type="wazuh_alert",
        source_ref="wazuh:alert:alert-1",
        observed_at=alert.timestamp,
        summary=alert.summary,
        content_hash="a" * 64,
    )
    capability = capability_for_alert(alert)
    collection_results = [
        EvidenceCollectionResult(
            evidence_type=requirement.evidence_type,
            collector=requirement.collector,
            required=requirement.required,
            purpose=requirement.purpose,
            status="collected",
            records=1,
            source="test",
            evidence_ids=[evidence.evidence_id],
        )
        for requirement in (
            capability.evidence_requirements if capability is not None else ()
        )
    ]
    return IncidentWorkflowState(
        incident_id="INC-CAPABILITY",
        investigation_id="INV-CAPABILITY",
        alert_id="alert-1",
        agent_id="001",
        normalized_alerts=[alert],
        evidence=[evidence],
        evidence_collection_results=collection_results,
        monitor_context={"related_alerts_truncated": False},
    )


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_attack_capability_matrix(case):
    diagnosis = diagnose_with_capabilities(_state(case))

    assert diagnosis is not None
    assert diagnosis.incident_type == case["expected"]
    assert diagnosis.deterministic is True
    assert diagnosis.evidence_ids == ["EV-AAAAAAAAAAAA"]
    assert diagnosis.needs_more_evidence is False
    assert diagnosis.evidence_completeness == 1.0
    assert diagnosis.supporting_evidence_ids == ["EV-AAAAAAAAAAAA"]


def test_low_severity_process_event_does_not_become_an_attack():
    case = next(item for item in CASES if item["name"] == "suspicious process")

    assert diagnose_with_capabilities(_state(case, rule_level=5)) is None


def test_missing_capability_entity_requests_more_evidence():
    case = next(item for item in CASES if item["name"] == "command and control")
    case = {**case, "destination_ip": None}

    diagnosis = diagnose_with_capabilities(_state(case))

    assert diagnosis is not None
    assert diagnosis.needs_more_evidence is True


def test_unavailable_required_collector_caps_evidence_completeness():
    case = next(item for item in CASES if item["name"] == "suspicious process")
    state = _state(case)
    results = list(state.evidence_collection_results)
    results[1] = results[1].model_copy(
        update={"status": "collector_unavailable", "evidence_ids": []}
    )

    diagnosis = diagnose_with_capabilities(
        state.model_copy(update={"evidence_collection_results": results})
    )

    assert diagnosis.needs_more_evidence is True
    assert diagnosis.evidence_completeness < 0.8
    assert results[1].evidence_type in diagnosis.missing_evidence
