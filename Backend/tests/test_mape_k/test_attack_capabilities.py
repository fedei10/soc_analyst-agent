import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.mape_k.capabilities import diagnose_with_capabilities
from app.mape_k.schemas import (
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
    return IncidentWorkflowState(
        incident_id="INC-CAPABILITY",
        investigation_id="INV-CAPABILITY",
        alert_id="alert-1",
        agent_id="001",
        normalized_alerts=[alert],
        evidence=[evidence],
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


def test_low_severity_process_event_does_not_become_an_attack():
    case = next(item for item in CASES if item["name"] == "suspicious process")

    assert diagnose_with_capabilities(_state(case, rule_level=5)) is None


def test_missing_capability_entity_requests_more_evidence():
    case = next(item for item in CASES if item["name"] == "command and control")
    case = {**case, "destination_ip": None}

    diagnosis = diagnose_with_capabilities(_state(case))

    assert diagnosis is not None
    assert diagnosis.needs_more_evidence is True
