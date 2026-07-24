import pytest

from app.coreAgents.orchestration.evidence import validate_result_evidence
from app.coreAgents.orchestration.schemas import L1Result, L3Result


STATE = {
    "normalized_alert": {"alert_id": "alert-1"},
    "evidence": [],
}


def test_supported_conclusion_reference_is_accepted():
    validate_result_evidence(
        STATE,
        L1Result(
            summary="Suspicious authentication",
            classification="suspicious",
            severity="high",
            confidence=0.9,
            evidence_refs=["alert:alert-1"],
        ),
    )


def test_unknown_conclusion_reference_is_rejected():
    with pytest.raises(ValueError):
        validate_result_evidence(
            STATE,
            L1Result(
                summary="Suspicious authentication",
                classification="suspicious",
                severity="high",
                confidence=0.9,
                evidence_refs=["alert:invented"],
            ),
        )


def test_l3_action_without_evidence_reference_is_rejected():
    with pytest.raises(ValueError):
        validate_result_evidence(
            STATE,
            L3Result(
                summary="Containment",
                evidence_refs=["alert:alert-1"],
                proposed_actions=[{
                    "action_type": "block_ip",
                    "target": "192.0.2.10",
                    "reason": "Contain source",
                    "risk_level": "medium",
                    "operational_impact": "May block a legitimate user",
                }],
            ),
        )
