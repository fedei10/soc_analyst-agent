import pytest
from pydantic import ValidationError

from app.api.v1.schemas.investigation import L1Result, ProposedAction


def test_l1_result_accepts_valid_output():
    result = L1Result(
        summary="Repeated SSH authentication failures",
        classification="suspicious",
        severity="medium",
        confidence=0.82,
        source_ip="192.0.2.10",
        escalate=True,
        escalation_reason="Related activity requires investigation",
    )

    assert result.severity.value == "medium"
    assert result.escalate is True


def test_l1_result_rejects_unknown_classification():
    with pytest.raises(ValidationError):
        L1Result(
            summary="Invalid classification",
            classification="credential_access",
            severity="medium",
            confidence=0.8,
        )


def test_confidence_must_be_between_zero_and_one():
    with pytest.raises(ValidationError):
        L1Result(
            summary="Invalid confidence",
            classification="unknown",
            severity="low",
            confidence=1.5,
        )


def test_write_action_requires_approval():
    action = ProposedAction(
        action_type="block_ip",
        target="192.0.2.10",
        reason="Repeated malicious authentication",
        risk_level="medium",
        operational_impact="Could block a legitimate user",
    )

    assert action.requires_approval is True


def test_read_action_does_not_require_approval():
    action = ProposedAction(
        action_type="collect_more_evidence",
        target="agent-001",
        reason="Insufficient telemetry",
        risk_level="low",
        operational_impact="Longer investigation",
    )

    assert action.requires_approval is False


def test_llm_cannot_override_approval_policy():
    with pytest.raises(ValidationError):
        ProposedAction(
            action_type="block_ip",
            target="192.0.2.10",
            reason="Malicious activity",
            risk_level="high",
            operational_impact="Possible disruption",
            requires_approval=False,
        )


def test_action_risk_cannot_be_informational():
    with pytest.raises(ValidationError):
        ProposedAction(
            action_type="collect_more_evidence",
            target="agent-001",
            reason="Review telemetry",
            risk_level="informational",
            operational_impact="None",
        )
