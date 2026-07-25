import pytest
from pydantic import ValidationError

from app.api.v1.schemas.investigation import (
    ApprovalDecisionInput,
    L1Result,
    ProposedAction,
)


def test_l1_result_accepts_valid_output():
    result = L1Result(
        summary="Repeated SSH authentication failures",
        classification="suspicious",
        severity="medium",
        confidence=0.82,
        source_ip="192.0.2.10",
        escalate=True,
        escalation_reason="Related activity requires investigation",
        evidence_refs=["alert:alert-1"],
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
    assert action.execution_preview == (
        "Wazuh active response: firewall-drop target=192.0.2.10"
    )


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


def test_llm_cannot_override_execution_preview():
    with pytest.raises(ValidationError):
        ProposedAction(
            action_type="restart_service",
            target="wazuh-agent.service",
            reason="Restore telemetry",
            risk_level="medium",
            operational_impact="Brief telemetry interruption",
            execution_preview="bash -c unsafe-command",
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


@pytest.mark.parametrize(
    "injected_field",
    ("approved_by", "approver_roles", "actor_user_id", "actor_roles"),
)
def test_approval_input_rejects_client_supplied_identity(injected_field):
    with pytest.raises(ValidationError):
        ApprovalDecisionInput.model_validate({
            "approval_id": "APR-001",
            "decision": "approve",
            injected_field: ["soc_l3"] if "roles" in injected_field else "attacker",
        })


def test_approval_input_accepts_only_decision_and_comment():
    submission = ApprovalDecisionInput(
        approval_id="APR-001",
        decision="reject",
        comment="Evidence is incomplete.",
    )

    assert submission.model_dump() == {
        "approval_id": "APR-001",
        "decision": "reject",
        "comment": "Evidence is incomplete.",
    }
