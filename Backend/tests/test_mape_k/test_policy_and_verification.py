from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from app.config import settings
from app.mape_k.playbooks import PlaybookPlanner
from app.mape_k.policy import PolicyEngine
from app.mape_k.registries import (
    ACTION_REGISTRY,
    PLAYBOOK_REGISTRY,
    VERIFICATION_CHECK_REGISTRY,
)
from app.mape_k.schemas import (
    ActionType,
    Diagnosis,
    EvidenceReference,
    ExecutionResult,
    IncidentWorkflowState,
    RemediationAction,
    RemediationPlan,
    VerificationOutcome,
)
from app.mape_k.verify import ResponseVerifier
from app.services.wazuh.models import (
    AgentSummary,
    AlertEvidence,
    AlertSearchResult,
    EndpointInventory,
)


EVIDENCE_ID = "EV-1234567890AB"
SOURCE_IP = "192.0.2.10"


def _planned_state() -> IncidentWorkflowState:
    evidence = EvidenceReference(
        evidence_id=EVIDENCE_ID,
        source_type="wazuh_alert",
        source_ref="wazuh:alert:primary",
        observed_at=datetime.now(UTC) - timedelta(minutes=5),
        summary="Repeated SSH authentication failures",
        content_hash="a" * 64,
    )
    state = IncidentWorkflowState(
        incident_id="INC-POLICY-VERIFY",
        investigation_id="INV-POLICY-VERIFY",
        alert_id="alert-primary",
        agent_id="001",
        evidence=[evidence],
        evidence_version="evidence-v1",
        diagnosis=Diagnosis(
            incident_type="ssh_brute_force",
            summary="Repeated password guessing",
            root_cause="One source exceeded the authentication failure threshold.",
            affected_assets=["server-01"],
            affected_entities={"source_ip": SOURCE_IP},
            evidence_ids=[EVIDENCE_ID],
            confidence=0.95,
            deterministic=True,
        ),
    )
    return state.model_copy(
        update={"remediation_plan": PlaybookPlanner().run(state)}
    )


def _rebuild_plan(plan: RemediationPlan, **updates) -> RemediationPlan:
    payload = plan.model_dump(mode="python")
    payload.update(updates)
    payload["plan_id"] = None
    payload["plan_hash"] = None
    return RemediationPlan.model_validate(payload)


def _execution(
    *,
    completed_at: datetime,
    status: str = "executed",
) -> ExecutionResult:
    return ExecutionResult(
        execution_id="EXE-TEST",
        action_id="ACT-TEST",
        incident_id="INC-POLICY-VERIFY",
        idempotency_key="IDEM-TEST",
        action_type=ActionType.BLOCK_IP,
        target=SOURCE_IP,
        status=status,
        started_at=completed_at - timedelta(seconds=1),
        completed_at=completed_at,
    )


def _alert(
    alert_id: str,
    *,
    timestamp: datetime,
    level: int = 10,
    outcome: str = "failure",
) -> AlertEvidence:
    return AlertEvidence(
        alert_id=alert_id,
        timestamp=timestamp,
        agent_id="001",
        agent_name="server-01",
        rule_id="5712",
        rule_level=level,
        description="sshd: failed password",
        source_ip=SOURCE_IP,
        decoder_name="sshd",
        rule_groups=["authentication_failures"],
        event_outcome=outcome,
    )


class VerificationGateway:
    def __init__(
        self,
        alerts: list[AlertEvidence],
        *,
        truncated: bool = False,
    ) -> None:
        self.alerts = alerts
        self.truncated = truncated
        self.related_calls = 0

    def get_related_alerts(self, **_kwargs):
        self.related_calls += 1
        return AlertSearchResult(
            total=len(self.alerts) + int(self.truncated),
            returned=len(self.alerts),
            truncated=self.truncated,
            alerts=self.alerts,
        )

    def get_agent_summary(self, _agent_id):
        return AgentSummary(agent_id="001", status="active")

    def get_agent_inventory(self, **_kwargs):
        return EndpointInventory(
            agent_id="001",
            component="ports",
            total=1,
            returned=1,
            truncated=False,
            items=[{"local_port": 22}],
        )


class ExactWindowGateway(VerificationGateway):
    def __init__(self, alerts: list[AlertEvidence]) -> None:
        super().__init__(alerts)
        self.window = None

    def search_alerts(
        self,
        *,
        start_time,
        end_time,
        agent_id=None,
        limit=100,
        **_kwargs,
    ):
        self.window = {
            "start_time": start_time,
            "end_time": end_time,
            "agent_id": agent_id,
            "limit": limit,
        }
        return AlertSearchResult(
            total=len(self.alerts),
            returned=len(self.alerts),
            truncated=False,
            alerts=self.alerts,
        )

    def get_related_alerts(self, **_kwargs):
        raise AssertionError("The exact post-execution search must be used.")


def _verifier_settings(
    *,
    dry_run: bool,
    observation_seconds: int = 0,
    require_management_probe: bool = False,
):
    return SimpleNamespace(
        MAPEK_DRY_RUN=dry_run,
        MAPEK_REAL_EXECUTION_ENABLED=not dry_run,
        MAPEK_VERIFICATION_OBSERVATION_SECONDS=observation_seconds,
        MAPEK_REQUIRE_MANAGEMENT_PROBE=require_management_probe,
    )


def test_published_ssh_playbook_uses_only_registered_surfaces():
    state = _planned_state()
    plan = state.remediation_plan

    assert ACTION_REGISTRY.require(ActionType.BLOCK_IP).minimum_role == "soc_l2"
    assert ACTION_REGISTRY.require(ActionType.UNBLOCK_IP).executor_key
    assert VERIFICATION_CHECK_REGISTRY.require(
        "management_ssh_reachable"
    ).required is False
    assert plan.health_checks == [
        "wazuh_agent_connected",
        "ssh_port_listening",
        "management_ssh_reachable",
    ]
    assert plan.evidence_version == state.evidence_version
    assert plan.policy_version == settings.MAPEK_POLICY_VERSION
    assert (
        plan.action_catalogue_version
        == settings.MAPEK_ACTION_CATALOGUE_VERSION
    )
    PLAYBOOK_REGISTRY.validate_plan(
        plan,
        diagnosis_type=state.diagnosis.incident_type,
    )


def test_policy_applies_role_floor_and_requires_approval():
    state = _planned_state()
    lowered = _rebuild_plan(
        state.remediation_plan,
        approval_required=False,
        required_role=None,
    )

    decision = PolicyEngine().evaluate(
        state.model_copy(update={"remediation_plan": lowered})
    )

    assert decision.allowed is True
    assert decision.approval_required is True
    assert decision.required_role == "soc_l2"


def test_policy_rejects_action_evidence_and_risk_mismatches():
    state = _planned_state()
    action = state.remediation_plan.actions[0].model_copy(
        update={"evidence_refs": ["EV-FFFFFFFFFFFF"]}
    )
    invalid = _rebuild_plan(
        state.remediation_plan,
        actions=[action],
        risk_level=0,
    )

    decision = PolicyEngine().evaluate(
        state.model_copy(update={"remediation_plan": invalid})
    )

    assert decision.allowed is False
    assert "INVALID_ACTION_EVIDENCE_REFERENCES" in decision.reason_codes
    assert "PLAN_RISK_TOO_LOW" in decision.reason_codes


def test_policy_rejects_unregistered_verification_check():
    state = _planned_state()
    invalid = _rebuild_plan(
        state.remediation_plan,
        security_checks=[
            *state.remediation_plan.security_checks,
            "unknown_check",
        ],
    )

    decision = PolicyEngine().evaluate(
        state.model_copy(update={"remediation_plan": invalid})
    )

    assert decision.allowed is False
    assert "UNREGISTERED_VERIFICATION_CHECK" in decision.reason_codes
    assert "INVALID_PLAYBOOK_REGISTRATION" in decision.reason_codes


def test_published_playbook_rejects_extra_actions_and_parameters():
    plan = _planned_state().remediation_plan
    extra_action = plan.actions[0].model_copy(
        update={"action_id": "ACT-EXTRA"}
    )
    too_many = _rebuild_plan(plan, actions=[*plan.actions, extra_action])
    bad_parameters = _rebuild_plan(
        plan,
        actions=[
            plan.actions[0].model_copy(
                update={"parameters": {"scope": "wazuh_active_response", "extra": True}}
            )
        ],
    )

    with pytest.raises(ValueError, match="action count"):
        PLAYBOOK_REGISTRY.validate_plan(
            too_many,
            diagnosis_type="ssh_brute_force",
        )
    with pytest.raises(ValueError, match="unpublished parameters"):
        PLAYBOOK_REGISTRY.validate_plan(
            bad_parameters,
            diagnosis_type="ssh_brute_force",
        )


def test_policy_binds_the_block_target_to_diagnosed_source_ip():
    state = _planned_state()
    action = state.remediation_plan.actions[0].model_copy(
        update={"target": "198.51.100.25"}
    )
    rollback = state.remediation_plan.rollback_actions[0].model_copy(
        update={
            "target": action.target,
            "parameters": {"reverts_action_id": action.action_id},
        }
    )
    changed = _rebuild_plan(
        state.remediation_plan,
        actions=[action],
        rollback_actions=[rollback],
    )

    decision = PolicyEngine().evaluate(
        state.model_copy(update={"remediation_plan": changed})
    )

    assert decision.allowed is False
    assert "ACTION_TARGET_NOT_EVIDENCE_BOUND" in decision.reason_codes


def test_policy_rejects_incident_mismatch_and_missing_rollback():
    state = _planned_state()
    invalid = _rebuild_plan(
        state.remediation_plan,
        incident_id="INC-OTHER",
        rollback_actions=[],
    )

    decision = PolicyEngine().evaluate(
        state.model_copy(update={"remediation_plan": invalid})
    )

    assert decision.allowed is False
    assert "PLAN_INCIDENT_MISMATCH" in decision.reason_codes
    assert "ROLLBACK_UNAVAILABLE" in decision.reason_codes


def test_policy_rejects_approved_administrative_ip(monkeypatch):
    state = _planned_state()
    monkeypatch.setattr(settings, "MAPEK_APPROVED_ADMIN_IPS", SOURCE_IP)

    decision = PolicyEngine().evaluate(state)

    assert decision.allowed is False
    assert "APPROVED_ADMIN_IP" in decision.reason_codes


def test_ip_actions_and_protected_lists_use_canonical_ipv6(monkeypatch):
    state = _planned_state()
    expanded = "2001:0db8:0000:0000:0000:0000:0000:0001"
    diagnosis = state.diagnosis.model_copy(
        update={"affected_entities": {"source_ip": expanded}}
    )
    action = state.remediation_plan.actions[0].model_copy(
        update={"target": expanded}
    )
    rollback = state.remediation_plan.rollback_actions[0].model_copy(
        update={
            "target": expanded,
            "parameters": {"reverts_action_id": action.action_id},
        }
    )
    plan = _rebuild_plan(
        state.remediation_plan,
        actions=[action],
        rollback_actions=[rollback],
    )
    monkeypatch.setattr(
        settings,
        "MAPEK_PROTECTED_IPS",
        "2001:db8::1",
    )

    decision = PolicyEngine().evaluate(
        state.model_copy(
            update={"diagnosis": diagnosis, "remediation_plan": plan}
        )
    )

    assert plan.actions[0].target == "2001:db8::1"
    assert "ACTION_TARGET_NOT_EVIDENCE_BOUND" not in decision.reason_codes
    assert "PROTECTED_IP" in decision.reason_codes


@pytest.mark.parametrize(
    ("action_type", "rollback_type", "target", "reason_code", "unregistered"),
    (
        # disable_user is a registered action now, so only the protected
        # account guard should stop it - that guard is what must hold.
        (
            ActionType.DISABLE_USER,
            ActionType.ENABLE_USER,
            "root",
            "PROTECTED_ACCOUNT",
            False,
        ),
        (
            ActionType.STOP_SERVICE,
            ActionType.START_SERVICE,
            "sshd",
            "PROTECTED_SERVICE",
            True,
        ),
    ),
)
def test_policy_rejects_protected_mutations(
    action_type,
    rollback_type,
    target,
    reason_code,
    unregistered,
):
    state = _planned_state()
    action = RemediationAction(
        action_id="ACT-UNSUPPORTED",
        action_type=action_type,
        target=target,
        risk_level=4,
        evidence_refs=[EVIDENCE_ID],
    )
    rollback = RemediationAction(
        action_id="ACT-UNSUPPORTED-ROLLBACK",
        action_type=rollback_type,
        target=target,
        risk_level=4,
        evidence_refs=[EVIDENCE_ID],
        parameters={"reverts_action_id": action.action_id},
    )
    invalid = _rebuild_plan(
        state.remediation_plan,
        actions=[action],
        rollback_actions=[rollback],
        risk_level=4,
        required_role=None,
    )

    decision = PolicyEngine().evaluate(
        state.model_copy(update={"remediation_plan": invalid})
    )

    assert decision.allowed is False
    assert ("UNREGISTERED_ACTION" in decision.reason_codes) is unregistered
    assert reason_code in decision.reason_codes


def test_dry_run_is_simulated_and_never_marked_passed():
    state = _planned_state()
    result = ResponseVerifier(
        gateway=VerificationGateway([]),
        settings_obj=_verifier_settings(dry_run=True),
    ).run(state)

    assert result.outcome == VerificationOutcome.SIMULATED
    assert result.security_checks_passed is False
    assert result.health_checks_passed is False
    assert result.passed is False
    assert all(item["outcome"] == "simulated" for item in result.checks)
    assert all("passed" not in item for item in result.checks)


def test_verification_excludes_pre_execution_alerts_and_labels_port_correctly():
    completed_at = datetime.now(UTC) - timedelta(seconds=10)
    gateway = VerificationGateway(
        [_alert("alert-before", timestamp=completed_at - timedelta(seconds=1))]
    )
    state = _planned_state().model_copy(
        update={
            "execution_results": [
                _execution(completed_at=completed_at, status="accepted")
            ]
        }
    )

    result = ResponseVerifier(
        gateway=gateway,
        settings_obj=_verifier_settings(dry_run=False),
    ).run(state)

    checks = {item["check"]: item for item in result.checks}
    assert result.outcome == VerificationOutcome.PASSED
    assert checks["ssh_attempts_stopped"]["observed_failures"] == 0
    assert checks["ssh_port_listening"]["outcome"] == "passed"
    assert "legitimate_ssh_reachable" not in checks
    assert checks["management_ssh_reachable"]["outcome"] == "not_verified"
    assert checks["management_ssh_reachable"]["required"] is False
    assert gateway.related_calls == 1


def test_no_op_execution_can_still_run_security_verification():
    completed_at = datetime.now(UTC) - timedelta(seconds=10)
    state = _planned_state().model_copy(
        update={
            "execution_results": [
                _execution(completed_at=completed_at, status="no_op")
            ]
        }
    )

    result = ResponseVerifier(
        gateway=VerificationGateway([]),
        settings_obj=_verifier_settings(dry_run=False),
    ).run(state)

    assert result.outcome == VerificationOutcome.PASSED
    assert result.security_checks_passed is True


def test_new_post_execution_failures_and_critical_alerts_fail_verification():
    completed_at = datetime.now(UTC) - timedelta(seconds=10)
    gateway = VerificationGateway(
        [
            _alert(
                "alert-after",
                timestamp=completed_at + timedelta(seconds=1),
                level=13,
            )
        ]
    )
    state = _planned_state().model_copy(
        update={"execution_results": [_execution(completed_at=completed_at)]}
    )

    result = ResponseVerifier(
        gateway=gateway,
        settings_obj=_verifier_settings(dry_run=False),
    ).run(state)

    checks = {item["check"]: item for item in result.checks}
    assert result.outcome == VerificationOutcome.FAILED
    assert checks["ssh_attempts_stopped"]["outcome"] == "failed"
    assert checks["no_new_critical_alerts"]["outcome"] == "failed"


def test_verifier_uses_the_gateway_exact_post_execution_window():
    completed_at = datetime.now(UTC) - timedelta(seconds=10)
    gateway = ExactWindowGateway([])
    state = _planned_state().model_copy(
        update={"execution_results": [_execution(completed_at=completed_at)]}
    )

    result = ResponseVerifier(
        gateway=gateway,
        settings_obj=_verifier_settings(dry_run=False),
    ).run(state)

    assert result.outcome == VerificationOutcome.PASSED
    assert gateway.window["start_time"] == completed_at
    assert gateway.window["end_time"] > completed_at
    assert gateway.window["agent_id"] == "001"


def test_truncated_alert_results_cannot_produce_a_clean_pass():
    completed_at = datetime.now(UTC) - timedelta(seconds=10)
    state = _planned_state().model_copy(
        update={"execution_results": [_execution(completed_at=completed_at)]}
    )

    result = ResponseVerifier(
        gateway=VerificationGateway([], truncated=True),
        settings_obj=_verifier_settings(dry_run=False),
    ).run(state)

    checks = {item["check"]: item for item in result.checks}
    assert result.outcome == VerificationOutcome.PARTIAL
    assert checks["ssh_attempts_stopped"]["outcome"] == "not_verified"
    assert checks["no_new_critical_alerts"]["outcome"] == "not_verified"


def test_verification_waits_for_the_observation_interval():
    gateway = VerificationGateway([])
    completed_at = datetime.now(UTC)
    state = _planned_state().model_copy(
        update={"execution_results": [_execution(completed_at=completed_at)]}
    )

    result = ResponseVerifier(
        gateway=gateway,
        settings_obj=_verifier_settings(
            dry_run=False,
            observation_seconds=60,
        ),
    ).run(state)

    assert result.outcome == VerificationOutcome.NOT_VERIFIED
    assert result.checks[0]["check"] == "observation_window"
    assert gateway.related_calls == 0


def test_required_management_probe_cannot_silently_pass():
    completed_at = datetime.now(UTC) - timedelta(seconds=10)
    state = _planned_state().model_copy(
        update={"execution_results": [_execution(completed_at=completed_at)]}
    )

    result = ResponseVerifier(
        gateway=VerificationGateway([]),
        settings_obj=_verifier_settings(
            dry_run=False,
            require_management_probe=True,
        ),
    ).run(state)

    management = next(
        item
        for item in result.checks
        if item["check"] == "management_ssh_reachable"
    )
    assert management["required"] is True
    assert management["outcome"] == "not_verified"
    assert result.outcome == VerificationOutcome.PARTIAL
    assert result.passed is False
