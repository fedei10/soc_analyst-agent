from datetime import UTC, datetime, timedelta
import json
from types import SimpleNamespace

import pytest
import redis
from langgraph.types import Command
from pydantic import ValidationError

from app.config import settings
from app.orchestration.investigation_service import (
    InvestigationService,
    _worst_severity,
)
from app.db.repositories.investigations import (
    InMemoryInvestigationRepository,
    ResponseExecutionConflictError,
)
from app.mape_k.analyze import IncidentAnalyzer
from app.mape_k.executor import RestrictedExecutor
from app.mape_k.graph import (
    create_mape_k_graph,
    investigation_config,
)
from app.mape_k.nodes import _validate_approval_binding
from app.mape_k.llm import LLMInputLimitError, LLMProvider
from app.mape_k.monitor import WazuhMonitor
from app.mape_k.playbooks import PlaybookPlanner, PlaybookSelection
from app.mape_k.policy import PolicyEngine, role_allows
from app.mape_k.utils import response_resource_namespace
from app.mape_k.schemas import (
    ActionType,
    ApprovalRequestRecord,
    Diagnosis,
    EvidenceReference,
    ExecutionAuthorization,
    ExecutionResult,
    IncidentWorkflowState,
    MAX_CHECKPOINT_AUDIT_EVENTS,
    RemediationAction,
    RemediationPlan,
    VerificationOutcome,
    VerificationResult,
    WorkflowStatus,
    merge_bounded_audit_events,
)
from app.mape_k.verify import verification_observation_ready_at
from app.services.redis.ephemeral import EphemeralRedis
from app.services.wazuh.models import AlertEvidence, AlertSearchResult, EndpointInventory


class FakeWazuhGateway:
    def __init__(self) -> None:
        observed_at = datetime.now(UTC)
        self.alerts = [
            AlertEvidence(
                alert_id=f"alert-{index}",
                timestamp=observed_at + timedelta(seconds=index * 10),
                agent_id="001",
                agent_name="linux-server-01",
                rule_id="5712",
                rule_level=10,
                description="sshd: multiple failed password attempts (brute force)",
                source_ip="192.0.2.10",
                target_user="admin",
                full_log=(
                    "Failed password for admin from 192.0.2.10 "
                    f"port {2200 + index} ssh2"
                ),
                rule_groups=["authentication_failures"],
                mitre_ids=["T1110"],
                event_outcome="failure",
            )
            for index in range(5)
        ]

    def get_alert_by_id(self, alert_id):
        return self.alerts[0] if alert_id == "alert-0" else None

    def get_related_alerts(self, **_kwargs):
        return AlertSearchResult(
            total=4,
            returned=4,
            truncated=False,
            alerts=self.alerts[1:],
        )

    def get_agent_inventory(self, *, agent_id, component, limit):
        return EndpointInventory(
            agent_id=agent_id,
            component=component,
            total=0,
            returned=0,
            truncated=False,
            items=[],
        )


class NoLLM:
    def invoke_structured(self, *_args, **_kwargs):
        raise AssertionError("Known SSH incidents must not call an LLM.")


class MemoryCache:
    def __init__(self):
        self.values = {}
        self.claims = set()

    def get_json(self, *, namespace, organization_id, cache_key):
        return self.values.get((namespace, organization_id, cache_key))

    def set_json(
        self, *, namespace, organization_id, cache_key, value, ttl_seconds
    ):
        self.values[(namespace, organization_id, cache_key)] = value
        return True

    def claim_idempotency(
        self, *, organization_id, operation_key, ttl_seconds
    ):
        from app.services.redis.ephemeral import IdempotencyClaim

        key = (organization_id, operation_key)
        claimed = key not in self.claims
        self.claims.add(key)
        return IdempotencyClaim(claimed=claimed)


def initial_state(investigation_id="INV-TEST"):
    return IncidentWorkflowState(
        incident_id=f"INC-{investigation_id.removeprefix('INV-')}",
        investigation_id=investigation_id,
        alert_id="alert-0",
        agent_id="001",
    )


def monitored_state(cache=None):
    state = initial_state()
    update = WazuhMonitor(
        gateway=FakeWazuhGateway(),
        cache=cache or MemoryCache(),
    ).run(state)
    return state.model_copy(update=update)


def diagnosed_state(cache=None):
    state = monitored_state(cache)
    diagnosis, usage = IncidentAnalyzer(
        llm=NoLLM(),
        cache=cache or MemoryCache(),
    ).run(state)
    return state.model_copy(
        update={
            "diagnosis": diagnosis,
            "llm_input_tokens": usage["input_tokens"],
            "llm_output_tokens": usage["output_tokens"],
        }
    )


def planned_state(cache=None):
    from app.mape_k.playbooks import PlaybookPlanner

    state = diagnosed_state(cache)
    plan = PlaybookPlanner().run(state)
    return state.model_copy(
        update={
            "remediation_plan": plan,
            "proposed_actions": [
                action.model_dump(mode="json") for action in plan.actions
            ],
        }
    )


def test_monitor_normalizes_deduplicates_and_correlates_alerts():
    state = monitored_state()

    assert len(state.normalized_alerts) == 5
    assert len(state.findings) == 1
    assert state.findings[0]["alert_count"] == 5
    assert len(state.evidence) == 5
    assert state.incident_fingerprint.startswith("FP-")
    assert "payload" not in state.evidence_records[0]
    assert (
        state.evidence_records[0]["raw_source_document_id"]
        == state.normalized_alerts[0].alert_id
    )
    assert state.evidence_records[0]["normalizer_name"]
    assert state.evidence_records[0]["normalized_document_hash"]


def test_known_ssh_incident_is_deterministic_and_evidence_bound():
    state = diagnosed_state()

    assert state.diagnosis.incident_type == "ssh_brute_force"
    assert state.diagnosis.deterministic is True
    assert state.diagnosis.attack_techniques == ["T1110.001"]
    assert set(state.diagnosis.evidence_ids) <= {
        item.evidence_id for item in state.evidence
    }
    assert state.llm_input_tokens == 0


def test_structured_diagnosis_cannot_reference_unknown_evidence():
    evidence = EvidenceReference(
        evidence_id="EV-1234567890AB",
        source_type="wazuh_alert",
        source_ref="wazuh:alert:generic",
        summary="Generic event",
        content_hash="a" * 64,
    )
    state = initial_state().model_copy(update={"evidence": [evidence]})

    class InventingLLM:
        def invoke_structured(self, *_args, **_kwargs):
            return (
                Diagnosis(
                    incident_type="unknown",
                    summary="Unsupported",
                    root_cause="Unsupported",
                    evidence_ids=["EV-FFFFFFFFFFFF"],
                    confidence=0.9,
                ),
                {"input_tokens": 10, "output_tokens": 10},
            )

    with pytest.raises(ValueError, match="unknown evidence"):
        IncidentAnalyzer(llm=InventingLLM(), cache=MemoryCache()).run(state)


def test_low_confidence_diagnosis_escalates_without_planning():
    class LowConfidenceAnalyzer:
        def run(self, state):
            return (
                Diagnosis(
                    incident_type="unknown",
                    summary="Insufficient support",
                    root_cause="Unknown",
                    evidence_ids=[state.evidence[0].evidence_id],
                    confidence=0.2,
                    needs_more_evidence=True,
                ),
                {"input_tokens": 10, "output_tokens": 5},
            )

    graph = create_mape_k_graph(
        monitor=WazuhMonitor(gateway=FakeWazuhGateway(), cache=MemoryCache()),
        analyzer=LowConfidenceAnalyzer(),
    )
    snapshot = graph.invoke(
        initial_state("INV-LOW").model_dump(),
        config=investigation_config("INV-LOW"),
    )

    assert snapshot["status"] == WorkflowStatus.ESCALATED
    assert snapshot["remediation_plan"] is None
    # It escalates only after exhausting its re-collect attempts, not on the
    # first inconclusive pass.
    assert snapshot["analysis_attempts"] == settings.MAPEK_MAX_ANALYSIS_ATTEMPTS


def test_unknown_attack_produces_advisory_without_execution_path():
    class ExfiltrationAnalyzer:
        def run(self, state):
            return (
                Diagnosis(
                    incident_type="data_exfiltration",
                    summary="Possible archive transfer to an external destination.",
                    root_cause="A suspicious process initiated an outbound transfer.",
                    attack_techniques=["T1041"],
                    affected_assets=["linux-server-01"],
                    affected_entities={"host": "linux-server-01"},
                    evidence_ids=[state.evidence[0].evidence_id],
                    confidence=0.94,
                ),
                {"input_tokens": 12, "output_tokens": 8, "model_calls": 1},
            )

    class AdvisoryLLM:
        def invoke_structured(self, _schema, _messages):
            return (
                PlaybookSelection(
                    applies=False,
                    rationale="No registered response matches exfiltration.",
                    advisory_summary="Investigate and contain possible exfiltration.",
                    investigation_steps=[
                        "Correlate transfer volume, destination, process, and user."
                    ],
                    containment_recommendations=[
                        "After impact review, isolate the affected host "
                        "using an approved runbook."
                    ],
                    eradication_recommendations=[
                        "Remove the confirmed persistence and transfer mechanism."
                    ],
                    recovery_recommendations=[
                        "Restore a known-good state and monitor outbound traffic."
                    ],
                    detection_improvements=[
                        "Alert on unusual archive creation followed by "
                        "outbound transfer."
                    ],
                ),
                {"input_tokens": 20, "output_tokens": 15, "model_calls": 1},
            )

    graph = create_mape_k_graph(
        monitor=WazuhMonitor(gateway=FakeWazuhGateway(), cache=MemoryCache()),
        analyzer=ExfiltrationAnalyzer(),
        planner=PlaybookPlanner(llm=AdvisoryLLM()),
        executor=RestrictedExecutor(cache=MemoryCache()),
    )
    config = investigation_config("INV-EXFIL")

    snapshot = graph.invoke(
        initial_state("INV-EXFIL").model_dump(),
        config=config,
    )

    assert snapshot["status"] == WorkflowStatus.ESCALATED
    assert snapshot["remediation_plan"] is None
    assert snapshot["advisory_plan"].diagnosis_type == "data_exfiltration"
    assert snapshot["advisory_plan"].executable is False
    assert snapshot["approval_request"] is None
    assert snapshot["execution_results"] == []
    assert snapshot["final_report"]["advisory_plan"]["executable"] is False
    assert graph.get_state(config).next == ()
    assert any(
        event["event"] == "advisory_plan_created"
        for event in snapshot["audit_events"]
    )


def test_inconclusive_analysis_recollects_over_a_wider_window():
    """The MAPE-K loop: look wider and re-diagnose before giving up."""

    windows: list[int] = []

    class WindowRecordingMonitor(WazuhMonitor):
        def run(self, state):
            windows.append(self._correlation_window_seconds(state))
            return super().run(state)

    class ImprovingAnalyzer:
        """Inconclusive first, decisive once more evidence arrives."""

        def __init__(self):
            self.calls = 0

        def run(self, state):
            self.calls += 1
            inconclusive = self.calls == 1
            return (
                Diagnosis(
                    incident_type="unknown" if inconclusive else "ssh_brute_force",
                    summary="Summary",
                    root_cause="Root cause",
                    evidence_ids=[state.evidence[0].evidence_id],
                    affected_entities={} if inconclusive else {"source_ip": "10.0.0.9"},
                    confidence=0.2 if inconclusive else 0.96,
                    needs_more_evidence=inconclusive,
                ),
                {"input_tokens": 10, "output_tokens": 5},
            )

    analyzer = ImprovingAnalyzer()
    graph = create_mape_k_graph(
        monitor=WindowRecordingMonitor(
            gateway=FakeWazuhGateway(),
            cache=MemoryCache(),
        ),
        analyzer=analyzer,
    )
    snapshot = graph.invoke(
        initial_state("INV-RECOLLECT").model_dump(),
        config=investigation_config("INV-RECOLLECT"),
    )

    assert analyzer.calls == 2, "Analyze must run again after re-collection"
    assert len(windows) == 2, "Monitor must run again"
    assert windows[1] > windows[0], "The second pass must look wider"
    assert snapshot["status"] != WorkflowStatus.ESCALATED
    assert snapshot["remediation_plan"] is not None


@pytest.mark.parametrize(
    ("resume_payload", "expected_code"),
    (
        (
            {
                "approval_id": "APR-SOMEONE-ELSES",
                "decision": "approve",
                "actor_user_id": "user-l2",
                "actor_roles": ["soc_l2"],
            },
            "APPROVAL_ID_MISMATCH",
        ),
        (
            {"decision": "maybe", "actor_user_id": "user-l2"},
            "APPROVAL_PAYLOAD_INVALID",
        ),
    ),
)
def test_bad_approval_resume_escalates_instead_of_raising(
    resume_payload,
    expected_code,
):
    """A bad resume is an audited refusal, not an exception out of the graph."""

    graph = create_mape_k_graph(
        monitor=WazuhMonitor(gateway=FakeWazuhGateway(), cache=MemoryCache()),
        analyzer=IncidentAnalyzer(llm=NoLLM(), cache=MemoryCache()),
        executor=RestrictedExecutor(cache=MemoryCache()),
    )
    config = investigation_config(f"INV-BAD-{expected_code}")
    snapshot = graph.invoke(
        initial_state(f"INV-BAD-{expected_code}").model_dump(),
        config=config,
    )
    assert snapshot["status"] == WorkflowStatus.AWAITING_APPROVAL

    snapshot = graph.invoke(Command(resume=resume_payload), config=config)

    assert snapshot["status"] == WorkflowStatus.ESCALATED
    assert snapshot["error"].code == expected_code
    assert snapshot["execution_results"] == []
    assert any(
        event["event"] == "approval_invalidated"
        for event in snapshot["audit_events"]
    )


def test_unknown_action_and_arbitrary_command_are_rejected():
    with pytest.raises(ValidationError):
        RemediationAction(
            action_id="ACT-1",
            action_type="run_shell",
            target="host",
            risk_level=5,
        )
    with pytest.raises(ValidationError):
        RemediationAction(
            action_id="ACT-2",
            action_type=ActionType.BLOCK_IP,
            target="192.0.2.10",
            ttl_seconds=900,
            risk_level=1,
            parameters={"command": "iptables -F"},
        )


def test_policy_denies_protected_ip(monkeypatch):
    state = planned_state()
    monkeypatch.setattr(settings, "MAPEK_PROTECTED_IPS", "192.0.2.10")

    decision = PolicyEngine().evaluate(state)

    assert decision.allowed is False
    assert "PROTECTED_IP" in decision.reason_codes


def test_approval_roles_are_hierarchical():
    assert role_allows(["soc_l2"], "soc_l2")
    assert role_allows(["soc_l3"], "soc_l2")
    assert not role_allows(["soc_l1"], "soc_l2")


def approval_request_for(state, **updates):
    plan = state.remediation_plan
    values = {
        "approval_id": "APR-TEST",
        "investigation_id": state.investigation_id,
        "incident_id": state.incident_id,
        "plan_id": plan.plan_id,
        "plan_version": plan.plan_version,
        "plan_hash": plan.plan_hash,
        "evidence_version": state.evidence_version,
        "policy_version": plan.policy_version,
        "action_catalogue_version": plan.action_catalogue_version,
        "action_ids": [action.action_id for action in plan.actions],
        "required_role": "soc_l2",
        "requested_at": datetime.now(UTC),
        "expires_at": datetime.now(UTC) + timedelta(minutes=5),
    }
    values.update(updates)
    return ApprovalRequestRecord(**values)


@pytest.mark.parametrize(
    "updates",
    (
        {"incident_id": "INC-OTHER"},
        {"plan_hash": "0" * 64},
        {"evidence_version": "stale-evidence"},
        {"action_ids": ["ACT-WRONG"]},
    ),
)
def test_approval_binding_rejects_stale_or_wrong_scope(updates):
    state = planned_state()

    with pytest.raises(ValueError, match="stale"):
        _validate_approval_binding(
            state,
            approval_request_for(state, **updates),
        )


def test_expired_approval_binding_is_rejected():
    state = planned_state()
    request = approval_request_for(
        state,
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )

    with pytest.raises(ValueError, match="expired"):
        _validate_approval_binding(state, request)


def test_execution_authorization_rejects_duplicate_action_ids():
    with pytest.raises(ValidationError, match="unique"):
        ExecutionAuthorization(
            approval_id="APR-TEST",
            execution_id="EXE-TEST",
            action_ids=["ACT-1", "ACT-1"],
            actor_user_id="user-1",
            actor_roles=["soc_l3"],
        )


def test_dry_run_executor_is_idempotent_and_never_calls_responder():
    class ForbiddenResponder:
        def run_active_response(self, **_kwargs):
            raise AssertionError("Dry-run must not perform a real response.")

    state = planned_state()
    cache = MemoryCache()
    executor = RestrictedExecutor(
        responder=ForbiddenResponder(),
        cache=cache,
    )

    first = executor.run(state)
    second = executor.run(state)

    assert first[0].status == "dry_run"
    assert second[0].status == "duplicate"


def test_executor_timeout_is_recorded_without_retrying():
    class DurableActionRepository:
        durable = True

        def __init__(self):
            self.preflight = None
            self.completed = None

        def begin_response_action(self, *_args, **kwargs):
            self.preflight = kwargs
            return True

        def complete_response_action(self, *_args, **kwargs):
            self.completed = kwargs
            return None

    class TimeoutResponder:
        def run_active_response(self, **_kwargs):
            assert repository.preflight is not None
            raise TimeoutError("response timed out")

    real_settings = SimpleNamespace(
        MAPEK_EXECUTION_MODE="enabled",
        MAPEK_REAL_EXECUTION_ENABLED=True,
        MAPEK_DRY_RUN=False,
        WAZUH_READ_ONLY=False,
        WAZUH_ALLOW_DANGEROUS_TOOLS=True,
    )
    repository = DurableActionRepository()
    result = RestrictedExecutor(
        responder=TimeoutResponder(),
        cache=MemoryCache(),
        action_repository=repository,
        before_state_provider=lambda **_kwargs: {
            "target": "192.0.2.10",
            "action_present": False,
            "wazuh_agent_status": "active",
            "management_connectivity": True,
        },
        settings_obj=real_settings,
    ).run(planned_state())

    assert result[0].status == "outcome_unknown"
    assert result[0].result["error"] == "executor_timeout"
    assert result[0].result["outcome"] == "unknown"
    assert repository.preflight["before_state"]["action_present"] is False
    assert repository.preflight["intended_expires_at"] is not None
    assert repository.preflight["idempotency_key"] == result[0].idempotency_key
    assert repository.completed["status"] == "outcome_unknown"
    assert repository.completed["expires_at"] is not None


@pytest.mark.parametrize(
    ("action_type", "action_present", "expected_reason"),
    (
        (ActionType.BLOCK_IP, True, "effect_already_present"),
        (ActionType.UNBLOCK_IP, False, "effect_already_absent"),
    ),
)
def test_executor_skips_provider_when_firewall_state_is_already_satisfied(
    action_type,
    action_present,
    expected_reason,
):
    class DurableActionRepository:
        durable = True

        def __init__(self):
            self.preflight = None
            self.completed = None

        def begin_response_action(self, *_args, **kwargs):
            self.preflight = kwargs
            return True

        def complete_response_action(self, *_args, **kwargs):
            self.completed = kwargs

    class ForbiddenResponder:
        def run_active_response(self, **_kwargs):
            raise AssertionError("A no-op must not call the response provider.")

    state = planned_state()
    action = state.remediation_plan.actions[0].model_copy(
        update={"action_type": action_type}
    )
    plan = state.remediation_plan.model_copy(
        update={"actions": [action]}
    )
    state = state.model_copy(update={"remediation_plan": plan})
    repository = DurableActionRepository()
    real_settings = SimpleNamespace(
        MAPEK_EXECUTION_MODE="enabled",
        MAPEK_REAL_EXECUTION_ENABLED=True,
        MAPEK_DRY_RUN=False,
        WAZUH_READ_ONLY=False,
        WAZUH_ALLOW_DANGEROUS_TOOLS=True,
    )

    result = RestrictedExecutor(
        responder=ForbiddenResponder(),
        cache=MemoryCache(),
        action_repository=repository,
        before_state_provider=lambda **_kwargs: {
            "target": "192.0.2.10",
            "action_present": action_present,
            "wazuh_agent_status": "active",
            "management_connectivity": True,
        },
        settings_obj=real_settings,
    ).run(state)

    assert result[0].status == "no_op"
    assert result[0].result["reason"] == expected_reason
    assert result[0].result["provider_called"] is False
    assert repository.preflight["intended_expires_at"] is None
    assert repository.completed["status"] == "no_op"
    assert repository.completed["expires_at"] is None


def test_end_to_end_ssh_flow_waits_for_approval_and_execution():
    graph = create_mape_k_graph(
        monitor=WazuhMonitor(gateway=FakeWazuhGateway(), cache=MemoryCache()),
        analyzer=IncidentAnalyzer(llm=NoLLM(), cache=MemoryCache()),
        executor=RestrictedExecutor(cache=MemoryCache()),
    )
    config = investigation_config("INV-FLOW")

    snapshot = graph.invoke(initial_state("INV-FLOW").model_dump(), config=config)
    assert snapshot["status"] == WorkflowStatus.AWAITING_APPROVAL
    assert snapshot["proposed_actions"] == []
    assert graph.get_state(config).next == ("human_approval",)

    approval_request = snapshot["approval_request"]
    approval_id = approval_request.approval_id
    action_ids = approval_request.action_ids
    snapshot = graph.invoke(
        Command(
            resume={
                "approval_id": approval_id,
                "decision": "approve",
                "actor_user_id": "user-l2",
                "actor_roles": ["soc_l2"],
            }
        ),
        config=config,
    )
    assert graph.get_state(config).next == ("execution_authorization",)

    snapshot = graph.invoke(
        Command(
            resume={
                "approval_id": approval_id,
                "execution_id": "EXE-CLAIM",
                "action_ids": action_ids,
                "actor_user_id": "user-l3",
                "actor_roles": ["soc_l3"],
            }
        ),
        config=config,
    )
    assert snapshot["status"] == WorkflowStatus.ESCALATED
    assert snapshot["verification"].outcome == VerificationOutcome.SIMULATED
    assert snapshot["verification"].passed is False
    assert snapshot["execution_results"][0].status == "dry_run"
    assert snapshot["executed_actions"] == []


def test_real_execution_waits_durably_before_server_resumes_verification(
    monkeypatch,
):
    class AcceptedExecutor:
        def run(self, state):
            action = state.remediation_plan.actions[0]
            now = datetime.now(UTC)
            return [
                ExecutionResult(
                    execution_id="EXE-REAL",
                    action_id=action.action_id,
                    incident_id=state.incident_id,
                    idempotency_key="IDEM-REAL",
                    action_type=action.action_type,
                    target=action.target,
                    status="accepted",
                    started_at=now,
                    completed_at=now,
                )
            ]

        def rollback(self, _state):
            return []

    class PassingVerifier:
        def observation_ready_at(self, state):
            return verification_observation_ready_at(
                list(state.execution_results),
                observation_seconds=int(
                    settings.MAPEK_VERIFICATION_OBSERVATION_SECONDS
                ),
            )

        def run(self, _state):
            return VerificationResult(
                outcome=VerificationOutcome.PASSED,
                security_checks_passed=True,
                health_checks_passed=True,
                checks=[],
            )

    monkeypatch.setattr(
        settings,
        "MAPEK_VERIFICATION_OBSERVATION_SECONDS",
        60,
    )
    repository = InMemoryInvestigationRepository()
    graph = create_mape_k_graph(
        monitor=WazuhMonitor(gateway=FakeWazuhGateway(), cache=MemoryCache()),
        analyzer=IncidentAnalyzer(llm=NoLLM(), cache=MemoryCache()),
        executor=AcceptedExecutor(),
        verifier=PassingVerifier(),
    )
    service = InvestigationService(graph=graph, repository=repository)
    started = service.start(
        alert_id="alert-0",
        agent_id="001",
        organization_id="user-1",
        owner_user_id="user-1",
    )
    approval_id = started["approval_request"]["approval_id"]
    service.submit_approval(
        started["investigation_id"],
        approval_id=approval_id,
        decision="approve",
        comment=None,
        actor_user_id="user-l2",
        actor_roles=["soc_l2"],
        organization_id="user-1",
    )

    waiting = service.execute_approved(
        started["investigation_id"],
        approval_id=approval_id,
        executed_by="user-l3",
        executor_roles=["soc_l3"],
        organization_id="user-1",
    )

    assert waiting["status"] == "waiting_verification"
    assert waiting["pending_nodes"] == ["verification_wait"]
    assert waiting["verification_not_before"] is not None
    assert waiting["verification"] is None
    assert waiting["final_report"] is None
    with pytest.raises(
        ResponseExecutionConflictError,
        match="observation window is not complete",
    ):
        service.resume_verification(
            started["investigation_id"],
            resumed_by="worker-1",
            executor_roles=["soc_l3"],
            organization_id="user-1",
        )

    future = datetime.now(UTC) + timedelta(seconds=61)

    class FutureDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return future if tz is not None else future.replace(tzinfo=None)

    monkeypatch.setattr(
        "app.orchestration.investigation_service.datetime",
        FutureDateTime,
    )
    monkeypatch.setattr("app.mape_k.nodes.datetime", FutureDateTime)
    completed = service.resume_verification(
        started["investigation_id"],
        resumed_by="worker-1",
        executor_roles=["soc_l3"],
        organization_id="user-1",
    )

    assert completed["status"] == "completed"
    assert completed["pending_nodes"] == []
    assert completed["verification"]["outcome"] == "passed"


def test_verification_failure_rolls_back_and_escalates():
    class FailingVerifier:
        def run(self, _state):
            return VerificationResult(
                outcome=VerificationOutcome.FAILED,
                security_checks_passed=False,
                health_checks_passed=True,
                checks=[{"check": "attempts_stopped", "passed": False}],
            )

    graph = create_mape_k_graph(
        monitor=WazuhMonitor(gateway=FakeWazuhGateway(), cache=MemoryCache()),
        analyzer=IncidentAnalyzer(llm=NoLLM(), cache=MemoryCache()),
        executor=RestrictedExecutor(cache=MemoryCache()),
        verifier=FailingVerifier(),
    )
    config = investigation_config("INV-ROLLBACK")
    snapshot = graph.invoke(initial_state("INV-ROLLBACK").model_dump(), config=config)
    approval_request = snapshot["approval_request"]
    approval_id = approval_request.approval_id
    action_ids = approval_request.action_ids
    graph.invoke(
        Command(
            resume={
                "approval_id": approval_id,
                "decision": "approve",
                "actor_user_id": "user-l2",
                "actor_roles": ["soc_l2"],
            }
        ),
        config=config,
    )
    snapshot = graph.invoke(
        Command(
            resume={
                "approval_id": approval_id,
                "execution_id": "EXE-ROLLBACK",
                "action_ids": action_ids,
                "actor_user_id": "user-l3",
                "actor_roles": ["soc_l3"],
            }
        ),
        config=config,
    )

    assert snapshot["status"] == WorkflowStatus.ESCALATED
    assert snapshot["rollback"].attempted is True
    assert snapshot["rollback"].successful is True


def test_redis_failure_does_not_lose_monitor_evidence():
    class BrokenRedis:
        def get(self, *_args, **_kwargs):
            raise redis.ConnectionError("offline")

        def set(self, *_args, **_kwargs):
            raise redis.ConnectionError("offline")

    state = monitored_state(EphemeralRedis(BrokenRedis()))

    assert len(state.evidence_records) == 5
    assert state.incident_fingerprint


def test_llm_input_limit_is_enforced_before_client_invocation(monkeypatch):
    class ForbiddenClient:
        def with_structured_output(self, *_args, **_kwargs):
            raise AssertionError("Client should not be called for oversized input.")

    monkeypatch.setattr(settings, "MAPEK_MAX_INPUT_TOKENS", 1)
    provider = LLMProvider(client=ForbiddenClient())

    with pytest.raises(LLMInputLimitError):
        provider.invoke_structured(
            Diagnosis,
            [{"role": "user", "content": "too much evidence"}],
        )


def test_api_key_is_not_part_of_workflow_state():
    rendered = json.dumps(initial_state().model_dump(mode="json"))

    assert settings.LLM_API_KEY.get_secret_value() not in rendered
    assert "api_key" not in rendered.lower()


def test_checkpoint_audit_window_is_bounded():
    events = [{"event": f"event-{index}"} for index in range(100)]

    retained = merge_bounded_audit_events([], events)

    assert len(retained) == MAX_CHECKPOINT_AUDIT_EVENTS
    assert retained[0]["event"] == "event-36"
    assert retained[-1]["event"] == "event-99"


def test_service_persists_the_controlled_snapshot():
    repository = InMemoryInvestigationRepository()
    graph = create_mape_k_graph(
        monitor=WazuhMonitor(gateway=FakeWazuhGateway(), cache=MemoryCache()),
        analyzer=IncidentAnalyzer(llm=NoLLM(), cache=MemoryCache()),
        executor=RestrictedExecutor(cache=MemoryCache()),
    )
    service = InvestigationService(graph=graph, repository=repository)

    snapshot = service.start(
        alert_id="alert-0",
        agent_id="001",
        organization_id="user-1",
        owner_user_id="user-1",
    )
    stored = repository.get_snapshot(
        snapshot["investigation_id"],
        organization_id="user-1",
    )
    repeated = service.start(
        alert_id="alert-0",
        agent_id="001",
        organization_id="user-1",
        owner_user_id="user-1",
    )

    assert snapshot["pending_nodes"] == ["human_approval"]
    assert repeated["investigation_id"] == snapshot["investigation_id"]
    assert stored["diagnosis"]["incident_type"] == "ssh_brute_force"
    assert len(stored["evidence_records"]) == 5
    assert snapshot["proposed_actions"]

    approval_id = snapshot["approval_request"]["approval_id"]
    approved = service.submit_approval(
        snapshot["investigation_id"],
        approval_id=approval_id,
        decision="approve",
        comment=None,
        actor_user_id="user-l2",
        actor_roles=["soc_l2"],
        organization_id="user-1",
    )
    assert approved["pending_nodes"] == ["execution_authorization"]

    completed = service.execute_approved(
        snapshot["investigation_id"],
        approval_id=approval_id,
        executed_by="user-l3",
        executor_roles=["soc_l3"],
        organization_id="user-1",
    )
    assert completed["status"] == "escalated"
    assert completed["verification"]["outcome"] == "simulated"
    assert completed["verification"]["dry_run"] is True
    assert completed["executed_actions"][0]["status"] == "dry_run"


def test_enqueue_persists_without_running_the_graph():
    class EmptyGraph:
        invoked = False

        def get_state(self, _config):
            return SimpleNamespace(values={}, next=[])

        def invoke(self, *_args, **_kwargs):
            self.invoked = True

    graph = EmptyGraph()
    service = InvestigationService(
        graph=graph,
        repository=InMemoryInvestigationRepository(),
    )

    snapshot = service.enqueue(
        alert_id="alert-queued",
        agent_id="001",
        organization_id="user-1",
    )

    assert snapshot["status"] == "queued"
    assert snapshot["current_stage"] == "monitor"
    assert graph.invoked is False


def test_worker_candidates_put_verifications_and_criticals_first():
    from app.db.repositories.investigations import worker_candidate_priority

    rows = [
        {"status": "queued", "severity": "low", "updated_at": "1"},
        {"status": "queued", "severity": "critical", "updated_at": "9"},
        {"status": "waiting_verification", "severity": "low", "updated_at": "5"},
        {"status": "queued", "severity": "high", "updated_at": "2"},
    ]
    ordered = [
        (row["status"], row["severity"])
        for row in sorted(rows, key=worker_candidate_priority)
    ]
    assert ordered == [
        ("waiting_verification", "low"),
        ("queued", "critical"),
        ("queued", "high"),
        ("queued", "low"),
    ]


def test_start_runs_through_the_leased_queued_path():
    """start() must not invoke the graph outside run_queued's incident lease."""

    repository = InMemoryInvestigationRepository()
    graph = create_mape_k_graph(
        monitor=WazuhMonitor(gateway=FakeWazuhGateway(), cache=MemoryCache()),
        analyzer=IncidentAnalyzer(llm=NoLLM(), cache=MemoryCache()),
        executor=RestrictedExecutor(cache=MemoryCache()),
    )
    service = InvestigationService(graph=graph, repository=repository)
    seen: list[str] = []
    original = service.run_queued

    def spy(investigation_id, *, organization_id):
        seen.append(investigation_id)
        return original(investigation_id, organization_id=organization_id)

    service.run_queued = spy
    snapshot = service.start(
        alert_id="alert-0",
        agent_id="001",
        organization_id="user-1",
        owner_user_id="user-1",
    )
    assert seen == [snapshot["investigation_id"]]
    assert snapshot["status"] != "queued"


def test_worker_marks_poison_pill_failed_after_retry_limit():
    class ExplodingGraph:
        def get_state(self, _config):
            return SimpleNamespace(values={}, next=[])

        def invoke(self, *_args, **_kwargs):
            raise RuntimeError("boom")

    repository = InMemoryInvestigationRepository()
    service = InvestigationService(
        graph=ExplodingGraph(),
        repository=repository,
    )
    snapshot = service.enqueue(
        alert_id="alert-poison",
        organization_id="user-1",
    )

    for _ in range(settings.MAPEK_WORKER_MAX_ATTEMPTS):
        service.process_background_once()

    stored = repository.get_snapshot(
        snapshot["investigation_id"],
        organization_id="user-1",
    )
    assert stored["status"] == "failed"
    assert stored["worker_attempts"] == settings.MAPEK_WORKER_MAX_ATTEMPTS
    assert stored["errors"][-1]["code"] == "WORKER_RETRY_LIMIT"
    assert (
        repository.list_worker_candidates(
            statuses=("queued",),
            limit=10,
        )
        == []
    )


def test_service_rejects_execution_when_target_resource_is_locked():
    repository = InMemoryInvestigationRepository()
    graph = create_mape_k_graph(
        monitor=WazuhMonitor(gateway=FakeWazuhGateway(), cache=MemoryCache()),
        analyzer=IncidentAnalyzer(llm=NoLLM(), cache=MemoryCache()),
        executor=RestrictedExecutor(cache=MemoryCache()),
    )
    service = InvestigationService(graph=graph, repository=repository)
    snapshot = service.start(
        alert_id="alert-0",
        agent_id="001",
        organization_id="user-1",
        owner_user_id="user-1",
    )
    approval_id = snapshot["approval_request"]["approval_id"]
    approved = service.submit_approval(
        snapshot["investigation_id"],
        approval_id=approval_id,
        decision="approve",
        comment=None,
        actor_user_id="user-l2",
        actor_roles=["soc_l2"],
        organization_id="user-1",
    )
    lock_namespace = response_resource_namespace(settings)
    repository.acquire_resource_lease(
        organization_id=lock_namespace,
        resource_type="ip",
        resource_id="192.0.2.10",
        owner_id="other-worker",
        lease_seconds=60,
    )

    with pytest.raises(ResponseExecutionConflictError, match="resource lock"):
        service.execute_approved(
            snapshot["investigation_id"],
            approval_id=approval_id,
            executed_by="user-l3",
            executor_roles=["soc_l3"],
            organization_id="user-1",
        )

    assert approved["pending_nodes"] == ["execution_authorization"]
    released_incident_lease = repository.acquire_resource_lease(
        organization_id=lock_namespace,
        resource_type="incident",
        resource_id=snapshot["incident_id"],
        owner_id="next-worker",
        lease_seconds=60,
    )
    assert released_incident_lease["owner_id"] == "next-worker"


def test_notify_investigation_transition_sends_for_approval_and_escalation(
    monkeypatch,
):
    from app.orchestration.investigation_service import (
        _notify_investigation_transition,
    )

    sent = []
    monkeypatch.setattr(
        "app.orchestration.investigation_service.get_telegram_notifier",
        lambda: type(
            "N",
            (),
            {"configured": True, "send": lambda self, text: sent.append(text)},
        )(),
    )
    monkeypatch.setattr(
        "app.orchestration.investigation_service.settings.TELEGRAM_NOTIFY_APPROVALS",
        True,
    )

    _notify_investigation_transition(
        {
            "status": "awaiting_approval",
            "investigation_id": "INV-1",
            "alert_id": "AL-1",
            "approval_request": {"required_role": "soc_l2", "action_ids": ["a"]},
        }
    )
    _notify_investigation_transition(
        {
            "status": "escalated",
            "investigation_id": "INV-2",
            "alert_id": "AL-2",
            "current_stage": "execute",
            "error": {"message": "boom"},
        }
    )
    _notify_investigation_transition({"status": "running"})
    assert len(sent) == 2
    assert "INV-1" in sent[0]
    assert "INV-2" in sent[1]


def test_notify_investigation_transition_respects_approval_flag(monkeypatch):
    from app.orchestration.investigation_service import (
        _notify_investigation_transition,
    )

    sent = []
    monkeypatch.setattr(
        "app.orchestration.investigation_service.get_telegram_notifier",
        lambda: type(
            "N",
            (),
            {"configured": True, "send": lambda self, text: sent.append(text)},
        )(),
    )
    monkeypatch.setattr(
        "app.orchestration.investigation_service.settings.TELEGRAM_NOTIFY_APPROVALS",
        False,
    )

    _notify_investigation_transition(
        {"status": "awaiting_approval", "investigation_id": "INV-3"}
    )
    assert sent == []


def test_worst_severity_picks_the_highest_not_the_first_finding():
    findings = [
        {"severity": "informational"},
        {"severity": "critical"},
        {"severity": "low"},
    ]
    assert _worst_severity(findings) == "critical"


def test_worst_severity_handles_empty_or_missing_findings():
    assert _worst_severity([]) is None
    assert _worst_severity([{"finding_id": "no-severity-key"}]) is None
