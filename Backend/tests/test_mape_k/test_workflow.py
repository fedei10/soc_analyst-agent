from datetime import UTC, datetime, timedelta
import json
from types import SimpleNamespace

import pytest
import redis
from langgraph.types import Command
from pydantic import ValidationError

from app.config import settings
from app.coreAgents.orchestration.investigation_service import InvestigationService
from app.db.repositories.investigations import InMemoryInvestigationRepository
from app.mape_k.analyze import IncidentAnalyzer
from app.mape_k.executor import RestrictedExecutor
from app.mape_k.graph import create_mape_k_graph, investigation_config
from app.mape_k.llm import LLMInputLimitError, LLMProvider
from app.mape_k.monitor import WazuhMonitor
from app.mape_k.policy import PolicyEngine, role_allows
from app.mape_k.schemas import (
    ActionType,
    Diagnosis,
    EvidenceReference,
    IncidentWorkflowState,
    RemediationAction,
    RemediationPlan,
    VerificationResult,
    WorkflowStatus,
)
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
            for index in range(2)
        ]

    def get_alert_by_id(self, alert_id):
        return self.alerts[0] if alert_id == "alert-0" else None

    def get_related_alerts(self, **_kwargs):
        return AlertSearchResult(
            total=1,
            returned=1,
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

    assert len(state.normalized_alerts) == 2
    assert len(state.findings) == 1
    assert state.findings[0]["alert_count"] == 2
    assert len(state.evidence) == 2
    assert state.incident_fingerprint.startswith("FP-")


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
    class TimeoutResponder:
        def run_active_response(self, **_kwargs):
            raise TimeoutError("response timed out")

    real_settings = SimpleNamespace(
        MAPEK_REAL_EXECUTION_ENABLED=True,
        MAPEK_DRY_RUN=False,
        WAZUH_READ_ONLY=False,
        WAZUH_ALLOW_DANGEROUS_TOOLS=True,
    )
    result = RestrictedExecutor(
        responder=TimeoutResponder(),
        cache=MemoryCache(),
        settings_obj=real_settings,
    ).run(planned_state())

    assert result[0].status == "timed_out"
    assert result[0].result == {"error": "executor_timeout"}


def test_end_to_end_ssh_flow_waits_for_approval_and_execution():
    graph = create_mape_k_graph(
        monitor=WazuhMonitor(gateway=FakeWazuhGateway(), cache=MemoryCache()),
        analyzer=IncidentAnalyzer(llm=NoLLM(), cache=MemoryCache()),
        executor=RestrictedExecutor(cache=MemoryCache()),
    )
    config = investigation_config("INV-FLOW")

    snapshot = graph.invoke(initial_state("INV-FLOW").model_dump(), config=config)
    assert snapshot["status"] == WorkflowStatus.AWAITING_APPROVAL
    assert graph.get_state(config).next == ("human_approval",)

    approval_id = snapshot["approval_request"]["approval_id"]
    snapshot = graph.invoke(
        Command(
            resume={
                "approval_id": approval_id,
                "decision": "approve",
                "approved_by": "user-l2",
                "approver_roles": ["soc_l2"],
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
                "action_ids": ["ACT-CLAIM"],
                "executed_by": "user-l3",
            }
        ),
        config=config,
    )
    assert snapshot["status"] == WorkflowStatus.COMPLETED
    assert snapshot["verification"].passed is True
    assert snapshot["execution_results"][0].status == "dry_run"


def test_verification_failure_rolls_back_and_escalates():
    class FailingVerifier:
        def run(self, _state):
            return VerificationResult(
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
    approval_id = snapshot["approval_request"]["approval_id"]
    graph.invoke(
        Command(
            resume={
                "approval_id": approval_id,
                "decision": "approve",
                "approved_by": "user-l2",
                "approver_roles": ["soc_l2"],
            }
        ),
        config=config,
    )
    snapshot = graph.invoke(
        Command(
            resume={
                "approval_id": approval_id,
                "execution_id": "EXE-ROLLBACK",
                "action_ids": ["ACT-CLAIM"],
                "executed_by": "user-l3",
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

    assert len(state.evidence_records) == 2
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
    assert len(stored["evidence_records"]) == 2

    approval_id = snapshot["approval_request"]["approval_id"]
    approved = service.resume(
        snapshot["investigation_id"],
        {
            "approval_id": approval_id,
            "decision": "approve",
            "approved_by": "user-l2",
            "approver_roles": ["soc_l2"],
        },
        organization_id="user-1",
    )
    assert approved["pending_nodes"] == ["execution_authorization"]

    completed = service.execute_approved(
        snapshot["investigation_id"],
        approval_id=approval_id,
        executed_by="user-l3",
        organization_id="user-1",
    )
    assert completed["status"] == "completed"
    assert completed["verification"]["dry_run"] is True
