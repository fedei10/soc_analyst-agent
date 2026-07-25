import json
from datetime import UTC, datetime, timedelta

from app.config import settings
from app.mape_k.analyze import IncidentAnalyzer
from app.mape_k.monitor import WazuhMonitor
from app.mape_k.schemas import (
    Diagnosis,
    EvidenceReference,
    IncidentWorkflowState,
)
from app.services.wazuh.gateway import WazuhGateway
from app.services.wazuh.models import AlertEvidence, AlertSearchResult


BASE_TIME = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)


class MemoryCache:
    def __init__(self):
        self.values = {}

    def get_json(self, *, namespace, organization_id, cache_key):
        return self.values.get((namespace, organization_id, cache_key))

    def set_json(
        self, *, namespace, organization_id, cache_key, value, ttl_seconds
    ):
        self.values[(namespace, organization_id, cache_key)] = value
        return True


class NoLLM:
    def invoke_structured(self, *_args, **_kwargs):
        raise AssertionError("Deterministic SSH analysis must not call the LLM.")


def ssh_alert(
    index: int,
    *,
    outcome: str = "failure",
    user: str = "admin",
    source_ip: str = "192.0.2.10",
    invalid_user: bool = False,
    event_count: int = 1,
) -> AlertEvidence:
    timestamp = BASE_TIME + timedelta(seconds=index * 10)
    if outcome == "success":
        description = "sshd: successful authentication"
        full_log = (
            f"Accepted password for {user} from {source_ip} port 4422 ssh2"
        )
        groups = ["sshd", "authentication_success"]
        rule_id = "5715"
    else:
        description = "sshd: authentication failed"
        invalid = "invalid user " if invalid_user else ""
        full_log = (
            f"Failed password for {invalid}{user} from {source_ip} "
            "port 4422 ssh2"
        )
        groups = ["sshd", "authentication_failures"]
        rule_id = "5710"
    return AlertEvidence(
        alert_id=f"ssh-{index}",
        timestamp=timestamp,
        agent_id="001",
        agent_name="server-01",
        rule_id=rule_id,
        rule_level=8,
        description=description,
        source_ip=source_ip,
        target_user=user,
        full_log=full_log,
        rule_groups=groups,
        event_count=event_count,
        event_outcome=outcome,
    )


class AuthenticationGateway:
    def __init__(
        self,
        alerts: list[AlertEvidence],
        *,
        total: int | None = None,
        truncated: bool = False,
    ):
        self.alerts = alerts
        self.total = total if total is not None else len(alerts) - 1
        self.truncated = truncated
        self.related_call = None
        self.inventory_called = False

    def get_alert_by_id(self, alert_id):
        return self.alerts[0] if alert_id == self.alerts[0].alert_id else None

    def get_related_alerts(self, **kwargs):
        self.related_call = kwargs
        return AlertSearchResult(
            total=self.total,
            returned=len(self.alerts) - 1,
            truncated=self.truncated,
            alerts=self.alerts[1:],
        )

    def get_agent_inventory(self, **_kwargs):
        self.inventory_called = True
        raise AssertionError("SSH monitoring must not collect generic inventory.")


def monitored_state(
    alerts: list[AlertEvidence],
    *,
    total: int | None = None,
    truncated: bool = False,
):
    gateway = AuthenticationGateway(
        alerts,
        total=total,
        truncated=truncated,
    )
    initial = IncidentWorkflowState(
        incident_id="INC-AUTH",
        investigation_id="INV-AUTH",
        alert_id=alerts[0].alert_id,
        agent_id="001",
    )
    update = WazuhMonitor(gateway=gateway, cache=MemoryCache()).run(initial)
    return initial.model_copy(update=update), gateway


def diagnose(alerts: list[AlertEvidence]):
    state, gateway = monitored_state(alerts)
    diagnosis, usage = IncidentAnalyzer(
        llm=NoLLM(),
        cache=MemoryCache(),
    ).run(state)
    return diagnosis, usage, state, gateway


def test_ssh_monitor_uses_exact_window_and_authentication_profile():
    state, gateway = monitored_state(
        [ssh_alert(0), ssh_alert(1)],
        total=10,
        truncated=True,
    )

    call = gateway.related_call
    assert call["start_time"] == BASE_TIME - timedelta(
        seconds=settings.MAPEK_CORRELATION_WINDOW_SECONDS
    )
    assert call["end_time"] == BASE_TIME + timedelta(
        seconds=settings.MAPEK_CORRELATION_WINDOW_SECONDS
    )
    assert call["authentication_only"] is True
    assert gateway.inventory_called is False
    assert state.monitor_context["evidence_profile"] == "ssh_authentication"
    assert state.monitor_context["correlation"]["truncated"] is True
    assert state.authentication_evidence.failed_attempt_count == 2
    assert state.authentication_evidence.total_hits == 11
    assert state.authentication_evidence.returned_hits == 2
    assert state.authentication_evidence.successful_login_after_failures is None
    assert "authentication_search_truncated" in (
        state.authentication_evidence.missing_evidence
    )


def test_single_ssh_failure_is_not_brute_force():
    diagnosis, usage, _state, _gateway = diagnose([ssh_alert(0)])

    assert diagnosis.incident_type == "ssh_login_failure"
    assert diagnosis.needs_more_evidence is True
    assert diagnosis.confidence < settings.MAPEK_ANALYSIS_CONFIDENCE_THRESHOLD
    assert "remote" not in diagnosis.root_cause.lower()
    assert usage == {"input_tokens": 0, "output_tokens": 0}


def test_invalid_user_attempt_is_distinct_and_requires_more_evidence():
    diagnosis, _usage, _state, _gateway = diagnose(
        [ssh_alert(0, invalid_user=True)]
    )

    assert diagnosis.incident_type == "ssh_invalid_user_attempt"
    assert diagnosis.needs_more_evidence is True


def test_brute_force_requires_configured_event_thresholds():
    diagnosis, _usage, _state, _gateway = diagnose(
        [ssh_alert(index) for index in range(5)]
    )

    assert diagnosis.incident_type == "ssh_brute_force"
    assert diagnosis.needs_more_evidence is False
    assert diagnosis.attack_techniques == ["T1110.001"]


def test_brute_force_uses_failure_and_distinct_event_thresholds():
    diagnosis, _usage, state, _gateway = diagnose(
        [
            ssh_alert(0, event_count=2),
            ssh_alert(1, event_count=2),
            ssh_alert(2, event_count=1),
        ]
    )

    assert state.authentication_evidence.failed_attempt_count == 5
    assert state.authentication_evidence.distinct_event_count == 3
    assert diagnosis.incident_type == "ssh_brute_force"


def test_brute_force_events_outside_policy_window_are_not_promoted():
    alerts = [
        ssh_alert(index).model_copy(
            update={"timestamp": BASE_TIME + timedelta(seconds=index * 100)}
        )
        for index in range(5)
    ]

    diagnosis, _usage, _state, _gateway = diagnose(alerts)

    assert diagnosis.incident_type == "ssh_login_failure"
    assert diagnosis.needs_more_evidence is True


def test_password_spraying_is_distinct_from_single_user_brute_force():
    alerts = [
        ssh_alert(index, user=f"user-{index % 5}")
        for index in range(10)
    ]

    diagnosis, _usage, _state, _gateway = diagnose(alerts)

    assert diagnosis.incident_type == "ssh_password_spraying"
    assert diagnosis.attack_techniques == ["T1110.003"]


def test_success_after_failures_is_classified_without_compromise_claim():
    diagnosis, _usage, state, _gateway = diagnose(
        [
            ssh_alert(0),
            ssh_alert(1, outcome="success"),
        ]
    )

    assert state.authentication_evidence.successful_login_after_failures is True
    assert diagnosis.incident_type == "ssh_success_after_failures"
    assert "does not by itself prove account compromise" in diagnosis.root_cause


def test_semantic_analysis_prompt_is_structured_bounded_json():
    evidence = EvidenceReference(
        evidence_id="EV-1234567890AB",
        source_type="wazuh_alert",
        source_ref="wazuh:alert:generic",
        summary="Generic bounded evidence",
        content_hash="a" * 64,
    )
    state = IncidentWorkflowState(
        incident_id="INC-GENERIC",
        investigation_id="INV-GENERIC",
        alert_id="generic",
        evidence=[evidence],
        incident_fingerprint="FP-GENERIC",
        evidence_version="version-1",
    )

    class CapturingLLM:
        def __init__(self):
            self.payload = None

        def invoke_structured(self, _schema, messages):
            self.payload = json.loads(messages[-1]["content"])
            return (
                Diagnosis(
                    incident_type="unknown",
                    summary="Insufficient evidence",
                    root_cause="Unknown",
                    evidence_ids=[evidence.evidence_id],
                    confidence=0.2,
                    needs_more_evidence=True,
                ),
                {"input_tokens": 10, "output_tokens": 5},
            )

    llm = CapturingLLM()
    diagnosis, _usage = IncidentAnalyzer(
        llm=llm,
        cache=MemoryCache(),
    ).run(state)

    assert diagnosis.incident_type == "unknown"
    assert llm.payload["incident_id"] == "INC-GENERIC"
    assert llm.payload["evidence"] == [
        {
            "evidence_id": evidence.evidence_id,
            "source_type": "wazuh_alert",
            "summary": "Generic bounded evidence",
        }
    ]
    assert "questions" in llm.payload


def test_gateway_passes_exact_bounds_and_authentication_filter():
    primary = ssh_alert(0)
    start = primary.timestamp - timedelta(seconds=300)
    end = primary.timestamp + timedelta(seconds=300)

    class Indexer:
        def __init__(self):
            self.kwargs = None

        def get_alert_by_id(self, alert_id):
            return primary if alert_id == primary.alert_id else None

        def search_alerts(self, **kwargs):
            self.kwargs = kwargs
            return AlertSearchResult(
                total=1,
                returned=1,
                truncated=False,
                alerts=[primary],
            )

    indexer = Indexer()
    gateway = WazuhGateway(server=object(), indexer=indexer)
    result = gateway.get_related_alerts(
        alert_id=primary.alert_id,
        start_time=start,
        end_time=end,
        authentication_only=True,
    )

    assert indexer.kwargs["start_time"] == start
    assert indexer.kwargs["end_time"] == end
    assert indexer.kwargs["authentication_only"] is True
    assert indexer.kwargs["oldest_first"] is True
    assert result.returned == 0
