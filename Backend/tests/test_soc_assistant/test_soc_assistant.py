from datetime import UTC, datetime

import pytest
from opensearchpy import exceptions as opensearch_exc

from app.services.wazuh.models import (
    AlertEvidence,
    AlertIngestionDocument,
    AlertSearchResult,
    ArchivedLogSearchResult,
    IOCHuntResult,
    RawAlertDocument,
)
from app.soc_assistant.router import AssistantIntentRouter
from app.soc_assistant.schemas import AssistantCommandName, AssistantIntent
from app.soc_assistant.service import SOCAssistant
from app.db.repositories.alert_memory import InMemoryAlertMemoryRepository


class FailingLLM:
    def invoke_structured(self, schema, messages):
        raise RuntimeError("provider unavailable")


class RoutedLLM:
    def invoke_structured(self, schema, messages):
        return (
            AssistantIntent(
                command=AssistantCommandName.SUMMARY,
                confidence=0.9,
            ),
            {"input_tokens": 10, "output_tokens": 4},
        )


class FakeGateway:
    def __init__(self):
        self.calls = []

    def search_alerts(self, **kwargs):
        self.calls.append(("search_alerts", kwargs))
        return AlertSearchResult(
            total=1,
            returned=1,
            truncated=False,
            alerts=[
                AlertEvidence(
                    alert_id="alert-1",
                    timestamp=datetime(2026, 7, 24, tzinfo=UTC),
                    agent_id="001",
                    agent_name="servervb",
                    rule_id="5712",
                    rule_level=10,
                    description="sshd brute force",
                    source_ip="192.0.2.10",
                    rule_groups=["sshd"],
                    mitre_ids=["T1110"],
                    event_outcome="failure",
                )
            ],
        )

    def alert_summary(self, *, hours):
        self.calls.append(("alert_summary", {"hours": hours}))
        return {"total_alerts": 7, "by_level": {"10": 2}}

    def hunt_ioc_telemetry(self, **kwargs):
        self.calls.append(("hunt_ioc_telemetry", kwargs))
        return IOCHuntResult(
            indicator=kwargs["indicator"],
            indicator_type=kwargs["indicator_type"],
            alerts=AlertSearchResult(
                total=1,
                returned=1,
                truncated=False,
                alerts=[],
            ),
            archived_logs=ArchivedLogSearchResult(
                index_pattern="wazuh-archives-*",
                archive_status="available",
                total=2,
                returned=2,
                truncated=False,
                events=[],
            ),
        )

    def indexer_health(self):
        self.calls.append(("indexer_health", {}))
        return {"status": "green"}

    def validate_server(self):
        self.calls.append(("validate_server", {}))
        return {"data": {}}

    def get_raw_alert_by_id(self, alert_id):
        self.calls.append(("get_raw_alert_by_id", {"alert_id": alert_id}))
        if alert_id != "alert-1":
            return None
        normalized = self.search_alerts().alerts[0]
        return RawAlertDocument(
            alert_id=alert_id,
            normalized=normalized,
            raw_document=normalized.model_dump(mode="json"),
        )


class UnreachableWazuhGateway(FakeGateway):
    def search_alerts(self, **kwargs):
        self.calls.append(("search_alerts", kwargs))
        raise opensearch_exc.ConnectionError("connection refused")


class FakeInvestigations:
    def __init__(self):
        self.started = []

    def start(self, **kwargs):
        self.started.append(kwargs)
        return {
            "investigation_id": "INV-TEST",
            "alert_id": kwargs["alert_id"],
            "agent_id": kwargs["agent_id"],
            "status": "awaiting_approval",
            "current_stage": "human_approval",
            "diagnosis": {"classification": "malicious"},
            "pending_nodes": ["execute"],
        }

    def snapshot(self, investigation_id, *, organization_id):
        if investigation_id == "INV-MISSING":
            from app.coreAgents.orchestration.investigation_service import (
                InvestigationNotFoundError,
            )

            raise InvestigationNotFoundError(investigation_id)
        return {
            "investigation_id": investigation_id,
            "alert_id": "alert-1",
            "agent_id": "001",
            "status": "completed",
            "current_stage": "report",
            "pending_nodes": [],
        }

    def active_for_alert(self, alert_id, *, organization_id):
        return None


def test_slash_commands_are_strict_and_typed():
    router = AssistantIntentRouter(llm=FailingLLM())

    alerts = router.parse_slash(
        "/alerts ssh --hours 6 --min-level 10 --limit 5 --agent 001"
    )
    assert alerts.command == AssistantCommandName.ALERTS
    assert alerts.arguments == {
        "text": "ssh",
        "hours": 6,
        "min_level": 10,
        "limit": 5,
        "agent_id": "001",
    }
    assert router.parse_slash("/mapek alert-1").command == (
        AssistantCommandName.INVESTIGATE
    )
    with pytest.raises(ValueError, match="Unsupported option"):
        router.parse_slash("/alerts --write yes")
    with pytest.raises(ValueError, match="Unknown command"):
        router.parse_slash("/shell")


@pytest.mark.parametrize(
    ("message", "command"),
    [
        ("hello", AssistantCommandName.CHAT),
        ("get only alerts", AssistantCommandName.ALERTS),
        ("give me the latest alerts", AssistantCommandName.ALERTS),
        ("threat hunt for 192.0.2.10", AssistantCommandName.HUNT),
        (
            "run the whole MAPE-K process for alert alert-1",
            AssistantCommandName.INVESTIGATE,
        ),
        ("investigate it", AssistantCommandName.INVESTIGATE),
        ("check status INV-ABC123", AssistantCommandName.STATUS),
    ],
)
def test_common_natural_language_routes_without_llm(message, command):
    intent, usage = AssistantIntentRouter(llm=FailingLLM()).route(message)

    assert intent.command == command
    assert usage == {"input_tokens": 0, "output_tokens": 0}


def test_ambiguous_language_uses_oxy_classifier_and_fails_soft():
    routed, usage = AssistantIntentRouter(llm=RoutedLLM()).route(
        "Give me an operational picture."
    )
    assert routed.command == AssistantCommandName.SUMMARY
    assert routed.source == "oxy"
    assert usage["input_tokens"] == 10

    fallback, usage = AssistantIntentRouter(llm=FailingLLM()).route(
        "Give me an operational picture."
    )
    assert fallback.command == AssistantCommandName.HELP
    assert fallback.source == "fallback"
    assert usage == {"input_tokens": 0, "output_tokens": 0}


def assistant() -> tuple[SOCAssistant, FakeGateway, FakeInvestigations]:
    gateway = FakeGateway()
    investigations = FakeInvestigations()
    return (
        SOCAssistant(
            gateway=gateway,
            investigations=investigations,
            router=AssistantIntentRouter(llm=FailingLLM()),
        ),
        gateway,
        investigations,
    )


def respond(service: SOCAssistant, message: str):
    return service.respond(
        message=message,
        conversation_id="conversation-test",
        organization_id="user-test",
        user_id="user-test",
    )


def test_alerts_and_hunt_execute_only_bounded_gateway_methods(monkeypatch):
    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    service, gateway, _ = assistant()

    alerts = respond(service, "/alerts --hours 6 --min-level 10")
    assert alerts.selected_command == AssistantCommandName.ALERTS
    assert alerts.tools_used == ["search_alerts"]
    assert alerts.response["finding_count"] == 1
    assert gateway.calls[0][1]["hours"] == 6

    hunt = respond(service, "/hunt 192.0.2.10 --type ip")
    assert hunt.selected_command == AssistantCommandName.HUNT
    assert hunt.response["indicator"] == "192.0.2.10"
    assert hunt.response["alerts"]["total"] == 1
    assert hunt.response["archived_logs"]["total"] == 2
    assert hunt.tools_used == ["hunt_ioc_telemetry"]


def test_greeting_is_conversational_and_does_not_call_tools(monkeypatch):
    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    service, gateway, _ = assistant()

    response = respond(service, "hello")

    assert response.selected_command == AssistantCommandName.CHAT
    assert response.tools_used == []
    assert response.response["display_mode"] == "conversation"
    assert gateway.calls == []


def test_triage_groups_alerts_and_returns_evidence_backed_verdicts(monkeypatch):
    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    from app.db.repositories.findings import InMemoryFindingRepository, get_finding_repository

    get_finding_repository.cache_clear()
    monkeypatch.setattr(
        "app.services.wazuh.triage.service.get_finding_repository",
        lambda: InMemoryFindingRepository(),
    )
    service, gateway, _ = assistant()

    triage = respond(service, "/triage --hours 6 --min-level 10")
    assert triage.selected_command == AssistantCommandName.TRIAGE
    assert triage.tools_used == ["run_triage"]
    assert triage.response["finding_count"] == 1
    assert triage.response["findings"][0]["verdict"] == "malicious"
    assert gateway.calls[-1][1]["hours"] == 6


def test_investigate_and_status_use_durable_workflow_service(monkeypatch):
    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    service, _, investigations = assistant()

    started = respond(service, "/investigate alert-1 --agent 001")
    assert started.active_investigation_id == "INV-TEST"
    assert started.investigation["current_stage"] == "human_approval"
    assert investigations.started[0]["initiated_by"] == "user-test"

    status = respond(service, "/status INV-TEST")
    assert status.response["status"] == "completed"
    assert status.active_investigation_id == "INV-TEST"


def test_investigate_rejects_placeholder_before_starting(monkeypatch):
    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    service, _, investigations = assistant()

    result = respond(service, "/investigate ALERT-ID --agent 001")

    assert result.response["error"] == "INVALID_ALERT_ID"
    assert "placeholder" in result.response["message"]
    assert investigations.started == []


def test_investigate_rejects_agent_mismatch(monkeypatch):
    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    service, _, investigations = assistant()

    result = respond(service, "/investigate alert-1 --agent 999")

    assert result.response["error"] == "ALERT_AGENT_MISMATCH"
    assert investigations.started == []


def test_investigate_returns_existing_active_investigation(monkeypatch):
    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    service, _, investigations = assistant()
    investigations.active_for_alert = lambda alert_id, organization_id: {
        "investigation_id": "INV-EXISTING",
        "alert_id": alert_id,
        "agent_id": "001",
        "status": "running",
        "current_stage": "analyze",
    }

    result = respond(service, "/investigate alert-1 --agent 001")

    assert result.response["investigation_id"] == "INV-EXISTING"
    assert result.response["existing"] is True
    assert investigations.started == []


def test_alert_cursor_is_per_user_and_advances(monkeypatch):
    memory = InMemoryAlertMemoryRepository()
    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    monkeypatch.setattr(
        "app.soc_assistant.service.get_alert_memory_repository",
        lambda: memory,
    )
    service, _, _ = assistant()

    first = respond(service, "/alerts")
    second = respond(service, "/alerts")
    other_user = service.respond(
        message="/alerts",
        conversation_id="conversation-other",
        organization_id="user-other",
        user_id="user-other",
    )

    assert first.response["new_alerts"] == 1
    assert first.response["since"] is None
    assert second.response["new_alerts"] == 0
    assert second.response["since"] is not None
    assert other_user.response["new_alerts"] == 1


def test_durable_alerts_query_postgresql_memory_not_live_wazuh(monkeypatch):
    class DurableMemory(InMemoryAlertMemoryRepository):
        durable = True

    memory = DurableMemory()
    observed_at = datetime.now(UTC).replace(microsecond=0)
    memory.remember_alert_document(
        AlertIngestionDocument(
            document_id="alert-persisted",
            index_name="wazuh-alerts-test",
            normalized=AlertEvidence(
                alert_id="alert-persisted",
                timestamp=observed_at,
                agent_id="001",
                agent_name="servervb",
                rule_id="5712",
                rule_level=10,
                description="sshd brute force",
                source_ip="192.0.2.10",
            ),
            raw_document={},
        )
    )

    class FindingRepository:
        def list(self, **kwargs):
            return [
                {
                    "finding_id": "FND-PERSISTED",
                    "status": "open",
                    "version": 1,
                    "event_type": "ssh_brute_force",
                    "created_at": observed_at,
                    "updated_at": observed_at,
                    "finding": {
                        "finding_id": "FND-PERSISTED",
                        "title": "Repeated SSH authentication failures",
                        "summary": "Correlated from persisted Wazuh alerts.",
                        "severity": "high",
                        "first_seen": observed_at.isoformat(),
                        "last_seen": observed_at.isoformat(),
                        "representative_alert_id": "alert-persisted",
                    },
                    "verdict": {
                        "verdict": "malicious",
                        "confidence": 0.9,
                    },
                }
            ]

    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    monkeypatch.setattr(
        "app.soc_assistant.service.get_alert_memory_repository",
        lambda: memory,
    )
    monkeypatch.setattr(
        "app.soc_assistant.service.get_finding_repository",
        lambda: FindingRepository(),
    )
    service, gateway, _ = assistant()

    first = respond(service, "/alerts")
    second = respond(service, "/alerts")

    assert first.response["source"] == "postgresql"
    assert first.response["new_alerts"] == 1
    assert first.response["new_findings"] == 1
    assert first.tools_used == ["query_alert_memory"]
    assert second.response["new_alerts"] == 0
    assert second.response["findings"] == []
    assert gateway.calls == []


def test_conversation_reference_resolves_investigate_it(monkeypatch):
    memory = InMemoryAlertMemoryRepository()
    memory.remember_alert_document(
        AlertIngestionDocument(
            document_id="alert-1",
            index_name="wazuh-alerts-test",
            normalized=FakeGateway().search_alerts().alerts[0],
            raw_document={},
        )
    )
    memory.add_conversation_reference(
        conversation_id="conversation-test",
        message_id="message-1",
        organization_id="user-test",
        reference_type="wazuh_alert",
        reference_value="alert-1",
    )
    monkeypatch.setattr(
        "app.soc_assistant.service.database_url",
        lambda: "configured",
    )
    monkeypatch.setattr(
        "app.soc_assistant.service.get_alert_memory_repository",
        lambda: memory,
    )
    monkeypatch.setattr(
        "app.soc_assistant.references.get_alert_memory_repository",
        lambda: memory,
    )
    monkeypatch.setattr(
        SOCAssistant,
        "_persist",
        staticmethod(lambda **kwargs: None),
    )
    service, gateway, investigations = assistant()

    result = respond(service, "investigate it")

    assert result.active_alert_id == "alert-1"
    assert result.active_investigation_id == "INV-TEST"
    assert investigations.started[0]["alert_id"] == "alert-1"
    assert not any(call[0] == "get_raw_alert_by_id" for call in gateway.calls)


def test_help_and_health_are_available_without_llm(monkeypatch):
    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    service, _, _ = assistant()

    help_response = respond(service, "/help")
    assert len(help_response.response["commands"]) == 8
    assert help_response.tools_used == []

    health = respond(service, "/health")
    assert health.response["status"] == "healthy"
    assert health.tools_used == ["indexer_health", "validate_server"]


def test_wazuh_connection_failure_returns_assistant_message(monkeypatch):
    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    gateway = UnreachableWazuhGateway()
    service = SOCAssistant(
        gateway=gateway,
        investigations=FakeInvestigations(),
        router=AssistantIntentRouter(llm=FailingLLM()),
    )

    result = respond(service, "give me the latest alerts")

    assert result.selected_command == AssistantCommandName.ALERTS
    assert result.tools_used == ["search_alerts"]
    assert result.response["status"] == "unavailable"
    assert result.response["error"]["code"] == "WAZUH_UNAVAILABLE"
    assert "Wazuh is unreachable" in result.assistant_message
    assert result.activities[-1].status == "failed"
