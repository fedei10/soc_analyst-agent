from datetime import UTC, datetime

import pytest

from app.services.wazuh.models import (
    AlertEvidence,
    AlertSearchResult,
    ArchivedLogSearchResult,
    IOCHuntResult,
)
from app.soc_assistant.router import AssistantIntentRouter
from app.soc_assistant.schemas import AssistantCommandName, AssistantIntent
from app.soc_assistant.service import SOCAssistant


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
        ("get only alerts", AssistantCommandName.ALERTS),
        ("threat hunt for 192.0.2.10", AssistantCommandName.HUNT),
        (
            "run the whole MAPE-K process for alert alert-1",
            AssistantCommandName.INVESTIGATE,
        ),
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


def test_help_and_health_are_available_without_llm(monkeypatch):
    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    service, _, _ = assistant()

    help_response = respond(service, "/help")
    assert len(help_response.response["commands"]) == 7
    assert help_response.tools_used == []

    health = respond(service, "/health")
    assert health.response["status"] == "healthy"
    assert health.tools_used == ["indexer_health", "validate_server"]
