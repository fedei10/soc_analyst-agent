"""Regression cover for "new" vs "recent" vs "changed" in the SOC chat.

These three questions have three different reference points - the user's
previous successful check, a time window, and a state comparison - and used to
collapse into one broad alert listing that reported a baseline's entire history
as newly created alerts.
"""

from datetime import UTC, datetime, timedelta

import pytest

from app.db.repositories.alert_memory import InMemoryAlertMemoryRepository
from app.services.wazuh.models import AlertEvidence, AlertIngestionDocument
from app.soc_assistant.router import AssistantIntentRouter
from app.soc_assistant.schemas import AssistantCommandName
from app.soc_assistant.service import SOCAssistant


class DurableMemory(InMemoryAlertMemoryRepository):
    durable = True


class FakeFindingRepository:
    """Finding store whose rows the test can mutate between checks."""

    def __init__(self, records=None):
        self.records = list(records or [])
        self.fail_counts = False

    def _matching(self, **filters):
        records = [
            record
            for record in self.records
            if record.get("organization_id", "org-a") == filters["organization_id"]
        ]
        if filters.get("severity"):
            records = [item for item in records if item["severity"] == filters["severity"]]
        if filters.get("status"):
            records = [item for item in records if item["status"] == filters["status"]]
        if filters.get("finding_ids") is not None:
            records = [
                item for item in records if item["finding_id"] in filters["finding_ids"]
            ]
        if filters.get("text"):
            needle = filters["text"].lower()
            records = [
                item
                for item in records
                if needle
                in " ".join(
                    [
                        item["finding"].get("title", ""),
                        item["finding"].get("summary", ""),
                        item.get("event_type", ""),
                    ]
                ).lower()
            ]
        if filters.get("created_after"):
            records = [
                item for item in records if item["created_at"] > filters["created_after"]
            ]
        if filters.get("updated_after"):
            records = [
                item for item in records if item["updated_at"] > filters["updated_after"]
            ]
        if filters.get("created_on_or_before"):
            records = [
                item
                for item in records
                if item["created_at"] <= filters["created_on_or_before"]
            ]
        if filters.get("changed_after"):
            records = [
                item
                for item in records
                if item["created_at"] > filters["changed_after"]
                or item["updated_at"] > filters["changed_after"]
            ]
        if filters.get("has_verdict") is not None:
            records = [
                item
                for item in records
                if bool((item.get("verdict") or {}).get("verdict"))
                is filters["has_verdict"]
            ]
        return sorted(records, key=lambda item: item["updated_at"], reverse=True)

    def list(self, *, limit, offset=0, **filters):
        return self._matching(**filters)[offset : offset + limit]

    def count(self, **filters):
        if self.fail_counts:
            raise RuntimeError("count failed")
        return len(self._matching(**filters))


class FakeGateway:
    def search_alerts(self, **kwargs):  # pragma: no cover - must stay unused
        raise AssertionError("durable memory must not fall back to live Wazuh")


class UnusedToolAgent:
    def answer(self, **_kwargs):  # pragma: no cover - must stay unused
        raise AssertionError("a change report must not spend a model call")


class FakeInvestigations:
    def __init__(self):
        self.analysis_events: list[tuple[str, datetime]] = []
        self.available = True

    def completed_analysis_count(
        self,
        *,
        organization_id,
        occurred_after,
        occurred_on_or_before,
    ):
        if not self.available:
            raise RuntimeError("audit source unavailable")
        return sum(
            org_id == organization_id
            and occurred_after < occurred_at <= occurred_on_or_before
            for org_id, occurred_at in self.analysis_events
        )


def finding(
    finding_id: str,
    *,
    created_at: datetime,
    updated_at: datetime,
    verdict: str | None = "suspicious",
    organization_id: str = "org-a",
):
    return {
        "finding_id": finding_id,
        "organization_id": organization_id,
        "status": "open",
        "severity": "high",
        "version": 1,
        "event_type": "ssh_brute_force",
        "created_at": created_at,
        "updated_at": updated_at,
        "finding": {
            "finding_id": finding_id,
            "title": "Repeated SSH authentication failures",
            "summary": "Correlated from persisted Wazuh alerts.",
            "severity": "high",
        },
        "verdict": {"verdict": verdict, "confidence": 0.6} if verdict else {},
    }


def alert_document(document_id: str) -> AlertIngestionDocument:
    return AlertIngestionDocument(
        document_id=document_id,
        index_name="wazuh-alerts-test",
        normalized=AlertEvidence(
            alert_id=document_id,
            timestamp=datetime.now(UTC),
            agent_id="001",
            agent_name="server-a",
            rule_id="5712",
            rule_level=10,
            description="sshd brute force",
            source_ip="192.0.2.10",
        ),
        raw_document={},
    )


@pytest.fixture
def wired(monkeypatch):
    memory = DurableMemory()
    findings = FakeFindingRepository()
    monkeypatch.setattr("app.soc_assistant.service.database_url", lambda: None)
    monkeypatch.setattr(
        "app.soc_assistant.service.get_alert_memory_repository",
        lambda: memory,
    )
    monkeypatch.setattr(
        "app.soc_assistant.service.get_finding_repository",
        lambda: findings,
    )
    service = SOCAssistant(
        gateway=FakeGateway(),
        investigations=FakeInvestigations(),
        router=AssistantIntentRouter(),
        tool_agent=UnusedToolAgent(),
    )
    return service, memory, findings


def ask(service, message, *, organization_id="org-a", user_id="analyst-1"):
    return service.respond(
        message=message,
        conversation_id="conversation-test",
        organization_id=organization_id,
        user_id=user_id,
    )


def test_first_new_alerts_question_establishes_a_baseline(wired):
    service, memory, findings = wired
    memory.remember_alert_document(alert_document("alert-old"))
    findings.records = [
        finding(
            "FND-1",
            created_at=datetime.now(UTC) - timedelta(hours=2),
            updated_at=datetime.now(UTC) - timedelta(hours=2),
        )
    ]

    result = ask(service, "any new alerts?")

    assert result.selected_command == AssistantCommandName.ALERTS
    assert result.response["baseline_established"] is True
    # The window's existing history is not "new".
    assert result.response["new_alerts"] is None
    assert result.response["new_findings"] is None
    assert result.response["recent_alerts"] == 1
    assert "cannot yet say what is new" in result.assistant_message
    assert result.response["cursor_advanced"] is True


def test_second_check_with_no_changes_names_the_previous_check(wired):
    service, _, findings = wired
    findings.records = [
        finding(
            "FND-1",
            created_at=datetime.now(UTC) - timedelta(hours=2),
            updated_at=datetime.now(UTC) - timedelta(hours=2),
        )
    ]
    ask(service, "any new alerts?")

    result = ask(service, "any new alerts?")

    assert result.response["baseline_established"] is False
    assert result.response["new_alerts"] == 0
    assert result.response["new_findings"] == 0
    assert result.response["updated_findings"] == 0
    assert "No new alerts have appeared since your previous check at" in (
        result.assistant_message
    )
    assert "1 existing finding" in result.assistant_message


def test_new_alerts_after_the_baseline_are_reported(wired):
    service, memory, _ = wired
    ask(service, "any new alerts?")

    memory.remember_alert_document(alert_document("alert-fresh"))
    result = ask(service, "any new alerts?")

    assert result.response["new_alerts"] == 1
    assert "1 new alert" in result.assistant_message


def test_updated_finding_without_new_alerts(wired):
    service, _, findings = wired
    created = datetime.now(UTC) - timedelta(hours=3)
    findings.records = [finding("FND-1", created_at=created, updated_at=created)]
    ask(service, "any new alerts?")

    findings.records = [
        finding("FND-1", created_at=created, updated_at=datetime.now(UTC))
    ]
    result = ask(service, "any new findings?")

    assert result.response["new_alerts"] == 0
    assert result.response["new_findings"] == 0
    assert result.response["updated_findings"] == 1
    assert "1 updated finding" in result.assistant_message


def test_finding_update_does_not_count_as_completed_analysis(wired):
    service, _, findings = wired
    created = datetime.now(UTC) - timedelta(hours=3)
    findings.records = [finding("FND-1", created_at=created, updated_at=created)]
    ask(service, "any new alerts?")

    result = ask(service, "is there any new analysis?")

    assert result.response["change_subject"] == "analysis"
    assert result.response["reanalyzed_findings"] == 0
    assert result.response["completed_analyses"] == 0
    assert "No new analysis since your previous check at" in (
        result.assistant_message
    )


def test_completed_analysis_comes_from_authoritative_audit_event(wired):
    service, _, findings = wired
    created = datetime.now(UTC) - timedelta(hours=3)
    findings.records = [finding("FND-1", created_at=created, updated_at=created)]
    ask(service, "any new alerts?")
    service.investigations.analysis_events.append(("org-a", datetime.now(UTC)))

    result = ask(service, "is there any new analysis?")

    assert result.response["completed_analyses"] == 1
    assert result.response["reanalyzed_findings"] == 1
    assert result.response["analysis_count"]["source"] == "soc_audit_events"
    assert "1 MAPE-K analysis completed" in result.assistant_message


def test_unavailable_analysis_audit_is_explicit_and_does_not_advance_cursor(wired):
    service, memory, _ = wired
    ask(service, "any new alerts?")
    baseline = memory.get_user_cursor("org-a:analyst-1")
    service.investigations.available = False

    result = ask(service, "is there any new analysis?")

    assert result.response["completed_analyses"] is None
    assert result.response["analysis_count"]["status"] == "unavailable"
    assert result.response["cursor_advanced"] is False
    assert memory.get_user_cursor("org-a:analyst-1") == baseline
    assert "audit source could not be counted" in result.assistant_message


def test_change_reports_are_conversational_not_raw_json(wired):
    service, _, _ = wired

    result = ask(service, "any new alerts?")

    assert result.response["display_mode"] == "conversation"
    assert not result.assistant_message.lstrip().startswith("{")


def test_cursor_is_scoped_per_organization(wired):
    service, memory, _ = wired
    ask(service, "any new alerts?", organization_id="org-a")

    other = ask(service, "any new alerts?", organization_id="org-b")

    # A second tenant starts from its own baseline, not org-a's mark.
    assert other.response["baseline_established"] is True
    assert memory.get_user_cursor("org-a:analyst-1") is not None
    assert memory.get_user_cursor("org-b:analyst-1") is not None


def test_out_of_order_check_does_not_rewind_the_cursor():
    memory = DurableMemory()
    later = datetime.now(UTC)
    earlier = later - timedelta(minutes=10)

    memory.advance_user_cursor("org-a:analyst-1", later)
    memory.advance_user_cursor("org-a:analyst-1", earlier)

    assert memory.get_user_cursor("org-a:analyst-1") == later


def test_finding_counts_are_exact_beyond_the_display_page_and_tenant_scoped(wired):
    service, memory, findings = wired
    old = datetime.now(UTC) - timedelta(hours=3)
    findings.records = [
        finding(f"OLD-{index}", created_at=old, updated_at=old)
        for index in range(25)
    ] + [
        finding(
            "OTHER-TENANT",
            created_at=old,
            updated_at=old,
            organization_id="org-b",
        )
    ]
    ask(service, "any new alerts?")
    baseline = memory.get_user_cursor("org-a:analyst-1")
    assert baseline is not None
    fresh = baseline + timedelta(seconds=1)
    findings.records.extend(
        finding(f"NEW-{index}", created_at=fresh, updated_at=fresh)
        for index in range(7)
    )
    for index in range(4):
        findings.records[index]["updated_at"] = fresh

    _answer, payload, _tools, _context = service._alerts_capability(
        {"change_mode": "changed", "limit": 2},
        organization_id="org-a",
        user_id="analyst-1",
    )

    assert payload["finding_count"] == 2
    assert payload["total_findings"] == 32
    assert payload["new_findings"] == 7
    assert payload["updated_findings"] == 4
    assert payload["unchanged_findings"] == 21
    assert payload["count_filters"]["same_filters"] is False
    assert payload["count_filters"]["raw_alerts"]["source"] == (
        "soc_wazuh_alerts"
    )
    assert payload["count_filters"]["findings"]["source"] == "soc_findings"


def test_failed_finding_count_does_not_advance_change_cursor(wired):
    service, memory, findings = wired
    ask(service, "any new alerts?")
    baseline = memory.get_user_cursor("org-a:analyst-1")
    findings.fail_counts = True

    with pytest.raises(RuntimeError, match="count failed"):
        service._alerts_capability(
            {"change_mode": "changed"},
            organization_id="org-a",
            user_id="analyst-1",
        )

    assert memory.get_user_cursor("org-a:analyst-1") == baseline


@pytest.mark.parametrize(
    "message",
    [
        "which IP is responsible for most of these alerts?",
        "why did rule 5712 fire so many times?",
        "is this alert volume a brute force attempt?",
        "any recent alerts?",
        "what alerts came in over the last 6 hours?",
    ],
)
def test_investigative_alert_questions_reach_the_analyst_not_a_listing(message):
    intent, _ = AssistantIntentRouter().route(message)

    assert intent.command == AssistantCommandName.CHAT
    assert intent.arguments["question"] == message


@pytest.mark.parametrize(
    ("message", "mode"),
    [
        ("any new alerts?", "new"),
        ("any new findings?", "new"),
        ("is there any new analysis?", "new"),
        ("what changed?", "changed"),
    ],
)
def test_change_questions_classify_into_distinct_modes(message, mode):
    intent, _ = AssistantIntentRouter().route(message)

    assert intent.command == AssistantCommandName.ALERTS
    assert intent.arguments["change_mode"] == mode
