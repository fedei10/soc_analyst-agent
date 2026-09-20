from datetime import UTC, datetime, timedelta

from app.services.wazuh.correlation import (
    authentication_activity,
    summarize_alert_activity,
)
from app.services.wazuh.gateway import WazuhGateway
from app.services.wazuh.models import AlertEvidence, AlertSearchResult


BASE = datetime(2026, 9, 18, 8, 0, tzinfo=UTC)


def event(
    alert_id: str,
    minute: int,
    outcome: str,
    *,
    user: str = "ubuntu",
    source: str = "192.0.2.10",
    agent: str = "001",
    description: str | None = None,
) -> AlertEvidence:
    return AlertEvidence(
        alert_id=alert_id,
        timestamp=BASE + timedelta(minutes=minute),
        agent_id=agent,
        rule_id="5710",
        rule_level=8,
        description=description or outcome,
        source_ip=source,
        target_user=user,
        event_outcome=outcome,
        rule_groups=["sshd", "authentication_failed"],
    )


def result(*alerts: AlertEvidence, total: int | None = None, truncated=False):
    return AlertSearchResult(
        total=len(alerts) if total is None else total,
        returned=len(alerts),
        truncated=truncated,
        alerts=list(alerts),
    )


def test_one_account_is_not_presented_as_password_spraying():
    analysis = authentication_activity(
        result(*(event(f"f-{index}", index, "failure") for index in range(6))),
        source_ip="192.0.2.10",
        agent_id="001",
    )

    observations = analysis["observations"]
    assert observations["failure_count"] == 6
    assert observations["unique_target_user_count"] == 1
    assert observations["target_users"] == ["ubuntu"]


def test_multi_account_failures_preserve_cardinality_for_spray_reasoning():
    alerts = [
        event(f"f-{index}", index, "failure", user=f"user-{index}")
        for index in range(5)
    ]
    analysis = authentication_activity(
        result(*alerts), source_ip="192.0.2.10", agent_id="001"
    )

    assert analysis["observations"]["unique_target_user_count"] == 5
    assert analysis["observations"]["failure_count"] == 5


def test_success_after_failure_requires_exact_source_account_and_agent():
    analysis = authentication_activity(
        result(
            event("failure", 1, "failure", user="ubuntu"),
            event("other-user", 2, "success", user="root"),
            event("other-source", 3, "success", source="192.0.2.99"),
            event("other-agent", 4, "success", agent="002"),
            event("exact", 5, "success"),
        ),
        source_ip="192.0.2.10",
        agent_id="001",
    )

    matches = analysis["observations"]["success_after_failures_exact_match"]
    assert len(matches) == 1
    assert matches[0]["success_evidence_ref"] == "wazuh:alert:exact"


def test_post_login_activity_is_tied_to_exact_success_and_same_agent():
    auth = result(event("failure", 1, "failure"), event("success", 2, "success"))
    related = [
        event("before", 1, "unknown", description="before login"),
        event("process", 3, "unknown", description="new process"),
        event("other-agent", 4, "unknown", agent="002"),
    ]
    analysis = authentication_activity(
        auth,
        source_ip="192.0.2.10",
        agent_id="001",
        related_events=related,
    )

    events = analysis["observations"]["post_login_activity"][0]["events"]
    assert [item["evidence_ref"] for item in events] == ["wazuh:alert:process"]


def test_coverage_distinguishes_complete_zero_partial_and_deduplication():
    empty = summarize_alert_activity(result())
    assert empty["coverage"]["status"] == "complete"
    assert empty["coverage"]["matched"] == 0

    duplicate = event("same-id", 1, "failure")
    partial = summarize_alert_activity(
        result(duplicate, duplicate, total=20, truncated=True)
    )
    assert partial["coverage"] == {
        "matched": 20,
        "returned": 2,
        "unique_returned": 1,
        "duplicates_removed": 1,
        "truncated": True,
        "status": "partial",
    }
    assert partial["evidence_references"] == ["wazuh:alert:same-id"]


def test_gateway_does_not_match_success_for_a_different_principal():
    class Indexer:
        def search_alerts(self, **_kwargs):
            return result(
                event("failure", 1, "failure", user="ubuntu"),
                event("root-success", 2, "success", user="root"),
            )

    class Server:
        pass

    gateway = WazuhGateway(server=Server(), indexer=Indexer(), cache=object())
    analysis = gateway.check_successful_login_after_failures(
        source_ip="192.0.2.10", agent_id="001"
    )

    assert analysis.successful_login_observed is False
    assert analysis.conclusion == "no_success_in_returned_alerts"


def test_admin_like_success_is_reported_as_fact_without_static_verdict():
    analysis = authentication_activity(
        result(event("admin-login", 1, "success", user="ops-admin")),
        source_ip="192.0.2.10",
        agent_id="001",
    )

    assert analysis["observations"]["success_count"] == 1
    assert analysis["observations"]["failure_count"] == 0
    assert analysis["observations"]["success_after_failures_exact_match"] == []
    rendered_keys = str(analysis.keys()) + str(analysis["observations"].keys())
    assert "verdict" not in rendered_keys
    assert "malicious" not in str(analysis).lower()
    assert "compromised" not in str(analysis).lower()
