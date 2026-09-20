"""Deterministic, verdict-free operations over normalized Wazuh evidence."""

from __future__ import annotations

from collections import Counter
from typing import Any, Iterable

from app.services.wazuh.models import AlertEvidence, AlertSearchResult


def evidence_ref(alert_id: str) -> str:
    return f"wazuh:alert:{alert_id}"


def deduplicate_alerts(alerts: Iterable[AlertEvidence]) -> list[AlertEvidence]:
    """Keep one stable event per Wazuh document ID, ordered by time."""

    by_id: dict[str, AlertEvidence] = {}
    for alert in alerts:
        by_id.setdefault(alert.alert_id, alert)
    return sorted(by_id.values(), key=lambda item: (item.timestamp, item.alert_id))


def summarize_alert_activity(result: AlertSearchResult) -> dict[str, Any]:
    """Return counts and coverage facts without assigning a security verdict."""

    alerts = deduplicate_alerts(result.alerts)

    def counts(attribute: str) -> dict[str, int]:
        values = Counter(
            str(value)
            for alert in alerts
            if (value := getattr(alert, attribute, None)) not in (None, "")
        )
        return dict(sorted(values.items(), key=lambda item: (-item[1], item[0])))

    outcomes = Counter(alert.event_outcome for alert in alerts)
    return {
        "coverage": {
            "matched": result.total,
            "returned": result.returned,
            "unique_returned": len(alerts),
            "duplicates_removed": max(0, result.returned - len(alerts)),
            "truncated": result.truncated,
            "status": "partial" if result.truncated else "complete",
        },
        "time_range": {
            "first": alerts[0].timestamp.isoformat() if alerts else None,
            "last": alerts[-1].timestamp.isoformat() if alerts else None,
        },
        "counts": {
            "by_source_ip": counts("source_ip"),
            "by_target_user": counts("target_user"),
            "by_agent_id": counts("agent_id"),
            "by_rule_id": counts("rule_id"),
            "by_outcome": dict(sorted(outcomes.items())),
        },
        "evidence_references": [evidence_ref(item.alert_id) for item in alerts],
    }


def authentication_activity(
    result: AlertSearchResult,
    *,
    source_ip: str | None = None,
    target_user: str | None = None,
    agent_id: str | None = None,
    related_events: Iterable[AlertEvidence] = (),
) -> dict[str, Any]:
    """Correlate authentication facts on an exact principal/asset tuple.

    This deliberately reports observations, not "compromised", "malicious",
    or other verdicts. Interpretation belongs to the analyst model.
    """

    alerts = [
        item
        for item in deduplicate_alerts(result.alerts)
        if (not source_ip or item.source_ip == source_ip)
        and (not target_user or item.target_user == target_user)
        and (not agent_id or item.agent_id == agent_id)
    ]
    failures = [item for item in alerts if item.event_outcome == "failure"]
    successes = [item for item in alerts if item.event_outcome == "success"]
    failures_by_key: dict[tuple[str, str, str], list[AlertEvidence]] = {}
    for item in failures:
        if item.source_ip and item.target_user and item.agent_id:
            failures_by_key.setdefault(
                (item.source_ip, item.target_user, item.agent_id), []
            ).append(item)

    exact_successes: list[dict[str, Any]] = []
    exact_success_alerts: list[AlertEvidence] = []
    for success in successes:
        key = (success.source_ip, success.target_user, success.agent_id)
        prior = [
            item
            for item in failures_by_key.get(key, [])
            if item.timestamp < success.timestamp
        ]
        if prior:
            exact_success_alerts.append(success)
            exact_successes.append(
                {
                    "source_ip": success.source_ip,
                    "target_user": success.target_user,
                    "agent_id": success.agent_id,
                    "success_timestamp": success.timestamp.isoformat(),
                    "success_evidence_ref": evidence_ref(success.alert_id),
                    "prior_failure_count": len(prior),
                    "first_failure": prior[0].timestamp.isoformat(),
                    "last_failure": prior[-1].timestamp.isoformat(),
                    "failure_evidence_refs": [
                        evidence_ref(item.alert_id) for item in prior
                    ],
                }
            )

    users = sorted({item.target_user for item in failures if item.target_user})
    sources = sorted({item.source_ip for item in failures if item.source_ip})
    auth_ids = {item.alert_id for item in alerts}
    related = deduplicate_alerts(related_events)
    post_login = []
    for success in exact_success_alerts:
        following = [
            item
            for item in related
            if item.alert_id not in auth_ids
            and item.agent_id == success.agent_id
            and item.timestamp > success.timestamp
        ]
        post_login.append(
            {
                "success_evidence_ref": evidence_ref(success.alert_id),
                "agent_id": success.agent_id,
                "events": [
                    {
                        "timestamp": item.timestamp.isoformat(),
                        "rule_id": item.rule_id,
                        "description": item.description,
                        "source_ip": item.source_ip,
                        "target_user": item.target_user,
                        "evidence_ref": evidence_ref(item.alert_id),
                    }
                    for item in following
                ],
            }
        )

    return {
        "scope": {
            "source_ip": source_ip,
            "target_user": target_user,
            "agent_id": agent_id,
        },
        "coverage": {
            "matched": result.total,
            "returned": result.returned,
            "unique_scoped_events": len(alerts),
            "truncated": result.truncated,
            "status": "partial" if result.truncated else "complete",
        },
        "observations": {
            "failure_count": len(failures),
            "success_count": len(successes),
            "unique_target_user_count": len(users),
            "target_users": users,
            "unique_source_ip_count": len(sources),
            "source_ips": sources,
            "success_after_failures_exact_match": exact_successes,
            "post_login_activity": post_login,
        },
        "timeline": [
            {
                "timestamp": item.timestamp.isoformat(),
                "outcome": item.event_outcome,
                "source_ip": item.source_ip,
                "target_user": item.target_user,
                "agent_id": item.agent_id,
                "rule_id": item.rule_id,
                "evidence_ref": evidence_ref(item.alert_id),
            }
            for item in alerts
        ],
        "evidence_references": [evidence_ref(item.alert_id) for item in alerts],
    }
