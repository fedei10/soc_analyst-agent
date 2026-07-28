"""Priors this SOC has already earned, fed back into Analyze.

The K in MAPE-K used to be write-only: every incident produced a report and
nothing was ever read back. Two signals were already being captured and then
ignored - analyst dispositions on findings (`soc_finding_feedback`) and raw
alert prevalence (`alert_memory`). This module turns them into a compact,
deterministic block of facts the model sees before it diagnoses, so "analysts
called this exact pattern benign eleven times out of twelve on this host"
lands as evidence rather than being rediscovered from scratch every run.

Everything here is best-effort: a database that is slow, empty or missing
must degrade the diagnosis to what it was before, never fail the workflow.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

from app.config import settings


# Dispositions an analyst can record, split by what they imply about a future
# lookalike. Anything unrecognized is counted but stays out of both buckets
# rather than being guessed into one.
BENIGN_DISPOSITIONS = frozenset({"confirmed_benign", "expected_admin_activity"})
MALICIOUS_DISPOSITIONS = frozenset({"confirmed_malicious"})

# Bounds so a busy organization cannot turn priors into an unbounded scan.
MAX_FINDINGS_SCANNED = 200
MAX_FINDINGS_JOINED = 20


def _event_types(state: Any) -> set[str]:
    types = set()
    for finding in getattr(state, "findings", []) or []:
        if isinstance(finding, dict) and finding.get("event_type"):
            types.add(str(finding["event_type"]))
    return types


def _attack_families(state: Any) -> set[str]:
    families = set()
    for finding in getattr(state, "findings", []) or []:
        if isinstance(finding, dict) and finding.get("attack_family"):
            families.add(str(finding["attack_family"]))
    return families


def _feedback_priors(
    state: Any,
    repository: Any,
    *,
    organization_id: str,
    since: datetime,
) -> dict[str, Any] | None:
    """How analysts have historically dispositioned lookalike findings."""

    event_types = _event_types(state)
    families = _attack_families(state)
    if not event_types and not families:
        return None

    records = repository.list(
        organization_id=organization_id,
        limit=MAX_FINDINGS_SCANNED,
    )
    similar = [
        record
        for record in records
        if str(record.get("event_type") or "") in event_types
        or str(record.get("attack_family") or "") in families
    ][:MAX_FINDINGS_JOINED]
    if not similar:
        return None

    dispositions: Counter[str] = Counter()
    reviewed_findings = 0
    notes: list[str] = []
    for record in similar:
        entries = repository.list_feedback(
            str(record["finding_id"]),
            organization_id=organization_id,
        )
        recent = [
            entry
            for entry in entries
            if _at_or_after(entry.get("created_at"), since)
        ]
        if not recent:
            continue
        reviewed_findings += 1
        for entry in recent:
            dispositions[str(entry.get("disposition") or "unknown")] += 1
            note = str(entry.get("notes") or "").strip()
            if note and len(notes) < 3:
                notes.append(note[:280])

    total = sum(dispositions.values())
    if not total:
        return None
    benign = sum(
        count
        for disposition, count in dispositions.items()
        if disposition in BENIGN_DISPOSITIONS
    )
    malicious = sum(
        count
        for disposition, count in dispositions.items()
        if disposition in MALICIOUS_DISPOSITIONS
    )
    return {
        "matched_on": sorted(event_types or families),
        "similar_findings_reviewed": reviewed_findings,
        "total_dispositions": total,
        "dispositions": dict(dispositions),
        "benign_rate": round(benign / total, 3),
        "malicious_rate": round(malicious / total, 3),
        "analyst_notes": notes,
    }


def _at_or_after(value: Any, since: datetime) -> bool:
    if not isinstance(value, datetime):
        # Repositories that hand back ISO strings still get counted; an
        # unparsable timestamp is included rather than silently dropped.
        try:
            value = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return True
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value >= since


def _prevalence_priors(
    state: Any,
    repository: Any,
    *,
    since: datetime,
) -> dict[str, Any] | None:
    """How noisy this asset normally is, so 'a lot' has a denominator."""

    agent_id = getattr(state, "agent_id", None)
    if not agent_id:
        return None
    total = repository.count_alerts_since(since, agent_id=str(agent_id))
    significant = repository.count_alerts_since(
        since,
        agent_id=str(agent_id),
        min_level=10,
    )
    if not total:
        return None
    window_days = max(
        int((datetime.now(UTC) - since).total_seconds() // 86_400),
        1,
    )
    return {
        "agent_id": str(agent_id),
        "window_days": window_days,
        "alerts_in_window": total,
        "high_level_alerts_in_window": significant,
        "alerts_per_day": round(total / window_days, 2),
    }


def incident_priors(
    state: Any,
    *,
    finding_repository: Any | None = None,
    memory_repository: Any | None = None,
    settings_obj: Any = settings,
) -> dict[str, Any]:
    """Compact prior knowledge for this incident. Never raises."""

    if not getattr(settings_obj, "MAPEK_LEARNING_ENABLED", True):
        return {}
    lookback_days = max(
        int(getattr(settings_obj, "MAPEK_LEARNING_LOOKBACK_DAYS", 30)),
        1,
    )
    since = datetime.now(UTC) - timedelta(days=lookback_days)
    organization_id = str(getattr(state, "organization_id", "local") or "local")
    priors: dict[str, Any] = {}

    try:
        if finding_repository is None:
            from app.db.repositories.findings import get_finding_repository

            finding_repository = get_finding_repository()
        feedback = _feedback_priors(
            state,
            finding_repository,
            organization_id=organization_id,
            since=since,
        )
        if feedback:
            priors["analyst_feedback"] = feedback
    except Exception:
        # Priors are an optimization. A repository outage degrades the
        # diagnosis to evidence-only; it must not fail the investigation.
        pass

    try:
        if memory_repository is None:
            from app.db.repositories.alert_memory import (
                get_alert_memory_repository,
            )

            memory_repository = get_alert_memory_repository()
        prevalence = _prevalence_priors(state, memory_repository, since=since)
        if prevalence:
            priors["asset_prevalence"] = prevalence
    except Exception:
        pass

    return priors
