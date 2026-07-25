"""Deterministic, read-only finding report (no LLM call)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


def build_finding_report(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "report_type": "finding_triage_report",
        "finding_id": record["finding_id"],
        "finding": record["finding"],
        "verdict": record["verdict"],
        "enrichment": record.get("enrichment", []),
        "feedback": record.get("feedback", []),
        "generated_at": datetime.now(UTC).isoformat(),
    }
