"""Separate bounded payload serializers for storage, APIs, agents, and traces."""

from __future__ import annotations

import json
from typing import Any, Literal

import structlog
from pydantic import BaseModel

from app.config import settings
from app.core.observability.redaction import sanitize
from app.db.sanitization import sanitize_for_storage
from app.services.wazuh.models import AlertSearchResult
from app.services.wazuh.normalization.aggregation import (
    aggregate_alerts,
    build_findings,
)
from app.services.wazuh.normalization.registry import normalize_alerts
from app.services.wazuh.normalization.schemas import (
    AlertEnvelope,
    AlertGroup,
    SecurityFinding,
)


logger = structlog.get_logger("tsage.wazuh.normalization")
ResponseMode = Literal["compact", "normalized", "raw"]

DROP_TRACE_KEYS = {
    "__gemini_function_call_thought_signatures__",
    "extras.signature",
    "signature",
    "full_log",
    "raw_document",
}
DROP_AGENT_KEYS = DROP_TRACE_KEYS | {
    "audit_events",
    "specialist_runs",
    "provider_signature",
}


def _plain(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    return value


def serialize_for_storage(value: Any) -> Any:
    return sanitize_for_storage(_plain(value))


def serialize_for_api(
    *,
    mode: ResponseMode,
    raw: Any = None,
    envelopes: list[AlertEnvelope] | None = None,
    findings: list[SecurityFinding] | None = None,
) -> Any:
    if mode == "raw":
        if not settings.WAZUH_RAW_EVIDENCE_ENABLED:
            raise ValueError("Raw Wazuh evidence retrieval is disabled.")
        return sanitize_for_storage(_plain(raw), max_items=200, max_string_length=8000)
    if mode == "normalized":
        return [
            item.model_dump(mode="json")
            for item in (envelopes or [])[: settings.MAX_NORMALIZED_ALERTS_PER_RESPONSE]
        ]
    return [
        item.model_dump(mode="json")
        for item in (findings or [])[: settings.MAX_FINDINGS_PER_AGENT_RESPONSE]
    ]


def _compact_finding(finding: SecurityFinding) -> dict[str, Any]:
    return finding.model_dump(
        mode="json",
        include={
            "finding_id",
            "title",
            "summary",
            "category",
            "attack_family",
            "event_type",
            "severity",
            "severity_score",
            "confidence",
            "first_seen",
            "last_seen",
            "affected_assets",
            "source_ips",
            "target_users",
            "mitre_techniques",
            "alert_count",
            "representative_alert_id",
            "evidence_refs",
            "investigation_recommended",
            "recommendation_reason_code",
        },
    )


def compact_alert_search_result(result: AlertSearchResult) -> dict[str, Any]:
    raw_alerts = [alert.model_dump(mode="json") for alert in result.alerts]
    envelopes = normalize_alerts(raw_alerts)
    groups = aggregate_alerts(envelopes)
    findings = build_findings(groups)
    highest = max(
        (item.normalized.rule_level for item in envelopes),
        default=0,
    )
    data = {
        "total_raw_alerts": result.total,
        "normalized_alerts": len(envelopes),
        "group_count": len(groups),
        "finding_count": len(findings),
        "truncated": result.truncated,
        "highest_severity": highest,
        # Redis cursor tracking is optional; null avoids inventing a delta.
        "new_since_last_check": None,
        "findings": [
            _compact_finding(item)
            for item in findings[: settings.MAX_FINDINGS_PER_AGENT_RESPONSE]
        ],
    }
    before = len(json.dumps(result.model_dump(mode="json"), default=str))
    after = len(json.dumps(data, default=str))
    logger.info(
        "alert_context_compacted",
        raw_alert_count=result.total,
        returned_alert_count=result.returned,
        finding_count=len(data["findings"]),
        characters_before=before,
        characters_after=after,
        compaction_ratio=round(1 - after / before, 4) if before else 0,
        estimated_tokens_before=round(before / 4),
        estimated_tokens_after=round(after / 4),
    )
    return data


def serialize_for_agent(value: Any) -> Any:
    if isinstance(value, AlertSearchResult):
        return compact_alert_search_result(value)
    if isinstance(value, list) and value and isinstance(value[0], SecurityFinding):
        return [
            _compact_finding(item)
            for item in value[: settings.MAX_FINDINGS_PER_AGENT_RESPONSE]
        ]
    return sanitize_for_storage(
        _strip_fields(_plain(value), DROP_AGENT_KEYS),
        max_depth=5,
        max_items=settings.MAX_NORMALIZED_ALERTS_PER_RESPONSE,
        max_string_length=2000,
    )


def _strip_fields(value: Any, dropped: set[str]) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _strip_fields(item, dropped)
            for key, item in value.items()
            if str(key).lower() not in dropped
            and not str(key).lower().endswith(".signature")
        }
    if isinstance(value, list):
        return [_strip_fields(item, dropped) for item in value[:20]]
    return value


def serialize_for_trace(value: Any) -> Any:
    compacted = serialize_for_agent(value)
    return sanitize(
        _strip_fields(compacted, DROP_TRACE_KEYS),
        max_depth=5,
        max_items=20,
        max_string_length=1000,
    )


def compact_tool_result(tool_name: str, result: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(result, dict):
        return {"ok": False, "error": {"code": "INVALID_TOOL_RESULT"}}
    if not result.get("ok"):
        return serialize_for_agent(result)
    data = result.get("data")
    if tool_name in {"get_recent_wazuh_alerts", "get_high_severity_alerts"}:
        if isinstance(data, AlertSearchResult):
            compact = compact_alert_search_result(data)
        elif isinstance(data, dict) and "alerts" in data:
            compact = compact_alert_search_result(AlertSearchResult.model_validate(data))
        else:
            compact = serialize_for_agent(data)
        return {"ok": True, "data": compact}
    if tool_name == "get_alert_details":
        alert = data.get("alert") if isinstance(data, dict) else None
        compact_alert = (
            {
                key: alert.get(key)
                for key in (
                    "alert_id",
                    "timestamp",
                    "agent_id",
                    "agent_name",
                    "hostname",
                    "rule_id",
                    "rule_level",
                    "description",
                    "source_ip",
                    "target_user",
                    "decoder_name",
                    "rule_groups",
                    "mitre_ids",
                    "event_outcome",
                )
                if alert.get(key) is not None
            }
            if isinstance(alert, dict)
            else None
        )
        return {
            "ok": True,
            "data": {
                "found": bool(compact_alert),
                "alert": compact_alert,
                "evidence_ref": (
                    f"wazuh:alert:{compact_alert['alert_id']}"
                    if compact_alert
                    else None
                ),
            },
        }
    if tool_name == "get_raw_alert_document":
        document = data.get("document") if isinstance(data, dict) else None
        normalized = (
            document.get("normalized")
            if isinstance(document, dict)
            and isinstance(document.get("normalized"), dict)
            else None
        )
        alert_id = document.get("alert_id") if isinstance(document, dict) else None
        return {
            "ok": True,
            "data": {
                "found": bool(document),
                "alert_id": alert_id,
                "evidence_ref": f"wazuh:alert:{alert_id}" if alert_id else None,
                "normalized": serialize_for_agent(normalized) if normalized else None,
                "raw_document_retained_in_wazuh": bool(document),
            },
        }
    if tool_name in {"start_investigation", "get_investigation_status"}:
        snapshot = data if isinstance(data, dict) else {}
        return {
            "ok": True,
            "data": {
                key: snapshot.get(key)
                for key in (
                    "investigation_id",
                    "alert_id",
                    "status",
                    "current_stage",
                    "completed_stages",
                    "failed_stages",
                    "severity",
                    "confidence",
                    "errors",
                )
                if snapshot.get(key) is not None
            }
            | {
                "l1_summary": (snapshot.get("l1_result") or {}).get("summary"),
                "l2_summary": (snapshot.get("l2_result") or {}).get("summary"),
                "l3_summary": (snapshot.get("l3_result") or {}).get("summary"),
                "proposed_action_count": len(snapshot.get("proposed_actions") or []),
            },
        }
    return {"ok": True, "data": serialize_for_agent(data)}
