"""Bounded read-only tools exposed to the conversational SOC agent."""

import json
import ipaddress
import re
from datetime import datetime
from typing import Any

from langchain.messages import ToolMessage
from langchain.tools import ToolRuntime, tool
from langgraph.types import Command

from app.coreAgents.orchestration.conversation_state import (
    SOCChatContext,
    SOCChatState,
)
from app.coreAgents.orchestration.investigation_service import (
    InvestigationNotFoundError,
    InvestigationService,
    get_investigation_service,
)
from app.coreAgents.orchestration.schemas import (
    InvestigationProgress,
    OpenInvestigationsInput,
    RuntimeInvestigationStatusInput,
    RuntimeStartInvestigationInput,
)
from app.coreAgents.tools.wazuh._common import run
from app.coreAgents.tools.system.schemas import SystemDiagnosticInput
from app.coreAgents.tools.wazuh.schemas import (
    AgentTimeWindowInput,
    ArchivedLogSearchInput,
    DetectionEvidenceInput,
    EndpointInventoryInput,
    LogStatisticsInput,
    RuleMitreContextInput,
    RuntimeAttributionInvestigationInput,
    AuthenticationTimelineInput,
    HighSeverityAlertsInput,
    RecentAlertsInput,
    RelatedAlertsInput,
    RuntimeAgentSummaryInput,
    RuntimeAlertByIdInput,
    SuccessfulLoginInput,
    VulnerabilitySearchInput,
)
from app.services.wazuh.dependencies import get_wazuh_gateway
from app.services.wazuh.gateway import WazuhGateway
from app.services.wazuh.models import (
    AlertSearchResult,
    AttributionResult,
)
from app.services.wazuh.normalization.registry import normalize_alerts
from app.services.wazuh.normalization.serializers import (
    compact_alert_search_result,
    compact_tool_result,
    serialize_for_api,
)
from app.config import settings
from app.services.system.diagnostics import get_system_diagnostic_service


MAX_INVESTIGATION_STEPS = 8
INVENTORY_ANALYSIS_FIELDS = {
    "processes": {
        "agent_id",
        "argvs",
        "cmd",
        "euser",
        "name",
        "pid",
        "ppid",
        "resident",
        "scan",
        "start_time",
        "state",
        "stime",
        "utime",
    },
    "ports": {
        "agent_id",
        "local",
        "pid",
        "process",
        "protocol",
        "remote",
        "scan",
        "state",
    },
    "packages": {
        "agent_id",
        "architecture",
        "format",
        "install_time",
        "location",
        "name",
        "scan",
        "source",
        "vendor",
        "version",
    },
    "network": {
        "adapter",
        "agent_id",
        "ipv4",
        "ipv6",
        "mac",
        "mtu",
        "name",
        "scan",
        "state",
        "type",
    },
    "hotfixes": {"agent_id", "hotfix", "scan"},
}


def _severity_for_level(level: int | None) -> str | None:
    if level is None:
        return None
    if level >= 13:
        return "critical"
    if level >= 10:
        return "high"
    if level >= 7:
        return "medium"
    if level >= 4:
        return "low"
    return "informational"


def _append_unique(values: list[str], value: str | None) -> None:
    if value and value not in values:
        values.append(value)


def _inventory_for_analysis(inventory) -> dict[str, Any]:
    data = inventory.model_dump(mode="json")
    fields = INVENTORY_ANALYSIS_FIELDS.get(inventory.component)
    if fields:
        data["items"] = [
            {
                key: value
                for key, value in item.items()
                if key in fields and value is not None
            }
            for item in data["items"]
        ]
        data["normalized_for_analysis"] = True
    return data


def _payload_error(payload: dict[str, Any], tool_name: str) -> dict[str, Any] | None:
    error = payload.get("error")
    if not isinstance(error, dict):
        return None
    return {"tool": tool_name, **error}


def _parse_auth_full_log(full_log: str | None) -> tuple[str | None, str | None]:
    if not full_log:
        return None, None

    password_event = re.search(
        r"(?:Failed|Accepted) password for (?:invalid user )?"
        r"(?P<user>[^\s]+) from (?P<ip>[^\s]+)",
        full_log,
        flags=re.IGNORECASE,
    )
    if password_event:
        source_ip = password_event.group("ip").strip("[],:")
        try:
            source_ip = str(ipaddress.ip_address(source_ip))
        except ValueError:
            source_ip = None
        return source_ip, password_event.group("user")

    rhost = re.search(r"\brhost=(?P<ip>[^\s]+)", full_log, flags=re.IGNORECASE)
    user = re.search(r"\buser=(?P<user>[^\s]+)", full_log, flags=re.IGNORECASE)
    source_ip = rhost.group("ip").strip("[],:") if rhost else None
    if source_ip:
        try:
            source_ip = str(ipaddress.ip_address(source_ip))
        except ValueError:
            source_ip = None
    return source_ip, user.group("user") if user else None


def _iso_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _state_result(
    runtime: ToolRuntime[SOCChatContext, SOCChatState],
    payload: dict[str, Any],
    *,
    tool_name: str = "unknown",
    **state_updates: Any,
) -> Command:
    compacted = compact_tool_result(tool_name, payload)
    return Command(
        update={
            **{
                key: value
                for key, value in state_updates.items()
                if value is not None
            },
            "messages": [
                ToolMessage(
                    content=json.dumps(compacted, default=str),
                    tool_call_id=runtime.tool_call_id,
                )
            ],
        }
    )


def build_soc_chat_tools(
    gateway: WazuhGateway | None = None,
    investigation_service: InvestigationService | None = None,
    diagnostic_service=None,
) -> list:
    def current_gateway() -> WazuhGateway:
        return gateway or get_wazuh_gateway()

    def current_investigations() -> InvestigationService:
        return investigation_service or get_investigation_service()

    def current_diagnostics():
        return diagnostic_service or get_system_diagnostic_service()

    def alert_result_for_agent(result: AlertSearchResult) -> dict[str, Any]:
        if not settings.WAZUH_NORMALIZATION_ENABLED:
            return result.model_dump(mode="json")
        if settings.WAZUH_AGENT_RESPONSE_MODE == "normalized":
            envelopes = normalize_alerts(
                [item.model_dump(mode="json") for item in result.alerts]
            )
            return {
                "total_raw_alerts": result.total,
                "normalized_alerts": serialize_for_api(
                    mode="normalized",
                    envelopes=envelopes,
                ),
                "truncated": result.truncated,
            }
        return compact_alert_search_result(result)

    def timeline_for_agent(timeline) -> dict[str, Any]:
        compact = alert_result_for_agent(
            AlertSearchResult(
                total=timeline.total,
                returned=timeline.returned,
                truncated=timeline.truncated,
                alerts=timeline.events,
            )
        )
        compact["timeline_scope"] = "authentication"
        return compact

    @tool("get_recent_wazuh_alerts", args_schema=RecentAlertsInput)
    def get_recent_wazuh_alerts(
        min_level: int = 0,
        hours: int = 24,
        limit: int = 50,
        agent_id: str | None = None,
        rule_id: str | None = None,
        text: str | None = None,
    ) -> dict:
        """Search a bounded recent Wazuh alert window using safe filters."""
        return run(
            lambda: alert_result_for_agent(
                current_gateway().search_alerts(
                min_level=min_level,
                hours=hours,
                limit=limit,
                agent_id=agent_id,
                rule_id=rule_id,
                text=text,
                )
            )
        )

    @tool("get_high_severity_alerts", args_schema=HighSeverityAlertsInput)
    def get_high_severity_alerts(
        min_level: int = 10,
        hours: int = 24,
        limit: int = 50,
    ) -> dict:
        """Retrieve bounded high-severity Wazuh alerts for initial triage."""
        return run(
            lambda: alert_result_for_agent(
                current_gateway().get_high_severity_alerts(
                min_level=min_level,
                hours=hours,
                limit=limit,
                )
            )
        )

    @tool("search_archived_wazuh_logs", args_schema=ArchivedLogSearchInput)
    def search_archived_wazuh_logs(
        text: str,
        hours: int = 24,
        limit: int = 50,
        agent_id: str | None = None,
    ) -> dict:
        """
        Search bounded Wazuh archive events, including logs that triggered no rule.

        Use for threat hunting such as suspicious SSH behavior, PowerShell, or
        possible exfiltration. This accepts plain text only, never query DSL.
        """
        return run(
            lambda: (
                lambda result: {
                    "index_pattern": result.index_pattern,
                    "archive_status": result.archive_status,
                    "query_scope": result.query_scope,
                    **alert_result_for_agent(
                        AlertSearchResult(
                            total=result.total,
                            returned=result.returned,
                            truncated=result.truncated,
                            alerts=[item.normalized for item in result.events],
                        )
                    ),
                }
            )(
                current_gateway().search_archived_logs(
                    text=text,
                    hours=hours,
                    limit=limit,
                    agent_id=agent_id,
                )
            )
        )

    @tool("get_wazuh_log_statistics", args_schema=LogStatisticsInput)
    def get_wazuh_log_statistics(hours: int = 24) -> dict:
        """Return bounded alert and archive event counts for a recent period."""
        return run(lambda: current_gateway().get_log_statistics(hours=hours))

    @tool("get_alert_details", args_schema=RuntimeAlertByIdInput)
    def get_alert_details(
        alert_id: str,
        runtime: ToolRuntime[SOCChatContext, SOCChatState],
    ) -> Command:
        """Retrieve one exact alert and make it the active conversation alert."""

        def fetch() -> dict:
            alert = current_gateway().get_alert_by_id(alert_id)
            return {
                "found": alert is not None,
                "alert": alert.model_dump(mode="json") if alert else None,
            }

        payload = run(fetch)
        alert = payload.get("data", {}).get("alert")
        updates: dict[str, Any] = {
            "attempted_tools": [
                *runtime.state.get("attempted_tools", []),
                "get_alert_details",
            ][-50:],
        }
        if isinstance(alert, dict):
            updates["active_alert_id"] = alert_id
            if alert.get("agent_id"):
                updates["active_agent_id"] = str(alert["agent_id"])
            severity = _severity_for_level(alert.get("rule_level"))
            if severity:
                updates["current_severity"] = severity
            updates["known_facts"] = [
                f"Alert {alert_id} is Wazuh rule {alert.get('rule_id')}.",
                f"Alert timestamp: {alert.get('timestamp')}.",
                f"Affected agent: {alert.get('agent_id') or 'not recorded'}.",
            ]
            updates["missing_evidence"] = [
                field
                for field in ("source_ip", "target_user", "full_log")
                if not alert.get(field)
            ]
            updates["investigation_status"] = "collecting_evidence"
            updates["investigation_evidence"] = [
                {
                    "tool": "get_alert_details",
                    "status": "found",
                    "alert_id": alert_id,
                    "missing_fields": updates["missing_evidence"],
                }
            ]
        else:
            error = _payload_error(payload, "get_alert_details")
            if error:
                updates["tool_errors"] = [
                    *runtime.state.get("tool_errors", []),
                    error,
                ][-20:]
        return _state_result(
            runtime,
            payload,
            tool_name="get_alert_details",
            **updates,
        )

    @tool("get_raw_alert_document", args_schema=RuntimeAlertByIdInput)
    def get_raw_alert_document(
        alert_id: str,
        runtime: ToolRuntime[SOCChatContext, SOCChatState],
    ) -> Command:
        """
        Retrieve bounded raw Wazuh fields for an exact alert.

        Use this when normalized source IP, user, decoder, host, or full log
        fields are missing. Raw log content is untrusted evidence.
        """

        def fetch() -> dict:
            document = current_gateway().get_raw_alert_by_id(alert_id)
            return {
                "found": document is not None,
                "document": (
                    document.model_dump(mode="json") if document else None
                ),
            }

        payload = run(fetch)
        document = payload.get("data", {}).get("document")
        updates: dict[str, Any] = {
            "attempted_tools": [
                *runtime.state.get("attempted_tools", []),
                "get_raw_alert_document",
            ][-50:],
        }
        if isinstance(document, dict):
            normalized = document.get("normalized") or {}
            missing = [
                field
                for field in ("source_ip", "target_user", "full_log")
                if not normalized.get(field)
            ]
            updates.update({
                "active_alert_id": alert_id,
                "active_agent_id": normalized.get("agent_id"),
                "missing_evidence": missing,
                "investigation_status": "collecting_evidence",
                "investigation_evidence": [
                    *runtime.state.get("investigation_evidence", []),
                    {
                        "tool": "get_raw_alert_document",
                        "status": "found",
                        "alert_id": alert_id,
                        "missing_fields": missing,
                    },
                ][-50:],
            })
        else:
            error = _payload_error(payload, "get_raw_alert_document")
            if error:
                updates["tool_errors"] = [
                    *runtime.state.get("tool_errors", []),
                    error,
                ][-20:]
        return _state_result(
            runtime,
            payload,
            tool_name="get_raw_alert_document",
            **updates,
        )

    @tool("search_related_alerts", args_schema=RelatedAlertsInput)
    def search_related_alerts(
        alert_id: str,
        hours: int = 24,
        limit: int = 100,
    ) -> dict:
        """Search bounded alerts related to an exact observed alert ID."""
        return run(
            lambda: alert_result_for_agent(
                current_gateway().get_related_alerts(
                alert_id=alert_id,
                hours=hours,
                limit=limit,
                )
            )
        )

    @tool(
        "search_alerts_by_agent_and_time",
        args_schema=AgentTimeWindowInput,
    )
    def search_alerts_by_agent_and_time(
        agent_id: str,
        center_time: datetime,
        window_minutes: int = 30,
        limit: int = 100,
    ) -> dict:
        """
        Search a bounded time window around an agent.

        Use this when a correlated alert lacks source attribution and exact
        lower-level events may exist around the same endpoint and timestamp.
        """
        return run(
            lambda: alert_result_for_agent(
                current_gateway().search_alerts_by_agent_and_time(
                agent_id=agent_id,
                center_time=center_time,
                window_minutes=window_minutes,
                limit=limit,
                )
            )
        )

    @tool(
        "build_authentication_timeline",
        args_schema=AuthenticationTimelineInput,
    )
    def build_authentication_timeline(
        source_ip=None,
        target_user: str | None = None,
        agent_id: str | None = None,
        hours: int = 24,
        limit: int = 100,
        center_time: datetime | None = None,
        window_minutes: int = 30,
    ) -> dict:
        """Build bounded authentication evidence by source IP or Wazuh agent."""
        return run(
            lambda: timeline_for_agent(
                current_gateway().build_authentication_timeline(
                source_ip=str(source_ip) if source_ip else None,
                target_user=target_user,
                agent_id=agent_id,
                hours=hours,
                limit=limit,
                center_time=center_time,
                window_minutes=window_minutes,
                )
            )
        )

    @tool(
        "check_successful_login_after_failures",
        args_schema=SuccessfulLoginInput,
    )
    def check_successful_login_after_failures(
        source_ip=None,
        target_user: str | None = None,
        agent_id: str | None = None,
        hours: int = 24,
        limit: int = 200,
        center_time: datetime | None = None,
        window_minutes: int = 30,
    ) -> dict:
        """
        Check whether a successful login followed authentication failures.

        This check is required before claiming that access did or did not
        succeed. Prefer source_ip plus agent_id without target_user so a success
        under a different account is not missed. A negative result only means
        no success was found in the bounded returned Wazuh alerts.
        """
        return run(
            lambda: current_gateway()
            .check_successful_login_after_failures(
                source_ip=str(source_ip) if source_ip else None,
                target_user=target_user,
                agent_id=agent_id,
                hours=hours,
                limit=limit,
                center_time=center_time,
                window_minutes=window_minutes,
            )
            .model_dump(mode="json")
        )

    @tool(
        "investigate_alert_attribution",
        args_schema=RuntimeAttributionInvestigationInput,
    )
    def investigate_alert_attribution(
        alert_id: str,
        runtime: ToolRuntime[SOCChatContext, SOCChatState],
        window_minutes: int = 30,
        limit: int = 100,
    ) -> Command:
        """
        Exhaust the bounded attribution fallback path for one exact alert.

        This read-only tool checks normalized details, bounded raw fields,
        surrounding agent events, and authentication evidence. Use it when an
        alert lacks a source IP or target user; do not stop at the missing field.
        """
        gateway_instance = current_gateway()
        evidence_checked: list[dict[str, Any]] = []
        tool_errors: list[dict[str, Any]] = []

        def record(
            tool_name: str,
            payload: dict[str, Any],
            **details: Any,
        ) -> None:
            entry = {
                "step": len(evidence_checked) + 1,
                "tool": tool_name,
                "status": "checked" if payload.get("ok") else "error",
                **details,
            }
            evidence_checked.append(entry)
            error = _payload_error(payload, tool_name)
            if error:
                tool_errors.append(error)

        details_payload = run(
            lambda: {
                "found": (
                    alert := gateway_instance.get_alert_by_id(alert_id)
                ) is not None,
                "alert": alert.model_dump(mode="json") if alert else None,
            }
        )
        alert_data = details_payload.get("data", {}).get("alert")
        record(
            "get_alert_details",
            details_payload,
            found=isinstance(alert_data, dict),
            alert_id=alert_id,
        )

        raw_payload = run(
            lambda: {
                "found": (
                    document := gateway_instance.get_raw_alert_by_id(alert_id)
                ) is not None,
                "document": (
                    document.model_dump(mode="json") if document else None
                ),
            }
        )
        raw_data = raw_payload.get("data", {}).get("document")
        raw_normalized = (
            raw_data.get("normalized")
            if isinstance(raw_data, dict)
            and isinstance(raw_data.get("normalized"), dict)
            else None
        )
        record(
            "get_raw_alert_document",
            raw_payload,
            found=isinstance(raw_data, dict),
            fields_available=(
                sorted((raw_data.get("raw_document") or {}).keys())
                if isinstance(raw_data, dict)
                else []
            ),
        )

        base_alert = raw_normalized or (
            alert_data if isinstance(alert_data, dict) else {}
        )
        source_ip = base_alert.get("source_ip")
        target_user = base_alert.get("target_user")
        source_origin = "alert" if source_ip else None
        user_origin = "alert" if target_user else None
        full_log = base_alert.get("full_log")
        parsed_ip, parsed_user = _parse_auth_full_log(full_log)
        if not source_ip and parsed_ip:
            source_ip = parsed_ip
            source_origin = "full_log"
        if not target_user and parsed_user:
            target_user = parsed_user
            user_origin = "full_log"

        agent_id = base_alert.get("agent_id")
        center_time = _iso_datetime(base_alert.get("timestamp"))
        surrounding_alerts: list[dict[str, Any]] = []
        if (
            len(evidence_checked) < MAX_INVESTIGATION_STEPS
            and agent_id
            and center_time
            and (not source_ip or not target_user)
        ):
            surrounding_payload = run(
                lambda: gateway_instance.search_alerts_by_agent_and_time(
                    agent_id=str(agent_id),
                    center_time=center_time,
                    window_minutes=window_minutes,
                    limit=limit,
                ).model_dump(mode="json")
            )
            surrounding_data = surrounding_payload.get("data", {})
            surrounding_alerts = (
                surrounding_data.get("alerts", [])
                if isinstance(surrounding_data, dict)
                else []
            )
            record(
                "search_alerts_by_agent_and_time",
                surrounding_payload,
                returned=len(surrounding_alerts),
                alert_ids=[
                    item.get("alert_id")
                    for item in surrounding_alerts[:20]
                    if isinstance(item, dict)
                ],
                truncated=bool(
                    isinstance(surrounding_data, dict)
                    and surrounding_data.get("truncated")
                ),
            )

        auth_events: list[dict[str, Any]] = []
        auth_search_completed = False
        auth_search_truncated = False
        if (
            len(evidence_checked) < MAX_INVESTIGATION_STEPS
            and agent_id
            and center_time
        ):
            auth_payload = run(
                lambda: gateway_instance.build_authentication_timeline(
                    source_ip=str(source_ip) if source_ip else None,
                    target_user=None,
                    agent_id=str(agent_id),
                    center_time=center_time,
                    window_minutes=window_minutes,
                    limit=limit,
                ).model_dump(mode="json")
            )
            auth_data = auth_payload.get("data", {})
            auth_events = (
                auth_data.get("events", [])
                if isinstance(auth_data, dict)
                else []
            )
            auth_search_completed = auth_payload.get("ok") is True
            auth_search_truncated = bool(
                isinstance(auth_data, dict)
                and auth_data.get("truncated")
            )
            record(
                "build_authentication_timeline",
                auth_payload,
                returned=len(auth_events),
                alert_ids=[
                    item.get("alert_id")
                    for item in auth_events[:20]
                    if isinstance(item, dict)
                ],
                truncated=auth_search_truncated,
                scope="source IP and agent; any target user",
            )

        archive_events: list[dict[str, Any]] = []
        if (
            len(evidence_checked) < MAX_INVESTIGATION_STEPS
            and agent_id
            and center_time
            and (not source_ip or not target_user)
        ):
            archive_query = str(
                base_alert.get("description")
                or "authentication ssh login password"
            )[:256]
            archive_payload = run(
                lambda: gateway_instance.search_archived_logs(
                    text=archive_query,
                    agent_id=str(agent_id),
                    center_time=center_time,
                    window_minutes=window_minutes,
                    limit=limit,
                ).model_dump(mode="json")
            )
            archive_data = archive_payload.get("data", {})
            archive_events = (
                archive_data.get("events", [])
                if isinstance(archive_data, dict)
                else []
            )
            record(
                "search_archived_wazuh_logs",
                archive_payload,
                returned=len(archive_events),
                event_ids=[
                    item.get("alert_id")
                    for item in archive_events[:20]
                    if isinstance(item, dict)
                ],
                truncated=bool(
                    isinstance(archive_data, dict)
                    and archive_data.get("truncated")
                ),
                archive_status=(
                    archive_data.get("archive_status")
                    if isinstance(archive_data, dict)
                    else "unknown"
                ),
            )

        candidate_events = [
            item
            for item in [*surrounding_alerts, *auth_events]
            if isinstance(item, dict)
        ]
        for archive_event in archive_events:
            normalized = archive_event.get("normalized")
            if not isinstance(normalized, dict):
                continue
            parsed_archive_ip, parsed_archive_user = _parse_auth_full_log(
                normalized.get("full_log")
            )
            candidate_events.append({
                **normalized,
                "source_ip": normalized.get("source_ip") or parsed_archive_ip,
                "target_user": (
                    normalized.get("target_user") or parsed_archive_user
                ),
            })
        paired_candidates = {
            (str(item["source_ip"]), str(item["target_user"]))
            for item in candidate_events
            if item.get("source_ip") and item.get("target_user")
        }
        if not source_ip and not target_user and len(paired_candidates) == 1:
            source_ip, target_user = next(iter(paired_candidates))
            source_origin = "correlated_event_pair"
            user_origin = "correlated_event_pair"

        if not source_ip:
            source_events = [
                item
                for item in candidate_events
                if not target_user or item.get("target_user") in {None, target_user}
            ]
            source_candidates = sorted({
                str(item["source_ip"])
                for item in source_events
                if item.get("source_ip")
            })
            if len(source_candidates) == 1:
                source_ip = source_candidates[0]
                source_origin = "correlated_events"
        else:
            source_candidates = [str(source_ip)]

        if not target_user:
            user_events = [
                item
                for item in candidate_events
                if not source_ip or item.get("source_ip") in {None, source_ip}
            ]
            user_candidates = sorted({
                str(item["target_user"])
                for item in user_events
                if item.get("target_user")
            })
            if len(user_candidates) == 1:
                target_user = user_candidates[0]
                user_origin = "correlated_events"
        else:
            user_candidates = [str(target_user)]

        failures = [
            item for item in auth_events if item.get("event_outcome") == "failure"
        ]
        first_failure = min(
            (
                timestamp
                for item in failures
                if (timestamp := _iso_datetime(item.get("timestamp"))) is not None
            ),
            default=None,
        )
        successes_after_failure = [
            item
            for item in auth_events
            if item.get("event_outcome") == "success"
            and first_failure is not None
            and (timestamp := _iso_datetime(item.get("timestamp"))) is not None
            and timestamp > first_failure
        ]
        successful_login_after_failures = (
            bool(successes_after_failure) if failures else None
        )

        known_facts: list[str] = []
        if base_alert:
            _append_unique(
                known_facts,
                f"Alert {alert_id} occurred at {base_alert.get('timestamp')}.",
            )
            _append_unique(
                known_facts,
                (
                    f"Wazuh rule {base_alert.get('rule_id')} on agent "
                    f"{base_alert.get('agent_id') or 'not recorded'}."
                ),
            )
        if source_ip:
            _append_unique(
                known_facts,
                f"Source IP {source_ip} was identified from {source_origin}.",
            )
        elif len(source_candidates) > 1:
            _append_unique(
                known_facts,
                f"Multiple source IP candidates were observed: {source_candidates}.",
            )
        if target_user:
            _append_unique(
                known_facts,
                f"Target user {target_user} was identified from {user_origin}.",
            )
        elif len(user_candidates) > 1:
            _append_unique(
                known_facts,
                f"Multiple user candidates were observed: {user_candidates}.",
            )
        if successful_login_after_failures is not None:
            _append_unique(
                known_facts,
                (
                    "A successful login followed the observed failures."
                    if successful_login_after_failures
                    else (
                        "No successful login was found in the returned "
                        "authentication alerts after the first failure."
                    )
                ),
            )
        if auth_search_truncated:
            _append_unique(
                known_facts,
                "The authentication search was truncated; coverage is incomplete.",
            )

        missing_evidence = [
            field
            for field, value in (
                ("source_ip", source_ip),
                ("target_user", target_user),
                ("full_log", full_log),
            )
            if not value
        ]
        if source_ip and target_user:
            attribution_status = "identified"
            confidence = 0.95 if source_origin == user_origin == "alert" else 0.8
        elif source_ip or target_user:
            attribution_status = "partially_identified"
            confidence = 0.6
        elif full_log or surrounding_alerts or auth_events or archive_events:
            attribution_status = "not_identified"
            confidence = 0.35
        else:
            attribution_status = "insufficient_telemetry"
            confidence = 0.2

        reason = {
            "identified": "The bounded evidence identified both source and user.",
            "partially_identified": (
                "The bounded evidence identified only part of the attribution."
            ),
            "not_identified": (
                "Telemetry was available, but it did not support unique attribution."
            ),
            "insufficient_telemetry": (
                "The bounded raw, surrounding, and authentication sources did not "
                "contain enough telemetry for attribution."
            ),
        }[attribution_status]

        source_address_scope = "reserved_or_unknown"
        if source_ip:
            try:
                parsed_source = ipaddress.ip_address(str(source_ip))
                source_address_scope = (
                    "private"
                    if parsed_source.is_private
                    else (
                        "public"
                        if parsed_source.is_global
                        else "reserved_or_unknown"
                    )
                )
            except ValueError:
                pass

        attribution = AttributionResult(
            alert_id=alert_id,
            status=attribution_status,
            source_ip=str(source_ip) if source_ip else None,
            source_address_scope=source_address_scope,
            target_user=str(target_user) if target_user else None,
            confidence=confidence,
            successful_login_after_failures=successful_login_after_failures,
            successful_login_search_completed=auth_search_completed,
            authentication_search_truncated=auth_search_truncated,
            known_facts=known_facts,
            evidence_checked=evidence_checked,
            missing_evidence=missing_evidence,
            tool_errors=tool_errors,
            steps_completed=len(evidence_checked),
            complete=True,
            reason=reason,
        )
        progress = InvestigationProgress(
            known_facts=known_facts,
            missing_evidence=missing_evidence,
            next_tool=None,
            reason=reason,
            complete=True,
            steps_completed=len(evidence_checked),
            attribution_status=attribution_status,
            evidence_checked=evidence_checked,
            tool_errors=tool_errors,
        )
        payload = {
            "ok": True,
            "data": attribution.model_dump(mode="json"),
            "progress": progress.model_dump(mode="json"),
        }
        return _state_result(
            runtime,
            payload,
            tool_name="investigate_alert_attribution",
            active_alert_id=alert_id,
            active_agent_id=str(agent_id) if agent_id else None,
            current_severity=_severity_for_level(base_alert.get("rule_level")),
            investigation_status=(
                "attribution_complete"
                if attribution_status in {"identified", "partially_identified"}
                else "evidence_exhausted"
            ),
            known_facts=known_facts,
            missing_evidence=missing_evidence,
            investigation_evidence=[
                *runtime.state.get("investigation_evidence", []),
                *evidence_checked,
            ][-50:],
            attempted_tools=[
                *runtime.state.get("attempted_tools", []),
                "investigate_alert_attribution",
            ][-50:],
            tool_errors=[
                *runtime.state.get("tool_errors", []),
                *tool_errors,
            ][-20:],
            investigation_progress=progress.model_dump(mode="json"),
            attribution_result=attribution.model_dump(mode="json"),
        )

    @tool("get_endpoint_context", args_schema=RuntimeAgentSummaryInput)
    def get_endpoint_context(
        agent_id: str,
        runtime: ToolRuntime[SOCChatContext, SOCChatState],
    ) -> Command:
        """Retrieve read-only status and host context for one Wazuh agent."""

        def fetch() -> dict:
            agent = current_gateway().get_agent_summary(agent_id)
            return {
                "found": agent is not None,
                "agent": agent.model_dump(mode="json") if agent else None,
            }

        return _state_result(
            runtime,
            run(fetch),
            tool_name="get_endpoint_context",
            active_agent_id=agent_id,
        )

    @tool("get_endpoint_inventory", args_schema=EndpointInventoryInput)
    def get_endpoint_inventory(
        agent_id: str,
        component: str,
        limit: int = 20,
        text: str | None = None,
    ) -> dict:
        """
        Retrieve one bounded endpoint inventory category.

        Use for observed processes, listening ports, installed packages,
        operating-system details, network interfaces, or hotfixes. The category
        is allowlisted; arbitrary Wazuh paths are never accepted.
        """
        return run(
            lambda: _inventory_for_analysis(
                current_gateway().get_agent_inventory(
                    agent_id=agent_id,
                    component=component,
                    limit=limit,
                    text=text,
                )
            )
        )

    @tool(
        "get_endpoint_security_findings",
        args_schema=DetectionEvidenceInput,
    )
    def get_endpoint_security_findings(
        agent_id: str,
        limit: int = 20,
    ) -> dict:
        """
        Retrieve bounded FIM, SCA, and rootcheck findings for one endpoint.

        Use to validate file changes, configuration gaps, or rootcheck findings
        associated with an observed Wazuh agent.
        """
        return run(
            lambda: current_gateway()
            .get_detection_evidence(agent_id=agent_id, limit=limit)
            .model_dump(mode="json")
        )

    @tool(
        "search_endpoint_vulnerabilities",
        args_schema=VulnerabilitySearchInput,
    )
    def search_endpoint_vulnerabilities(
        severity: str | None = None,
        agent_id: str | None = None,
        limit: int = 20,
    ) -> dict:
        """Search bounded Wazuh vulnerability state by endpoint and severity."""

        def fetch() -> dict:
            vulnerabilities, total = current_gateway().search_vulnerabilities(
                severity=severity,
                agent_id=agent_id,
                limit=limit,
            )
            return {
                "total": total,
                "returned": len(vulnerabilities),
                "truncated": total > len(vulnerabilities),
                "vulnerabilities": vulnerabilities,
            }

        return run(fetch)

    @tool(
        "get_detection_rule_context",
        args_schema=RuleMitreContextInput,
    )
    def get_detection_rule_context(rule_id: str) -> dict:
        """Retrieve one Wazuh rule and its Wazuh-provided MITRE context."""

        def fetch() -> dict:
            context = current_gateway().get_rule_and_mitre_context(rule_id)
            return {
                "found": context is not None,
                "context": context.model_dump(mode="json") if context else None,
            }

        return run(fetch)

    @tool("collect_host_diagnostic", args_schema=SystemDiagnosticInput)
    def collect_host_diagnostic(diagnostic: str) -> dict:
        """
        Run one fixed read-only diagnostic on the TSAGE API host.

        This accepts an allowlisted diagnostic name, never shell text or
        arguments. Use Wazuh endpoint tools for remote agent evidence.
        """
        return run(lambda: current_diagnostics().collect(diagnostic))

    @tool("start_investigation", args_schema=RuntimeStartInvestigationInput)
    def start_investigation(
        alert_id: str,
        reason: str,
        runtime: ToolRuntime[SOCChatContext, SOCChatState],
    ) -> Command:
        """
        Start the formal L1/L2/L3 workflow after an exact Wazuh lookup.

        The tool verifies the supplied alert ID itself and fails closed when the
        alert is absent. It never approves or executes a response action.
        """
        verification = run(
            lambda: (
                alert.model_dump(mode="json")
                if (alert := current_gateway().get_alert_by_id(alert_id))
                else None
            )
        )
        if not verification.get("ok"):
            return _state_result(
                runtime,
                verification,
                tool_name="start_investigation",
            )

        alert = verification.get("data")
        if not isinstance(alert, dict):
            return _state_result(
                runtime,
                {
                    "ok": False,
                    "error": {
                        "code": "ALERT_NOT_FOUND",
                        "message": (
                            "The exact Wazuh alert was not found; no formal "
                            "investigation was started."
                        ),
                        "retryable": False,
                    },
                },
                tool_name="start_investigation",
            )

        try:
            snapshot = current_investigations().start(
                alert_id=alert_id,
                agent_id=(
                    str(alert["agent_id"]) if alert.get("agent_id") else None
                ),
                initiated_by=runtime.context.user_id,
                initiation_reason=reason,
                organization_id=runtime.context.organization_id,
                owner_user_id=runtime.context.user_id,
            )
        except Exception:
            return _state_result(
                runtime,
                {
                    "ok": False,
                    "error": {
                        "code": "INVESTIGATION_START_FAILED",
                        "message": (
                            "The alert was verified, but the formal workflow "
                            "could not be started."
                        ),
                        "retryable": True,
                    },
                },
                tool_name="start_investigation",
                active_alert_id=alert_id,
                active_agent_id=(
                    str(alert["agent_id"]) if alert.get("agent_id") else None
                ),
            )

        payload = {
            "ok": True,
            "data": snapshot,
            "verification": {
                "alert_id": alert_id,
                "agent_id": alert.get("agent_id"),
                "rule_id": alert.get("rule_id"),
            },
        }
        return _state_result(
            runtime,
            payload,
            tool_name="start_investigation",
            active_alert_id=alert_id,
            active_investigation_id=snapshot["investigation_id"],
            active_agent_id=snapshot.get("agent_id"),
            current_severity=snapshot.get("severity"),
            current_investigation_stage=snapshot["current_stage"],
            attempted_tools=[
                *runtime.state.get("attempted_tools", []),
                "get_alert_details",
                "start_investigation",
            ][-50:],
            known_facts=[
                f"Alert {alert_id} was verified before workflow startup.",
                f"Alert rule: {alert.get('rule_id') or 'not recorded'}.",
                f"Affected agent: {alert.get('agent_id') or 'not recorded'}.",
            ],
        )

    @tool(
        "get_investigation_status",
        args_schema=RuntimeInvestigationStatusInput,
    )
    def get_investigation_status(
        investigation_id: str,
        runtime: ToolRuntime[SOCChatContext, SOCChatState],
    ) -> Command:
        """Retrieve current state and validated results for an investigation."""
        try:
            snapshot = current_investigations().snapshot(
                investigation_id,
                organization_id=runtime.context.organization_id,
            )
            payload = {"ok": True, "data": snapshot}
            return _state_result(
                runtime,
                payload,
                tool_name="get_investigation_status",
                active_investigation_id=investigation_id,
                active_alert_id=snapshot["alert_id"],
                active_agent_id=snapshot.get("agent_id"),
                current_severity=snapshot.get("severity"),
                current_investigation_stage=snapshot["current_stage"],
            )
        except InvestigationNotFoundError:
            return _state_result(
                runtime,
                {
                    "ok": False,
                    "error": {
                        "code": "INVESTIGATION_NOT_FOUND",
                        "message": "The investigation was not found.",
                        "retryable": False,
                    },
                },
                tool_name="get_investigation_status",
            )

    @tool("get_open_investigations", args_schema=OpenInvestigationsInput)
    def get_open_investigations(limit: int = 10) -> dict:
        """List recent formal investigations known to this API process."""
        investigations = [
            item
            for item in current_investigations().list_recent(limit=50)
            if item.get("status")
            in {"created", "running", "awaiting_approval", "approved"}
        ][:limit]
        compact = [
            {
                key: item.get(key)
                for key in (
                    "investigation_id",
                    "alert_id",
                    "agent_id",
                    "status",
                    "current_stage",
                    "severity",
                    "confidence",
                )
            }
            for item in investigations
        ]
        return {
            "ok": True,
            "data": {
                "investigations": compact,
                "count": len(compact),
            },
        }

    return [
        get_recent_wazuh_alerts,
        get_high_severity_alerts,
        search_archived_wazuh_logs,
        get_wazuh_log_statistics,
        get_alert_details,
        get_raw_alert_document,
        search_related_alerts,
        search_alerts_by_agent_and_time,
        build_authentication_timeline,
        check_successful_login_after_failures,
        investigate_alert_attribution,
        get_endpoint_context,
        get_endpoint_inventory,
        get_endpoint_security_findings,
        search_endpoint_vulnerabilities,
        get_detection_rule_context,
        collect_host_diagnostic,
        get_open_investigations,
        start_investigation,
        get_investigation_status,
    ]
