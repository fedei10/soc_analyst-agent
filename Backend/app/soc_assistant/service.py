"""Execute typed SOC assistant capabilities over deterministic services."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from langsmith import traceable
from opensearchpy import exceptions as opensearch_exc

from app.config import settings
from app.mape_k.llm import is_rate_limit_error
from app.orchestration.investigation_service import (
    InvestigationNotFoundError,
    InvestigationService,
    get_investigation_service,
)
from app.services.wazuh.tool_results import failure as wazuh_tool_failure
from app.db.session import database_url
from app.db.repositories.alert_memory import get_alert_memory_repository
from app.db.repositories.findings import get_finding_repository
from app.services.wazuh.exceptions import (
    WazuhAPIError,
    WazuhAuthError,
    WazuhPermissionError,
)
from app.services.wazuh.gateway import WazuhGateway
from app.services.wazuh.normalization.serializers import (
    compact_alert_search_result,
    serialize_for_trace,
    serialize_for_agent,
)
from app.services.wazuh.triage.service import run_triage
from app.soc_assistant.catalog import public_catalog
from app.soc_assistant.command_explainer import MAX_COMMAND_LENGTH, explain_command
from app.soc_assistant.question_agent import SOCQuestionAgent
from app.soc_assistant.tool_agent import SOCToolAgent
from app.soc_assistant.router import AssistantIntentRouter
from app.soc_assistant.references import (
    InvestigationReferenceError,
    resolve_investigation_reference,
)
from app.soc_assistant.schemas import (
    AssistantActivity,
    AssistantCommandName,
    AssistantIntent,
    AssistantResponse,
)


INDICATOR_TYPES = {"ip", "domain", "hash", "process", "user", "path", "other"}
RUNNING_ACTIVITY = {
    AssistantCommandName.CHAT: (
        "soc_tool_agent",
        "Preparing an evidence-backed SOC answer",
    ),
    AssistantCommandName.ALERTS: (
        "search_alerts",
        "Searching and correlating bounded Wazuh alerts",
    ),
    AssistantCommandName.SUMMARY: (
        "alert_summary",
        "Loading the Wazuh alert overview",
    ),
    AssistantCommandName.HUNT: (
        "hunt_ioc_telemetry",
        "Searching Wazuh alert and archive telemetry",
    ),
    AssistantCommandName.TRIAGE: (
        "run_triage",
        "Grouping alerts into findings and generating evidence-backed verdicts",
    ),
    AssistantCommandName.INVESTIGATE: (
        "start_investigation",
        "Starting the controlled MAPE-K workflow",
    ),
    AssistantCommandName.STATUS: (
        "get_investigation",
        "Loading the durable investigation state",
    ),
    AssistantCommandName.HEALTH: (
        "wazuh_health",
        "Checking Wazuh manager and indexer connectivity",
    ),
    AssistantCommandName.EXPLAIN: (
        "explain_command",
        "Analyzing the command line as untrusted data",
    ),
    AssistantCommandName.HELP: (
        None,
        "Loading the SOC capability catalog",
    ),
}
WAZUH_BACKED_COMMANDS = {
    AssistantCommandName.CHAT,
    AssistantCommandName.ALERTS,
    AssistantCommandName.SUMMARY,
    AssistantCommandName.HUNT,
    AssistantCommandName.TRIAGE,
    AssistantCommandName.INVESTIGATE,
    AssistantCommandName.HEALTH,
}
WAZUH_RETRY_HINTS = {
    "WAZUH_UNAVAILABLE": (
        "Wazuh is unreachable right now. Check that the Wazuh indexer/API tunnel "
        "is running, then retry `/health` or your original request."
    ),
    "WAZUH_TIMEOUT": (
        "Wazuh did not answer before the tool timeout. Check service load and "
        "retry with a smaller time window."
    ),
    "WAZUH_AUTH_FAILED": (
        "Wazuh rejected the configured service credentials. Check the backend "
        "Wazuh environment variables."
    ),
    "WAZUH_FORBIDDEN": (
        "Wazuh denied the configured service account. Check the account's API "
        "permissions."
    ),
}


def _is_wazuh_runtime_error(error: Exception) -> bool:
    return isinstance(
        error,
        (
            httpx.TimeoutException,
            httpx.TransportError,
            opensearch_exc.ConnectionTimeout,
            opensearch_exc.ConnectionError,
            WazuhAPIError,
            WazuhAuthError,
            WazuhPermissionError,
        ),
    )


def _trace_inputs(inputs: dict[str, Any]) -> dict[str, Any]:
    return serialize_for_trace(
        {
            key: value
            for key, value in inputs.items()
            if key not in {"self", "fn"}
        }
    )


def _trace_outputs(outputs: Any) -> Any:
    if isinstance(outputs, AssistantResponse):
        return {
            "conversation_id": outputs.conversation_id,
            "selected_command": outputs.selected_command,
            "tools_used": outputs.tools_used,
            "activity_statuses": [
                {
                    "tool": activity.tool,
                    "label": activity.label,
                    "status": activity.status,
                }
                for activity in outputs.activities
            ],
            "active_investigation_id": outputs.active_investigation_id,
            "response": serialize_for_trace(outputs.response),
        }
    if isinstance(outputs, tuple) and len(outputs) == 4:
        assistant_message, payload, tools, active = outputs
        return serialize_for_trace(
            {
                "assistant_message": assistant_message,
                "payload": payload,
                "tools_used": tools,
                "active_context": active,
            }
        )
    return serialize_for_trace(outputs)


def _langsmith_metadata() -> dict[str, Any]:
    return {
        "service": settings.SERVICE_NAME,
        "environment": settings.ENVIRONMENT,
        "revision_id": settings.REVISION_ID,
        "llm_provider": settings.LLM_PROVIDER,
        "llm_model": settings.LLM_MODEL,
    }


def _bounded_int(
    value: Any,
    *,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    if not minimum <= parsed <= maximum:
        raise ValueError(f"Value must be between {minimum} and {maximum}.")
    return parsed


def _stage_phrase(status: str, current_stage: str) -> str:
    """`status="escalated"` means the graph already reached its terminal
    state (pending_nodes is empty) waiting on a human, not "still working" -
    say so plainly instead of just naming the stage it stopped at."""
    if status == "escalated":
        return f"escalated for analyst review (stopped at stage: {current_stage})"
    return f"{status} at stage {current_stage}"


def _duration_hours(value: Any, *, default: int = 24) -> int:
    if value in (None, ""):
        return default
    text = str(value).strip().lower()
    multipliers = {"m": 1 / 60, "h": 1, "d": 24}
    try:
        amount = int(text[:-1])
        hours = amount * multipliers[text[-1]]
    except (KeyError, TypeError, ValueError):
        raise ValueError(
            "--since must use a duration such as 15m, 6h, or 2d."
        )
    return max(1, min(168, int(hours) + int(hours % 1 > 0)))


def _as_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


class SOCAssistant:
    def __init__(
        self,
        *,
        gateway: WazuhGateway | None = None,
        investigations: InvestigationService | None = None,
        router: AssistantIntentRouter | None = None,
        question_agent: SOCQuestionAgent | None = None,
        tool_agent: "SOCToolAgent | None" = None,
    ) -> None:
        self.gateway = gateway or WazuhGateway()
        self.investigations = investigations or get_investigation_service()
        self.router = router or AssistantIntentRouter()
        self.question_agent = question_agent or SOCQuestionAgent()
        self.tool_agent = tool_agent or SOCToolAgent(
            gateway=self.gateway, investigations=self.investigations
        )

    def _question_context(
        self,
        *,
        recent_context: dict[str, str],
        organization_id: str,
    ) -> dict[str, Any]:
        context: dict[str, Any] = {
            "references": dict(recent_context),
        }
        alert_id = recent_context.get("wazuh_alert")
        if alert_id:
            try:
                alert = get_alert_memory_repository().get_alert_by_document_id(
                    alert_id
                )
            except Exception:
                alert = None
            if alert:
                context["alert"] = {
                    key: alert.get(key)
                    for key in (
                        "wazuh_document_id",
                        "event_timestamp",
                        "agent_id",
                        "agent_name",
                        "rule_id",
                        "rule_level",
                        "source_ip",
                        "target_user",
                        "event_type",
                        "correlation_status",
                    )
                }

        finding_id = recent_context.get("finding")
        if finding_id:
            try:
                finding = get_finding_repository().get(
                    finding_id,
                    organization_id=settings.WAZUH_INGESTION_ORGANIZATION_ID,
                )
            except Exception:
                finding = None
            if finding:
                context["finding"] = {
                    "finding_id": finding["finding_id"],
                    "status": finding.get("status"),
                    "version": finding.get("version"),
                    "finding": finding.get("finding"),
                    "verdict": finding.get("verdict"),
                }

        investigation_id = recent_context.get("investigation")
        if investigation_id:
            try:
                snapshot = self.investigations.snapshot(
                    investigation_id,
                    organization_id=organization_id,
                )
            except Exception:
                snapshot = None
            if snapshot:
                context["investigation"] = {
                    key: snapshot.get(key)
                    for key in (
                        "investigation_id",
                        "alert_id",
                        "finding_id",
                        "agent_id",
                        "status",
                        "current_stage",
                        "severity",
                        "confidence",
                        "diagnosis",
                        "remediation_plan",
                        "advisory_plan",
                        "verification",
                        "failure_code",
                        "failure_reason",
                        "pending_nodes",
                    )
                }
        return context

    @staticmethod
    def _activity(
        index: int,
        label: str,
        *,
        tool: str | None = None,
        status: str = "completed",
    ) -> AssistantActivity:
        return AssistantActivity(
            id=f"activity-{index}",
            tool=tool,
            label=label,
            status=status,
        )

    def route(
        self,
        message: str,
    ) -> tuple[AssistantIntent, dict[str, int]]:
        return self.router.route(message)

    @traceable(
        run_type="chain",
        name="soc_assistant.route",
        process_inputs=_trace_inputs,
        process_outputs=_trace_outputs,
        metadata=_langsmith_metadata(),
        tags=["tsage", "soc-assistant", "router"],
    )
    def _trace_route(
        self,
        *,
        message: str,
    ) -> tuple[AssistantIntent, dict[str, int]]:
        return self.route(message)

    @staticmethod
    def running_activity(command: AssistantCommandName) -> AssistantActivity:
        tool, label = RUNNING_ACTIVITY[command]
        return AssistantActivity(
            id=f"activity-running-{command.value}",
            tool=tool,
            label=label,
            status="running",
        )

    @staticmethod
    def _wazuh_failure_response(
        *,
        command: AssistantCommandName,
        error: Exception,
    ) -> tuple[str, dict[str, Any], list[str], dict[str, Any]]:
        tool, _ = RUNNING_ACTIVITY[command]
        failed = wazuh_tool_failure(error)["error"]
        code = str(failed.get("code") or "WAZUH_TOOL_ERROR")
        message = WAZUH_RETRY_HINTS.get(
            code,
            "The selected Wazuh-backed capability could not complete.",
        )
        payload = {
            "status": "unavailable",
            "error": failed,
            "next_steps": [
                "Run `/health` to see which Wazuh service is failing.",
                "Confirm the Wazuh indexer is reachable on the configured host and port.",
                "Retry with a smaller window, for example `/alerts --hours 1 --limit 10`.",
            ],
        }
        if command == AssistantCommandName.CHAT:
            payload.update(
                {
                    "display_mode": "conversation",
                    "answer_type": "live_data_unavailable",
                    "grounded": False,
                }
            )
        return message, payload, [tool] if tool else [], {}

    @staticmethod
    def _persist(
        *,
        conversation_id: str,
        organization_id: str,
        user_id: str,
        user_message: str,
        response: AssistantResponse,
    ) -> None:
        if not database_url():
            return
        try:
            from app.db.repositories.conversations import (
                get_conversation_repository,
            )

            repository = get_conversation_repository()
            conversation = repository.get_conversation(
                conversation_id,
                organization_id=organization_id,
            )
            if conversation is None:
                repository.create_conversation(
                    conversation_id=conversation_id,
                    organization_id=organization_id,
                    owner_user_id=user_id,
                    title=user_message[:120],
                    metadata={"surface": "soc_assistant"},
                )
            repository.append_message(
                conversation_id=conversation_id,
                organization_id=organization_id,
                role="user",
                content=user_message,
                sender_user_id=user_id,
            )
            assistant_record = repository.append_message(
                conversation_id=conversation_id,
                organization_id=organization_id,
                role="assistant",
                content=response.assistant_message,
                metadata={
                    "command": response.selected_command,
                    "tools_used": response.tools_used,
                    "active_investigation_id": response.active_investigation_id,
                },
            )
            references: list[tuple[str, str]] = []
            if response.active_alert_id:
                references.append(("wazuh_alert", response.active_alert_id))
            if response.active_investigation_id:
                references.append(
                    ("investigation", response.active_investigation_id)
                )
            for finding in response.response.get("findings", []):
                if isinstance(finding, dict) and finding.get("finding_id"):
                    references.append(("finding", str(finding["finding_id"])))
                if (
                    isinstance(finding, dict)
                    and finding.get("representative_alert_id")
                ):
                    references.append(
                        (
                            "wazuh_alert",
                            str(finding["representative_alert_id"]),
                        )
                    )
            memory = get_alert_memory_repository()
            for reference_type, reference_value in dict.fromkeys(references):
                memory.add_conversation_reference(
                    conversation_id=conversation_id,
                    message_id=assistant_record["message_id"],
                    organization_id=organization_id,
                    reference_type=reference_type,
                    reference_value=reference_value,
                )
        except Exception:
            # Conversation persistence must not hide a successful SOC operation.
            return

    def _execute(
        self,
        command: AssistantCommandName,
        arguments: dict[str, Any],
        *,
        organization_id: str,
        user_id: str,
        conversation_id: str | None = None,
        recent_context: dict[str, str] | None = None,
        conversation_history: list[dict[str, str]] | None = None,
    ) -> tuple[str, dict[str, Any], list[str], dict[str, Any]]:
        if command == AssistantCommandName.CHAT:
            question = str(arguments.get("question") or "").strip()
            if question.lower() in {
                "hi",
                "hello",
                "hey",
                "yo",
                "good morning",
                "good afternoon",
                "good evening",
            }:
                return (
                    (
                        "Hi. Ask me about an alert, finding, investigation, "
                        "Wazuh, or defensive remediation."
                    ),
                    {
                        "display_mode": "conversation",
                        "answer_type": "greeting",
                    },
                    [],
                    {},
                )
            try:
                agent_answer, tool_calls, active_alert_id = self.tool_agent.answer(
                    question=question,
                    history=conversation_history or [],
                    organization_id=organization_id,
                    created_by=user_id,
                    conversation_id=conversation_id,
                )
                return (
                    agent_answer,
                    {
                        "display_mode": "conversation",
                        "answer_type": "soc_tool_agent",
                        "tools_called": tool_calls,
                    },
                    ["soc_tool_agent", *tool_calls],
                    (
                        {"active_alert_id": active_alert_id}
                        if active_alert_id
                        else {}
                    ),
                )
            except Exception as exc:
                if is_rate_limit_error(exc):
                    # Falling through to question_agent would just spend
                    # another request against the same exhausted limit.
                    return (
                        (
                            "The AI provider's rate limit was reached. Please "
                            "wait a moment and try again."
                        ),
                        {
                            "display_mode": "conversation",
                            "answer_type": "rate_limited",
                        },
                        [],
                        {},
                    )
                if _is_wazuh_runtime_error(exc):
                    # A live-tool failure must remain visible. Falling back
                    # to the tool-less question agent would turn an outage
                    # into a fluent but ungrounded SOC answer.
                    raise
                # Fall through to the context-primed question agent.
                pass
            try:
                answer, answer_usage = self.question_agent.answer(
                    question=question,
                    context=self._question_context(
                        recent_context=recent_context or {},
                        organization_id=organization_id,
                    ),
                    history=conversation_history or [],
                )
            except Exception as exc:
                # "Unavailable" sends the analyst hunting for an outage; a
                # rate limit only means "try again shortly". Same handling as
                # the tool-agent path above, so both say which one it was.
                rate_limited = is_rate_limit_error(exc)
                return (
                    (
                        "The AI provider's rate limit was reached. Please "
                        "wait a moment and try again."
                        if rate_limited
                        else "I could not generate the SOC explanation "
                        "because the question-answer model is unavailable. "
                        "Deterministic commands such as `/alerts`, "
                        "`/status`, and `/health` are still available."
                    ),
                    {
                        "display_mode": "conversation",
                        "answer_type": (
                            "rate_limited"
                            if rate_limited
                            else "model_unavailable"
                        ),
                    },
                    [],
                    {},
                )
            return (
                answer.answer,
                {
                    "display_mode": "conversation",
                    "answer_type": "soc_question",
                    "confidence": answer.confidence,
                    "references": answer.references,
                    "limitations": answer.limitations,
                    "model_usage": answer_usage,
                },
                ["soc_question_agent"],
                {},
            )

        if command == AssistantCommandName.HELP:
            catalog = public_catalog()
            return (
                "Choose a capability below or type `/` to search commands.",
                {"commands": catalog},
                [],
                {},
            )

        if command == AssistantCommandName.EXPLAIN:
            command_line = str(arguments.get("command") or "").strip()
            if not command_line:
                return (
                    "Provide a command line, for example `/explain whoami`.",
                    {"required": ["command"]},
                    [],
                    {},
                )
            explanation, explanation_usage = explain_command(
                command_line[:MAX_COMMAND_LENGTH]
            )
            payload = explanation.model_dump(mode="json")
            payload.update(
                {
                    "display_mode": "command_explanation",
                    "model_usage": explanation_usage,
                }
            )
            return (
                explanation.plain_english,
                payload,
                ["explain_command"],
                {},
            )

        if command == AssistantCommandName.ALERTS:
            checked_at = datetime.now(UTC)
            memory = get_alert_memory_repository()
            previous_check = memory.get_user_cursor(user_id)
            severity_levels = {
                "informational": 0,
                "low": 4,
                "medium": 7,
                "high": 10,
                "critical": 13,
            }
            severity = str(arguments.get("severity") or "").lower()
            if severity and severity not in severity_levels:
                raise ValueError("Unsupported severity filter.")
            tool_inputs = {
                "min_level": (
                    severity_levels[severity]
                    if severity
                    else _bounded_int(
                        arguments.get("min_level"),
                        default=0,
                        minimum=0,
                        maximum=16,
                    )
                ),
                "hours": (
                    _duration_hours(arguments.get("since"))
                    if arguments.get("since")
                    else _bounded_int(
                        arguments.get("hours"),
                        default=24,
                        minimum=1,
                        maximum=168,
                    )
                ),
                "limit": _bounded_int(
                    arguments.get("limit"), default=20, minimum=1, maximum=50
                ),
                "agent_id": arguments.get("agent_id"),
                "text": arguments.get("text"),
            }
            if getattr(memory, "durable", False):
                explicit_window = bool(
                    arguments.get("since") or "hours" in arguments
                )
                window_hours = (
                    _duration_hours(arguments.get("since"))
                    if arguments.get("since")
                    else _bounded_int(
                        arguments.get("hours"),
                        default=24,
                        minimum=1,
                        maximum=168,
                    )
                )
                effective_since = (
                    checked_at - timedelta(hours=window_hours)
                    if explicit_window or previous_check is None
                    else previous_check
                )
                finding_scope = settings.WAZUH_INGESTION_ORGANIZATION_ID
                records = get_finding_repository().list(
                    organization_id=finding_scope,
                    limit=tool_inputs["limit"],
                    severity=severity or None,
                    status=(
                        "open" if arguments.get("open_only") else None
                    ),
                )
                if tool_inputs["agent_id"]:
                    finding_ids = memory.finding_ids_for_agent(
                        tool_inputs["agent_id"]
                    )
                    records = [
                        record
                        for record in records
                        if record["finding_id"] in finding_ids
                    ]
                text_filter = str(tool_inputs["text"] or "").strip().lower()
                if text_filter:
                    records = [
                        record
                        for record in records
                        if text_filter
                        in " ".join(
                            (
                                str(record["finding"].get("title") or ""),
                                str(record["finding"].get("summary") or ""),
                                str(record.get("event_type") or ""),
                            )
                        ).lower()
                    ]

                new_records = [
                    record
                    for record in records
                    if _as_datetime(record["created_at"]) > effective_since
                ]
                updated_records = [
                    record
                    for record in records
                    if _as_datetime(record["created_at"]) <= effective_since
                    and _as_datetime(record["updated_at"]) > effective_since
                ]
                changed_ids = {
                    record["finding_id"]
                    for record in [*new_records, *updated_records]
                }
                if arguments.get("new_only"):
                    visible = new_records
                elif arguments.get("all_results") or arguments.get(
                    "open_only"
                ):
                    visible = records
                else:
                    visible = [
                        record
                        for record in records
                        if record["finding_id"] in changed_ids
                    ]

                findings = []
                for record in visible:
                    finding = dict(record["finding"])
                    finding.update(
                        {
                            "finding_id": record["finding_id"],
                            "status": record["status"],
                            "version": record["version"],
                            "verdict": record["verdict"].get("verdict"),
                            "verdict_confidence": record[
                                "verdict"
                            ].get("confidence"),
                        }
                    )
                    findings.append(finding)
                new_alerts = memory.count_alerts_since(
                    effective_since,
                    agent_id=tool_inputs["agent_id"],
                    min_level=tool_inputs["min_level"],
                )
                payload = {
                    "raw_alert_count": new_alerts,
                    "recent_alerts": new_alerts,
                    "finding_count": len(findings),
                    "findings": findings,
                    "new_alerts": (
                        new_alerts if previous_check is not None else None
                    ),
                    "new_findings": (
                        len(new_records) if previous_check is not None else None
                    ),
                    "updated_findings": (
                        len(updated_records)
                        if previous_check is not None
                        else None
                    ),
                    "unchanged_findings": (
                        len(records) - len(changed_ids)
                    ),
                    "since": (
                        effective_since.isoformat()
                        if explicit_window or previous_check
                        else None
                    ),
                    "checked_at": checked_at.isoformat(),
                    "new_since_last_check": (
                        previous_check.isoformat()
                        if previous_check
                        else None
                    ),
                    "baseline_established": previous_check is None,
                    "cursor_status": "durable",
                    "mode": (
                        "new"
                        if arguments.get("new_only")
                        else "open"
                        if arguments.get("open_only")
                        else "all"
                        if arguments.get("all_results")
                        else "updated_since_last_check"
                    ),
                    "source": "postgresql",
                }
                memory.advance_user_cursor(
                    user_id,
                    checked_at,
                    finding_version=max(
                        (
                            int(record.get("version") or 0)
                            for record in records
                        ),
                        default=None,
                    ),
                )
                if previous_check is None:
                    summary = (
                        f"Found {new_alerts} recent alert"
                        f"{'' if new_alerts == 1 else 's'} and "
                        f"{len(records)} current finding"
                        f"{'' if len(records) == 1 else 's'}. "
                        "This check established your durable baseline."
                    )
                else:
                    summary = (
                        f"Found {new_alerts} new alert"
                        f"{'' if new_alerts == 1 else 's'}, "
                        f"{len(new_records)} new finding"
                        f"{'' if len(new_records) == 1 else 's'}, and "
                        f"{len(updated_records)} updated finding"
                        f"{'' if len(updated_records) == 1 else 's'}."
                    )
                return (
                    summary,
                    payload,
                    ["query_alert_memory"],
                    {},
                )
            result = self._run_tool(
                tool_name="search_alerts",
                inputs=tool_inputs,
                fn=lambda: self.gateway.search_alerts(**tool_inputs),
            )
            compact = compact_alert_search_result(result)
            compact.update(
                {
                    "recent_alerts": result.returned,
                    "new_alerts": None,
                    "new_findings": None,
                    "updated_findings": None,
                    "since": None,
                    "checked_at": checked_at.isoformat(),
                    "new_since_last_check": None,
                    "baseline_established": False,
                    "cursor_status": "unavailable",
                }
            )
            compact["mode"] = (
                "open"
                if arguments.get("open_only")
                else "all"
                if arguments.get("all_results")
                else "recent"
            )
            return (
                (
                    f"Found {result.returned} recent alert"
                    f"{'' if result.returned == 1 else 's'} in the selected window. "
                    "PostgreSQL alert memory is unavailable, so this result "
                    "cannot prove what is new since your previous check."
                ),
                compact,
                ["search_alerts"],
                {},
            )

        if command == AssistantCommandName.TRIAGE:
            tool_inputs = {
                "hours": _bounded_int(
                    arguments.get("hours"), default=24, minimum=1, maximum=168
                ),
                "min_level": _bounded_int(
                    arguments.get("min_level"), default=0, minimum=0, maximum=16
                ),
                "limit": _bounded_int(
                    arguments.get("limit"), default=20, minimum=1, maximum=200
                ),
                "organization_id": settings.WAZUH_INGESTION_ORGANIZATION_ID,
            }
            triaged = self._run_tool(
                tool_name="run_triage",
                inputs=tool_inputs,
                fn=lambda: run_triage(gateway=self.gateway, **tool_inputs),
            )
            payload = {
                "finding_count": len(triaged),
                "findings": [
                    {
                        "finding_id": item.finding.finding_id,
                        "title": item.finding.title,
                        "severity": item.finding.severity,
                        "verdict": item.verdict.verdict,
                        "verdict_confidence": item.verdict.confidence,
                        "escalation_recommended": item.verdict.escalation_recommended,
                        "summary": item.verdict.summary,
                    }
                    for item in triaged
                ],
            }
            return (
                f"Triaged {len(triaged)} finding(s) from recent Wazuh alerts.",
                payload,
                ["run_triage"],
                {},
            )

        if command == AssistantCommandName.SUMMARY:
            hours = _bounded_int(
                arguments.get("hours"),
                default=24,
                minimum=1,
                maximum=168,
            )
            summary = serialize_for_agent(
                self._run_tool(
                    tool_name="alert_summary",
                    inputs={"hours": hours},
                    fn=lambda: self.gateway.alert_summary(hours=hours),
                )
            )
            message = f"Loaded the Wazuh alert overview for the last {hours} hours."
            if arguments.get("vague_fallback"):
                message += (
                    " Your message didn't name a specific alert, agent, IP, rule, "
                    "or time range, so here's the broad picture instead of a deep "
                    "dive — tell me which alert or asset to look into next."
                )
            return (
                message,
                {"hours": hours, "summary": summary},
                ["alert_summary"],
                {},
            )

        if command == AssistantCommandName.HUNT:
            indicator = str(arguments.get("indicator") or "").strip()
            if not indicator:
                return (
                    "Provide one indicator, for example `/hunt 192.0.2.10 --type ip`.",
                    {"required": ["indicator"]},
                    [],
                    {},
                )
            indicator_type = str(arguments.get("indicator_type") or "other")
            if indicator_type not in INDICATOR_TYPES:
                raise ValueError(f"Unsupported indicator type: {indicator_type}")
            tool_inputs = {
                "indicator": indicator,
                "indicator_type": indicator_type,
                "hours": _bounded_int(
                    arguments.get("hours"), default=24, minimum=1, maximum=168
                ),
                "limit": _bounded_int(
                    arguments.get("limit"), default=10, minimum=1, maximum=20
                ),
                "agent_id": arguments.get("agent_id"),
            }
            hunt = self._run_tool(
                tool_name="hunt_ioc_telemetry",
                inputs=tool_inputs,
                fn=lambda: self.gateway.hunt_ioc_telemetry(**tool_inputs),
            )
            payload = serialize_for_agent(hunt)
            alert_count = (
                hunt.alerts.total if hunt.alerts is not None else 0
            )
            archive_count = (
                hunt.archived_logs.total
                if hunt.archived_logs is not None
                else 0
            )
            return (
                (
                    f"Threat hunt completed for `{indicator}`: {alert_count} alert "
                    f"matches and {archive_count} archived-log matches."
                ),
                payload,
                ["hunt_ioc_telemetry"],
                {},
            )

        if command == AssistantCommandName.INVESTIGATE:
            alert_id = str(arguments.get("alert_id") or "").strip()
            if not alert_id:
                return (
                    "Run `/alerts`, then pass a returned alert document ID to `/investigate`.",
                    {"required": ["alert_id"]},
                    [],
                    {},
                )
            try:
                resolved = resolve_investigation_reference(
                    alert_id,
                    agent_id=arguments.get("agent_id"),
                    organization_id=organization_id,
                    gateway=self.gateway,
                    investigations=self.investigations,
                    suggested_alert_id=(recent_context or {}).get(
                        "wazuh_alert"
                    ),
                )
            except InvestigationReferenceError as exc:
                return (
                    str(exc),
                    exc.payload(),
                    [],
                    {},
                )
            if resolved.existing_investigation is not None:
                snapshot = resolved.existing_investigation
                return (
                    (
                        f"Investigation {snapshot['investigation_id']} already "
                        f"tracks this reference. Current stage: "
                        f"{snapshot['current_stage']}."
                    ),
                    {
                        "investigation_id": snapshot["investigation_id"],
                        "status": snapshot["status"],
                        "current_stage": snapshot["current_stage"],
                        "existing": True,
                    },
                    ["get_investigation"],
                    {
                        "active_investigation_id": snapshot[
                            "investigation_id"
                        ],
                        "active_alert_id": resolved.alert_id,
                        "active_agent_id": snapshot.get("agent_id"),
                        "investigation": snapshot,
                    },
                )
            tool_inputs = {
                "alert_id": resolved.alert_id,
                "finding_id": resolved.finding_id,
                "agent_id": resolved.agent_id,
                "initiated_by": user_id,
                "initiation_reason": "Started from the SOC assistant.",
                "organization_id": organization_id,
                "owner_user_id": user_id,
            }
            snapshot = self._run_tool(
                tool_name="start_investigation",
                inputs=tool_inputs,
                fn=lambda: getattr(
                    self.investigations,
                    "enqueue",
                    self.investigations.start,
                )(**tool_inputs),
            )
            return (
                (
                    f"Started MAPE-K investigation {snapshot['investigation_id']}, "
                    f"{_stage_phrase(snapshot['status'], snapshot['current_stage'])}."
                ),
                {
                    "investigation_id": snapshot["investigation_id"],
                    "status": snapshot["status"],
                    "current_stage": snapshot["current_stage"],
                    "diagnosis": snapshot.get("diagnosis"),
                    "advisory_plan": snapshot.get("advisory_plan"),
                    "pending_nodes": snapshot.get("pending_nodes", []),
                },
                ["start_investigation"],
                {
                    "active_investigation_id": snapshot["investigation_id"],
                    "active_alert_id": resolved.alert_id,
                    "active_agent_id": snapshot.get("agent_id"),
                    "investigation": snapshot,
                },
            )

        if command == AssistantCommandName.STATUS:
            investigation_id = str(
                arguments.get("investigation_id") or ""
            ).strip()
            if not investigation_id:
                alert_reference = (recent_context or {}).get("wazuh_alert")
                if alert_reference:
                    active = self.investigations.active_for_alert(
                        alert_reference,
                        organization_id=organization_id,
                    )
                    if active is not None:
                        investigation_id = str(
                            active["investigation_id"]
                        )
            if not investigation_id:
                return (
                    "Provide an investigation ID, for example `/status INV-ABC123`.",
                    {"required": ["investigation_id"]},
                    [],
                    {},
                )
            try:
                snapshot = self._run_tool(
                    tool_name="get_investigation",
                    inputs={
                        "investigation_id": investigation_id,
                        "organization_id": organization_id,
                    },
                    fn=lambda: self.investigations.snapshot(
                        investigation_id,
                        organization_id=organization_id,
                    ),
                )
            except InvestigationNotFoundError as exc:
                raise LookupError(
                    f"Investigation {investigation_id} was not found."
                ) from exc
            return (
                (
                    f"Investigation {investigation_id} is "
                    f"{_stage_phrase(snapshot['status'], snapshot['current_stage'])}."
                ),
                {
                    "investigation_id": investigation_id,
                    "status": snapshot["status"],
                    "current_stage": snapshot["current_stage"],
                    "pending_nodes": snapshot.get("pending_nodes", []),
                    "diagnosis": snapshot.get("diagnosis"),
                    "advisory_plan": snapshot.get("advisory_plan"),
                    "verification": snapshot.get("verification"),
                },
                ["get_investigation"],
                {
                    "active_investigation_id": investigation_id,
                    "active_alert_id": snapshot.get("alert_id"),
                    "active_agent_id": snapshot.get("agent_id"),
                    "investigation": snapshot,
                },
            )

        if command == AssistantCommandName.HEALTH:
            checks: dict[str, dict[str, Any]] = {}
            for name, tool_name, operation in (
                ("indexer", "indexer_health", self.gateway.indexer_health),
                ("manager", "validate_server", self.gateway.validate_server),
            ):
                try:
                    self._run_tool(
                        tool_name=tool_name,
                        inputs={},
                        fn=operation,
                    )
                    checks[name] = {"status": "healthy"}
                except Exception as exc:
                    checks[name] = {
                        "status": "unhealthy",
                        "error": type(exc).__name__,
                    }
            healthy = all(item["status"] == "healthy" for item in checks.values())
            return (
                (
                    "Wazuh manager and indexer are reachable."
                    if healthy
                    else "One or more Wazuh services are unavailable."
                ),
                {"status": "healthy" if healthy else "unhealthy", "checks": checks},
                ["indexer_health", "validate_server"],
                {},
            )

        raise ValueError(f"Unsupported assistant command: {command}")

    @traceable(
        run_type="tool",
        name="soc_assistant.tool_call",
        process_inputs=_trace_inputs,
        process_outputs=_trace_outputs,
        metadata=_langsmith_metadata(),
        tags=["tsage", "soc-assistant", "tool"],
    )
    def _run_tool(
        self,
        *,
        tool_name: str,
        inputs: dict[str, Any],
        fn: Callable[[], Any],
    ) -> Any:
        return fn()

    @traceable(
        run_type="chain",
        name="soc_assistant.execute",
        process_inputs=_trace_inputs,
        process_outputs=_trace_outputs,
        metadata=_langsmith_metadata(),
        tags=["tsage", "soc-assistant", "execute"],
    )
    def _execute_traced(
        self,
        command: AssistantCommandName,
        arguments: dict[str, Any],
        *,
        organization_id: str,
        user_id: str,
        conversation_id: str | None = None,
        recent_context: dict[str, str] | None = None,
        conversation_history: list[dict[str, str]] | None = None,
    ) -> tuple[str, dict[str, Any], list[str], dict[str, Any]]:
        return self._execute(
            command,
            arguments,
            organization_id=organization_id,
            user_id=user_id,
            conversation_id=conversation_id,
            recent_context=recent_context,
            conversation_history=conversation_history,
        )

    @traceable(
        run_type="chain",
        name="soc_assistant.respond",
        process_inputs=_trace_inputs,
        process_outputs=_trace_outputs,
        metadata=_langsmith_metadata(),
        tags=["tsage", "soc-assistant"],
    )
    def respond(
        self,
        *,
        message: str,
        conversation_id: str | None,
        organization_id: str,
        user_id: str,
        routed: tuple[AssistantIntent, dict[str, int]] | None = None,
    ) -> AssistantResponse:
        active_conversation_id = conversation_id or uuid.uuid4().hex
        recent_context: dict[str, str] = {}
        conversation_history: list[dict[str, str]] = []
        if database_url():
            try:
                recent_context = (
                    get_alert_memory_repository()
                    .recent_conversation_references(
                        conversation_id=active_conversation_id,
                        organization_id=organization_id,
                    )
                )
            except Exception:
                recent_context = {}
            try:
                from app.db.repositories.conversations import (
                    get_conversation_repository,
                )

                conversation_repository = get_conversation_repository()
                if conversation_repository.get_conversation(
                    active_conversation_id,
                    organization_id=organization_id,
                ):
                    conversation_history = [
                        {
                            "role": str(item["role"]),
                            "content": str(item["content"]),
                        }
                        for item in conversation_repository.list_messages(
                            active_conversation_id,
                            organization_id=organization_id,
                            limit=200,
                        )[-8:]
                        if item["role"] in {"user", "assistant"}
                    ]
            except Exception:
                conversation_history = []
        intent, usage = routed or self._trace_route(message=message)
        if intent.command == AssistantCommandName.CHAT:
            intent.arguments["question"] = (
                intent.arguments.get("question") or message
            )
        if intent.command == AssistantCommandName.INVESTIGATE and not intent.arguments.get(
            "alert_id"
        ):
            if "finding" in message.lower() and recent_context.get("finding"):
                intent.arguments["alert_id"] = recent_context["finding"]
            elif recent_context.get("wazuh_alert"):
                intent.arguments["alert_id"] = recent_context["wazuh_alert"]
        if intent.command == AssistantCommandName.STATUS and not intent.arguments.get(
            "investigation_id"
        ):
            if recent_context.get("investigation"):
                intent.arguments["investigation_id"] = recent_context[
                    "investigation"
                ]
        activities = [
            self._activity(
                1,
                f"Selected {intent.command.value} capability",
                tool="intent_router",
            )
        ]
        try:
            assistant_message, payload, tools, active = self._execute_traced(
                intent.command,
                intent.arguments,
                organization_id=organization_id,
                user_id=user_id,
                conversation_id=active_conversation_id,
                recent_context=recent_context,
                conversation_history=conversation_history,
            )
            for tool_name in payload.get("tools_called") or []:
                activities.append(
                    self._activity(
                        len(activities) + 1,
                        f"Queried {tool_name}",
                        tool=tool_name,
                    )
                )
            activities.append(
                self._activity(
                    len(activities) + 1,
                    f"Completed {intent.command.value}",
                    tool=tools[-1] if tools else None,
                )
            )
        except Exception as exc:
            activities.append(
                self._activity(
                    2,
                    f"{intent.command.value} failed",
                    tool=RUNNING_ACTIVITY[intent.command][0],
                    status="failed",
                )
            )
            if intent.command not in WAZUH_BACKED_COMMANDS or not _is_wazuh_runtime_error(exc):
                raise
            assistant_message, payload, tools, active = self._wazuh_failure_response(
                command=intent.command,
                error=exc,
            )

        response = AssistantResponse(
            conversation_id=active_conversation_id,
            assistant_message=assistant_message,
            response={
                **payload,
                "intent": {
                    "command": intent.command,
                    "source": intent.source,
                    "confidence": intent.confidence,
                },
                "token_usage": usage,
                "recent_context": {
                    "last_alert_id": recent_context.get("wazuh_alert"),
                    "last_finding_id": recent_context.get("finding"),
                    "last_investigation_id": recent_context.get(
                        "investigation"
                    ),
                },
            },
            tools_used=tools,
            activities=activities,
            selected_command=intent.command,
            **active,
        )
        self._persist(
            conversation_id=active_conversation_id,
            organization_id=organization_id,
            user_id=user_id,
            user_message=message,
            response=response,
        )
        return response
