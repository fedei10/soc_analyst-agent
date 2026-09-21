"""Execute typed SOC assistant capabilities over deterministic services."""

from __future__ import annotations

import logging
import re
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from langsmith import traceable
from opensearchpy import exceptions as opensearch_exc

from app.config import settings
from app.orchestration.investigation_service import (
    InvestigationNotFoundError,
    InvestigationService,
    get_investigation_service,
)
from app.services.wazuh.tool_results import failure as wazuh_tool_failure
from app.db.session import database_url
from app.db.repositories.alert_memory import get_alert_memory_repository
from app.db.repositories.findings import get_finding_repository
from app.db.repositories.investigations import ResponseExecutionConflictError
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
from app.soc_assistant.tool_agent import (
    SOCAnalyst,
    SOCToolAgent,
    classify_agent_interruption,
)
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


logger = logging.getLogger("tsage.soc_assistant")
INDICATOR_TYPES = {"ip", "domain", "hash", "process", "user", "path", "other"}
RUNNING_ACTIVITY = {
    AssistantCommandName.CHAT: (
        "soc_analyst",
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
    AssistantCommandName.PLAN: (
        "get_investigation",
        "Loading the evidence-bound investigation plan",
    ),
    AssistantCommandName.COLLECT: (
        "collect_more_evidence",
        "Collecting more evidence in the existing workflow",
    ),
    AssistantCommandName.CONTINUE: (
        "continue_investigation",
        "Continuing the existing controlled workflow",
    ),
    AssistantCommandName.HEALTH: (
        "wazuh_health",
        "Checking Wazuh manager and indexer connectivity",
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
    AssistantCommandName.COLLECT,
    AssistantCommandName.CONTINUE,
    AssistantCommandName.HEALTH,
}

INVESTIGATION_FOLLOW_UP_PATTERN = re.compile(
    r"(?:what happened(?: now)?|what(?:'s| is) happening(?: now)?|"
    r"where are we(?: now)?|what(?:'s| is) the status(?: now)?|"
    r"status(?: now)?|any updates?|what did (?:it|the investigation) find)"
)
COLLECT_FOLLOW_UP_PATTERN = re.compile(
    r"(?:collect|gather|fetch)(?: some)? (?:more )?(?:evidence|telemetry|data)"
)
CONTINUE_FOLLOW_UP_PATTERN = re.compile(
    r"(?:continue|resume)(?: it| the investigation| the workflow)?"
)
PLAN_FOLLOW_UP_PATTERN = re.compile(
    # "start/generate a remediation plan" is a request to see the plan for the
    # active investigation, not a new capability. It still routes to PLAN,
    # which reports plan availability - it never bypasses Analyze.
    r"(?:show|review|open|start|create|generate|prepare|build)"
    r"(?: me)? (?:a |the )?(?:plan|remediation plan)"
)
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


class SOCAssistant:
    def __init__(
        self,
        *,
        gateway: WazuhGateway | None = None,
        investigations: InvestigationService | None = None,
        router: AssistantIntentRouter | None = None,
        tool_agent: "SOCToolAgent | None" = None,
    ) -> None:
        self.gateway = gateway or WazuhGateway()
        self.investigations = investigations or get_investigation_service()
        self.router = router or AssistantIntentRouter()
        self.tool_agent = tool_agent or SOCAnalyst(
            gateway=self.gateway, investigations=self.investigations
        )

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

    @staticmethod
    def _apply_recent_context(
        intent: AssistantIntent,
        *,
        message: str,
        recent_context: dict[str, str],
    ) -> AssistantIntent:
        """Resolve only tightly bounded conversational follow-ups.

        This deliberately does not treat every vague question as a status
        request. A recent investigation must exist and the whole message must
        match a small follow-up vocabulary.
        """

        investigation_id = recent_context.get("investigation")
        normalized = re.sub(r"[^a-z0-9'\s]", "", message.lower()).strip()
        if investigation_id and intent.command == AssistantCommandName.CHAT:
            contextual_commands = (
                (INVESTIGATION_FOLLOW_UP_PATTERN, AssistantCommandName.STATUS),
                (COLLECT_FOLLOW_UP_PATTERN, AssistantCommandName.COLLECT),
                (CONTINUE_FOLLOW_UP_PATTERN, AssistantCommandName.CONTINUE),
                (PLAN_FOLLOW_UP_PATTERN, AssistantCommandName.PLAN),
            )
            for pattern, command in contextual_commands:
                if pattern.fullmatch(normalized):
                    return AssistantIntent(
                        command=command,
                        arguments={"investigation_id": investigation_id},
                        confidence=1.0,
                        source="conversation_context",
                    )
        return intent

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
            for reference_type, reference_value in (
                response.response.get("context_references") or {}
            ).items():
                if reference_type in {"source_ip", "target_user", "agent"}:
                    references.append((str(reference_type), str(reference_value)))
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

    @staticmethod
    def _cursor_key(organization_id: str, user_id: str) -> str:
        """Scope the durable change cursor to one tenant *and* one analyst.

        The cursor row is keyed by a single string, so the scope is encoded in
        the key rather than migrating the table. An analyst who can see two
        organizations gets an independent "since my last check" in each, which
        is the only reading of "what is new" that is not misleading.
        """

        return f"{organization_id}:{user_id}"

    @staticmethod
    def _interval_phrase(previous: datetime, now: datetime) -> str:
        """Say how long ago the previous check was, from the real clock.

        Both sides are timezone-aware UTC, so this never claims "a few minutes
        ago" for a timestamp it never compared against the request time.
        """

        seconds = max(0, int((now - previous).total_seconds()))
        if seconds < 90:
            return f"{seconds} second{'' if seconds == 1 else 's'} ago"
        minutes = seconds // 60
        if minutes < 90:
            return f"{minutes} minute{'' if minutes == 1 else 's'} ago"
        hours = minutes // 60
        if hours < 48:
            return f"{hours} hour{'' if hours == 1 else 's'} ago"
        days = hours // 24
        return f"{days} day{'' if days == 1 else 's'} ago"

    @staticmethod
    def _clock(value: datetime) -> str:
        return value.strftime("%H:%M:%S UTC")

    def _alerts_capability(
        self,
        arguments: dict[str, Any],
        *,
        organization_id: str,
        user_id: str,
    ) -> tuple[str, dict[str, Any], list[str], dict[str, Any]]:
        """Answer "any new / recent / changed alerts, findings, analysis?".

        The three questions have three different reference points and used to
        share one. `recent` is a time window; `new` and `changed` are measured
        against this analyst's previous successful check. Only the latter two
        move the durable cursor, and never for an explicitly historical window.
        """

        checked_at = datetime.now(UTC)
        memory = get_alert_memory_repository()
        cursor_key = self._cursor_key(organization_id, user_id)
        previous_check = memory.get_user_cursor(cursor_key)

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
        explicit_window = bool(arguments.get("since") or "hours" in arguments)
        window_hours = (
            _duration_hours(arguments.get("since"))
            if arguments.get("since")
            else _bounded_int(
                arguments.get("hours"), default=24, minimum=1, maximum=168
            )
        )
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
            "hours": window_hours,
            "limit": _bounded_int(
                arguments.get("limit"), default=20, minimum=1, maximum=50
            ),
            "agent_id": arguments.get("agent_id"),
            "text": arguments.get("text"),
        }

        subject = str(arguments.get("change_subject") or "all")
        mode = str(arguments.get("change_mode") or "")
        if arguments.get("new_only"):
            mode = "new"
        elif not mode:
            mode = (
                "recent"
                if explicit_window
                or arguments.get("all_results")
                or arguments.get("open_only")
                else "new"
            )
        # An explicit window is a historical question. Answering it must not
        # move the mark the next "what is new?" is measured from.
        historical = explicit_window and mode != "new"
        if historical:
            mode = "recent"

        if not getattr(memory, "durable", False):
            return self._alerts_without_cursor(
                tool_inputs,
                checked_at=checked_at,
                mode=mode,
                subject=subject,
            )

        # Three questions, three reference points. Only "new"/"changed" with a
        # cursor on record measures against the previous check; everything else
        # measures against the requested window.
        baseline_only = mode in {"new", "changed"} and previous_check is None
        reference = (
            previous_check
            if previous_check is not None and not baseline_only and mode != "recent"
            else checked_at - timedelta(hours=window_hours)
        )

        repository = get_finding_repository()
        finding_ids: set[str] | None = None
        if tool_inputs["agent_id"]:
            finding_ids = set(memory.finding_ids_for_agent(tool_inputs["agent_id"]))
        finding_filters: dict[str, Any] = {
            "organization_id": organization_id,
            "severity": severity or None,
            "status": "open" if arguments.get("open_only") else None,
            "finding_ids": finding_ids,
            "text": str(tool_inputs["text"] or "").strip() or None,
        }
        # Counts are independent database queries over the same tenant and
        # filters as the displayed page. A failure here exits before the cursor
        # is advanced, so the next successful check sees the same interval.
        total_findings = repository.count(**finding_filters)
        new_finding_count = repository.count(
            **finding_filters,
            created_after=reference,
        )
        updated_finding_count = repository.count(
            **finding_filters,
            updated_after=reference,
            created_on_or_before=reference,
        )
        analysis_count: int | None = None
        analysis_count_status = "available"
        analysis_count_error: str | None = None
        try:
            analysis_count = self.investigations.completed_analysis_count(
                organization_id=organization_id,
                occurred_after=reference,
                occurred_on_or_before=checked_at,
            )
        except Exception as exc:
            # The audit store is the only authoritative source for completed
            # diagnoses. Finding timestamps/verdicts are not a fallback.
            analysis_count_status = "unavailable"
            analysis_count_error = type(exc).__name__
            logger.warning(
                "soc_completed_analysis_count_unavailable error_type=%s",
                analysis_count_error,
            )
        visible_filters = dict(finding_filters)
        if mode == "new" and not baseline_only:
            visible_filters["created_after"] = reference
        elif not (
            arguments.get("all_results")
            or arguments.get("open_only")
            or mode == "recent"
        ):
            visible_filters["changed_after"] = reference
        records = repository.list(
            **visible_filters,
            limit=tool_inputs["limit"],
        )

        findings = []
        for record in records:
            finding = dict(record["finding"])
            finding.update(
                {
                    "finding_id": record["finding_id"],
                    "status": record["status"],
                    "version": record["version"],
                    "verdict": record["verdict"].get("verdict"),
                    "verdict_confidence": record["verdict"].get("confidence"),
                }
            )
            findings.append(finding)

        alert_count = memory.count_alerts_since(
            reference,
            agent_id=tool_inputs["agent_id"],
            min_level=tool_inputs["min_level"],
        )
        comparable = mode in {"new", "changed"} and not baseline_only
        payload: dict[str, Any] = {
            "display_mode": "conversation",
            "answer_type": f"change_report_{mode}",
            "grounded": True,
            "grounding_status": "grounded",
            "change_subject": subject,
            "mode": mode,
            "raw_alert_count": alert_count,
            "recent_alerts": alert_count,
            "finding_count": len(findings),
            "findings": findings,
            "total_findings": total_findings,
            # None, not 0: before a baseline exists there is no such quantity,
            # and reporting the window's whole history as "new" was the bug.
            "new_alerts": alert_count if comparable else None,
            "new_findings": new_finding_count if comparable else None,
            "updated_findings": updated_finding_count if comparable else None,
            # Compatibility name retained for existing clients. This is now
            # the count of completed MAPE-K analysis audit events, not a count
            # inferred from finding updates.
            "reanalyzed_findings": analysis_count if comparable else None,
            "completed_analyses": analysis_count if comparable else None,
            "analysis_count": {
                "status": analysis_count_status,
                "count": analysis_count if comparable else None,
                "source": "soc_audit_events",
                "event": "analysis_completed",
                "stage": "analyze",
                "error_type": analysis_count_error,
            },
            "unchanged_findings": max(
                0,
                total_findings - new_finding_count - updated_finding_count,
            ),
            "since": reference.isoformat(),
            "checked_at": checked_at.isoformat(),
            "new_since_last_check": (
                previous_check.isoformat() if previous_check else None
            ),
            "baseline_established": baseline_only,
            "window_hours": window_hours if not comparable else None,
            "cursor_status": "durable",
            "cursor_advanced": False,
            "source": "postgresql",
            "count_filters": {
                "raw_alerts": {
                    "source": "soc_wazuh_alerts",
                    "organization_id": organization_id,
                    "agent_id": tool_inputs["agent_id"],
                    "min_rule_level": tool_inputs["min_level"],
                    "observed_after": reference.isoformat(),
                },
                "findings": {
                    "source": "soc_findings",
                    "organization_id": organization_id,
                    "agent_id": tool_inputs["agent_id"],
                    "severity": severity or None,
                    "status": "open" if arguments.get("open_only") else None,
                    "text": str(tool_inputs["text"] or "").strip() or None,
                    "change_reference": reference.isoformat(),
                },
                "completed_analyses": {
                    "source": "soc_audit_events",
                    "organization_id": organization_id,
                    "event": "analysis_completed",
                    "stage": "analyze",
                    "occurred_after": reference.isoformat(),
                    "occurred_on_or_before": checked_at.isoformat(),
                },
                "same_filters": False,
            },
        }

        if (
            mode in {"new", "changed"}
            and not historical
            and analysis_count_status == "available"
        ):
            memory.advance_user_cursor(
                cursor_key,
                checked_at,
                finding_version=max(
                    (int(record.get("version") or 0) for record in records),
                    default=None,
                ),
            )
            payload["cursor_advanced"] = True

        return (
            self._change_summary(
                subject=subject,
                mode=mode,
                baseline_only=baseline_only,
                previous_check=previous_check,
                checked_at=checked_at,
                window_hours=window_hours,
                alert_count=alert_count,
                total_findings=total_findings,
                new_findings=new_finding_count,
                updated_findings=updated_finding_count,
                reanalyzed=analysis_count,
                analysis_count_status=analysis_count_status,
            ),
            payload,
            ["query_alert_memory"],
            {},
        )

    def _alerts_without_cursor(
        self,
        tool_inputs: dict[str, Any],
        *,
        checked_at: datetime,
        mode: str,
        subject: str,
    ) -> tuple[str, dict[str, Any], list[str], dict[str, Any]]:
        """Live Wazuh answer for deployments with no durable alert memory.

        Without the cursor there is no honest answer to "what is new", so this
        says so instead of presenting a time window as a comparison.
        """

        result = self._run_tool(
            tool_name="search_alerts",
            inputs=tool_inputs,
            fn=lambda: self.gateway.search_alerts(**tool_inputs),
        )
        compact = compact_alert_search_result(result)
        compact.update(
            {
                "display_mode": "conversation",
                "answer_type": "change_report_unavailable",
                "grounded": True,
                "grounding_status": "partial",
                "change_subject": subject,
                "mode": "recent",
                "recent_alerts": result.returned,
                "matched_alerts": result.total,
                "new_alerts": None,
                "new_findings": None,
                "updated_findings": None,
                "since": None,
                "window_hours": tool_inputs["hours"],
                "checked_at": checked_at.isoformat(),
                "new_since_last_check": None,
                "baseline_established": False,
                "cursor_status": "unavailable",
                "cursor_advanced": False,
            }
        )
        comparison_note = (
            " I cannot tell you what is new since your previous check: the "
            "durable alert memory that stores that mark is unavailable."
            if mode in {"new", "changed"}
            else ""
        )
        return (
            (
                f"In the last {tool_inputs['hours']} hours Wazuh matched "
                f"{result.total} alert{'' if result.total == 1 else 's'} and "
                f"returned {result.returned} of them."
                f"{comparison_note}"
            ),
            compact,
            ["search_alerts"],
            {},
        )

    def _change_summary(
        self,
        *,
        subject: str,
        mode: str,
        baseline_only: bool,
        previous_check: datetime | None,
        checked_at: datetime,
        window_hours: int,
        alert_count: int,
        total_findings: int,
        new_findings: int,
        updated_findings: int,
        reanalyzed: int | None,
        analysis_count_status: str,
    ) -> str:
        """Plain-language answer built from the numbers actually retrieved."""

        def plural(count: int, noun: str) -> str:
            return f"{count} {noun}{'' if count == 1 else 's'}"

        if subject == "analysis" and analysis_count_status != "available":
            return (
                "Completed-analysis activity is unavailable because the "
                "MAPE-K audit source could not be counted. I did not estimate "
                "it from finding updates or verdict fields, and I did not "
                "advance your change cursor."
            )

        if baseline_only:
            baseline_note = (
                "I could not set the change baseline because the completed-analysis "
                "audit count is unavailable."
                if analysis_count_status != "available"
                else f"I have set your baseline at {self._clock(checked_at)}."
            )
            return (
                "This is the first check I have on record for you, so I "
                "cannot yet say what is new relative to an earlier one. "
                f"{baseline_note} As of now "
                f"there {'is' if alert_count == 1 else 'are'} "
                f"{plural(alert_count, 'alert')} in the last {window_hours} "
                f"hours and {plural(total_findings, 'finding')} on record — "
                "that is the current state, not a list of new activity. From "
                "your next check I will report only what moved since this "
                "moment."
            )

        if mode == "recent" or previous_check is None:
            headline = (
                f"In the last {window_hours} hours there "
                f"{'is' if alert_count == 1 else 'are'} "
                f"{plural(alert_count, 'alert')} and "
                f"{plural(total_findings, 'finding')} on record."
            )
            return (
                f"{headline} This is a time window, not a comparison against "
                "your previous check — ask \"anything new?\" for that."
            )

        stamp = self._clock(previous_check)
        ago = self._interval_phrase(previous_check, checked_at)
        unchanged = max(0, total_findings - new_findings - updated_findings)

        if subject == "analysis":
            if reanalyzed == 0:
                return (
                    f"No new analysis since your previous check at {stamp} "
                    f"({ago}). The authoritative MAPE-K audit contains no "
                    "completed Analyze-stage diagnosis in that interval."
                )
            return (
                f"{plural(int(reanalyzed or 0), 'MAPE-K analysis')} completed "
                f"since your previous check at {stamp} ({ago}). This count "
                "comes from Analyze-stage audit events, not finding updates."
            )

        if alert_count == 0 and new_findings == 0 and updated_findings == 0:
            noun = "findings" if subject == "findings" else "alerts"
            return (
                f"No new {noun} have appeared since your previous check at "
                f"{stamp} ({ago}). There are still "
                f"{plural(total_findings, 'existing finding')}, and none has "
                "been updated."
            )

        parts = [
            f"{plural(alert_count, 'new alert')}",
            f"{plural(new_findings, 'new finding')}",
            f"{plural(updated_findings, 'updated finding')}",
        ]
        return (
            f"Since your previous check at {stamp} ({ago}): "
            f"{', '.join(parts[:-1])}, and {parts[-1]}. "
            f"{plural(unchanged, 'finding')} "
            f"{'is' if unchanged == 1 else 'are'} unchanged."
        )

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
        intent_source: str = "deterministic",
        intent_confidence: float = 1.0,
    ) -> tuple[str, dict[str, Any], list[str], dict[str, Any]]:
        if command == AssistantCommandName.CLARIFY:
            # The router could not resolve the target. Ask, change nothing,
            # and spend no model call doing it.
            return (
                str(
                    arguments.get("question")
                    or "Which alert or finding should I use? I could not "
                    "resolve that to a single candidate."
                ),
                {
                    "display_mode": "conversation",
                    "answer_type": "clarification_required",
                },
                [],
                {},
            )
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
                agent_result = self.tool_agent.answer(
                    question=question,
                    history=conversation_history or [],
                    organization_id=organization_id,
                    created_by=user_id,
                    conversation_id=conversation_id,
                    recent_context=recent_context or {},
                    intent_source=intent_source,
                    intent_confidence=intent_confidence,
                )
                agent_answer, tool_calls, active_alert_id = agent_result
                failed_tools = list(
                    getattr(agent_result, "failed_tools", []) or []
                )
                evidence_references = list(
                    getattr(agent_result, "evidence_references", []) or []
                )
                retrieved_evidence_references = list(
                    getattr(agent_result, "retrieved_evidence_references", []) or []
                )
                metrics = dict(getattr(agent_result, "metrics", {}) or {})
                context_references = dict(
                    getattr(agent_result, "context_references", {}) or {}
                )
                return (
                    agent_answer,
                    {
                        "display_mode": "conversation",
                        "answer_type": (
                            "soc_analyst_partial"
                            if failed_tools
                            or metrics.get("investigation_status") == "incomplete"
                            else "soc_analyst"
                        ),
                        # Citation presence, query coverage, and investigation
                        # completion are intentionally separate dimensions.
                        "grounding_status": (
                            grounding_status := str(
                                metrics.get("grounding_status") or "ungrounded"
                            )
                        ),
                        "grounded": grounding_status == "cited",
                        "failed_tools": failed_tools,
                        "evidence_references": evidence_references,
                        "retrieved_evidence_references": retrieved_evidence_references,
                        "tools_called": tool_calls,
                        "analyst_metrics": metrics,
                        "context_references": context_references,
                    },
                    ["soc_analyst", *tool_calls],
                    (
                        {"active_alert_id": active_alert_id}
                        if active_alert_id
                        else {}
                    ),
                )
            except Exception as exc:
                interruption = classify_agent_interruption(exc)
                category = str(interruption["category"])
                if category in {"source_failure", "application_error"}:
                    # Preserve Wazuh's normalized API failure and let an
                    # unexpected programming error reach the application error
                    # handler. Neither is a model outage.
                    raise
                messages = {
                    "model_rate_limit": (
                        "The AI provider's rate limit was reached. Please wait "
                        "a moment and try again."
                    ),
                    "model_context_limit": (
                        "The analyst request exceeded the model context limit. "
                        "Narrow the agent, technique/CVE, or time range."
                    ),
                    "model_configuration": (
                        "The analyst model is not configured. Deterministic "
                        "commands such as `/alerts`, `/status`, and `/health` "
                        "are still available."
                    ),
                    "model_provider_outage": (
                        "The analyst model provider is unavailable. "
                        "Deterministic commands remain available."
                    ),
                    "model_response_failure": (
                        "The analyst model returned an unusable response."
                    ),
                    "model_request_failure": (
                        "The analyst model request failed before evidence was retrieved."
                    ),
                }
                answer_types = {
                    "model_rate_limit": "rate_limited",
                    "model_context_limit": "context_limit_exceeded",
                    "model_configuration": "model_unavailable",
                    "model_provider_outage": "model_unavailable",
                    "model_response_failure": "model_response_failure",
                    "model_request_failure": "model_request_failure",
                }
                return (
                    messages[category],
                    {
                        "display_mode": "conversation",
                        "answer_type": answer_types[category],
                        "grounded": False,
                        "grounding_status": "ungrounded",
                        "evidence_references": [],
                        "retrieved_evidence_references": [],
                        "analyst_metrics": {
                            "evidence_retrieved": 0,
                            "evidence_cited": 0,
                            "event_details_examined": 0,
                            "investigation_status": "incomplete",
                            "interruption_reason": interruption["code"],
                            "interruption_category": category,
                            "failure": interruption,
                        },
                    },
                    [],
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

        if command == AssistantCommandName.ALERTS:
            return self._alerts_capability(
                arguments,
                organization_id=organization_id,
                user_id=user_id,
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

        if command == AssistantCommandName.PLAN:
            investigation_id = str(
                arguments.get("investigation_id") or ""
            ).strip()
            if not investigation_id:
                return (
                    "Provide an investigation ID, for example `/plan INV-ABC123`.",
                    {"required": ["investigation_id"]},
                    [],
                    {},
                )
            snapshot = self.investigations.snapshot(
                investigation_id,
                organization_id=organization_id,
            )
            plan = snapshot.get("remediation_plan") or snapshot.get(
                "advisory_plan"
            )
            if plan is None:
                message = (
                    f"Investigation {investigation_id} has no evidence-bound "
                    "plan yet. Analyze must reach a conclusive diagnosis before "
                    "Plan can run; use `/collect "
                    f"{investigation_id}` if more evidence is needed."
                )
            else:
                message = (
                    f"Loaded the existing evidence-bound plan for "
                    f"investigation {investigation_id}."
                )
            return (
                message,
                {
                    "investigation_id": investigation_id,
                    "status": snapshot["status"],
                    "current_stage": snapshot["current_stage"],
                    "plan_available": plan is not None,
                    "plan": plan,
                    "grounded": True,
                },
                ["get_investigation"],
                {
                    "active_investigation_id": investigation_id,
                    "active_alert_id": snapshot.get("alert_id"),
                    "active_agent_id": snapshot.get("agent_id"),
                    "investigation": snapshot,
                },
            )

        if command in {
            AssistantCommandName.COLLECT,
            AssistantCommandName.CONTINUE,
        }:
            investigation_id = str(
                arguments.get("investigation_id") or ""
            ).strip()
            if not investigation_id:
                return (
                    (
                        f"Provide an investigation ID, for example "
                        f"`/{command.value} INV-ABC123`."
                    ),
                    {"required": ["investigation_id"]},
                    [],
                    {},
                )
            operation_name = (
                "collect_more_evidence"
                if command == AssistantCommandName.COLLECT
                else "continue_investigation"
            )
            operation = getattr(self.investigations, operation_name)
            try:
                snapshot = self._run_tool(
                    tool_name=operation_name,
                    inputs={
                        "investigation_id": investigation_id,
                        "organization_id": organization_id,
                    },
                    fn=lambda: operation(
                        investigation_id,
                        organization_id=organization_id,
                    ),
                )
            except ResponseExecutionConflictError as exc:
                return (
                    str(exc),
                    {
                        "investigation_id": investigation_id,
                        "status": "conflict",
                        "grounded": True,
                    },
                    [operation_name],
                    {"active_investigation_id": investigation_id},
                )
            return (
                (
                    f"Investigation {investigation_id} is now "
                    f"{_stage_phrase(snapshot['status'], snapshot['current_stage'])}."
                ),
                {
                    "investigation_id": investigation_id,
                    "status": snapshot["status"],
                    "current_stage": snapshot["current_stage"],
                    "pending_nodes": snapshot.get("pending_nodes", []),
                    "diagnosis": snapshot.get("diagnosis"),
                    "advisory_plan": snapshot.get("advisory_plan"),
                    "grounded": True,
                },
                [operation_name],
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
        intent_source: str = "deterministic",
        intent_confidence: float = 1.0,
    ) -> tuple[str, dict[str, Any], list[str], dict[str, Any]]:
        return self._execute(
            command,
            arguments,
            organization_id=organization_id,
            user_id=user_id,
            conversation_id=conversation_id,
            recent_context=recent_context,
            conversation_history=conversation_history,
            intent_source=intent_source,
            intent_confidence=intent_confidence,
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
        intent = self._apply_recent_context(
            intent,
            message=message,
            recent_context=recent_context,
        )
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
        router_failed = intent.source == "router_error"
        activities = [
            self._activity(
                1,
                (
                    "Intent router failed; answering read-only"
                    if router_failed
                    else f"Selected {intent.command.value} capability"
                ),
                tool="deterministic_router",
                status="failed" if router_failed else "completed",
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
                intent_source=intent.source,
                intent_confidence=intent.confidence,
            )
            tool_events = (
                payload.get("analyst_metrics", {}).get("tool_events") or []
            )
            if tool_events:
                for event in tool_events:
                    tool_name = str(event.get("tool") or "unknown_tool")
                    outcome = str(event.get("outcome") or "success")
                    failed = outcome in {
                        "recoverable_validation_error",
                        "source_failure",
                        "tool_error",
                        "budget_rejection",
                    }
                    labels = {
                        "cache_hit": f"Used cached {tool_name}",
                        "recoverable_validation_error": (
                            f"Validation failed for {tool_name}"
                        ),
                        "source_failure": f"Source failed for {tool_name}",
                        "tool_error": f"Tool failed: {tool_name}",
                        "budget_rejection": (
                            f"Rejected {tool_name}: tool-call budget reached"
                        ),
                    }
                    activities.append(
                        self._activity(
                            len(activities) + 1,
                            labels.get(outcome, f"Queried {tool_name}"),
                            tool=tool_name,
                            status="failed" if failed else "completed",
                        )
                    )
            else:
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
