"""Execute typed SOC assistant capabilities over deterministic services."""

from __future__ import annotations

import uuid
from typing import Any

from app.coreAgents.orchestration.investigation_service import (
    InvestigationNotFoundError,
    InvestigationService,
    get_investigation_service,
)
from app.db.session import database_url
from app.services.wazuh.gateway import WazuhGateway
from app.services.wazuh.normalization.serializers import (
    compact_alert_search_result,
    serialize_for_agent,
)
from app.soc_assistant.catalog import public_catalog
from app.soc_assistant.router import AssistantIntentRouter
from app.soc_assistant.schemas import (
    AssistantActivity,
    AssistantCommandName,
    AssistantIntent,
    AssistantResponse,
)


INDICATOR_TYPES = {"ip", "domain", "hash", "process", "user", "path", "other"}
RUNNING_ACTIVITY = {
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
    AssistantCommandName.HELP: (
        None,
        "Loading the SOC capability catalog",
    ),
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


class SOCAssistant:
    def __init__(
        self,
        *,
        gateway: WazuhGateway | None = None,
        investigations: InvestigationService | None = None,
        router: AssistantIntentRouter | None = None,
    ) -> None:
        self.gateway = gateway or WazuhGateway()
        self.investigations = investigations or get_investigation_service()
        self.router = router or AssistantIntentRouter()

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
    def running_activity(command: AssistantCommandName) -> AssistantActivity:
        tool, label = RUNNING_ACTIVITY[command]
        return AssistantActivity(
            id=f"activity-running-{command.value}",
            tool=tool,
            label=label,
            status="running",
        )

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
            repository.append_message(
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
    ) -> tuple[str, dict[str, Any], list[str], dict[str, Any]]:
        if command == AssistantCommandName.HELP:
            catalog = public_catalog()
            return (
                "Choose a capability below or type `/` to search commands.",
                {"commands": catalog},
                [],
                {},
            )

        if command == AssistantCommandName.ALERTS:
            result = self.gateway.search_alerts(
                min_level=_bounded_int(
                    arguments.get("min_level"),
                    default=0,
                    minimum=0,
                    maximum=16,
                ),
                hours=_bounded_int(
                    arguments.get("hours"),
                    default=24,
                    minimum=1,
                    maximum=168,
                ),
                limit=_bounded_int(
                    arguments.get("limit"),
                    default=20,
                    minimum=1,
                    maximum=50,
                ),
                agent_id=arguments.get("agent_id"),
                text=arguments.get("text"),
            )
            compact = compact_alert_search_result(result)
            return (
                (
                    f"Found {compact['total_raw_alerts']} matching Wazuh alerts "
                    f"and grouped them into {compact['finding_count']} findings."
                ),
                compact,
                ["search_alerts"],
                {},
            )

        if command == AssistantCommandName.SUMMARY:
            hours = _bounded_int(
                arguments.get("hours"),
                default=24,
                minimum=1,
                maximum=168,
            )
            summary = serialize_for_agent(self.gateway.alert_summary(hours=hours))
            return (
                f"Loaded the Wazuh alert overview for the last {hours} hours.",
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
            hunt = self.gateway.hunt_ioc_telemetry(
                indicator=indicator,
                indicator_type=indicator_type,
                hours=_bounded_int(
                    arguments.get("hours"),
                    default=24,
                    minimum=1,
                    maximum=168,
                ),
                limit=_bounded_int(
                    arguments.get("limit"),
                    default=10,
                    minimum=1,
                    maximum=20,
                ),
                agent_id=arguments.get("agent_id"),
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
                    "Provide the Wazuh alert document ID, for example `/investigate ALERT-ID --agent 001`.",
                    {"required": ["alert_id"]},
                    [],
                    {},
                )
            snapshot = self.investigations.start(
                alert_id=alert_id,
                agent_id=arguments.get("agent_id"),
                initiated_by=user_id,
                initiation_reason="Started from the SOC assistant.",
                organization_id=organization_id,
                owner_user_id=user_id,
            )
            return (
                (
                    f"Started MAPE-K investigation {snapshot['investigation_id']}. "
                    f"Current stage: {snapshot['current_stage']}."
                ),
                {
                    "investigation_id": snapshot["investigation_id"],
                    "status": snapshot["status"],
                    "current_stage": snapshot["current_stage"],
                    "diagnosis": snapshot.get("diagnosis"),
                    "pending_nodes": snapshot.get("pending_nodes", []),
                },
                ["start_investigation"],
                {
                    "active_investigation_id": snapshot["investigation_id"],
                    "active_alert_id": alert_id,
                    "active_agent_id": snapshot.get("agent_id"),
                    "investigation": snapshot,
                },
            )

        if command == AssistantCommandName.STATUS:
            investigation_id = str(
                arguments.get("investigation_id") or ""
            ).strip()
            if not investigation_id:
                return (
                    "Provide an investigation ID, for example `/status INV-ABC123`.",
                    {"required": ["investigation_id"]},
                    [],
                    {},
                )
            try:
                snapshot = self.investigations.snapshot(
                    investigation_id,
                    organization_id=organization_id,
                )
            except InvestigationNotFoundError as exc:
                raise LookupError(
                    f"Investigation {investigation_id} was not found."
                ) from exc
            return (
                (
                    f"Investigation {investigation_id} is {snapshot['status']} "
                    f"at stage {snapshot['current_stage']}."
                ),
                {
                    "investigation_id": investigation_id,
                    "status": snapshot["status"],
                    "current_stage": snapshot["current_stage"],
                    "pending_nodes": snapshot.get("pending_nodes", []),
                    "diagnosis": snapshot.get("diagnosis"),
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
            for name, operation in (
                ("indexer", self.gateway.indexer_health),
                ("manager", self.gateway.validate_server),
            ):
                try:
                    operation()
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
        intent, usage = routed or self.route(message)
        activities = [
            self._activity(
                1,
                f"Selected {intent.command.value} capability",
                tool="intent_router",
            )
        ]
        try:
            assistant_message, payload, tools, active = self._execute(
                intent.command,
                intent.arguments,
                organization_id=organization_id,
                user_id=user_id,
            )
            activities.append(
                self._activity(
                    2,
                    f"Completed {intent.command.value}",
                    tool=tools[-1] if tools else None,
                )
            )
        except Exception:
            activities.append(
                self._activity(
                    2,
                    f"{intent.command.value} failed",
                    status="failed",
                )
            )
            raise

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
