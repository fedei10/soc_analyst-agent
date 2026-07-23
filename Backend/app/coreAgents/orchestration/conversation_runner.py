"""Invoke and stream the conversational SOC agent without exposing reasoning."""

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

from langchain.messages import AIMessage, HumanMessage, ToolMessage

from app.config import settings
from app.coreAgents.orchestration.conversation_agent import (
    get_soc_chat_agent,
)
from app.coreAgents.orchestration.conversation_state import SOCChatContext
from app.coreAgents.orchestration.conversation_tools import (
    build_soc_chat_tools,
)
from app.coreAgents.orchestration.investigation_service import (
    InvestigationNotFoundError,
    InvestigationService,
    get_investigation_service,
)
from app.services.wazuh.dependencies import get_wazuh_gateway


TOOL_ACTIVITY_LABELS = {
    "get_recent_wazuh_alerts": "Checking recent Wazuh alerts",
    "get_high_severity_alerts": "Checking high-severity Wazuh alerts",
    "search_archived_wazuh_logs": "Searching archived Wazuh logs",
    "get_wazuh_log_statistics": "Calculating Wazuh log statistics",
    "get_alert_details": "Inspecting alert details",
    "get_raw_alert_document": "Inspecting raw alert fields",
    "search_related_alerts": "Searching related alerts",
    "search_alerts_by_agent_and_time": (
        "Searching the endpoint time window"
    ),
    "build_authentication_timeline": "Building authentication timeline",
    "check_successful_login_after_failures": (
        "Checking for successful logins after failures"
    ),
    "investigate_alert_attribution": "Resolving alert attribution",
    "get_endpoint_context": "Retrieving endpoint context",
    "get_open_investigations": "Checking recent investigations",
    "start_investigation": "Running the formal investigation workflow",
    "get_investigation_status": "Retrieving investigation status",
}
CHAT_TOOL_NAMES = tuple(tool.name for tool in build_soc_chat_tools())


def conversation_config(conversation_id: str) -> dict:
    if not conversation_id:
        raise ValueError("conversation_id is required.")
    return {"configurable": {"thread_id": conversation_id}}


def build_chat_context(*, gateway=None) -> SOCChatContext:
    wazuh = gateway or get_wazuh_gateway()
    try:
        wazuh.indexer_health()
        wazuh.validate_server()
        wazuh_status = "healthy"
    except Exception:
        wazuh_status = "unavailable"

    return SOCChatContext(
        current_time=datetime.now(UTC).isoformat(),
        wazuh_status=wazuh_status,
        permissions=("wazuh:read",),
        allowed_tools=CHAT_TOOL_NAMES,
        active_response_enabled=(
            not settings.WAZUH_READ_ONLY
            and settings.WAZUH_ALLOW_DANGEROUS_TOOLS
        ),
    )


def _message_text(message: Any) -> str:
    text = getattr(message, "text", None)
    if isinstance(text, str) and text.strip():
        return text.strip()

    content = getattr(message, "content", "")
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict) and isinstance(block.get("text"), str):
                parts.append(block["text"])
        return "".join(parts).strip()
    return str(content).strip()


def _current_turn(messages: list[Any]) -> list[Any]:
    last_human_index = 0
    for index, message in enumerate(messages):
        if isinstance(message, HumanMessage) or getattr(message, "type", "") == "human":
            last_human_index = index
    return messages[last_human_index:]


def _parse_tool_content(message: ToolMessage) -> Any:
    content = message.content
    if not isinstance(content, str):
        return content
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        return content


def _turn_details(messages: list[Any]) -> tuple[list[str], list[dict], list[dict]]:
    turn = _current_turn(messages)
    calls: list[tuple[str | None, str]] = []
    completed_ids: set[str] = set()
    failed_ids: set[str] = set()
    tool_results: list[dict] = []

    for message in turn:
        for call in getattr(message, "tool_calls", []) or []:
            name = call.get("name")
            if name:
                calls.append((call.get("id"), name))
        if isinstance(message, ToolMessage):
            if message.tool_call_id:
                completed_ids.add(message.tool_call_id)
                parsed = _parse_tool_content(message)
                if isinstance(parsed, dict) and parsed.get("ok") is False:
                    failed_ids.add(message.tool_call_id)
            tool_results.append(
                {
                    "tool": message.name,
                    "result": _parse_tool_content(message),
                }
            )

    tools: list[str] = []
    activities: list[dict] = []
    for call_id, name in calls:
        if name not in tools:
            tools.append(name)
        activities.append(
            {
                "tool": name,
                "label": TOOL_ACTIVITY_LABELS.get(name, name.replace("_", " ")),
                "status": (
                    "failed"
                    if call_id in failed_ids
                    else (
                        "completed"
                        if call_id is None or call_id in completed_ids
                        else "failed"
                    )
                ),
            }
        )
    return tools, activities, tool_results


def _latest_answer(messages: list[Any]) -> str:
    for message in reversed(_current_turn(messages)):
        if isinstance(message, AIMessage) or getattr(message, "type", "") == "ai":
            if not (getattr(message, "tool_calls", None) or []):
                content = _message_text(message)
                if content:
                    return content
    raise ValueError("The conversational agent did not produce a final answer.")


def _formal_result(snapshot: dict[str, Any] | None) -> dict[str, Any] | None:
    if not snapshot:
        return None
    for key in ("final_report", "l3_result", "l2_result", "l1_result"):
        value = snapshot.get(key)
        if isinstance(value, dict):
            return value
    return {
        "investigation_id": snapshot["investigation_id"],
        "status": snapshot["status"],
        "current_stage": snapshot["current_stage"],
    }


def serialize_conversation_result(
    state: dict[str, Any],
    *,
    conversation_id: str,
    investigation_service: InvestigationService | None = None,
) -> dict[str, Any]:
    messages = list(state.get("messages") or [])
    tools, activities, tool_results = _turn_details(messages)
    active_investigation_id = state.get("active_investigation_id")
    snapshot = None
    if active_investigation_id:
        service = investigation_service or get_investigation_service()
        try:
            snapshot = service.snapshot(active_investigation_id)
        except InvestigationNotFoundError:
            snapshot = None

    structured_result = _formal_result(snapshot)
    if structured_result is None and isinstance(
        state.get("attribution_result"), dict
    ):
        structured_result = state["attribution_result"]
    if structured_result is None and tool_results:
        structured_result = {"tool_results": tool_results}

    return {
        "conversation_id": conversation_id,
        "assistant_message": _latest_answer(messages),
        "response": structured_result or {},
        "tools_used": tools,
        "activities": activities,
        "active_investigation_id": active_investigation_id,
        "active_alert_id": state.get("active_alert_id"),
        "investigation": snapshot,
        "investigation_progress": state.get("investigation_progress"),
        "missing_evidence": state.get("missing_evidence", []),
        "tool_errors": state.get("tool_errors", []),
    }


def run_soc_conversation(
    *,
    message: str,
    conversation_id: str,
    agent=None,
    context: SOCChatContext | None = None,
    investigation_service: InvestigationService | None = None,
) -> dict[str, Any]:
    chat_agent = agent or get_soc_chat_agent()
    result = chat_agent.invoke(
        {"messages": [{"role": "user", "content": message}]},
        config=conversation_config(conversation_id),
        context=context or build_chat_context(),
    )
    return serialize_conversation_result(
        result,
        conversation_id=conversation_id,
        investigation_service=investigation_service,
    )


def stream_soc_conversation(
    *,
    message: str,
    conversation_id: str,
    agent=None,
    context: SOCChatContext | None = None,
    investigation_service: InvestigationService | None = None,
) -> Iterator[tuple[str, dict[str, Any]]]:
    chat_agent = agent or get_soc_chat_agent()
    config = conversation_config(conversation_id)
    runtime_context = context or build_chat_context()
    emitted_calls: set[str] = set()
    emitted_completions: set[str] = set()

    yield (
        "activity",
        {
            "tool": None,
            "label": "Understanding the request",
            "status": "running",
        },
    )

    try:
        for mode, chunk in chat_agent.stream(
            {"messages": [{"role": "user", "content": message}]},
            config=config,
            context=runtime_context,
            stream_mode=["messages", "updates"],
        ):
            if mode == "messages":
                stream_message, metadata = chunk
                if metadata.get("langgraph_node") != "model":
                    continue
                if getattr(stream_message, "tool_calls", None):
                    continue
                content = _message_text(stream_message)
                if content:
                    yield ("token", {"content": content})
                continue

            for update in chunk.values():
                if not isinstance(update, dict):
                    continue
                for update_message in update.get("messages", []):
                    for call in getattr(update_message, "tool_calls", []) or []:
                        call_id = call.get("id") or call.get("name")
                        name = call.get("name")
                        if not name or call_id in emitted_calls:
                            continue
                        emitted_calls.add(call_id)
                        yield (
                            "activity",
                            {
                                "tool": name,
                                "label": TOOL_ACTIVITY_LABELS.get(
                                    name,
                                    name.replace("_", " "),
                                ),
                                "status": "running",
                            },
                        )
                    if isinstance(update_message, ToolMessage):
                        call_id = (
                            update_message.tool_call_id or update_message.name
                        )
                        if not call_id or call_id in emitted_completions:
                            continue
                        emitted_completions.add(call_id)
                        name = update_message.name or "tool"
                        parsed = _parse_tool_content(update_message)
                        status = (
                            "failed"
                            if isinstance(parsed, dict)
                            and parsed.get("ok") is False
                            else "completed"
                        )
                        yield (
                            "activity",
                            {
                                "tool": name,
                                "label": TOOL_ACTIVITY_LABELS.get(
                                    name,
                                    name.replace("_", " "),
                                ),
                                "status": status,
                            },
                        )

        state = dict(chat_agent.get_state(config).values)
        yield (
            "final",
            serialize_conversation_result(
                state,
                conversation_id=conversation_id,
                investigation_service=investigation_service,
            ),
        )
    except Exception:
        yield (
            "error",
            {
                "message": (
                    "The SOC conversation could not be completed. "
                    "Check the model providers and Wazuh connection."
                )
            },
        )
