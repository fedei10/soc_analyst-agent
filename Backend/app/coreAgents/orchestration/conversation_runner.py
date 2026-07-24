"""Invoke and stream the conversational SOC agent without exposing reasoning."""

import json
import logging
from copy import deepcopy
from collections.abc import Iterator
from datetime import UTC, datetime
from queue import Empty, Queue
from threading import Event, Thread
from typing import Any

from langchain.messages import AIMessage, HumanMessage, ToolMessage

from app.config import settings
from app.coreAgents.orchestration.conversation_agent import (
    get_soc_chat_agent,
    put_curated_soc_memory,
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
from app.db.session import database_url


logger = logging.getLogger("tsage.orchestration.conversation")

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
    "get_endpoint_inventory": "Retrieving endpoint inventory",
    "get_endpoint_security_findings": "Checking endpoint security findings",
    "search_endpoint_vulnerabilities": "Searching endpoint vulnerabilities",
    "get_detection_rule_context": "Retrieving rule and MITRE context",
    "collect_host_diagnostic": "Collecting API-host diagnostics",
    "get_open_investigations": "Checking recent investigations",
    "start_investigation": "Running the formal investigation workflow",
    "get_investigation_status": "Retrieving investigation status",
}
CHAT_TOOL_NAMES = tuple(tool.name for tool in build_soc_chat_tools())
STREAM_HEARTBEAT_SECONDS = 8.0
MAX_CLIENT_INVENTORY_ITEMS = 10
CONVERSATION_SUMMARY_INTERVAL = 20


def _conversation_repository():
    if not database_url():
        return None
    from app.db.repositories.conversations import get_conversation_repository

    return get_conversation_repository()


def _persist_user_message(
    *,
    conversation_id: str,
    organization_id: str,
    user_id: str,
    message: str,
):
    repository = _conversation_repository()
    if repository is None:
        return None
    repository.create_conversation(
        conversation_id=conversation_id,
        organization_id=organization_id,
        owner_user_id=user_id,
        title=message[:120],
        metadata={"source": "soc_orchestrator"},
    )
    repository.append_message(
        conversation_id=conversation_id,
        organization_id=organization_id,
        role="user",
        content=message,
        sender_user_id=user_id,
    )
    return repository


def _persist_assistant_result(
    repository,
    *,
    conversation_id: str,
    organization_id: str,
    user_id: str,
    result: dict[str, Any],
) -> None:
    if repository is None:
        return
    message = repository.append_message(
        conversation_id=conversation_id,
        organization_id=organization_id,
        role="assistant",
        content=str(result.get("assistant_message") or ""),
        metadata={
            "tools_used": result.get("tools_used", []),
            "activities": result.get("activities", []),
            "active_investigation_id": result.get(
                "active_investigation_id"
            ),
            "active_alert_id": result.get("active_alert_id"),
        },
    )
    messages = repository.list_messages(
        conversation_id,
        organization_id=organization_id,
        limit=200,
    )
    if (
        len(messages) >= CONVERSATION_SUMMARY_INTERVAL
        and len(messages) % CONVERSATION_SUMMARY_INTERVAL == 0
    ):
        digest = "\n".join(
            f"{item['role']}: {item['content']}"
            for item in messages[-10:]
        )
        repository.save_summary(
            conversation_id=conversation_id,
            organization_id=organization_id,
            content=digest,
            message_count=len(messages),
            through_message_id=message["message_id"],
        )

    structured = result.get("response")
    if isinstance(structured, dict) and structured:
        memory_value = {
            "assistant_summary": str(
                result.get("assistant_message") or ""
            )[:1000],
            "active_alert_id": result.get("active_alert_id"),
            "active_agent_id": result.get("active_agent_id"),
            "active_investigation_id": result.get(
                "active_investigation_id"
            ),
            "findings": structured,
        }
        repository.upsert_memory(
            organization_id=organization_id,
            user_id=user_id,
            namespace=f"org/{organization_id}/user/{user_id}/soc",
            memory_key=f"conversation:{conversation_id}:latest",
            asset_id=result.get("active_agent_id"),
            investigation_id=result.get("active_investigation_id"),
            value=memory_value,
        )
        put_curated_soc_memory(
            namespace=(
                organization_id,
                user_id,
                str(result.get("active_agent_id") or "no-asset"),
                str(
                    result.get("active_investigation_id")
                    or "no-investigation"
                ),
            ),
            key=f"conversation:{conversation_id}:latest",
            value=memory_value,
        )


def conversation_config(
    conversation_id: str,
    *,
    organization_id: str = "local",
) -> dict:
    if not conversation_id:
        raise ValueError("conversation_id is required.")
    if not organization_id:
        raise ValueError("organization_id is required.")
    return {
        "configurable": {
            "thread_id": f"{organization_id}:{conversation_id}",
        },
        "metadata": {
            "organization_id": organization_id,
            "conversation_id": conversation_id,
        },
    }


def build_chat_context(
    *,
    organization_id: str = "local",
    user_id: str = "local",
    gateway=None,
) -> SOCChatContext:
    wazuh = gateway or get_wazuh_gateway()
    try:
        wazuh.indexer_health()
        wazuh.validate_server()
        wazuh_status = "healthy"
    except Exception:
        wazuh_status = "unavailable"

    return SOCChatContext(
        organization_id=organization_id,
        user_id=user_id,
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
                "id": call_id,
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


def _client_tool_results(tool_results: list[dict]) -> list[dict]:
    """Bound large evidence arrays in the HTTP response, not the agent state."""
    compacted = deepcopy(tool_results)
    for item in compacted:
        result = item.get("result")
        data = result.get("data") if isinstance(result, dict) else None
        if not isinstance(data, dict):
            continue
        if item.get("tool") == "get_endpoint_inventory":
            values = data.get("items")
            if not isinstance(values, list):
                continue
            data["items"] = values[:MAX_CLIENT_INVENTORY_ITEMS]
            data["response_items"] = len(data["items"])
            data["response_truncated"] = len(values) > len(data["items"])
        elif item.get("tool") == "get_endpoint_security_findings":
            response_truncated = False
            for key in (
                "fim_findings",
                "sca_findings",
                "rootcheck_findings",
            ):
                values = data.get(key)
                if not isinstance(values, list):
                    continue
                data[key] = values[:MAX_CLIENT_INVENTORY_ITEMS]
                response_truncated = (
                    response_truncated or len(values) > len(data[key])
                )
            data["response_truncated"] = response_truncated
    return compacted


def _latest_answer(messages: list[Any]) -> str:
    for message in reversed(_current_turn(messages)):
        if isinstance(message, AIMessage) or getattr(message, "type", "") == "ai":
            if not (getattr(message, "tool_calls", None) or []):
                content = _message_text(message)
                if content:
                    return content
    fallback = _tool_result_fallback(messages)
    if fallback:
        return fallback
    raise ValueError("The conversational agent did not produce a final answer.")


def _tool_result_fallback(messages: list[Any]) -> str | None:
    """Produce a grounded answer when tools finished but final model synthesis failed."""
    _, _, tool_results = _turn_details(messages)
    if not tool_results:
        return None

    started = [
        item.get("result")
        for item in tool_results
        if item.get("tool") == "start_investigation"
        and isinstance(item.get("result"), dict)
        and item["result"].get("ok") is True
    ]
    if started:
        snapshot = started[-1].get("data") or {}
        return (
            "The exact alert was verified and formal investigation "
            f"{snapshot.get('investigation_id', '')} was started. Its current "
            f"status is {snapshot.get('status', 'unknown')}. The completed "
            "workflow result is available in the structured investigation "
            "record."
        )

    failed_start = [
        item.get("result")
        for item in tool_results
        if item.get("tool") == "start_investigation"
        and isinstance(item.get("result"), dict)
        and item["result"].get("ok") is False
    ]
    if failed_start:
        error = failed_start[-1].get("error") or {}
        return (
            f"{error.get('message', 'The formal investigation did not start.')} "
            "No investigation or response action was created."
        )

    inventory = [
        item.get("result")
        for item in tool_results
        if item.get("tool") == "get_endpoint_inventory"
        and isinstance(item.get("result"), dict)
        and item["result"].get("ok") is True
    ]
    endpoint_findings = [
        item.get("result")
        for item in tool_results
        if item.get("tool") == "get_endpoint_security_findings"
        and isinstance(item.get("result"), dict)
        and item["result"].get("ok") is True
    ]
    if inventory or endpoint_findings:
        details = []
        if inventory:
            data = inventory[-1].get("data") or {}
            details.append(
                f"{data.get('returned', 0)} of {data.get('total', 0)} "
                f"{data.get('component', 'inventory')} records"
            )
        if endpoint_findings:
            data = endpoint_findings[-1].get("data") or {}
            details.append(
                f"FIM {data.get('fim_total', 0)}, "
                f"SCA {data.get('sca_total', 0)}, and "
                f"rootcheck {data.get('rootcheck_total', 0)} findings"
            )
        return (
            f"The endpoint evidence query returned {'; '.join(details)}. "
            "The model provider did not complete an anomaly "
            "assessment, so the inventory alone must not be treated as proof "
            "that the endpoint is clean."
        )

    archive_results = [
        item.get("result")
        for item in tool_results
        if item.get("tool") == "search_archived_wazuh_logs"
        and isinstance(item.get("result"), dict)
    ]
    if archive_results:
        successful = [
            result
            for result in archive_results
            if result.get("ok") is True and isinstance(result.get("data"), dict)
        ]
        if successful and all(
            int(result["data"].get("returned") or 0) == 0
            for result in successful
        ):
            return (
                "The archived Wazuh searches completed, but no matching events "
                "were found. This does not prove the activity did not occur: "
                "archive indexing may be disabled, empty, or outside the searched "
                "window. The model provider failed before it could add further "
                "analysis."
            )
        if successful:
            return (
                "The archived Wazuh searches returned matching events, but the "
                "model provider failed before completing an evidence-grounded "
                "summary. Review the structured tool results for the retrieved "
                "evidence."
            )

    failed = [
        item
        for item in tool_results
        if isinstance(item.get("result"), dict)
        and item["result"].get("ok") is False
    ]
    if failed:
        error = failed[-1]["result"].get("error") or {}
        message = error.get("message") or "The Wazuh evidence request failed."
        return f"{message} The completed tool error is preserved in the result."

    return (
        "The Wazuh tools completed, but the model provider failed before "
        "producing a final analysis. Review the structured tool results."
    )


def _stream_error_payload(error: Exception) -> dict[str, str]:
    name = type(error).__name__.lower()
    if "timeout" in name:
        return {
            "code": "SOC_MODEL_TIMEOUT",
            "message": (
                "The model provider timed out. Completed Wazuh tool results were "
                "preserved; retry the analysis."
            ),
        }
    if "rate" in name or "resourceexhausted" in name:
        return {
            "code": "SOC_MODEL_RATE_LIMITED",
            "message": (
                "The model providers are temporarily rate limited. Retry after "
                "a short delay."
            ),
        }
    return {
        "code": "SOC_MODEL_UNAVAILABLE",
        "message": (
            "The model providers could not complete the SOC analysis. Wazuh may "
            "still be available; retry the request."
        ),
    }


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
    organization_id: str | None = None,
    investigation_service: InvestigationService | None = None,
) -> dict[str, Any]:
    messages = list(state.get("messages") or [])
    tools, activities, tool_results = _turn_details(messages)
    active_investigation_id = state.get("active_investigation_id")
    snapshot = None
    if active_investigation_id:
        service = investigation_service or get_investigation_service()
        try:
            if organization_id is None:
                snapshot = service.snapshot(active_investigation_id)
            else:
                snapshot = service.snapshot(
                    active_investigation_id,
                    organization_id=organization_id,
                )
        except InvestigationNotFoundError:
            snapshot = None

    structured_result = _formal_result(snapshot)
    if structured_result is None and isinstance(
        state.get("attribution_result"), dict
    ):
        structured_result = state["attribution_result"]
    if structured_result is None and tool_results:
        structured_result = {
            "tool_results": _client_tool_results(tool_results)
        }

    return {
        "conversation_id": conversation_id,
        "assistant_message": _latest_answer(messages),
        "response": structured_result or {},
        "tools_used": tools,
        "activities": activities,
        "active_investigation_id": active_investigation_id,
        "active_alert_id": state.get("active_alert_id"),
        "active_agent_id": state.get("active_agent_id"),
        "investigation": snapshot,
        "investigation_progress": state.get("investigation_progress"),
        "missing_evidence": state.get("missing_evidence", []),
        "tool_errors": state.get("tool_errors", []),
    }


def run_soc_conversation(
    *,
    message: str,
    conversation_id: str,
    organization_id: str = "local",
    user_id: str = "local",
    agent=None,
    context: SOCChatContext | None = None,
    investigation_service: InvestigationService | None = None,
) -> dict[str, Any]:
    chat_agent = agent or get_soc_chat_agent()
    repository = _persist_user_message(
        conversation_id=conversation_id,
        organization_id=organization_id,
        user_id=user_id,
        message=message,
    )
    result = chat_agent.invoke(
        {"messages": [{"role": "user", "content": message}]},
        config=conversation_config(
            conversation_id,
            organization_id=organization_id,
        ),
        context=context or build_chat_context(
            organization_id=organization_id,
            user_id=user_id,
        ),
    )
    serialized = serialize_conversation_result(
        result,
        conversation_id=conversation_id,
        organization_id=organization_id,
        investigation_service=investigation_service,
    )
    _persist_assistant_result(
        repository,
        conversation_id=conversation_id,
        organization_id=organization_id,
        user_id=user_id,
        result=serialized,
    )
    return serialized


def stream_soc_conversation(
    *,
    message: str,
    conversation_id: str,
    organization_id: str = "local",
    user_id: str = "local",
    agent=None,
    context: SOCChatContext | None = None,
    investigation_service: InvestigationService | None = None,
) -> Iterator[tuple[str, dict[str, Any]]]:
    chat_agent = agent or get_soc_chat_agent()
    repository = _persist_user_message(
        conversation_id=conversation_id,
        organization_id=organization_id,
        user_id=user_id,
        message=message,
    )
    config = conversation_config(
        conversation_id,
        organization_id=organization_id,
    )
    runtime_context = context or build_chat_context(
        organization_id=organization_id,
        user_id=user_id,
    )
    emitted_calls: set[str] = set()
    emitted_completions: set[str] = set()
    stream_queue: Queue[tuple[str, Any]] = Queue()
    stop_stream = Event()
    heartbeat_count = 0
    answer_started = False

    def consume_agent_stream() -> None:
        try:
            for item in chat_agent.stream(
                {"messages": [{"role": "user", "content": message}]},
                config=config,
                context=runtime_context,
                stream_mode=["messages", "updates"],
            ):
                if stop_stream.is_set():
                    break
                stream_queue.put(("chunk", item))
        except Exception as exc:
            stream_queue.put(("error", exc))
        finally:
            stream_queue.put(("done", None))

    Thread(
        target=consume_agent_stream,
        name=f"soc-chat-{conversation_id[:12]}",
        daemon=True,
    ).start()

    yield (
        "activity",
        {
            "id": "analysis",
            "tool": None,
            "label": "Understanding the request",
            "status": "running",
        },
    )

    try:
        while True:
            try:
                item_type, item = stream_queue.get(
                    timeout=STREAM_HEARTBEAT_SECONDS
                )
            except Empty:
                heartbeat_count += 1
                if emitted_completions:
                    label = "Reviewing retrieved evidence"
                elif emitted_calls:
                    label = "Waiting for Wazuh tool results"
                elif heartbeat_count == 1:
                    label = "Contacting the analysis model"
                else:
                    label = "Analysis is still running"
                yield (
                    "heartbeat",
                    {
                        "conversation_id": conversation_id,
                        "timestamp": datetime.now(UTC).isoformat(),
                    },
                )
                yield (
                    "activity",
                    {
                        "id": "analysis",
                        "tool": None,
                        "label": label,
                        "status": "running",
                    },
                )
                continue

            if item_type == "error":
                raise item
            if item_type == "done":
                break

            mode, chunk = item
            if mode == "messages":
                stream_message, metadata = chunk
                if metadata.get("langgraph_node") != "model":
                    continue
                if getattr(stream_message, "tool_calls", None):
                    continue
                content = _message_text(stream_message)
                if content:
                    if not answer_started:
                        answer_started = True
                        yield (
                            "activity",
                            {
                                "id": "analysis",
                                "tool": None,
                                "label": "Preparing the response",
                                "status": "running",
                            },
                        )
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
                                "id": call_id,
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
                                "id": call_id,
                                "tool": name,
                                "label": TOOL_ACTIVITY_LABELS.get(
                                    name,
                                    name.replace("_", " "),
                                ),
                                "status": status,
                            },
                        )
                        if status == "completed":
                            yield (
                                "activity",
                                {
                                    "id": "analysis",
                                    "tool": None,
                                    "label": "Reviewing retrieved evidence",
                                    "status": "running",
                                },
                            )

        state = dict(chat_agent.get_state(config).values)
        yield (
            "activity",
            {
                "id": "analysis",
                "tool": None,
                "label": "Analysis complete",
                "status": "completed",
            },
        )
        serialized = serialize_conversation_result(
            state,
            conversation_id=conversation_id,
            organization_id=organization_id,
            investigation_service=investigation_service,
        )
        _persist_assistant_result(
            repository,
            conversation_id=conversation_id,
            organization_id=organization_id,
            user_id=user_id,
            result=serialized,
        )
        yield ("final", serialized)
    except Exception as exc:
        logger.exception(
            "SOC conversation stream failed conversation_id=%s error_type=%s",
            conversation_id,
            type(exc).__name__,
        )
        try:
            state = dict(chat_agent.get_state(config).values)
            if _tool_result_fallback(list(state.get("messages") or [])):
                serialized = serialize_conversation_result(
                    state,
                    conversation_id=conversation_id,
                    organization_id=organization_id,
                    investigation_service=investigation_service,
                )
                _persist_assistant_result(
                    repository,
                    conversation_id=conversation_id,
                    organization_id=organization_id,
                    user_id=user_id,
                    result=serialized,
                )
                yield ("final", serialized)
                return
        except Exception:
            logger.exception(
                "SOC conversation recovery failed conversation_id=%s",
                conversation_id,
            )
        yield ("error", _stream_error_payload(exc))
    finally:
        stop_stream.set()
