"""Run a tool-capable agent and validate its final result separately."""

import json
import inspect
from typing import Any

from pydantic import BaseModel

from app.core.observability.callbacks import observability_callbacks
from app.services.wazuh.normalization.serializers import (
    compact_tool_result,
    serialize_for_trace,
)


MAX_TOOL_CONTENT_CHARS = 6000
MAX_COLLECTION_ITEMS = 12


class AgentResultValidationError(RuntimeError):
    """Final transcript exists, but structured normalization failed."""

    def __init__(self, response: dict[str, Any]) -> None:
        super().__init__("The agent output could not be validated.")
        self.response = response


def _compact_value(value: Any, *, depth: int = 0) -> Any:
    if depth >= 5:
        return "[depth limit]"
    if isinstance(value, dict):
        return {
            str(key): _compact_value(item, depth=depth + 1)
            for key, item in list(value.items())[:40]
        }
    if isinstance(value, list):
        compacted = [
            _compact_value(item, depth=depth + 1)
            for item in value[:MAX_COLLECTION_ITEMS]
        ]
        if len(value) > MAX_COLLECTION_ITEMS:
            compacted.append({
                "_truncated_items": len(value) - MAX_COLLECTION_ITEMS
            })
        return compacted
    if isinstance(value, str) and len(value) > 1500:
        return f"{value[:1500]}...[truncated]"
    return value


def _bounded_tool_content(content: Any) -> Any:
    if not isinstance(content, str):
        return _compact_value(content)
    try:
        parsed = json.loads(content)
    except (TypeError, ValueError):
        parsed = content
    compacted = _compact_value(parsed)
    rendered = (
        compacted
        if isinstance(compacted, str)
        else json.dumps(compacted, default=str)
    )
    if len(rendered) > MAX_TOOL_CONTENT_CHARS:
        return f"{rendered[:MAX_TOOL_CONTENT_CHARS]}...[truncated]"
    return rendered


def _serialize_message(message: Any) -> dict[str, Any]:
    if isinstance(message, dict):
        return serialize_for_trace(message)

    name = getattr(message, "name", None)
    serialized = {
        "type": getattr(message, "type", message.__class__.__name__),
        "content": getattr(message, "content", ""),
    }
    if serialized["type"] == "tool":
        content = serialized["content"]
        try:
            parsed = json.loads(content) if isinstance(content, str) else content
        except (TypeError, ValueError):
            parsed = content
        if isinstance(parsed, dict):
            parsed = compact_tool_result(name or "unknown", parsed)
        serialized["content"] = _bounded_tool_content(parsed)
    if name:
        serialized["name"] = name

    tool_calls = getattr(message, "tool_calls", None)
    if tool_calls:
        serialized["tool_calls"] = tool_calls

    return serialized


def _format_transcript(messages: list[Any]) -> str:
    return json.dumps(
        [_serialize_message(message) for message in messages],
        default=str,
    )


def invoke_validated_agent(
    agent,
    *,
    messages: list[dict[str, Any]],
    result_model: type[BaseModel],
    role: str | None = None,
) -> tuple[dict[str, Any], BaseModel]:
    """Execute tools, then normalize the transcript into a validated result."""
    from app.coreAgents.llm.model_pool import (
        get_agent_model,
        get_agent_provider,
    )

    provider = (
        get_agent_provider(role)
        if role in {"chat", "l1", "l2", "l3"}
        else "unknown"
    )
    model = (
        get_agent_model(role)
        if role in {"chat", "l1", "l2", "l3"}
        else None
    )
    model_name = str(
        getattr(model, "model_name", None)
        or getattr(model, "model", None)
        or "unknown"
    )
    config = {
        "callbacks": observability_callbacks(),
        "run_name": f"soc-{role or 'agent'}",
        "metadata": {
            "agent_role": role or "unknown",
            "provider": provider,
            "model": model_name,
        },
    }
    invoke_parameters = inspect.signature(agent.invoke).parameters
    supports_config = (
        "config" in invoke_parameters
        or any(
            parameter.kind is inspect.Parameter.VAR_KEYWORD
            for parameter in invoke_parameters.values()
        )
    )
    if supports_config:
        response = agent.invoke({"messages": messages}, config=config)
    else:
        response = agent.invoke({"messages": messages})
    if not isinstance(response, dict):
        raise ValueError("Agent response must be a mapping.")

    # Supports injected test agents and providers with native structured output.
    structured_response = response.get("structured_response")
    if structured_response is not None:
        return response, result_model.model_validate(structured_response)

    transcript = response.get("messages")
    if not isinstance(transcript, list) or not transcript:
        raise ValueError("Agent response did not contain a message transcript.")

    from app.coreAgents.llm.model_pool import (
        FORMATTER_PROVIDER_ORDER,
        get_structured_model,
    )

    provider_order = (
        (get_agent_provider(role),)
        if role is not None
        else FORMATTER_PROVIDER_ORDER
    )
    formatter = get_structured_model(
        result_model,
        provider_order,
    )
    try:
        formatted = formatter.invoke(
            [
                {
                    "role": "system",
                    "content": (
                        "Convert the completed SOC agent transcript into the "
                        "final result. Use only facts present in the "
                        "transcript. Return only the required structured "
                        "result. Do not infer evidence that the agent did not "
                        "observe."
                    ),
                },
                {
                    "role": "user",
                    "content": _format_transcript(transcript),
                },
            ],
            config={
                "callbacks": observability_callbacks(),
                "run_name": f"soc-{role or 'agent'}-formatter",
                "metadata": {
                    "agent_role": role or "unknown",
                    "provider": provider,
                    "model": model_name,
                },
            },
        )
        validated = result_model.model_validate(formatted)
    except Exception as exc:
        raise AgentResultValidationError(response) from exc
    return response, validated
