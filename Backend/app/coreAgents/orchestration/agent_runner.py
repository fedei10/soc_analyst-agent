"""Run a tool-capable agent and validate its final result separately."""

import json
from typing import Any

from pydantic import BaseModel


def _serialize_message(message: Any) -> dict[str, Any]:
    if isinstance(message, dict):
        return message

    serialized = {
        "type": getattr(message, "type", message.__class__.__name__),
        "content": getattr(message, "content", ""),
    }
    name = getattr(message, "name", None)
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
        get_agent_provider,
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
    validated = formatter.invoke(
        [
            {
                "role": "system",
                "content": (
                    "Convert the completed SOC agent transcript into the final "
                    "result. Use only facts present in the transcript. Return "
                    "only the required structured result. Do not infer evidence "
                    "that the agent did not observe."
                ),
            },
            {
                "role": "user",
                "content": _format_transcript(transcript),
            },
        ]
    )
    return response, result_model.model_validate(validated)
