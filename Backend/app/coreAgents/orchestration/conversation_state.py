"""Short-term state and invocation context for conversational SOC chat."""

from dataclasses import dataclass
from typing import Any, NotRequired

from langchain.agents import AgentState


class SOCChatState(AgentState):
    active_investigation_id: NotRequired[str]
    active_alert_id: NotRequired[str]
    active_agent_id: NotRequired[str]
    current_severity: NotRequired[str]
    current_investigation_stage: NotRequired[str]
    investigation_status: NotRequired[str]
    known_facts: NotRequired[list[str]]
    missing_evidence: NotRequired[list[str]]
    investigation_evidence: NotRequired[list[dict[str, Any]]]
    attempted_tools: NotRequired[list[str]]
    tool_errors: NotRequired[list[dict[str, Any]]]
    investigation_progress: NotRequired[dict[str, Any]]
    attribution_result: NotRequired[dict[str, Any]]


@dataclass(frozen=True)
class SOCChatContext:
    current_time: str
    wazuh_status: str
    permissions: tuple[str, ...]
    allowed_tools: tuple[str, ...]
    active_response_enabled: bool
