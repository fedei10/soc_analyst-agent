"""Tool-using, persistent conversational SOC agent."""

from functools import lru_cache

from langchain.agents import create_agent
from langchain.agents.middleware import ModelRequest, dynamic_prompt
from langgraph.checkpoint.memory import InMemorySaver

from app.coreAgents.llm.model_pool import (
    get_agent_middleware,
    get_agent_model,
)
from app.coreAgents.orchestration.conversation_state import (
    SOCChatContext,
    SOCChatState,
)
from app.coreAgents.orchestration.conversation_tools import (
    build_soc_chat_tools,
)
from app.coreAgents.tools.python_functions.yaml_loader import (
    load_prompt_template,
)


@dynamic_prompt
def soc_chat_prompt(request: ModelRequest) -> str:
    context: SOCChatContext = request.runtime.context
    state = request.state
    active_investigation = state.get("active_investigation_id", "none")
    active_alert = state.get("active_alert_id", "none")
    active_agent = state.get("active_agent_id", "none")
    severity = state.get("current_severity", "unknown")
    stage = state.get("current_investigation_stage", "none")
    investigation_status = state.get("investigation_status", "none")
    missing_evidence = state.get("missing_evidence", [])
    attempted_tools = state.get("attempted_tools", [])
    attribution = state.get("attribution_result", {})
    allowed_tools = ", ".join(context.allowed_tools)

    return (
        f"{load_prompt_template('soc_chat_system_prompt')}\n\n"
        "Current trusted runtime context:\n"
        f"- Current time: {context.current_time}\n"
        f"- Wazuh connection: {context.wazuh_status}\n"
        f"- Permissions: {', '.join(context.permissions)}\n"
        f"- Active response enabled: {context.active_response_enabled}\n"
        f"- Allowed tools: {allowed_tools}\n"
        f"- Active investigation ID: {active_investigation}\n"
        f"- Active alert ID: {active_alert}\n"
        f"- Active Wazuh agent ID: {active_agent}\n"
        f"- Current severity: {severity}\n"
        f"- Current investigation stage: {stage}\n"
        f"- Evidence collection status: {investigation_status}\n"
        f"- Missing evidence: {', '.join(missing_evidence) or 'none'}\n"
        f"- Previously attempted tools: {', '.join(attempted_tools[-12:]) or 'none'}\n"
        f"- Current attribution status: {attribution.get('status', 'none')}\n"
    )


def create_soc_chat_agent(
    *,
    model=None,
    tools=None,
    checkpointer=None,
):
    return create_agent(
        model=model or get_agent_model("chat"),
        tools=tools if tools is not None else build_soc_chat_tools(),
        middleware=[
            soc_chat_prompt,
            *get_agent_middleware("chat"),
        ],
        state_schema=SOCChatState,
        context_schema=SOCChatContext,
        checkpointer=checkpointer or InMemorySaver(),
        name="soc_chat_agent",
    )


@lru_cache(maxsize=1)
def get_soc_chat_agent():
    return create_soc_chat_agent()
