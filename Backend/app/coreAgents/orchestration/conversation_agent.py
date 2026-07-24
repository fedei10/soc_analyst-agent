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
from app.db.checkpointer import (
    CheckpointerHandle,
    create_investigation_checkpointer,
)
from app.db.store import StoreHandle, create_memory_store
from app.db.sanitization import sanitize_for_storage


_chat_checkpointer: CheckpointerHandle | None = None
_chat_store: StoreHandle | None = None


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
    store=None,
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
        store=store,
        name="soc_chat_agent",
    )


@lru_cache(maxsize=1)
def get_soc_chat_agent():
    global _chat_checkpointer, _chat_store

    _chat_checkpointer = create_investigation_checkpointer()
    _chat_store = create_memory_store()
    return create_soc_chat_agent(
        checkpointer=_chat_checkpointer.saver,
        store=_chat_store.store,
    )


def close_soc_chat_agent() -> None:
    global _chat_checkpointer, _chat_store

    get_soc_chat_agent.cache_clear()
    if _chat_store is not None:
        _chat_store.close()
        _chat_store = None
    if _chat_checkpointer is not None:
        _chat_checkpointer.close()
        _chat_checkpointer = None


def put_curated_soc_memory(
    *,
    namespace: tuple[str, ...],
    key: str,
    value: dict,
) -> None:
    """Write validated application memory to the active LangGraph store."""

    if _chat_store is None:
        return
    _chat_store.store.put(
        namespace,
        key,
        sanitize_for_storage(value),
    )
