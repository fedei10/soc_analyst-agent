"""Role-specific model selection and cross-provider fallbacks."""

from collections.abc import Sequence
from typing import Literal

from langchain.agents.middleware import (
    ModelCallLimitMiddleware,
    ModelFallbackMiddleware,
    ToolCallLimitMiddleware,
)
from pydantic import BaseModel

from app.coreAgents.llm.cerebras import llm as cerebras_llm
from app.coreAgents.llm.cerebras import structured_llm as cerebras_structured_llm
from app.coreAgents.llm.gemini import llm as gemini_llm
from app.coreAgents.llm.gemini import structured_llm as gemini_structured_llm
from app.coreAgents.llm.groq import llm as groq_llm
from app.coreAgents.llm.groq import structured_llm as groq_structured_llm
from app.coreAgents.llm.oxy import llm as oxy_llm
from app.coreAgents.llm.oxy import structured_llm as oxy_structured_llm


ProviderName = Literal["groq", "oxy", "cerebras", "gemini"]
AgentRole = Literal["chat", "l1", "l2", "l3"]

AGENT_MODELS = {
    "groq": groq_llm,
    "oxy": oxy_llm,
    "cerebras": cerebras_llm,
    "gemini": gemini_llm,
}

STRUCTURED_MODELS = {
    "groq": groq_structured_llm,
    "oxy": oxy_structured_llm,
    "cerebras": cerebras_structured_llm,
    "gemini": gemini_structured_llm,
}

# Different primaries spread normal traffic across quotas. Every model call can
# fail over to the other providers when a provider is throttled or unavailable.
AGENT_PROVIDER_ORDER: dict[AgentRole, tuple[ProviderName, ...]] = {
    "chat": ("gemini", "cerebras", "groq", "oxy"),
    "l1": ("groq", "oxy", "cerebras", "gemini"),
    "l2": ("cerebras", "oxy", "groq", "gemini"),
    "l3": ("gemini", "oxy", "cerebras", "groq"),
}
ROUTER_PROVIDER_ORDER: tuple[ProviderName, ...] = (
    "oxy",
    "groq",
    "gemini",
    "cerebras",
)
FORMATTER_PROVIDER_ORDER: tuple[ProviderName, ...] = (
    "gemini",
    "groq",
    "oxy",
    "cerebras",
)


def get_agent_model(role: AgentRole):
    return AGENT_MODELS[AGENT_PROVIDER_ORDER[role][0]]


def get_agent_middleware(role: AgentRole) -> list:
    order = AGENT_PROVIDER_ORDER[role]
    fallbacks = [AGENT_MODELS[name] for name in order[1:]]
    model_limit = 10 if role == "chat" else 8
    tool_limit = 8 if role == "chat" else 6
    return [
        ModelCallLimitMiddleware(run_limit=model_limit, exit_behavior="end"),
        ModelFallbackMiddleware(*fallbacks),
        ToolCallLimitMiddleware(run_limit=tool_limit, exit_behavior="continue"),
    ]


def _structured_runnable(model, schema: type[BaseModel]):
    method = "function_calling" if model is cerebras_structured_llm else "json_schema"
    return model.with_structured_output(schema, method=method)


def get_structured_model(
    schema: type[BaseModel],
    provider_order: Sequence[ProviderName],
):
    if not provider_order:
        raise ValueError("At least one structured model provider is required.")

    models = [
        _structured_runnable(STRUCTURED_MODELS[name], schema)
        for name in provider_order
    ]
    return models[0].with_fallbacks(models[1:])
