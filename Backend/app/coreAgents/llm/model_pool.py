"""Fixed provider assignment for each SOC role."""

from collections.abc import Sequence
from typing import Literal

from langchain.agents.middleware import (
    ModelCallLimitMiddleware,
    ModelRetryMiddleware,
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

AGENT_PROVIDER: dict[AgentRole, ProviderName] = {
    "chat": "gemini",
    "l1": "cerebras",
    "l2": "groq",
    "l3": "oxy",
}
ROUTER_PROVIDER_ORDER: tuple[ProviderName, ...] = ("gemini",)
FORMATTER_PROVIDER_ORDER: tuple[ProviderName, ...] = ("gemini",)


def _retryable_model_error(exc: Exception) -> bool:
    name = type(exc).__name__.lower()
    message = str(exc).lower()
    return (
        "ratelimit" in name
        or "timeout" in name
        or "429" in message
        or "queue_exceeded" in message
        or "temporarily unavailable" in message
        or "service unavailable" in message
    )


def get_agent_model(role: AgentRole):
    return AGENT_MODELS[get_agent_provider(role)]


def get_agent_provider(role: AgentRole) -> ProviderName:
    return AGENT_PROVIDER[role]


def get_agent_middleware(role: AgentRole) -> list:
    model_limit = 10 if role == "chat" else 8
    tool_limit = 8 if role == "chat" else 6
    return [
        ModelRetryMiddleware(
            max_retries=3,
            retry_on=_retryable_model_error,
            on_failure="error",
            initial_delay=2.0,
            backoff_factor=2.0,
            max_delay=20.0,
            jitter=True,
        ),
        ModelCallLimitMiddleware(run_limit=model_limit, exit_behavior="end"),
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
