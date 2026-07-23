from langchain.agents.middleware import (
    ModelCallLimitMiddleware,
    ModelFallbackMiddleware,
    ToolCallLimitMiddleware,
)
from langchain_core.runnables import RunnableLambda
from pydantic import BaseModel

from app.coreAgents.llm import model_pool


class SampleResult(BaseModel):
    summary: str


def test_each_soc_tier_has_a_different_primary_provider():
    assert model_pool.AGENT_PROVIDER_ORDER["l1"][0] == "groq"
    assert model_pool.AGENT_PROVIDER_ORDER["l2"][0] == "cerebras"
    assert model_pool.AGENT_PROVIDER_ORDER["l3"][0] == "gemini"


def test_every_agent_role_can_fall_back_to_all_other_providers():
    expected = {"groq", "oxy", "cerebras", "gemini"}
    for order in model_pool.AGENT_PROVIDER_ORDER.values():
        assert set(order) == expected
        assert len(order) == len(expected)


def test_agent_middleware_limits_calls_and_adds_fallbacks():
    middleware = model_pool.get_agent_middleware("l2")
    assert any(isinstance(item, ModelCallLimitMiddleware) for item in middleware)
    assert any(isinstance(item, ModelFallbackMiddleware) for item in middleware)
    assert any(isinstance(item, ToolCallLimitMiddleware) for item in middleware)


def test_structured_model_uses_next_provider_after_failure(monkeypatch):
    class FakeStructuredModel:
        def __init__(self, result=None, error=None):
            self.result = result
            self.error = error

        def with_structured_output(self, schema, method):
            def invoke(_):
                if self.error:
                    raise self.error
                return schema.model_validate(self.result)

            return RunnableLambda(invoke)

    monkeypatch.setitem(
        model_pool.STRUCTURED_MODELS,
        "oxy",
        FakeStructuredModel(error=RuntimeError("rate limited")),
    )
    monkeypatch.setitem(
        model_pool.STRUCTURED_MODELS,
        "groq",
        FakeStructuredModel(result={"summary": "fallback worked"}),
    )

    runnable = model_pool.get_structured_model(
        SampleResult,
        ("oxy", "groq"),
    )

    assert runnable.invoke("test").summary == "fallback worked"
