from langchain.agents.middleware import (
    ModelCallLimitMiddleware,
    ModelRetryMiddleware,
    ToolCallLimitMiddleware,
)
from langchain_core.runnables import RunnableLambda
from pydantic import BaseModel

from app.coreAgents.llm import model_pool


class SampleResult(BaseModel):
    summary: str


def test_each_soc_role_has_the_assigned_provider():
    assert model_pool.AGENT_PROVIDER["chat"] == "gemini"
    assert model_pool.AGENT_PROVIDER["l1"] == "cerebras"
    assert model_pool.AGENT_PROVIDER["l2"] == "groq"
    assert model_pool.AGENT_PROVIDER["l3"] == "oxy"


def test_orchestrator_uses_only_gemini():
    assert model_pool.ROUTER_PROVIDER_ORDER == ("gemini",)


def test_agent_middleware_limits_calls_without_cross_provider_fallbacks():
    middleware = model_pool.get_agent_middleware("l2")
    assert any(isinstance(item, ModelCallLimitMiddleware) for item in middleware)
    assert any(isinstance(item, ModelRetryMiddleware) for item in middleware)
    assert any(isinstance(item, ToolCallLimitMiddleware) for item in middleware)
    assert len(middleware) == 3


def test_structured_model_uses_only_assigned_provider(monkeypatch):
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
        "cerebras",
        FakeStructuredModel(result={"summary": "assigned provider worked"}),
    )

    runnable = model_pool.get_structured_model(
        SampleResult,
        ("cerebras",),
    )

    assert runnable.invoke("test").summary == "assigned provider worked"
