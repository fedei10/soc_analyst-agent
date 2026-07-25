import os
from types import SimpleNamespace

from pydantic import SecretStr

from app.core.langsmith import configure_langsmith


def test_langsmith_hides_soc_inputs_and_outputs_by_default(monkeypatch):
    for name in (
        "LANGSMITH_API_KEY",
        "LANGSMITH_TRACING",
        "LANGCHAIN_TRACING_V2",
        "LANGSMITH_PROJECT",
        "LANGSMITH_HIDE_INPUTS",
        "LANGSMITH_HIDE_OUTPUTS",
        "LANGSMITH_INCLUDE_RAW_ALERTS",
        "LANGSMITH_INCLUDE_FULL_LOG",
        "LANGSMITH_INCLUDE_FULL_INVENTORY",
    ):
        monkeypatch.delenv(name, raising=False)

    enabled = configure_langsmith(
        SimpleNamespace(
            LANGSMITH_API_KEY=SecretStr("test-key"),
            LANGSMITH_TRACING=True,
            LANGSMITH_PROJECT="tsage-test",
            LANGSMITH_ENDPOINT=None,
            LANGSMITH_HIDE_INPUTS=True,
            LANGSMITH_HIDE_OUTPUTS=True,
        )
    )

    assert enabled is True
    assert os.environ["LANGSMITH_HIDE_INPUTS"] == "true"
    assert os.environ["LANGSMITH_HIDE_OUTPUTS"] == "true"
    assert os.environ["LANGSMITH_INCLUDE_RAW_ALERTS"] == "false"
    assert os.environ["LANGSMITH_INCLUDE_FULL_LOG"] == "false"
    assert os.environ["LANGSMITH_INCLUDE_FULL_INVENTORY"] == "false"
