import os
from typing import Any


def configure_langsmith(settings: Any) -> bool:
    api_key = settings.LANGSMITH_API_KEY.get_secret_value()
    tracing_enabled = settings.LANGSMITH_TRACING

    if not tracing_enabled or not api_key:
        return False

    os.environ["LANGSMITH_API_KEY"] = api_key
    os.environ["LANGSMITH_TRACING"] = "true"
    # Keep the older flag in sync for LangChain versions that still read it.
    os.environ["LANGCHAIN_TRACING_V2"] = "true"
    os.environ["LANGSMITH_PROJECT"] = settings.LANGSMITH_PROJECT

    if settings.LANGSMITH_ENDPOINT:
        os.environ["LANGSMITH_ENDPOINT"] = settings.LANGSMITH_ENDPOINT

    return True
