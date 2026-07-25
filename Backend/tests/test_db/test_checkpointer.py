import pytest
from langgraph.checkpoint.memory import InMemorySaver

from app.config import settings
from app.db import checkpointer


def configure_memory(monkeypatch, *, environment="development", allowed=True):
    monkeypatch.setattr(settings, "ENVIRONMENT", environment)
    monkeypatch.setattr(settings, "MAPEK_CHECKPOINTER_BACKEND", "memory")
    monkeypatch.setattr(settings, "MAPEK_ALLOW_INMEMORY_CHECKPOINTER", allowed)
    monkeypatch.setattr(checkpointer, "database_url", lambda: None)


def test_development_can_explicitly_use_memory_checkpointer(monkeypatch):
    configure_memory(monkeypatch)

    handle = checkpointer.create_investigation_checkpointer()

    assert isinstance(handle.saver, InMemorySaver)
    assert handle.context is None


def test_production_rejects_memory_checkpointer(monkeypatch):
    configure_memory(monkeypatch, environment="production")

    with pytest.raises(
        checkpointer.CheckpointerConfigurationError,
        match="Production investigations require",
    ):
        checkpointer.create_investigation_checkpointer()


def test_memory_checkpointer_can_be_disabled_in_development(monkeypatch):
    configure_memory(monkeypatch, allowed=False)

    with pytest.raises(
        checkpointer.CheckpointerConfigurationError,
        match="in-memory investigation checkpointer is disabled",
    ):
        checkpointer.create_investigation_checkpointer()


def test_postgres_backend_requires_database_url(monkeypatch):
    monkeypatch.setattr(settings, "ENVIRONMENT", "development")
    monkeypatch.setattr(settings, "MAPEK_CHECKPOINTER_BACKEND", "postgres")
    monkeypatch.setattr(settings, "MAPEK_ALLOW_INMEMORY_CHECKPOINTER", True)
    monkeypatch.setattr(checkpointer, "database_url", lambda: None)

    with pytest.raises(
        checkpointer.CheckpointerConfigurationError,
        match="requires DATABASE_URL",
    ):
        checkpointer.create_investigation_checkpointer()
