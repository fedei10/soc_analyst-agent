"""LangGraph checkpoint selection and lifecycle."""

from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Any

from langgraph.checkpoint.memory import InMemorySaver

from app.config import settings
from app.db.session import database_url
from app.mape_k.serde import create_checkpoint_serializer


class CheckpointerConfigurationError(RuntimeError):
    """Raised when durable workflow state is required but unavailable."""


def _postgres_uri(value: str) -> str:
    return (
        value
        .replace("postgresql+psycopg2://", "postgresql://", 1)
        .replace("postgresql+psycopg://", "postgresql://", 1)
    )


@dataclass
class CheckpointerHandle:
    saver: Any
    context: AbstractContextManager | None = None

    def close(self) -> None:
        if self.context is not None:
            self.context.__exit__(None, None, None)
            self.context = None


def create_investigation_checkpointer() -> CheckpointerHandle:
    backend = settings.MAPEK_CHECKPOINTER_BACKEND.strip().lower()
    if backend not in {"auto", "memory", "postgres"}:
        raise CheckpointerConfigurationError(
            "MAPEK_CHECKPOINTER_BACKEND must be auto, memory, or postgres."
        )

    url = database_url()
    production = settings.ENVIRONMENT.strip().lower() in {"prod", "production"}
    in_memory_allowed = bool(settings.MAPEK_ALLOW_INMEMORY_CHECKPOINTER)
    use_postgres = backend == "postgres" or (backend == "auto" and bool(url))

    if use_postgres and not url:
        raise CheckpointerConfigurationError(
            "The PostgreSQL checkpointer requires DATABASE_URL."
        )

    if not use_postgres:
        if production:
            raise CheckpointerConfigurationError(
                "Production investigations require the PostgreSQL checkpointer."
            )
        if not in_memory_allowed:
            raise CheckpointerConfigurationError(
                "The in-memory investigation checkpointer is disabled."
            )
        return CheckpointerHandle(
            saver=InMemorySaver(serde=create_checkpoint_serializer())
        )

    from langgraph.checkpoint.postgres import PostgresSaver

    context = PostgresSaver.from_conn_string(_postgres_uri(url))
    saver = context.__enter__()
    saver.serde = create_checkpoint_serializer()
    if settings.DATABASE_AUTO_CREATE:
        saver.setup()
    return CheckpointerHandle(saver=saver, context=context)
