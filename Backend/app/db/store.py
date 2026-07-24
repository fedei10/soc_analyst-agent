"""LangGraph cross-thread store selection and lifecycle."""

from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Any

from langgraph.store.memory import InMemoryStore

from app.config import settings
from app.db.checkpointer import _postgres_uri
from app.db.session import database_url


@dataclass
class StoreHandle:
    store: Any
    context: AbstractContextManager | None = None

    def close(self) -> None:
        if self.context is not None:
            self.context.__exit__(None, None, None)
            self.context = None


def create_memory_store() -> StoreHandle:
    """Create the cross-thread store; PostgreSQL is authoritative when set."""

    url = database_url()
    if not url:
        return StoreHandle(store=InMemoryStore())

    from langgraph.store.postgres import PostgresStore

    context = PostgresStore.from_conn_string(_postgres_uri(url))
    store = context.__enter__()
    if settings.DATABASE_AUTO_CREATE:
        store.setup()
    return StoreHandle(store=store, context=context)
