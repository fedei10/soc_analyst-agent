"""Initialize TSAGE tables and LangGraph PostgreSQL checkpoint tables."""

from pathlib import Path

from alembic import command
from alembic.config import Config

from app.db.checkpointer import _postgres_uri
from app.db.session import database_url


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    url = database_url()
    if not url:
        raise SystemExit("DATABASE_URL is not configured.")

    from langgraph.checkpoint.postgres import PostgresSaver
    from langgraph.store.postgres import PostgresStore

    alembic_config = Config(str(PROJECT_ROOT / "alembic.ini"))
    alembic_config.set_main_option(
        "script_location",
        str(PROJECT_ROOT / "migrations"),
    )
    command.upgrade(alembic_config, "head")
    with PostgresSaver.from_conn_string(_postgres_uri(url)) as checkpointer:
        checkpointer.setup()
    with PostgresStore.from_conn_string(_postgres_uri(url)) as store:
        store.setup()
    print("TSAGE PostgreSQL schema initialized.")


if __name__ == "__main__":
    main()
