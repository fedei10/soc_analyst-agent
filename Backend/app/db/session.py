"""Lazy SQLAlchemy engine and session lifecycle."""

from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.config import settings
from app.db.base import Base


class DatabaseNotConfiguredError(RuntimeError):
    pass


def database_url() -> str | None:
    value = settings.DATABASE_URL.get_secret_value().strip()
    return value or None


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    url = database_url()
    if not url:
        raise DatabaseNotConfiguredError("DATABASE_URL is not configured.")
    return create_engine(
        url,
        pool_pre_ping=True,
        pool_recycle=1800,
    )


@lru_cache(maxsize=1)
def get_session_factory() -> sessionmaker[Session]:
    return sessionmaker(
        bind=get_engine(),
        expire_on_commit=False,
        autoflush=False,
    )


def init_database() -> None:
    from app.db import models  # noqa: F401

    Base.metadata.create_all(bind=get_engine())


def check_database() -> dict[str, str]:
    if not database_url():
        return {"status": "disabled"}
    with get_engine().connect() as connection:
        connection.execute(text("SELECT 1"))
    return {"status": "healthy"}


@contextmanager
def session_scope() -> Iterator[Session]:
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def close_database() -> None:
    if get_engine.cache_info().currsize:
        get_engine().dispose()
    get_session_factory.cache_clear()
    get_engine.cache_clear()
