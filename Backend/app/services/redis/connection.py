"""Optional Redis connection lifecycle."""

from __future__ import annotations

from functools import lru_cache
from typing import Any

import redis

from app.config import settings


class RedisNotConfiguredError(RuntimeError):
    pass


def _setting_value(name: str, default: Any = None) -> Any:
    value = getattr(settings, name, default)
    get_secret_value = getattr(value, "get_secret_value", None)
    return get_secret_value() if callable(get_secret_value) else value


def redis_url() -> str | None:
    configured_url = str(_setting_value("REDIS_URL", "") or "").strip()
    if configured_url:
        return configured_url

    host = str(_setting_value("REDIS_HOST", "") or "").strip()
    if not host:
        return None
    port = int(_setting_value("REDIS_PORT", 6379))
    database = int(_setting_value("REDIS_DB", 0))
    password = str(_setting_value("REDIS_PASSWORD", "") or "")
    if password:
        from urllib.parse import quote

        return f"redis://:{quote(password, safe='')}@{host}:{port}/{database}"
    return f"redis://{host}:{port}/{database}"


@lru_cache(maxsize=1)
def get_redis_connection() -> redis.Redis:
    url = redis_url()
    if not url:
        raise RedisNotConfiguredError("Redis is not configured.")
    return redis.Redis.from_url(
        url,
        decode_responses=True,
        socket_connect_timeout=1.0,
        socket_timeout=1.0,
        health_check_interval=30,
        retry_on_timeout=True,
    )


def check_redis() -> dict[str, str]:
    if not redis_url():
        return {"status": "disabled"}
    try:
        get_redis_connection().ping()
    except (redis.RedisError, OSError):
        return {"status": "degraded"}
    return {"status": "healthy"}


def close_redis_connection() -> None:
    if get_redis_connection.cache_info().currsize:
        get_redis_connection().close()
    get_redis_connection.cache_clear()


def test_redis_connection() -> str:
    """Compatibility wrapper for the original diagnostic helper."""

    return check_redis()["status"]
