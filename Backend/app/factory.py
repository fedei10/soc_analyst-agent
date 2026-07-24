"""FastAPI application factory with observability configured at startup."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from typing import Any

from fastapi import FastAPI

from app.config import get_settings
from app.core.observability.logging import configure_logging
from app.core.observability.middleware import RequestObservabilityMiddleware
from app.core.observability.telemetry import configure_telemetry


Lifespan = Callable[[FastAPI], AbstractAsyncContextManager[Any]]


def create_app(*, lifespan: Lifespan | None = None) -> FastAPI:
    settings = get_settings()
    configure_logging(
        log_level=settings.LOG_LEVEL,
        environment=settings.ENVIRONMENT,
        service_name=settings.SERVICE_NAME,
        json_logs=settings.LOG_FORMAT.lower() == "json",
        include_callsite=settings.LOG_INCLUDE_CALLSITE,
    )
    app = FastAPI(
        title="tsage SOC API",
        version=settings.SERVICE_VERSION,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        description=(
            "Wazuh-backed SOC platform API. Application endpoints require a "
            "verified Clerk user session."
        ),
        lifespan=lifespan,
    )
    app.add_middleware(
        RequestObservabilityMiddleware,
        service_name=settings.SERVICE_NAME,
        slow_request_threshold_ms=settings.SLOW_REQUEST_THRESHOLD_MS,
    )

    engine = None
    if settings.OTEL_ENABLED:
        from app.db.session import database_url, get_engine

        if database_url():
            engine = get_engine()
    configure_telemetry(app, settings, sqlalchemy_engine=engine)
    return app
