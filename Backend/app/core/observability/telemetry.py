"""Optional OpenTelemetry wiring with no collector dependency when disabled."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI


logger = logging.getLogger("tsage.telemetry")
_configured = False


def configure_telemetry(
    app: FastAPI,
    settings: Any,
    *,
    sqlalchemy_engine: Any = None,
) -> None:
    global _configured
    if not settings.OTEL_ENABLED or _configured:
        return

    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
        from opentelemetry.instrumentation.logging import LoggingInstrumentor
        from opentelemetry.instrumentation.psycopg import PsycopgInstrumentor
        from opentelemetry.instrumentation.redis import RedisInstrumentor
        from opentelemetry.instrumentation.requests import RequestsInstrumentor
        from opentelemetry.instrumentation.sqlalchemy import (
            SQLAlchemyInstrumentor,
        )
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.trace.sampling import (
            ParentBased,
            TraceIdRatioBased,
        )
        from opentelemetry.semconv.resource import ResourceAttributes
    except ImportError as exc:
        raise RuntimeError(
            "OTEL_ENABLED requires the OpenTelemetry packages in "
            "Backend/requirements.txt."
        ) from exc

    sample_ratio = min(max(float(settings.OTEL_TRACE_SAMPLE_RATIO), 0.0), 1.0)
    resource = Resource.create(
        {
            ResourceAttributes.SERVICE_NAME: settings.SERVICE_NAME,
            ResourceAttributes.SERVICE_VERSION: settings.SERVICE_VERSION,
            ResourceAttributes.DEPLOYMENT_ENVIRONMENT: settings.ENVIRONMENT,
        }
    )
    provider = TracerProvider(
        resource=resource,
        sampler=ParentBased(TraceIdRatioBased(sample_ratio)),
    )
    provider.add_span_processor(
        BatchSpanProcessor(
            OTLPSpanExporter(
                endpoint=settings.OTEL_EXPORTER_OTLP_ENDPOINT,
                insecure=settings.OTEL_EXPORTER_OTLP_INSECURE,
            )
        )
    )
    trace.set_tracer_provider(provider)
    FastAPIInstrumentor.instrument_app(
        app,
        tracer_provider=provider,
        excluded_urls="/health",
    )
    HTTPXClientInstrumentor().instrument(tracer_provider=provider)
    RequestsInstrumentor().instrument(tracer_provider=provider)
    RedisInstrumentor().instrument(tracer_provider=provider)
    PsycopgInstrumentor().instrument(tracer_provider=provider)
    LoggingInstrumentor().instrument(
        tracer_provider=provider,
        set_logging_format=False,
    )
    if sqlalchemy_engine is not None:
        SQLAlchemyInstrumentor().instrument(
            engine=sqlalchemy_engine,
            tracer_provider=provider,
        )
    _configured = True
    logger.info("OpenTelemetry instrumentation enabled.")
