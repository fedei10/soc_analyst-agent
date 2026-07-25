"""
tsage SOC API.

- GET /health           -> bare liveness probe, no auth, no dependency fan-out
- /api/v1/health/*      -> authed diagnostics (wazuh:read)
- /api/v1/*             -> Wazuh surface for the SOC agents (read/write scopes)

Every error uses one envelope:
  {"error": {"code": "...", "message": "...", "detail": ...}, "request_id": "..."}
and every response carries an X-Request-ID header for log correlation.
"""
from contextlib import asynccontextmanager

import httpx
import structlog
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from opensearchpy import exceptions as opensearch_exc
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.v1.endpoints.findings import read as finding_read_router
from app.api.v1.endpoints.findings import write as finding_write_router
from app.api.v1.endpoints.health import router as health_router
from app.api.v1.endpoints.investigations import read as investigation_read_router
from app.api.v1.endpoints.investigations import write as investigation_write_router
from app.api.v1.endpoints.wazuh import read as wazuh_read_router
from app.api.v1.endpoints.wazuh import write as wazuh_write_router
from app.services.wazuh.dependencies import close_wazuh_dependencies
from app.coreAgents.orchestration.investigation_service import (
    close_investigation_service,
)
from app.db.session import close_database
from app.db.repositories.findings import close_finding_repository
from app.db.repositories.alert_memory import close_alert_memory_repository
from app.db.repositories.investigations import close_investigation_repository
from app.services.wazuh.exceptions import (
    WazuhAPIError,
    WazuhAuthError,
    WazuhDangerousActionBlocked,
    WazuhPermissionError,
    WazuhValidationError,
)
from app.services.redis.connection import close_redis_connection
from app.factory import create_app

logger = structlog.get_logger("tsage.api")


@asynccontextmanager
async def lifespan(_: FastAPI):
    yield
    close_investigation_service()
    close_wazuh_dependencies()
    close_investigation_repository()
    close_finding_repository()
    close_alert_memory_repository()
    close_database()
    close_redis_connection()

app = create_app(lifespan=lifespan)
app.include_router(health_router, prefix="/api/v1")
app.include_router(wazuh_read_router, prefix="/api/v1")
app.include_router(wazuh_write_router, prefix="/api/v1")
app.include_router(investigation_read_router, prefix="/api/v1")
app.include_router(investigation_write_router, prefix="/api/v1")
app.include_router(finding_read_router, prefix="/api/v1")
app.include_router(finding_write_router, prefix="/api/v1")

_HTTP_ERROR_CODES = {
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    409: "conflict",
    415: "unsupported_media_type",
    422: "validation_failed",
    429: "rate_limited",
    503: "service_unavailable",
}


def error_envelope(
    request: Request,
    status_code: int,
    code: str,
    message: str,
    detail=None,
    headers: dict | None = None,
) -> JSONResponse:
    response = JSONResponse(
        status_code=status_code,
        content={
            "error": {"code": code, "message": message, "detail": detail},
            "request_id": getattr(request.state, "request_id", None),
        },
        headers=headers,
    )
    # set here too: the 500 handler runs outside the middleware below
    response.headers["X-Request-ID"] = getattr(request.state, "request_id", "-")
    return response


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    code = _HTTP_ERROR_CODES.get(exc.status_code, "error")
    detail = exc.detail
    if isinstance(detail, dict) and detail.get("message"):
        code = str(detail.get("error") or code)
        message = str(detail["message"])
        extra = {
            key: value
            for key, value in detail.items()
            if key not in {"error", "message"}
        } or None
    else:
        message = str(detail)
        extra = None
    return error_envelope(
        request,
        exc.status_code,
        code,
        message,
        detail=extra,
        headers=exc.headers,
    )


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    return error_envelope(
        request, 422, "validation_failed",
        "Request validation failed — a required field is missing or has the wrong type.",
        exc.errors(),
    )


@app.exception_handler(httpx.HTTPStatusError)
async def wazuh_api_error_handler(request: Request, exc: httpx.HTTPStatusError):
    """The Wazuh server API answered with an error."""
    upstream = exc.response.status_code
    if upstream == 404:
        return error_envelope(
            request, 404, "not_found", "The requested Wazuh resource does not exist."
        )
    try:
        body = exc.response.json()
        detail = body.get("detail") or body.get("title")
    except Exception:
        detail = None
    logger.warning(
        "wazuh_request_failed",
        wazuh_component="server",
        status_code=upstream,
        detail=detail,
    )
    return error_envelope(
        request, 502, "wazuh_api_error", f"Wazuh API returned HTTP {upstream}.", detail
    )


@app.exception_handler(httpx.TransportError)
@app.exception_handler(opensearch_exc.TransportError)
async def wazuh_unreachable_handler(request: Request, exc: Exception):
    """Wazuh (server API or indexer) errored below the HTTP-success level."""
    if (
        isinstance(exc, opensearch_exc.TransportError)
        and not isinstance(exc, opensearch_exc.ConnectionError)
        and isinstance(exc.status_code, int)
    ):
        logger.warning(
            "wazuh_request_failed",
            wazuh_component="indexer",
            status_code=exc.status_code,
        )
        return error_envelope(
            request, 502, "wazuh_api_error",
            f"Wazuh indexer returned HTTP {exc.status_code}.",
        )
    logger.warning(
        "wazuh_request_failed",
        error_type=type(exc).__name__,
        failure_reason="unreachable",
    )
    return error_envelope(
        request, 503, "wazuh_unavailable",
        "Wazuh is unreachable — check /api/v1/health/wazuh for diagnostics.",
    )


@app.exception_handler(WazuhValidationError)
async def wazuh_validation_error_handler(request: Request, exc: WazuhValidationError):
    return error_envelope(request, 422, "validation_failed", str(exc))


@app.exception_handler(WazuhPermissionError)
async def wazuh_permission_error_handler(request: Request, exc: WazuhPermissionError):
    return error_envelope(request, 403, "forbidden", str(exc))


@app.exception_handler(WazuhDangerousActionBlocked)
async def wazuh_response_disabled_handler(
    request: Request, exc: WazuhDangerousActionBlocked
):
    return error_envelope(request, 503, "response_actions_disabled", str(exc))


@app.exception_handler(WazuhAuthError)
async def wazuh_auth_error_handler(request: Request, exc: WazuhAuthError):
    logger.warning(
        "wazuh_request_failed",
        wazuh_component="server",
        failure_reason="authentication",
    )
    return error_envelope(
        request, 502, "wazuh_auth_failed", "Wazuh rejected the configured service credentials."
    )


@app.exception_handler(WazuhAPIError)
async def normalized_wazuh_error_handler(request: Request, exc: WazuhAPIError):
    if exc.status_code == 404:
        return error_envelope(request, 404, "not_found", "The requested Wazuh resource does not exist.")
    if exc.status_code is None:
        return error_envelope(
            request,
            503,
            "wazuh_unavailable",
            "Wazuh is unreachable — check /api/v1/health/wazuh for diagnostics.",
        )
    logger.warning(
        "wazuh_request_failed",
        wazuh_component="server",
        status_code=exc.status_code,
    )
    return error_envelope(
        request,
        502,
        "wazuh_api_error",
        f"Wazuh API returned an operation error (HTTP {exc.status_code}).",
    )


@app.exception_handler(Exception)
async def unhandled_error_handler(request: Request, exc: Exception):
    # full traceback goes to the server log, keyed by request_id — never to the client
    logger.exception(
        "http_request_failed",
        error_type=type(exc).__name__,
        status_code=500,
    )
    return error_envelope(
        request, 500, "internal_error",
        "Unhandled server error — give support the request_id.",
    )


@app.get("/health", tags=["health"])
async def liveness():
    """Bare liveness probe for uptime monitors and load balancers."""
    return {"status": "ok"}
