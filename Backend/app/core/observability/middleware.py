"""Canonical HTTP request logging and correlation middleware."""

from __future__ import annotations

import re
import time
import uuid
from typing import Any

import structlog
from fastapi import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


logger = structlog.get_logger("tsage.http")
REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def _request_id(request: Request) -> str:
    candidate = request.headers.get("x-request-id", "").strip()
    if candidate and REQUEST_ID_PATTERN.fullmatch(candidate):
        return candidate
    return uuid.uuid4().hex


class RequestObservabilityMiddleware:
    """Emit one bounded request lifecycle and preserve the API error contract."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        service_name: str,
        slow_request_threshold_ms: int = 1000,
    ) -> None:
        self.app = app
        self.service_name = service_name
        self.slow_request_threshold_ms = slow_request_threshold_ms

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        structlog.contextvars.clear_contextvars()
        request = Request(scope, receive=receive)
        request_id = _request_id(request)
        request.state.request_id = request_id
        structlog.contextvars.bind_contextvars(
            request_id=request_id,
            http_method=request.method,
            http_path=request.url.path,
            service=self.service_name,
        )
        started = time.perf_counter()
        status_code = 500
        response_size = 0
        failed = False

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code, response_size
            if message["type"] == "http.response.start":
                status_code = int(message["status"])
                headers = [
                    header
                    for header in message.get("headers", [])
                    if header[0].lower() != b"x-request-id"
                ]
                headers.append((b"x-request-id", request_id.encode("ascii")))
                message["headers"] = headers
            elif message["type"] == "http.response.body":
                response_size += len(message.get("body", b""))
            await send(message)

        logger.info(
            "http_request_started",
            client_ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )

        try:
            if (
                request.method in {"POST", "PUT", "PATCH"}
                and not request.headers.get("content-type", "").startswith(
                    "application/json"
                )
            ):
                response = JSONResponse(
                    status_code=415,
                    content={
                        "error": {
                            "code": "unsupported_media_type",
                            "message": "Unsupported Media Type - send JSON.",
                            "detail": "Expected Content-Type application/json.",
                        },
                        "request_id": request_id,
                    },
                )
                await response(scope, receive, send_wrapper)
                return
            await self.app(scope, receive, send_wrapper)
        except Exception:
            failed = True
            logger.exception(
                "http_request_failed",
                status_code=500,
                duration_ms=round(
                    (time.perf_counter() - started) * 1000,
                    2,
                ),
            )
            raise
        finally:
            duration_ms = round((time.perf_counter() - started) * 1000, 2)
            if not failed:
                log = (
                    logger.warning
                    if duration_ms >= self.slow_request_threshold_ms
                    else logger.info
                )
                log(
                    "http_request_completed",
                    status_code=status_code,
                    duration_ms=duration_ms,
                    response_size_bytes=response_size,
                    slow=duration_ms >= self.slow_request_threshold_ms,
                )
            structlog.contextvars.clear_contextvars()
