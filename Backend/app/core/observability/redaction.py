"""Central redaction for logs, traces, and bounded metadata."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any


SENSITIVE_KEY_PARTS = {
    "api_key",
    "apikey",
    "authorization",
    "chain_of_thought",
    "client_secret",
    "cookie",
    "credential",
    "database_url",
    "environment_variables",
    "password",
    "private_key",
    "proxy_authorization",
    "reasoning",
    "redis_url",
    "refresh_token",
    "signature",
    "secret",
    "set_cookie",
    "token",
    "wazuh_password",
}

BEARER_PATTERN = re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]+")
ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b(?:api[_-]?key|password|token|secret)"
    r"\s*[=:]\s*[^\s,;]+"
)
JWT_PATTERN = re.compile(
    r"\beyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}"
    r"\.[a-zA-Z0-9_-]{5,}\b"
)


def _normalized_key(key: object) -> str:
    return str(key).strip().lower().replace("-", "_")


def is_sensitive_key(key: object) -> bool:
    normalized = _normalized_key(key)
    return any(part in normalized for part in SENSITIVE_KEY_PARTS)


def redact_string(value: str, *, max_length: int = 8000) -> str:
    redacted = BEARER_PATTERN.sub("Bearer [REDACTED]", value)
    redacted = ASSIGNMENT_PATTERN.sub("[REDACTED]", redacted)
    redacted = JWT_PATTERN.sub("[REDACTED_JWT]", redacted)
    if len(redacted) > max_length:
        return f"{redacted[:max_length]}...[truncated]"
    return redacted


def sanitize(
    value: Any,
    *,
    depth: int = 0,
    max_depth: int = 8,
    max_items: int = 100,
    max_string_length: int = 8000,
) -> Any:
    """Return a bounded redacted copy suitable for logs and trace metadata."""

    if depth > max_depth:
        return "[MAX_DEPTH]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return redact_string(value, max_length=max_string_length)
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        items = list(value.items())
        for key, item in items[:max_items]:
            rendered_key = str(key)
            result[rendered_key] = (
                "[REDACTED]"
                if is_sensitive_key(key)
                else sanitize(
                    item,
                    depth=depth + 1,
                    max_depth=max_depth,
                    max_items=max_items,
                    max_string_length=max_string_length,
                )
            )
        if len(items) > max_items:
            result["_truncated_items"] = len(items) - max_items
        return result
    if isinstance(value, Sequence) and not isinstance(
        value,
        (bytes, bytearray),
    ):
        items = list(value)
        result = [
            sanitize(
                item,
                depth=depth + 1,
                max_depth=max_depth,
                max_items=max_items,
                max_string_length=max_string_length,
            )
            for item in items[:max_items]
        ]
        if len(items) > max_items:
            result.append(f"[{len(items) - max_items} items truncated]")
        return result
    return sanitize(
        str(value),
        depth=depth + 1,
        max_depth=max_depth,
        max_items=max_items,
        max_string_length=max_string_length,
    )
