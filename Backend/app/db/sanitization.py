"""Bound and sanitize model/tool data before durable or ephemeral storage."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any


SENSITIVE_KEY_PARTS = {
    "api_key",
    "authorization",
    "chain_of_thought",
    "credential",
    "environment",
    "password",
    "private_key",
    "reasoning",
    "secret",
    "token",
}


def _is_sensitive_key(key: object) -> bool:
    normalized = str(key).strip().lower().replace("-", "_")
    return any(part in normalized for part in SENSITIVE_KEY_PARTS)


def sanitize_for_storage(
    value: Any,
    *,
    max_depth: int = 5,
    max_items: int = 50,
    max_string_length: int = 4000,
) -> Any:
    """Return a JSON-safe, bounded copy without secrets or private reasoning."""

    def sanitize(item: Any, depth: int) -> Any:
        if depth > max_depth:
            return "[truncated]"
        if item is None or isinstance(item, (bool, int, float)):
            return item
        if isinstance(item, str):
            if len(item) <= max_string_length:
                return item
            return f"{item[:max_string_length]}...[truncated]"
        if isinstance(item, Mapping):
            result: dict[str, Any] = {}
            for index, (key, child) in enumerate(item.items()):
                if index >= max_items:
                    result["_truncated_items"] = len(item) - max_items
                    break
                if _is_sensitive_key(key):
                    continue
                result[str(key)] = sanitize(child, depth + 1)
            return result
        if isinstance(item, Sequence) and not isinstance(
            item,
            (bytes, bytearray),
        ):
            values = list(item)
            result = [
                sanitize(child, depth + 1)
                for child in values[:max_items]
            ]
            if len(values) > max_items:
                result.append(f"[{len(values) - max_items} items truncated]")
            return result
        return sanitize(str(item), depth + 1)

    sanitized = sanitize(value, 0)
    return json.loads(json.dumps(sanitized, default=str))


def bounded_excerpt(value: object, *, max_length: int = 2000) -> str:
    text = str(value)
    if len(text) <= max_length:
        return text
    return f"{text[:max_length]}...[truncated]"
