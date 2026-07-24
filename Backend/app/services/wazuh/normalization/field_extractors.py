"""Safe field extraction across inconsistent Wazuh decoder layouts."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import UTC, datetime
from typing import Any


INVALID_TIMESTAMP = datetime(1970, 1, 1, tzinfo=UTC)


def source_document(raw: dict[str, Any]) -> dict[str, Any]:
    source = raw.get("_source")
    return source if isinstance(source, dict) else raw


def nested(raw: dict[str, Any], path: str) -> Any:
    source = source_document(raw)
    if path in source:
        return source[path]
    value: Any = source
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def first(raw: dict[str, Any], *paths: str) -> Any:
    for path in paths:
        value = nested(raw, path)
        if value not in (None, ""):
            return value
    return None


def text(raw: dict[str, Any], *paths: str) -> str | None:
    value = first(raw, *paths)
    if value in (None, ""):
        return None
    return str(value)


def integer(raw: dict[str, Any], *paths: str, default: int | None = None) -> int | None:
    value = first(raw, *paths)
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def number(raw: dict[str, Any], *paths: str) -> float | None:
    value = first(raw, *paths)
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def string_list(raw: dict[str, Any], *paths: str) -> list[str]:
    value = first(raw, *paths)
    if value is None:
        return []
    values = value if isinstance(value, list) else [value]
    return list(dict.fromkeys(str(item) for item in values if item not in (None, "")))


def timestamp(raw: dict[str, Any]) -> tuple[datetime, bool]:
    value = first(raw, "@timestamp", "timestamp")
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return INVALID_TIMESTAMP, False
    else:
        return INVALID_TIMESTAMP, False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC), True


def ip(raw: dict[str, Any], *paths: str) -> str | None:
    value = first(raw, *paths)
    if value in (None, ""):
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip("[]")))
    except ValueError:
        return None


def port(raw: dict[str, Any], *paths: str) -> int | None:
    value = integer(raw, *paths)
    return value if value is not None and 0 <= value <= 65535 else None


def alert_id(raw: dict[str, Any]) -> str:
    value = raw.get("_id") or first(raw, "alert_id", "id")
    return str(value or "unknown-alert")


def evidence_ref(value: str) -> str:
    return f"wazuh:alert:{value}"


def hash_sensitive(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return f"sha256:{hashlib.sha256(str(value).encode()).hexdigest()}"


def combined_text(raw: dict[str, Any]) -> str:
    values = [
        text(raw, "decoder.name", "decoder_name"),
        text(raw, "rule.description", "description", "rule_description"),
        " ".join(string_list(raw, "rule.groups", "rule_groups")),
        text(raw, "full_log"),
        text(raw, "location"),
        text(raw, "data.integration"),
    ]
    return " ".join(value for value in values if value).lower()


def authentication_log_fields(
    raw: dict[str, Any],
) -> tuple[str | None, str | None, int | None]:
    full_log = text(raw, "full_log")
    if not full_log:
        return None, None, None
    match = re.search(
        r"(?:Failed|Accepted) password for (?:invalid user )?"
        r"(?P<user>\S+) from (?P<ip>\S+)(?: port (?P<port>\d+))?",
        full_log,
        flags=re.IGNORECASE,
    )
    if not match:
        return None, None, None
    try:
        source_ip = str(ipaddress.ip_address(match.group("ip").strip("[],:")))
    except ValueError:
        source_ip = None
    try:
        source_port = int(match.group("port")) if match.group("port") else None
    except ValueError:
        source_port = None
    return source_ip, match.group("user"), source_port
