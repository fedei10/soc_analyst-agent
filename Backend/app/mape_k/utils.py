"""Small deterministic helpers shared by MAPE-K stages."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any


def stable_id(prefix: str, *parts: object, length: int = 16) -> str:
    material = "|".join(str(part) for part in parts)
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:length].upper()
    return f"{prefix}-{digest}"


def content_hash(value: Any) -> str:
    rendered = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def csv_set(value: str) -> set[str]:
    return {item.strip() for item in value.split(",") if item.strip()}


def audit_event(
    event: str,
    *,
    stage: str | None = None,
    **payload: Any,
) -> dict[str, Any]:
    if stage is None:
        stage = next(
            (
                name
                for prefix, name in (
                    ("monitor", "monitor"),
                    ("analysis", "analyze"),
                    ("planning", "plan"),
                    ("plan_", "plan"),
                    ("policy", "policy_gate"),
                    ("approval", "human_approval"),
                    ("execution", "execute"),
                    ("verification", "verify"),
                    ("rollback", "rollback"),
                    ("knowledge", "update_knowledge"),
                )
                if event.startswith(prefix)
            ),
            "mapek",
        )
    return {
        "stage": stage,
        "event": event,
        "timestamp": datetime.now(UTC).isoformat(),
        "payload": payload,
    }
