"""Fail-soft Redis primitives for caches, progress, locks, and rate limits."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import redis

from app.config import settings
from app.db.sanitization import sanitize_for_storage
from app.services.redis.connection import (
    RedisNotConfiguredError,
    get_redis_connection,
)


CONTEXT_TTL_SECONDS = settings.REDIS_CONTEXT_TTL_SECONDS
WAZUH_CACHE_TTL_SECONDS = settings.REDIS_TOOL_TTL_SECONDS
ACTIVITY_TTL_SECONDS = settings.REDIS_ACTIVITY_TTL_SECONDS
IDEMPOTENCY_TTL_SECONDS = settings.REDIS_IDEMPOTENCY_TTL_SECONDS
LOCK_TTL_SECONDS = settings.REDIS_LOCK_TTL_SECONDS
MAX_ACTIVITY_EVENTS = settings.REDIS_ACTIVITY_MAX_EVENTS

_SAFE_PART = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


def _key_part(value: object) -> str:
    text = str(value)
    if _SAFE_PART.fullmatch(text):
        return text
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class IdempotencyClaim:
    claimed: bool
    degraded: bool = False


@dataclass(frozen=True)
class LockLease:
    acquired: bool
    token: str | None
    degraded: bool = False


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    count: int
    limit: int
    degraded: bool = False


class EphemeralRedis:
    """Redis facade where an outage disables optimization, not SOC history."""

    def __init__(self, client: redis.Redis | None = None) -> None:
        self._client = client

    def _redis(self) -> redis.Redis:
        if self._client is not None:
            return self._client
        return get_redis_connection()

    @staticmethod
    def _key(namespace: str, organization_id: str, *parts: object) -> str:
        return ":".join([
            "tsage",
            _key_part(organization_id),
            namespace,
            *(_key_part(part) for part in parts),
        ])

    def get_json(
        self,
        *,
        namespace: str,
        organization_id: str,
        cache_key: str,
    ) -> Any | None:
        try:
            value = self._redis().get(
                self._key(namespace, organization_id, cache_key)
            )
        except (RedisNotConfiguredError, redis.RedisError, OSError):
            return None
        if value is None:
            return None
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return None

    def set_json(
        self,
        *,
        namespace: str,
        organization_id: str,
        cache_key: str,
        value: Any,
        ttl_seconds: int,
    ) -> bool:
        safe_value = sanitize_for_storage(value)
        try:
            return bool(self._redis().set(
                self._key(namespace, organization_id, cache_key),
                json.dumps(safe_value, separators=(",", ":"), default=str),
                ex=max(ttl_seconds, 1),
            ))
        except (RedisNotConfiguredError, redis.RedisError, OSError):
            return False

    def get_context(
        self,
        *,
        organization_id: str,
        conversation_id: str,
    ) -> Any | None:
        return self.get_json(
            namespace="context",
            organization_id=organization_id,
            cache_key=conversation_id,
        )

    def set_context(
        self,
        *,
        organization_id: str,
        conversation_id: str,
        value: Any,
    ) -> bool:
        return self.set_json(
            namespace="context",
            organization_id=organization_id,
            cache_key=conversation_id,
            value=value,
            ttl_seconds=CONTEXT_TTL_SECONDS,
        )

    def get_wazuh_result(
        self,
        *,
        organization_id: str,
        query_fingerprint: str,
    ) -> Any | None:
        return self.get_json(
            namespace="wazuh",
            organization_id=organization_id,
            cache_key=query_fingerprint,
        )

    def set_wazuh_result(
        self,
        *,
        organization_id: str,
        query_fingerprint: str,
        value: Any,
    ) -> bool:
        return self.set_json(
            namespace="wazuh",
            organization_id=organization_id,
            cache_key=query_fingerprint,
            value=value,
            ttl_seconds=WAZUH_CACHE_TTL_SECONDS,
        )

    def claim_idempotency(
        self,
        *,
        organization_id: str,
        operation_key: str,
        ttl_seconds: int = IDEMPOTENCY_TTL_SECONDS,
    ) -> IdempotencyClaim:
        try:
            claimed = bool(self._redis().set(
                self._key(
                    "idempotency",
                    organization_id,
                    operation_key,
                ),
                datetime.now(UTC).isoformat(),
                nx=True,
                ex=max(ttl_seconds, 1),
            ))
            return IdempotencyClaim(claimed=claimed)
        except (RedisNotConfiguredError, redis.RedisError, OSError):
            return IdempotencyClaim(claimed=True, degraded=True)

    def acquire_lock(
        self,
        *,
        organization_id: str,
        resource: str,
        ttl_seconds: int = LOCK_TTL_SECONDS,
    ) -> LockLease:
        token = secrets.token_urlsafe(24)
        try:
            acquired = bool(self._redis().set(
                self._key("lock", organization_id, resource),
                token,
                nx=True,
                ex=max(ttl_seconds, 1),
            ))
            return LockLease(
                acquired=acquired,
                token=token if acquired else None,
            )
        except (RedisNotConfiguredError, redis.RedisError, OSError):
            return LockLease(acquired=True, token=None, degraded=True)

    def release_lock(
        self,
        *,
        organization_id: str,
        resource: str,
        lease: LockLease,
    ) -> bool:
        if lease.degraded or not lease.token:
            return False
        script = """
        if redis.call("get", KEYS[1]) == ARGV[1] then
          return redis.call("del", KEYS[1])
        end
        return 0
        """
        try:
            return bool(self._redis().eval(
                script,
                1,
                self._key("lock", organization_id, resource),
                lease.token,
            ))
        except (RedisNotConfiguredError, redis.RedisError, OSError):
            return False

    def append_activity(
        self,
        *,
        organization_id: str,
        investigation_id: str,
        event: str,
        payload: dict[str, Any] | None = None,
    ) -> str | None:
        stream_key = self._key(
            "activity",
            organization_id,
            investigation_id,
        )
        fields = {
            "event": event[:128],
            "timestamp": datetime.now(UTC).isoformat(),
            "payload": json.dumps(
                sanitize_for_storage(payload or {}),
                separators=(",", ":"),
                default=str,
            ),
        }
        try:
            pipeline = self._redis().pipeline(transaction=False)
            pipeline.xadd(
                stream_key,
                fields,
                maxlen=MAX_ACTIVITY_EVENTS,
                approximate=True,
            )
            pipeline.expire(stream_key, ACTIVITY_TTL_SECONDS)
            result = pipeline.execute()
            return str(result[0]) if result else None
        except (RedisNotConfiguredError, redis.RedisError, OSError):
            return None

    def read_activity(
        self,
        *,
        organization_id: str,
        investigation_id: str,
        after_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        minimum = f"({after_id}" if after_id else "-"
        try:
            rows = self._redis().xrange(
                self._key(
                    "activity",
                    organization_id,
                    investigation_id,
                ),
                min=minimum,
                max="+",
                count=min(max(limit, 1), 500),
            )
        except (RedisNotConfiguredError, redis.RedisError, OSError):
            return []
        events: list[dict[str, Any]] = []
        for event_id, fields in rows:
            try:
                payload = json.loads(fields.get("payload") or "{}")
            except (TypeError, ValueError):
                payload = {}
            events.append({
                "id": str(event_id),
                "event": fields.get("event", "unknown"),
                "timestamp": fields.get("timestamp"),
                "payload": payload,
            })
        return events

    def check_rate_limit(
        self,
        *,
        organization_id: str,
        subject: str,
        limit: int,
        window_seconds: int = 60,
    ) -> RateLimitResult:
        key = self._key("rate", organization_id, subject)
        try:
            pipeline = self._redis().pipeline(transaction=True)
            pipeline.incr(key)
            pipeline.expire(key, max(window_seconds, 1), nx=True)
            count = int(pipeline.execute()[0])
            return RateLimitResult(
                allowed=count <= max(limit, 1),
                count=count,
                limit=max(limit, 1),
            )
        except (RedisNotConfiguredError, redis.RedisError, OSError):
            return RateLimitResult(
                allowed=True,
                count=0,
                limit=max(limit, 1),
                degraded=True,
            )
