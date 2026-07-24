import json

import redis

from app.services.redis.ephemeral import EphemeralRedis


class FakePipeline:
    def __init__(self, client):
        self.client = client
        self.operations = []

    def set(self, *args, **kwargs):
        self.operations.append(("set", args, kwargs))
        return self

    def xadd(self, *args, **kwargs):
        self.operations.append(("xadd", args, kwargs))
        return self

    def expire(self, *args, **kwargs):
        self.operations.append(("expire", args, kwargs))
        return self

    def incr(self, *args, **kwargs):
        self.operations.append(("incr", args, kwargs))
        return self

    def execute(self):
        results = []
        for name, args, kwargs in self.operations:
            results.append(getattr(self.client, name)(*args, **kwargs))
        return results


class FakeRedis:
    def __init__(self):
        self.values = {}
        self.streams = {}
        self.expirations = {}

    def get(self, key):
        return self.values.get(key)

    def set(self, key, value, ex=None, nx=False):
        if nx and key in self.values:
            return False
        self.values[key] = value
        if ex:
            self.expirations[key] = ex
        return True

    def incr(self, key):
        self.values[key] = int(self.values.get(key, 0)) + 1
        return self.values[key]

    def expire(self, key, seconds, nx=False):
        if nx and key in self.expirations:
            return False
        self.expirations[key] = seconds
        return True

    def pipeline(self, transaction=False):
        return FakePipeline(self)

    def xadd(self, key, fields, maxlen=None, approximate=True):
        event_id = f"{len(self.streams.get(key, [])) + 1}-0"
        self.streams.setdefault(key, []).append((event_id, fields))
        return event_id

    def xrange(self, key, min="-", max="+", count=100):
        rows = self.streams.get(key, [])
        if min.startswith("("):
            rows = [row for row in rows if row[0] != min[1:]]
        return rows[:count]

    def eval(self, _script, _key_count, key, token):
        if self.values.get(key) != token:
            return 0
        del self.values[key]
        return 1


class BrokenRedis:
    def __getattr__(self, _name):
        def fail(*_args, **_kwargs):
            raise redis.ConnectionError("offline")

        return fail


def test_cache_activity_idempotency_lock_and_rate_limit():
    client = FakeRedis()
    service = EphemeralRedis(client)

    assert service.set_context(
        organization_id="org-1",
        conversation_id="conversation-1",
        value={"asset": "host-1", "token": "not-stored"},
    )
    assert service.get_context(
        organization_id="org-1",
        conversation_id="conversation-1",
    ) == {"asset": "host-1"}
    assert service.get_context(
        organization_id="org-2",
        conversation_id="conversation-1",
    ) is None

    event_id = service.append_activity(
        organization_id="org-1",
        investigation_id="INV-1",
        event="tool_completed",
        payload={"hits": 2, "api_key": "not-stored"},
    )
    activity = service.read_activity(
        organization_id="org-1",
        investigation_id="INV-1",
    )
    assert event_id == "1-0"
    assert activity[0]["payload"] == {"hits": 2}

    assert service.claim_idempotency(
        organization_id="org-1",
        operation_key="action-1",
    ).claimed
    assert not service.claim_idempotency(
        organization_id="org-1",
        operation_key="action-1",
    ).claimed

    lease = service.acquire_lock(
        organization_id="org-1",
        resource="INV-1",
    )
    assert lease.acquired
    assert service.release_lock(
        organization_id="org-1",
        resource="INV-1",
        lease=lease,
    )

    assert service.check_rate_limit(
        organization_id="org-1",
        subject="user-1",
        limit=1,
    ).allowed
    assert not service.check_rate_limit(
        organization_id="org-1",
        subject="user-1",
        limit=1,
    ).allowed


def test_redis_outage_fails_open_without_claiming_durability():
    service = EphemeralRedis(BrokenRedis())

    assert service.get_context(
        organization_id="org-1",
        conversation_id="conversation-1",
    ) is None
    assert not service.set_context(
        organization_id="org-1",
        conversation_id="conversation-1",
        value={},
    )
    assert service.claim_idempotency(
        organization_id="org-1",
        operation_key="action-1",
    ).degraded
    assert service.acquire_lock(
        organization_id="org-1",
        resource="INV-1",
    ).degraded
    assert service.check_rate_limit(
        organization_id="org-1",
        subject="user-1",
        limit=10,
    ).degraded
    assert service.append_activity(
        organization_id="org-1",
        investigation_id="INV-1",
        event="subagent_started",
    ) is None
