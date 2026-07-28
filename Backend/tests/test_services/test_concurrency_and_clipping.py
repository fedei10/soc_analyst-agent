import json
import threading
import time

from app.soc_assistant.tool_agent import MAX_TOOL_OUTPUT_CHARS, _clip
from app.utils.helpers import gather


def test_gather_runs_calls_concurrently():
    barrier = threading.Barrier(3, timeout=5)

    def waiter(value):
        # Deadlocks and fails the test if the calls are run one after another.
        def call():
            barrier.wait()
            return value

        return call

    results = gather(
        [("a", waiter(1)), ("b", waiter(2)), ("c", waiter(3))]
    )

    assert results == {"a": 1, "b": 2, "c": 3}


def test_gather_isolates_one_failing_call():
    def boom():
        raise RuntimeError("component is down")

    results = gather([("ok", lambda: "fine"), ("bad", boom)])

    assert results["ok"] == "fine"
    assert isinstance(results["bad"], RuntimeError)


def test_gather_handles_empty_and_single_task():
    assert gather([]) == {}
    assert gather([("only", lambda: 7)]) == {"only": 7}


def test_gather_is_faster_than_sequential():
    def slow():
        time.sleep(0.1)
        return True

    started = time.perf_counter()
    gather([(str(index), slow) for index in range(5)])
    elapsed = time.perf_counter() - started

    # Sequential would be ~0.5s; concurrent is ~0.1s.
    assert elapsed < 0.3


def test_clip_returns_valid_json_when_under_budget():
    payload = {"total": 1, "alerts": [{"alert_id": "a1"}]}

    assert json.loads(_clip(payload)) == payload


def test_clip_drops_whole_records_and_stays_parseable():
    payload = {
        "total": 5000,
        "alerts": [{"alert_id": f"a{index}", "blob": "x" * 200} for index in range(200)],
    }

    result = _clip(payload)
    parsed = json.loads(result)

    assert len(result) <= MAX_TOOL_OUTPUT_CHARS
    assert parsed["truncated"] is True
    assert parsed["total"] == 5000
    assert 0 < len(parsed["alerts"]) < 200
    # Every surviving record is complete, not cut in half.
    assert all("alert_id" in item and "blob" in item for item in parsed["alerts"])


def test_clip_of_an_oversized_non_list_payload_is_still_json():
    payload = {"blob": "x" * (MAX_TOOL_OUTPUT_CHARS * 2)}

    parsed = json.loads(_clip(payload))

    assert parsed["truncated"] is True
    assert "preview" in parsed
