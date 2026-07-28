"""Small shared helpers with no domain knowledge."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Iterable


MAX_PARALLEL_CALLS = 8


def gather(
    tasks: Iterable[tuple[str, Callable[[], Any]]],
    *,
    max_workers: int = MAX_PARALLEL_CALLS,
) -> dict[str, Any]:
    """Run independent blocking calls concurrently, keyed by label.

    Several Wazuh reads that do not depend on each other were being issued
    one after another, so an endpoint snapshot cost the sum of six round
    trips instead of the slowest one. Threads (not asyncio) because every
    client in this codebase is synchronous.

    An exception is returned in place of a result rather than raised, so one
    failing component degrades that key instead of the whole snapshot.
    """

    items = list(tasks)
    if not items:
        return {}
    if len(items) == 1:
        label, call = items[0]
        try:
            return {label: call()}
        except Exception as exc:
            return {label: exc}
    with ThreadPoolExecutor(
        max_workers=min(len(items), max(max_workers, 1))
    ) as pool:
        futures = {label: pool.submit(call) for label, call in items}
        results: dict[str, Any] = {}
        for label, future in futures.items():
            try:
                results[label] = future.result()
            except Exception as exc:
                results[label] = exc
        return results
