"""Unit tests for the alert ingestion worker entrypoint.

The worker is the process that pulls Wazuh alerts on a loop. The properties
that matter operationally: --once runs exactly one cycle, a failing cycle does
not kill the loop, and a stop signal ends it promptly.
"""

import pytest

from app.workers import alert_ingestion


class FakeIngestionService:
    """Stands in for AlertIngestionService; optionally fails or stops the loop."""

    def __init__(self, *, fail_times: int = 0, stop_after: int | None = None):
        self.calls = 0
        self._fail_times = fail_times
        self._stop_after = stop_after

    def ingest(self):
        self.calls += 1
        if self._stop_after is not None and self.calls >= self._stop_after:
            alert_ingestion._stop()
        if self.calls <= self._fail_times:
            raise RuntimeError("wazuh indexer unreachable")
        return {"ingested": 1}


class FakeClock:
    """A monotonic clock that only advances when the worker sleeps.

    Stubbing sleep to a no-op would leave the worker's `while now < deadline`
    delay loop spinning in real time, so the clock has to move instead.
    """

    def __init__(self):
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += max(float(seconds), 0.01)


@pytest.fixture(autouse=True)
def isolated_worker(monkeypatch):
    """Keep the module global, real signals, and real time out of the suite."""
    monkeypatch.setattr(alert_ingestion, "_running", True)
    monkeypatch.setattr(alert_ingestion.signal, "signal", lambda *_: None)
    monkeypatch.setattr(alert_ingestion, "time", FakeClock())
    yield
    alert_ingestion._running = True


@pytest.fixture
def install_service(monkeypatch):
    def install(service):
        monkeypatch.setattr(
            alert_ingestion,
            "AlertIngestionService",
            lambda *args, **kwargs: service,
        )
        return service

    return install


def test_once_runs_a_single_cycle_and_returns(install_service):
    service = install_service(FakeIngestionService())

    alert_ingestion.main(["--once"])

    assert service.calls == 1


def test_once_does_not_swallow_a_failure(install_service):
    """A one-shot run must surface errors so `make ingest-once` exits non-zero."""
    install_service(FakeIngestionService(fail_times=1))

    with pytest.raises(RuntimeError, match="wazuh indexer unreachable"):
        alert_ingestion.main(["--once"])


def test_loop_runs_until_stopped(install_service):
    service = install_service(FakeIngestionService(stop_after=3))

    alert_ingestion.main([])

    assert service.calls == 3


def test_loop_survives_a_failing_cycle(install_service):
    """A transient Wazuh outage must not terminate the worker."""
    service = install_service(FakeIngestionService(fail_times=2, stop_after=4))

    alert_ingestion.main([])

    assert service.calls == 4


def test_stop_signal_ends_the_loop(install_service):
    service = install_service(FakeIngestionService())
    alert_ingestion._stop()

    alert_ingestion.main([])

    assert service.calls == 0, "a stop received before the loop must prevent ingestion"


def test_default_argv_is_the_continuous_loop(install_service, monkeypatch):
    """No --once flag means loop mode, not a single cycle."""
    service = install_service(FakeIngestionService(stop_after=2))
    monkeypatch.setattr("sys.argv", ["alert_ingestion"])

    alert_ingestion.main()

    assert service.calls == 2


def test_signal_handlers_are_registered(install_service, monkeypatch):
    registered = []
    monkeypatch.setattr(
        alert_ingestion.signal,
        "signal",
        lambda sig, handler: registered.append(sig),
    )
    install_service(FakeIngestionService())

    alert_ingestion.main(["--once"])

    assert registered == [alert_ingestion.signal.SIGINT, alert_ingestion.signal.SIGTERM]


def test_stop_flips_the_module_flag():
    alert_ingestion._running = True

    alert_ingestion._stop()

    assert alert_ingestion._running is False
