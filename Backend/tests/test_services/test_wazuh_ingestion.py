from datetime import UTC, datetime

import pytest

from app.config import settings
from app.services.wazuh.ingestion import AlertIngestionService
from app.services.wazuh.models import (
    AlertEvidence,
    AlertIngestionDocument,
    AlertIngestionPage,
)


def document() -> AlertIngestionDocument:
    observed_at = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)
    return AlertIngestionDocument(
        document_id="alert-1",
        index_name="wazuh-alerts-test",
        sort_values=[observed_at.isoformat(), "alert-1"],
        normalized=AlertEvidence(
            alert_id="alert-1",
            timestamp=observed_at,
            agent_id="001",
            rule_id="5712",
            rule_level=10,
            description="sshd brute force",
        ),
        raw_document={},
    )


class AlertRepository:
    durable = True

    def __init__(self):
        self.started = []
        self.completed = []
        self.failed = []
        self.pages = []

    def checkpoint(self, source_name):
        return None

    def mark_ingestion_started(self, source_name):
        self.started.append(source_name)

    def ingest_page(self, **kwargs):
        self.pages.append(kwargs)
        return len(kwargs["documents"])

    def pending_normalized_events(self, *, limit):
        return []

    def mark_ingestion_completed(self, source_name, *, alert_count):
        self.completed.append((source_name, alert_count))

    def mark_ingestion_failed(self, source_name, error):
        self.failed.append((source_name, type(error).__name__))


class Gateway:
    def __init__(self, *, error=None):
        self.error = error
        self.calls = []

    def search_alert_page(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        item = document()
        return AlertIngestionPage(
            documents=[item],
            search_after=item.sort_values,
            total=1,
        )


def test_ingestion_commits_checkpoint_only_after_correlation(monkeypatch):
    monkeypatch.setattr(settings, "WAZUH_INGESTION_PAGE_SIZE", 500)
    repository = AlertRepository()
    gateway = Gateway()
    service = AlertIngestionService(
        gateway=gateway,
        alert_repository=repository,
        finding_repository=object(),
        analyzer=object(),
    )

    result = service.ingest()

    assert repository.started == ["wazuh-indexer"]
    assert repository.completed == [("wazuh-indexer", 1)]
    assert repository.failed == []
    assert result["inserted_alerts"] == 1
    assert result["correlated_alerts"] == 0


def test_ingestion_records_failure_without_advancing_completion():
    repository = AlertRepository()
    service = AlertIngestionService(
        gateway=Gateway(error=ConnectionError("indexer unavailable")),
        alert_repository=repository,
        finding_repository=object(),
        analyzer=object(),
    )

    with pytest.raises(ConnectionError):
        service.ingest()

    assert repository.completed == []
    assert repository.failed == [("wazuh-indexer", "ConnectionError")]
