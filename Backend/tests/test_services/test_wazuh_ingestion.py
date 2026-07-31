from datetime import UTC, datetime, timedelta

import pytest

from app.config import settings
from app.services.redis.ephemeral import LockLease
from app.services.wazuh.ingestion import (
    AlertIngestionService,
    IngestionAlreadyRunningError,
)
from app.services.wazuh.indexer_client import WazuhIndexerClient
from app.services.wazuh.models import (
    AlertEvidence,
    AlertIngestionDocument,
    AlertIngestionPage,
    AlertPagePersistenceResult,
)
from app.services.wazuh.normalization.registry import normalize_alert
from app.services.wazuh.triage.analyzer import TriageAnalyzer


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
        self.released = []
        self.pending = []
        self.attachments = []
        self.checkpoint_value = None
        self.claimed = True

    def checkpoint(self, source_name, **kwargs):
        return self.checkpoint_value

    def claim_ingestion(self, source_name, **kwargs):
        self.started.append(source_name)
        return "lease-token" if self.claimed else None

    def renew_ingestion_claim(self, source_name, **kwargs):
        return True

    def release_ingestion_claim(self, source_name, **kwargs):
        self.released.append(source_name)
        return True

    def ingest_page_result(self, **kwargs):
        self.pages.append(kwargs)
        return AlertPagePersistenceResult(
            inserted_count=len(kwargs["documents"]),
            duplicate_count=0,
            highest_new_rule_level=10,
            cursor_advanced=bool(kwargs["documents"]),
        )

    def pending_normalized_events(self, *, limit):
        return self.pending[:limit]

    def attach_finding(self, *, finding_id, alert_ids):
        self.attachments.append((finding_id, alert_ids))

    def mark_ingestion_completed(self, source_name, *, alert_count, **kwargs):
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


class Cache:
    def __init__(self, *, acquired=True):
        self.acquired = acquired
        self.released = []

    def acquire_lock(self, **kwargs):
        return LockLease(
            acquired=self.acquired,
            token="redis-token" if self.acquired else None,
        )

    def release_lock(self, **kwargs):
        self.released.append(kwargs)
        return True


class FindingRepository:
    def __init__(self):
        self.findings = {}

    def get(self, finding_id, *, organization_id):
        return self.findings.get(finding_id)

    def upsert(self, *, organization_id, finding, verdict, enrichment):
        record = {"version": 1}
        self.findings[finding.finding_id] = record
        return record


def test_indexer_ingestion_sort_is_stable_across_rolling_indices():
    class Client:
        def __init__(self):
            self.calls = []

        def search(self, **kwargs):
            self.calls.append(kwargs)
            return {
                "hits": {
                    "total": {"value": 1},
                    "hits": [
                        {
                            "_id": "alert-1",
                            "_index": "wazuh-alerts-test",
                            "_source": {
                                "@timestamp": "2026-07-25T12:00:00Z",
                                "rule": {
                                    "id": "5712",
                                    "level": 10,
                                    "description": "sshd brute force",
                                },
                            },
                            "sort": [
                                "2026-07-25T12:00:00Z",
                                "wazuh-alerts-test",
                                "alert-1",
                            ],
                        }
                    ],
                }
            }

    client = Client()
    page = WazuhIndexerClient(client=client).search_alert_page()

    assert client.calls[0]["body"]["sort"] == [
        {"@timestamp": {"order": "asc", "unmapped_type": "date"}},
        {"_index": {"order": "asc"}},
        {"_id": {"order": "asc"}},
    ]
    assert page.search_after == [
        "2026-07-25T12:00:00Z",
        "wazuh-alerts-test",
        "alert-1",
    ]


def test_ingestion_commits_checkpoint_only_after_correlation(monkeypatch):
    monkeypatch.setattr(settings, "WAZUH_INGESTION_PAGE_SIZE", 500)
    repository = AlertRepository()
    gateway = Gateway()
    service = AlertIngestionService(
        gateway=gateway,
        alert_repository=repository,
        finding_repository=object(),
        analyzer=object(),
        cache=Cache(),
    )

    result = service.ingest()

    assert repository.started == ["wazuh-indexer"]
    assert repository.completed == [("wazuh-indexer", 1)]
    assert repository.failed == []
    assert result.new_alert_count == 1
    assert result.duplicate_alert_count == 0
    assert result.new_finding_count == 0
    assert result.highest_new_rule_level == 10
    assert result.cursor_advanced is True
    assert result.has_new_alerts is True


def test_ingestion_records_failure_without_advancing_completion():
    repository = AlertRepository()
    service = AlertIngestionService(
        gateway=Gateway(error=ConnectionError("indexer unavailable")),
        alert_repository=repository,
        finding_repository=object(),
        analyzer=object(),
        cache=Cache(),
    )

    with pytest.raises(ConnectionError):
        service.ingest()

    assert repository.completed == []
    assert repository.failed == [("wazuh-indexer", "ConnectionError")]
    assert repository.released == ["wazuh-indexer"]


def test_ingestion_uses_overlap_and_resumes_only_truncated_scan(monkeypatch):
    monkeypatch.setattr(settings, "WAZUH_INGESTION_OVERLAP_SECONDS", 60)
    observed_at = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)
    repository = AlertRepository()
    repository.checkpoint_value = {
        "last_event_timestamp": observed_at,
        "last_run_completed_at": observed_at - timedelta(minutes=5),
        "last_truncated": False,
        "search_after": ["stale"],
    }
    gateway = Gateway()
    service = AlertIngestionService(
        gateway=gateway,
        alert_repository=repository,
        finding_repository=object(),
        analyzer=object(),
        cache=Cache(),
    )

    result = service.ingest()

    assert gateway.calls[0]["since"] == observed_at - timedelta(seconds=60)
    assert gateway.calls[0]["search_after"] is None
    assert result.previous_check_at == observed_at - timedelta(minutes=5)

    repository.checkpoint_value["last_truncated"] = True
    repository.checkpoint_value["search_after"] = [
        observed_at.isoformat(),
        "wazuh-alerts-test",
        "alert-0",
    ]
    gateway.calls.clear()
    service.ingest()
    assert gateway.calls[0]["search_after"] == (
        repository.checkpoint_value["search_after"]
    )


def test_ingestion_rejects_concurrent_redis_or_database_claim():
    repository = AlertRepository()
    service = AlertIngestionService(
        gateway=Gateway(),
        alert_repository=repository,
        finding_repository=object(),
        analyzer=object(),
        cache=Cache(acquired=False),
    )
    with pytest.raises(IngestionAlreadyRunningError):
        service.ingest()


def test_correlation_marks_every_group_member_beyond_evidence_display_cap():
    repository = AlertRepository()
    for index in range(25):
        timestamp = datetime(2026, 7, 25, 12, 0, index, tzinfo=UTC)
        envelope = normalize_alert(
            {
                "_id": f"ssh-{index}",
                "_source": {
                    "@timestamp": timestamp.isoformat(),
                    "agent": {"id": "001", "name": "servervb"},
                    "rule": {
                        "id": "5712",
                        "level": 10,
                        "description": "sshd brute force",
                        "groups": ["sshd", "authentication_failures"],
                    },
                    "decoder": {"name": "sshd"},
                    "data": {
                        "srcip": "192.0.2.10",
                        "srcuser": "analyst",
                    },
                    "full_log": (
                        "Failed password for analyst from 192.0.2.10 "
                        "port 4422 ssh2"
                    ),
                },
            }
        )
        repository.pending.append(
            (index + 1, envelope.model_dump(mode="json"))
        )

    service = AlertIngestionService(
        gateway=Gateway(),
        alert_repository=repository,
        finding_repository=FindingRepository(),
        analyzer=TriageAnalyzer(),
        cache=Cache(),
    )

    result = service.correlate(limit=500)

    assert result["correlated_alerts"] == 25
    assert len(repository.attachments) == 1
    assert repository.attachments[0][1] == list(range(1, 26))

    repository.claimed = False
    service = AlertIngestionService(
        gateway=Gateway(),
        alert_repository=repository,
        finding_repository=object(),
        analyzer=object(),
        cache=Cache(),
    )
    with pytest.raises(IngestionAlreadyRunningError):
        service.ingest()


class _Finding:
    def __init__(self, *, recommended=True, score=12):
        self.investigation_recommended = recommended
        self.severity_score = score


class _Verdict:
    def __init__(self, *, verdict="malicious", confidence=0.9):
        self.verdict = verdict
        self.confidence = confidence


def test_auto_investigate_is_off_by_default(monkeypatch):
    monkeypatch.setattr(settings, "MAPEK_AUTO_INVESTIGATE_ENABLED", False)
    assert (
        AlertIngestionService._should_auto_investigate(_Finding(), _Verdict())
        is False
    )


@pytest.mark.parametrize(
    "finding,verdict,expected",
    [
        (_Finding(), _Verdict(), True),
        # Not severe enough for the aggregator to recommend it.
        (_Finding(recommended=False), _Verdict(), False),
        # Benign and inconclusive verdicts must never open an incident.
        (_Finding(), _Verdict(verdict="benign"), False),
        (_Finding(), _Verdict(verdict="inconclusive"), False),
        # Below the confidence floor.
        (_Finding(), _Verdict(confidence=0.5), False),
    ],
)
def test_auto_investigate_policy_gate(monkeypatch, finding, verdict, expected):
    monkeypatch.setattr(settings, "MAPEK_AUTO_INVESTIGATE_ENABLED", True)
    monkeypatch.setattr(settings, "MAPEK_AUTO_INVESTIGATE_MIN_CONFIDENCE", 0.7)
    assert (
        AlertIngestionService._should_auto_investigate(finding, verdict)
        is expected
    )
