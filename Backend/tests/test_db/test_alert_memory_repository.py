from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.models import (
    InvestigationRecord,
    NormalizedEventRecord,
    WazuhAlertRecord,
)
from app.db.repositories.alert_memory import SQLAlchemyAlertMemoryRepository
from app.db.repositories.investigations import (
    SQLAlchemyInvestigationRepository,
)
from app.services.wazuh.models import AlertEvidence, AlertIngestionDocument


def repository():
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    return SQLAlchemyAlertMemoryRepository(factory), factory


def alert_document() -> AlertIngestionDocument:
    timestamp = datetime(2026, 7, 25, 12, 30, tzinfo=UTC)
    return AlertIngestionDocument(
        document_id="ClBwmZ8B3vQGyj_JbzZo",
        index_name="wazuh-alerts-4.x-2026.07.25",
        sort_values=[timestamp.isoformat(), "ClBwmZ8B3vQGyj_JbzZo"],
        normalized=AlertEvidence(
            alert_id="ClBwmZ8B3vQGyj_JbzZo",
            timestamp=timestamp,
            agent_id="001",
            agent_name="servervb",
            rule_id="5712",
            rule_level=10,
            description="sshd: brute force attempt",
            source_ip="192.0.2.10",
            rule_groups=["sshd", "authentication_failed"],
            mitre_ids=["T1110"],
            event_outcome="failure",
        ),
        raw_document={
            "@timestamp": timestamp.isoformat(),
            "agent": {"id": "001", "name": "servervb"},
            "rule": {
                "id": "5712",
                "level": 10,
                "description": "sshd: brute force attempt",
                "groups": ["sshd", "authentication_failed"],
                "mitre": {"id": ["T1110"]},
            },
            "data": {"srcip": "192.0.2.10"},
        },
    )


def test_ingestion_is_idempotent_and_normalizes_rich_source():
    store, factory = repository()
    document = alert_document()

    assert store.ingest_page(
        source_name="wazuh-indexer",
        documents=[document],
        search_after=document.sort_values,
    ) == 1
    assert store.ingest_page(
        source_name="wazuh-indexer",
        documents=[document],
        search_after=document.sort_values,
    ) == 0

    with factory() as session:
        alerts = list(session.scalars(select(WazuhAlertRecord)).all())
        events = list(session.scalars(select(NormalizedEventRecord)).all())
    assert len(alerts) == 1
    assert len(events) == 1
    assert alerts[0].event_type == "ssh_brute_force"
    assert events[0].event_type == "ssh_brute_force"
    assert events[0].source_ip == "192.0.2.10"


def test_page_result_counts_duplicates_and_preserves_highest_new_level():
    store, _ = repository()
    document = alert_document()

    first = store.ingest_page_result(
        source_name="wazuh-indexer",
        documents=[document],
        search_after=document.sort_values,
    )
    second = store.ingest_page_result(
        source_name="wazuh-indexer",
        documents=[document],
        search_after=document.sort_values,
    )

    assert first.inserted_count == 1
    assert first.duplicate_count == 0
    assert first.highest_new_rule_level == 10
    assert first.cursor_advanced is True
    assert second.inserted_count == 0
    assert second.duplicate_count == 1
    assert second.highest_new_rule_level is None
    assert second.cursor_advanced is False


def test_empty_page_preserves_the_stable_search_after_checkpoint():
    store, _ = repository()
    document = alert_document()
    store.ingest_page(
        source_name="wazuh-indexer",
        documents=[document],
        search_after=document.sort_values,
    )

    store.ingest_page(
        source_name="wazuh-indexer",
        documents=[],
        search_after=None,
    )

    checkpoint = store.checkpoint("wazuh-indexer")
    assert checkpoint is not None
    assert checkpoint["search_after"] == document.sort_values
    assert checkpoint["last_document_id"] == document.document_id


def test_late_arrival_is_new_by_ingestion_time_without_regressing_cursor():
    store, factory = repository()
    high_water = alert_document()
    store.ingest_page(
        source_name="wazuh-indexer",
        documents=[high_water],
        search_after=high_water.sort_values,
    )
    checkpoint_before = store.checkpoint("wazuh-indexer")
    assert checkpoint_before is not None

    late_timestamp = high_water.normalized.timestamp - timedelta(minutes=5)
    late = high_water.model_copy(
        update={
            "document_id": "late-alert",
            "index_name": "wazuh-alerts-4.x-2026.07.25",
            "sort_values": [
                late_timestamp.isoformat(),
                "wazuh-alerts-4.x-2026.07.25",
                "late-alert",
            ],
            "normalized": high_water.normalized.model_copy(
                update={
                    "alert_id": "late-alert",
                    "timestamp": late_timestamp,
                }
            ),
        }
    )
    result = store.ingest_page_result(
        source_name="wazuh-indexer",
        documents=[late],
        search_after=late.sort_values,
    )
    checkpoint_after = store.checkpoint("wazuh-indexer")
    assert checkpoint_after is not None

    assert result.inserted_count == 1
    assert result.cursor_advanced is False
    assert checkpoint_after["last_event_timestamp"] == (
        checkpoint_before["last_event_timestamp"]
    )
    assert checkpoint_after["last_document_id"] == (
        checkpoint_before["last_document_id"]
    )
    with factory() as session:
        late_record = session.scalar(
            select(WazuhAlertRecord).where(
                WazuhAlertRecord.wazuh_document_id == "late-alert"
            )
        )
    assert late_record is not None
    assert store.count_alerts_since(
        late_record.ingested_at - timedelta(microseconds=1)
    ) >= 1


def test_durable_ingestion_lease_rejects_second_owner_until_release():
    store, _ = repository()
    first = store.claim_ingestion(
        "wazuh-indexer",
        connection_profile_id="default",
        index_pattern="wazuh-alerts-*",
        lease_token="lease-one",
        lease_ttl_seconds=60,
    )
    second = store.claim_ingestion(
        "wazuh-indexer",
        connection_profile_id="default",
        index_pattern="wazuh-alerts-*",
        lease_token="lease-two",
        lease_ttl_seconds=60,
    )

    assert first == "lease-one"
    assert second is None
    assert store.release_ingestion_claim(
        "wazuh-indexer",
        lease_token="lease-one",
    )
    assert store.claim_ingestion(
        "wazuh-indexer",
        connection_profile_id="default",
        index_pattern="wazuh-alerts-*",
        lease_token="lease-two",
        lease_ttl_seconds=60,
    ) == "lease-two"


def test_investigation_links_to_the_persisted_primary_alert():
    alert_store, factory = repository()
    document = alert_document()
    alert_store.ingest_page(
        source_name="wazuh-indexer",
        documents=[document],
        search_after=document.sort_values,
    )
    investigation_store = SQLAlchemyInvestigationRepository(factory)
    investigation_store.save_snapshot(
        {
            "investigation_id": "INV-LINKED",
            "organization_id": "user-test",
            "owner_user_id": "user-test",
            "alert_id": document.document_id,
            "agent_id": "001",
            "status": "running",
            "current_stage": "monitor",
            "errors": [],
            "audit_events": [],
            "pending_nodes": [],
        }
    )

    with factory() as session:
        investigation = session.get(InvestigationRecord, "INV-LINKED")
        alert = session.scalar(select(WazuhAlertRecord))
    assert investigation is not None
    assert alert is not None
    assert investigation.primary_alert_id == alert.id
