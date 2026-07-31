"""Deterministic Wazuh ingestion, normalization, deduplication and correlation."""

from __future__ import annotations

import ipaddress
from datetime import timedelta
from typing import Any

from app.config import settings
from app.mape_k.capabilities import (
    GENERIC_EVIDENCE_REQUIREMENTS,
    SSH_EVIDENCE_REQUIREMENTS,
    capability_for_alert,
)
from app.mape_k.schemas import (
    AuthenticationEvidenceSummary,
    EvidenceCollectionResult,
    EvidenceCollectionStatus,
    EvidenceReference,
    IncidentWorkflowState,
    WorkflowStage,
    WorkflowStatus,
)
from app.mape_k.utils import audit_event, content_hash, stable_id
from app.services.redis.ephemeral import EphemeralRedis
from app.services.wazuh.gateway import WazuhGateway
from app.services.wazuh.normalization import (
    aggregate_alerts,
    build_findings,
    normalize_alerts,
)
from app.utils.helpers import gather


SSH_EVENT_TYPES = {
    "ssh_login_failure",
    "ssh_invalid_user_attempt",
    "ssh_brute_force",
    "ssh_password_spraying",
    "ssh_login_success",
    "ssh_success_after_failures",
}


def _same_authentication_subject(failure: Any, success: Any) -> bool:
    if (
        failure.source_ip
        and success.source_ip
        and failure.source_ip != success.source_ip
    ):
        return False
    if (
        failure.target_user
        and success.target_user
        and failure.target_user != success.target_user
    ):
        return False
    failure_asset = failure.hostname or failure.agent_name or failure.agent_id
    success_asset = success.hostname or success.agent_name or success.agent_id
    return not (failure_asset and success_asset and failure_asset != success_asset)


def _uniform_boolean(values: list[bool]) -> bool | None:
    unique = set(values)
    return unique.pop() if len(unique) == 1 else None


class WazuhMonitor:
    def __init__(
        self,
        gateway: WazuhGateway | None = None,
        cache: EphemeralRedis | None = None,
    ) -> None:
        self.gateway = gateway or WazuhGateway()
        self.cache = cache or EphemeralRedis()

    # A week is the widest correlation the indexer query itself accepts, so
    # widening past it would silently do nothing.
    MAX_CORRELATION_WINDOW_SECONDS = 168 * 3600

    @staticmethod
    def _correlation_window_seconds(state: IncidentWorkflowState) -> int:
        """Widen the window on each re-collect pass.

        Analyze sends an inconclusive incident back here rather than
        escalating it; looking at the same window again would return the same
        evidence and the same verdict, so each pass multiplies the window.
        """

        base = max(1, settings.MAPEK_CORRELATION_WINDOW_SECONDS)
        attempts = max(int(getattr(state, "analysis_attempts", 0) or 0), 0)
        if not attempts:
            return base
        factor = max(float(settings.MAPEK_EVIDENCE_WIDEN_FACTOR), 1.0)
        return int(
            min(
                base * (factor**attempts),
                WazuhMonitor.MAX_CORRELATION_WINDOW_SECONDS,
            )
        )

    def run(self, state: IncidentWorkflowState) -> dict[str, Any]:
        primary = self.gateway.get_alert_by_id(state.alert_id)
        if primary is None:
            raise LookupError(f"Wazuh alert {state.alert_id!r} was not found.")

        primary_envelope = normalize_alerts(
            [primary.model_dump(mode="json", exclude_none=True)]
        )[0]
        primary_capability = capability_for_alert(primary_envelope.normalized)
        primary_is_ssh = primary_envelope.normalized.event_type in SSH_EVENT_TYPES
        window_seconds = self._correlation_window_seconds(state)
        correlation_start = primary.timestamp - timedelta(seconds=window_seconds)
        correlation_end = primary.timestamp + timedelta(seconds=window_seconds)
        related = self.gateway.get_related_alerts(
            alert_id=state.alert_id,
            hours=max(1, min(168, (window_seconds + 3599) // 3600)),
            limit=100,
            start_time=correlation_start,
            end_time=correlation_end,
            authentication_only=primary_is_ssh,
        )
        alerts_by_id = {primary.alert_id: primary}
        for alert in related.alerts:
            alerts_by_id.setdefault(alert.alert_id, alert)

        agent_id = state.agent_id or primary.agent_id
        ssh_session_enrichment: dict[str, Any] = {
            "performed": False,
            "session_alert_ids": [],
            "archive_event_ids": [],
            "source_errors": [],
            "limitations": [],
        }
        # The first SSH pass stays authentication-only. If Analyze cannot
        # decide, the next pass deliberately widens to bounded post-login and
        # endpoint telemetry instead of repeating the same authentication
        # query with a larger clock window.
        if primary_is_ssh and state.analysis_attempts > 0 and agent_id:
            ssh_session_enrichment["performed"] = True
            window_minutes = max(
                1,
                min(1440, (window_seconds + 59) // 60),
            )
            try:
                session_alerts = self.gateway.search_alerts_by_agent_and_time(
                    agent_id=agent_id,
                    center_time=primary.timestamp,
                    window_minutes=window_minutes,
                    limit=50,
                    authentication_only=False,
                )
                for alert in session_alerts.alerts:
                    alerts_by_id.setdefault(alert.alert_id, alert)
                ssh_session_enrichment["session_alert_ids"] = [
                    alert.alert_id for alert in session_alerts.alerts
                ]
                ssh_session_enrichment["session_search_truncated"] = (
                    session_alerts.truncated
                )
            except Exception as exc:
                ssh_session_enrichment["source_errors"].append(
                    {
                        "source": "agent_alert_timeline",
                        "error": type(exc).__name__,
                    }
                )

            archive_term = (
                primary.target_user or primary.source_ip or "sshd"
            )
            try:
                archived = self.gateway.search_archived_logs(
                    text=archive_term,
                    agent_id=agent_id,
                    center_time=primary.timestamp,
                    window_minutes=window_minutes,
                    limit=25,
                )
                for event in archived.events:
                    alerts_by_id.setdefault(
                        event.normalized.alert_id,
                        event.normalized,
                    )
                ssh_session_enrichment["archive_status"] = (
                    archived.archive_status
                )
                ssh_session_enrichment["archive_event_ids"] = [
                    event.normalized.alert_id for event in archived.events
                ]
                ssh_session_enrichment["archive_search_truncated"] = (
                    archived.truncated
                )
            except Exception as exc:
                ssh_session_enrichment["source_errors"].append(
                    {
                        "source": "archived_logs",
                        "error": type(exc).__name__,
                    }
                )

        raw_alerts = [
            alert.model_dump(mode="json", exclude_none=True)
            for alert in alerts_by_id.values()
        ]
        envelopes = normalize_alerts(raw_alerts)
        groups = aggregate_alerts(envelopes)
        findings = build_findings(groups)
        normalized = [envelope.normalized for envelope in envelopes]

        authentication_evidence = None
        if primary_is_ssh:
            authentication_envelopes = [
                envelope
                for envelope in envelopes
                if envelope.normalized.event_type in SSH_EVENT_TYPES
            ]
            authentication_alerts = [
                envelope.normalized for envelope in authentication_envelopes
            ]
            failures = [
                alert
                for alert in authentication_alerts
                if alert.outcome == "failure"
            ]
            successes = [
                alert
                for alert in authentication_alerts
                if alert.outcome == "success"
            ]
            source_ips = list(
                dict.fromkeys(
                    alert.source_ip for alert in authentication_alerts
                    if alert.source_ip
                )
            )
            target_users = list(
                dict.fromkeys(
                    alert.target_user for alert in authentication_alerts
                    if alert.target_user
                )
            )
            affected_assets = list(
                dict.fromkeys(
                    alert.hostname or alert.agent_name or alert.agent_id
                    for alert in authentication_alerts
                    if alert.hostname or alert.agent_name or alert.agent_id
                )
            )
            successful_login_after_failures = None
            if failures:
                successful_login_after_failures = any(
                    failure.timestamp < success.timestamp
                    and (
                        success.timestamp - failure.timestamp
                    ).total_seconds()
                    <= settings.MAPEK_SSH_SUCCESS_AFTER_FAILURE_WINDOW_SECONDS
                    and _same_authentication_subject(failure, success)
                    for failure in failures
                    for success in successes
                )
                if related.truncated and not successful_login_after_failures:
                    successful_login_after_failures = None

            approved_admin_ips = {
                value.strip()
                for value in settings.MAPEK_APPROVED_ADMIN_IPS.split(",")
                if value.strip()
            }
            internal_flags = [
                ipaddress.ip_address(source_ip).is_private
                for source_ip in source_ips
            ]
            approved_flags = [
                source_ip in approved_admin_ips for source_ip in source_ips
            ]
            missing_evidence = []
            if not source_ips:
                missing_evidence.append("source_ip")
            if not target_users:
                missing_evidence.append("target_user")
            if not affected_assets:
                missing_evidence.append("affected_asset")
            if related.truncated:
                missing_evidence.append("authentication_search_truncated")
            missing_evidence.extend(
                ["source_asset_identity", "source_reputation"]
            )
            authentication_evidence = AuthenticationEvidenceSummary(
                first_seen=min(alert.timestamp for alert in authentication_alerts),
                last_seen=max(alert.timestamp for alert in authentication_alerts),
                failed_attempt_count=sum(
                    int(envelope.attack_details.get("attempt_count") or 1)
                    for envelope in authentication_envelopes
                    if envelope.normalized.outcome == "failure"
                ),
                successful_attempt_count=sum(
                    int(envelope.attack_details.get("attempt_count") or 1)
                    for envelope in authentication_envelopes
                    if envelope.normalized.outcome == "success"
                ),
                distinct_event_count=len(authentication_alerts),
                distinct_target_user_count=len(target_users),
                source_ips=source_ips,
                target_users=target_users,
                affected_assets=affected_assets,
                successful_login_after_failures=successful_login_after_failures,
                source_is_internal=(
                    _uniform_boolean(internal_flags) if internal_flags else None
                ),
                source_is_approved_admin=(
                    _uniform_boolean(approved_flags) if approved_flags else None
                ),
                source_asset_id=None,
                source_reputation=None,
                total_hits=max(len(authentication_alerts), related.total + 1),
                returned_hits=len(authentication_alerts),
                truncated=related.truncated,
                correlation_window_start=correlation_start,
                correlation_window_end=correlation_end,
                missing_evidence=missing_evidence,
            )

        evidence: list[EvidenceReference] = []
        evidence_records: list[dict[str, Any]] = []
        try:
            raw_primary = self.gateway.get_raw_alert_by_id(state.alert_id)
        except Exception:
            raw_primary = None
        for envelope in envelopes:
            alert = envelope.normalized
            safe_payload = alert.model_dump(mode="json")
            evidence_id = stable_id("EV", "wazuh-alert", alert.alert_id, length=16)
            digest = content_hash(safe_payload)
            reference = EvidenceReference(
                evidence_id=evidence_id,
                source_type="wazuh_alert",
                source_ref=f"wazuh:alert:{alert.alert_id}",
                observed_at=alert.timestamp,
                summary=alert.summary[:1000],
                content_hash=digest,
            )
            evidence.append(reference)
            evidence_records.append(
                {
                    "evidence_id": evidence_id,
                    "source_type": "wazuh_alert",
                    "source_ref": reference.source_ref,
                    "raw_source_type": "wazuh_opensearch",
                    "raw_source_index": (
                        raw_primary.index_name
                        if raw_primary is not None
                        and raw_primary.alert_id == alert.alert_id
                        else settings.WAZUH_ARCHIVE_INDEX
                    ),
                    "raw_source_document_id": alert.alert_id,
                    "raw_document_hash": (
                        raw_primary.raw_document_hash
                        if raw_primary is not None
                        and raw_primary.alert_id == alert.alert_id
                        else None
                    ),
                    "normalized_document_hash": digest,
                    "normalizer_name": envelope.normalizer_name,
                    "normalizer_version": envelope.normalizer_version,
                    "ingested_at": envelope.normalized_at.isoformat(),
                    "observed_at": alert.timestamp.isoformat(),
                    "organization_id": state.organization_id,
                    "summary": reference.summary,
                    "content_hash": digest,
                    "event_count": int(
                        envelope.attack_details.get("attempt_count") or 1
                    ),
                    "attack_details": envelope.attack_details,
                }
            )

        inventory: dict[str, Any] = {}
        inventory_errors: list[dict[str, str]] = []
        if agent_id and primary_is_ssh and state.analysis_attempts > 0:
            for component in ("processes", "ports"):
                try:
                    result = self.gateway.get_agent_inventory(
                        agent_id=agent_id,
                        component=component,
                        limit=10,
                    )
                    compact = result.model_dump(mode="json")
                    compact["items"] = compact.get("items", [])[:5]
                    inventory[component] = compact
                except Exception as exc:
                    inventory_errors.append(
                        {"component": component, "error": type(exc).__name__}
                    )
            try:
                detection = self.gateway.get_detection_evidence(
                    agent_id=agent_id,
                    limit=10,
                )
                ssh_session_enrichment["detection_evidence"] = {
                    "fim_findings": detection.fim_findings[:5],
                    "sca_findings": detection.sca_findings[:5],
                    "rootcheck_findings": detection.rootcheck_findings[:5],
                    "fim_total": detection.fim_total,
                    "sca_total": detection.sca_total,
                    "rootcheck_total": detection.rootcheck_total,
                    "truncated": detection.truncated,
                }
                ssh_session_enrichment["limitations"].append(
                    "Endpoint inventory and detection evidence are current-state "
                    "snapshots, not guaranteed historical state at login time."
                )
            except Exception as exc:
                ssh_session_enrichment["source_errors"].append(
                    {
                        "source": "endpoint_detection_evidence",
                        "error": type(exc).__name__,
                    }
                )
        elif agent_id and not primary_is_ssh:
            components = tuple(
                dict.fromkeys(
                    requirement.component
                    for requirement in (
                        primary_capability.evidence_requirements
                        if primary_capability is not None
                        else GENERIC_EVIDENCE_REQUIREMENTS
                    )
                    if requirement.collector == "agent_inventory"
                    and requirement.component
                )
            )
            components = components[: settings.MAPEK_MAX_TOOL_CALLS_PER_STAGE]

            def fetch(component: str):
                return lambda: self.gateway.get_agent_inventory(
                    agent_id=agent_id,
                    component=component,
                    limit=10,
                )

            # Independent inventory reads: one round trip's latency, not four.
            for component, result in gather(
                [(component, fetch(component)) for component in components]
            ).items():
                if isinstance(result, Exception):
                    inventory_errors.append(
                        {"component": component, "error": type(result).__name__}
                    )
                else:
                    compact = result.model_dump(mode="json")
                    compact["items"] = compact.get("items", [])[:5]
                    inventory[component] = compact

        requirements = (
            SSH_EVIDENCE_REQUIREMENTS
            if primary_is_ssh
            else (
                primary_capability.evidence_requirements
                if primary_capability is not None
                else GENERIC_EVIDENCE_REQUIREMENTS
            )
        )
        collection_results: list[EvidenceCollectionResult] = []
        capability_evidence: dict[str, Any] = {}
        collector_calls = len(inventory) + len(inventory_errors)
        max_collector_calls = max(
            1,
            int(settings.MAPEK_MAX_TOOL_CALLS_PER_STAGE),
        )
        collection_pass = state.analysis_attempts + 1

        for requirement in requirements:
            status = EvidenceCollectionStatus.UNSUPPORTED
            records = 0
            source = requirement.collector
            limitation: str | None = None
            payload: Any = None

            if collection_pass < requirement.minimum_pass:
                status = EvidenceCollectionStatus.DEFERRED
                limitation = (
                    f"Scheduled for collection pass {requirement.minimum_pass}."
                )
            elif requirement.collector == "primary_alert_field":
                value = getattr(
                    primary_envelope.normalized,
                    str(requirement.alert_field or ""),
                    None,
                )
                records = int(value not in (None, "", []))
                status = (
                    EvidenceCollectionStatus.COLLECTED
                    if records
                    else EvidenceCollectionStatus.NOT_FOUND
                )
                payload = {"field": requirement.alert_field, "value": value}
                source = "wazuh_alert"
            elif requirement.collector == "related_alerts":
                records = len(related.alerts) + 1
                status = (
                    EvidenceCollectionStatus.TRUNCATED
                    if related.truncated
                    else EvidenceCollectionStatus.COLLECTED
                )
                payload = {
                    "alert_ids": list(alerts_by_id),
                    "total": max(records, related.total + 1),
                }
                source = "wazuh_indexer"
            elif requirement.collector == "agent_inventory":
                component = str(requirement.component or "")
                payload = inventory.get(component)
                if payload is not None:
                    records = int(payload.get("returned") or 0)
                    status = (
                        EvidenceCollectionStatus.TRUNCATED
                        if payload.get("truncated")
                        else EvidenceCollectionStatus.COLLECTED
                        if records >= requirement.minimum_records
                        else EvidenceCollectionStatus.NOT_FOUND
                    )
                else:
                    status = EvidenceCollectionStatus.COLLECTOR_UNAVAILABLE
                    limitation = "The requested inventory component was unavailable."
                source = f"wazuh_syscollector:{component}"
            elif primary_is_ssh and requirement.collector == "agent_timeline":
                records = len(
                    ssh_session_enrichment.get("session_alert_ids") or []
                )
                status = (
                    EvidenceCollectionStatus.TRUNCATED
                    if ssh_session_enrichment.get("session_search_truncated")
                    else EvidenceCollectionStatus.COLLECTED
                    if records >= requirement.minimum_records
                    else EvidenceCollectionStatus.NOT_FOUND
                )
                payload = {
                    "alert_ids": ssh_session_enrichment.get(
                        "session_alert_ids", []
                    )
                }
                source = "wazuh_agent_timeline"
            elif primary_is_ssh and requirement.collector == "archived_logs":
                records = len(
                    ssh_session_enrichment.get("archive_event_ids") or []
                )
                archive_status = ssh_session_enrichment.get("archive_status")
                status = (
                    EvidenceCollectionStatus.NOT_CONFIGURED
                    if archive_status in {None, "unavailable", "unknown"}
                    else EvidenceCollectionStatus.TRUNCATED
                    if ssh_session_enrichment.get("archive_search_truncated")
                    else EvidenceCollectionStatus.COLLECTED
                    if records >= requirement.minimum_records
                    else EvidenceCollectionStatus.NOT_FOUND
                )
                payload = {
                    "archive_status": archive_status,
                    "event_ids": ssh_session_enrichment.get(
                        "archive_event_ids", []
                    ),
                }
                source = "wazuh_archives"
            elif primary_is_ssh and requirement.collector == "detection_evidence":
                payload = ssh_session_enrichment.get("detection_evidence")
                if payload is not None:
                    records = sum(
                        int(payload.get(key) or 0)
                        for key in ("fim_total", "sca_total", "rootcheck_total")
                    )
                    status = (
                        EvidenceCollectionStatus.TRUNCATED
                        if payload.get("truncated")
                        else EvidenceCollectionStatus.COLLECTED
                        if records >= requirement.minimum_records
                        else EvidenceCollectionStatus.NOT_FOUND
                    )
                else:
                    status = EvidenceCollectionStatus.COLLECTOR_UNAVAILABLE
                source = "wazuh_endpoint_detection"
            elif requirement.collector == "source_identity":
                status = EvidenceCollectionStatus.NOT_CONFIGURED
                limitation = (
                    "No source asset, VPN, or administrator identity mapping "
                    "provider is configured."
                )
            elif not agent_id:
                status = EvidenceCollectionStatus.NOT_FOUND
                limitation = "The alert does not identify a Wazuh agent."
            elif collector_calls >= max_collector_calls:
                status = EvidenceCollectionStatus.COLLECTOR_UNAVAILABLE
                limitation = "The bounded Monitor collector budget was exhausted."
            else:
                collector_calls += 1
                try:
                    if requirement.collector == "agent_timeline":
                        timeline = self.gateway.search_alerts_by_agent_and_time(
                            agent_id=agent_id,
                            center_time=primary.timestamp,
                            window_minutes=max(
                                1,
                                min(1440, (window_seconds + 59) // 60),
                            ),
                            limit=25,
                            authentication_only=False,
                        )
                        records = timeline.returned
                        payload = {
                            "alerts": [
                                alert.model_dump(mode="json")
                                for alert in timeline.alerts[:10]
                            ],
                            "total": timeline.total,
                        }
                        status = (
                            EvidenceCollectionStatus.TRUNCATED
                            if timeline.truncated
                            else EvidenceCollectionStatus.COLLECTED
                            if records >= requirement.minimum_records
                            else EvidenceCollectionStatus.NOT_FOUND
                        )
                        source = "wazuh_agent_timeline"
                    elif requirement.collector == "archived_logs":
                        search_term = next(
                            (
                                str(value)
                                for value in (
                                    primary_envelope.normalized.process_name,
                                    primary_envelope.normalized.file_path,
                                    primary_envelope.normalized.package_name,
                                    primary_envelope.normalized.destination_ip,
                                    primary_envelope.normalized.source_ip,
                                )
                                if value
                            ),
                            primary.description,
                        )
                        archived = self.gateway.search_archived_logs(
                            text=search_term,
                            agent_id=agent_id,
                            center_time=primary.timestamp,
                            window_minutes=max(
                                1,
                                min(1440, (window_seconds + 59) // 60),
                            ),
                            limit=25,
                        )
                        records = archived.returned
                        payload = {
                            "archive_status": archived.archive_status,
                            "events": [
                                event.normalized.model_dump(mode="json")
                                for event in archived.events[:10]
                            ],
                            "total": archived.total,
                        }
                        status = (
                            EvidenceCollectionStatus.NOT_CONFIGURED
                            if archived.archive_status
                            in {"unavailable", "unknown"}
                            else EvidenceCollectionStatus.TRUNCATED
                            if archived.truncated
                            else EvidenceCollectionStatus.COLLECTED
                            if records >= requirement.minimum_records
                            else EvidenceCollectionStatus.NOT_FOUND
                        )
                        source = "wazuh_archives"
                    elif requirement.collector == "detection_evidence":
                        detection = self.gateway.get_detection_evidence(
                            agent_id=agent_id,
                            limit=10,
                        )
                        payload = detection.model_dump(mode="json")
                        records = (
                            detection.fim_total
                            + detection.sca_total
                            + detection.rootcheck_total
                        )
                        status = (
                            EvidenceCollectionStatus.TRUNCATED
                            if detection.truncated
                            else EvidenceCollectionStatus.COLLECTED
                            if records >= requirement.minimum_records
                            else EvidenceCollectionStatus.NOT_FOUND
                        )
                        source = "wazuh_endpoint_detection"
                    elif requirement.collector == "agent_summary":
                        summary = self.gateway.get_agent_summary(agent_id)
                        records = int(summary is not None)
                        payload = (
                            summary.model_dump(mode="json") if summary else None
                        )
                        status = (
                            EvidenceCollectionStatus.COLLECTED
                            if summary
                            else EvidenceCollectionStatus.NOT_FOUND
                        )
                        source = "wazuh_manager"
                    elif requirement.collector == "vulnerability_inventory":
                        vulnerabilities, total = self.gateway.search_vulnerabilities(
                            agent_id=agent_id,
                            limit=20,
                        )
                        records = len(vulnerabilities)
                        payload = {
                            "items": vulnerabilities[:10],
                            "total": total,
                        }
                        status = (
                            EvidenceCollectionStatus.TRUNCATED
                            if total > records
                            else EvidenceCollectionStatus.COLLECTED
                            if records >= requirement.minimum_records
                            else EvidenceCollectionStatus.NOT_FOUND
                        )
                        source = "wazuh_vulnerability_detector"
                except Exception as exc:
                    status = EvidenceCollectionStatus.COLLECTOR_UNAVAILABLE
                    limitation = type(exc).__name__

            capability_evidence[requirement.evidence_type] = payload
            result = EvidenceCollectionResult(
                evidence_type=requirement.evidence_type,
                collector=requirement.collector,
                required=requirement.required,
                purpose=requirement.purpose,
                status=status,
                records=records,
                source=source,
                limitation=limitation,
            )
            if payload is not None and status in {
                EvidenceCollectionStatus.COLLECTED,
                EvidenceCollectionStatus.NOT_FOUND,
                EvidenceCollectionStatus.TRUNCATED,
            }:
                safe_payload = {
                    "collection": result.model_dump(mode="json"),
                    "payload": payload,
                }
                digest = content_hash(safe_payload)
                evidence_id = stable_id(
                    "EV",
                    "collection",
                    state.investigation_id,
                    requirement.evidence_type,
                    digest,
                    length=16,
                )
                evidence.append(
                    EvidenceReference(
                        evidence_id=evidence_id,
                        source_type="wazuh_context",
                        source_ref=(
                            f"wazuh:context:{agent_id or 'unknown'}:"
                            f"{requirement.evidence_type}:{digest[:12]}"
                        ),
                        observed_at=primary.timestamp,
                        summary=(
                            f"{requirement.evidence_type}: {status.value}; "
                            f"{records} record(s) in the bounded collection."
                        ),
                        content_hash=digest,
                    )
                )
                evidence_records.append(
                    {
                        "evidence_id": evidence_id,
                        "source_type": "wazuh_context",
                        "source_ref": evidence[-1].source_ref,
                        "raw_source_type": source,
                        "raw_source_index": None,
                        "raw_source_document_id": None,
                        "raw_document_hash": None,
                        "normalized_document_hash": digest,
                        "normalizer_name": "evidence_contract",
                        "normalizer_version": "1.0",
                        "ingested_at": primary.timestamp.isoformat(),
                        "observed_at": primary.timestamp.isoformat(),
                        "organization_id": state.organization_id,
                        "summary": evidence[-1].summary,
                        "content_hash": digest,
                        "event_count": max(records, 1),
                        "attack_details": safe_payload,
                    }
                )
                result = result.model_copy(
                    update={"evidence_ids": [evidence_id]}
                )
            collection_results.append(result)

        required_results = [item for item in collection_results if item.required]
        completed_results = [
            item
            for item in required_results
            if item.status
            in {
                EvidenceCollectionStatus.COLLECTED,
                EvidenceCollectionStatus.NOT_FOUND,
            }
        ]
        evidence_completeness = (
            len(completed_results) / len(required_results)
            if required_results
            else 1.0
        )

        fingerprint_material = [
            group.group_key for group in groups
        ] or [state.alert_id]
        fingerprint = stable_id(
            "FP",
            *sorted(fingerprint_material),
            length=32,
        )
        evidence_version = content_hash(
            sorted(item.content_hash for item in evidence)
        )
        self.cache.set_json(
            namespace="mapek-correlation",
            organization_id=state.organization_id,
            cache_key=fingerprint,
            value={
                "incident_id": state.incident_id,
                "evidence_version": evidence_version,
                "alert_ids": list(alerts_by_id),
            },
            ttl_seconds=settings.MAPEK_CORRELATION_WINDOW_SECONDS,
        )

        return {
            "stage": WorkflowStage.ANALYZE,
            "current_stage": WorkflowStage.ANALYZE,
            "status": WorkflowStatus.RUNNING,
            "agent_id": agent_id,
            "normalized_alerts": normalized,
            "evidence": evidence,
            "evidence_records": evidence_records,
            "evidence_collection_results": collection_results,
            "authentication_evidence": authentication_evidence,
            "findings": [
                finding.model_dump(mode="json") for finding in findings
            ],
            "incident_fingerprint": fingerprint,
            "evidence_version": evidence_version,
            "monitor_context": {
                "evidence_profile": (
                    "ssh_authentication"
                    if primary_is_ssh
                    else (
                        primary_capability.evidence_profile
                        if primary_capability is not None
                        else "generic_evidence"
                    )
                ),
                "capability_id": (
                    primary_capability.capability_id
                    if primary_capability is not None
                    else None
                ),
                "inventory": inventory,
                "inventory_errors": inventory_errors,
                "raw_alert_count": len(raw_alerts),
                "deduplicated_alert_count": len(normalized),
                "correlated_group_count": len(groups),
                "correlation": {
                    "total_hits": max(len(alerts_by_id), related.total + 1),
                    "returned_hits": len(alerts_by_id),
                    "truncated": related.truncated,
                    "window_start": correlation_start.isoformat(),
                    "window_end": correlation_end.isoformat(),
                    "window_seconds": window_seconds,
                    "collection_pass": state.analysis_attempts + 1,
                },
                "related_alerts_truncated": related.truncated,
                "ssh_session_enrichment": ssh_session_enrichment,
                "evidence_contract": {
                    "requirements": [
                        {
                            "evidence_type": item.evidence_type,
                            "collector": item.collector,
                            "required": item.required,
                            "purpose": item.purpose,
                        }
                        for item in requirements
                    ],
                    "results": [
                        item.model_dump(mode="json")
                        for item in collection_results
                    ],
                    "completeness": evidence_completeness,
                },
                "capability_evidence": capability_evidence,
            },
            "audit_events": [
                audit_event(
                    "monitor_completed",
                    alert_count=len(normalized),
                    finding_count=len(findings),
                    inventory_errors=inventory_errors,
                    window_seconds=window_seconds,
                    collection_pass=state.analysis_attempts + 1,
                )
            ],
        }
