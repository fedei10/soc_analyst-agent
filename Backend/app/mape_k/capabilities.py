"""Small evidence-backed attack capabilities used before LLM diagnosis."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.mape_k.schemas import (
    ANSWERED_COLLECTION_STATUSES,
    Diagnosis,
    IncidentWorkflowState,
)


@dataclass(frozen=True)
class EvidenceRequirement:
    evidence_type: str
    collector: str
    required: bool = True
    purpose: str = ""
    component: str | None = None
    alert_field: str | None = None
    minimum_records: int = 1
    minimum_pass: int = 1


@dataclass(frozen=True)
class AttackCapability:
    capability_id: str
    incident_type: str
    evidence_profile: str
    evidence_requirements: tuple[EvidenceRequirement, ...]
    summary: str
    root_cause: str
    event_types: frozenset[str] = frozenset()
    attack_families: frozenset[str] = frozenset()
    mitre_prefixes: tuple[str, ...] = ()
    min_rule_level: int = 10
    required_field: str | None = None
    confidence: float = 0.84
    # False when the capability establishes a fact rather than an attack: a
    # CVE is present, a package changed, a file was modified, someone
    # authenticated. `confidence` then measures certainty in that fact, and
    # must not be read as probability of compromise.
    threat_bearing: bool = True
    investigation_steps: tuple[str, ...] = ()
    containment_recommendations: tuple[str, ...] = ()

    def matches(self, alert: Any) -> bool:
        if int(alert.rule_level or 0) < self.min_rule_level:
            return False
        technique_match = bool(
            self.mitre_prefixes
            and any(
                str(technique).startswith(self.mitre_prefixes)
                for technique in alert.mitre_techniques
            )
        )
        classification_match = bool(
            alert.event_type in self.event_types
            or alert.attack_family in self.attack_families
        )
        return technique_match or classification_match


CAPABILITIES: tuple[AttackCapability, ...] = (
    AttackCapability(
        capability_id="privilege-escalation",
        incident_type="privilege_escalation_activity",
        evidence_profile="identity_and_process",
        evidence_requirements=(
            EvidenceRequirement(
                "process_identity", "primary_alert_field", alert_field="process_name"
            ),
            EvidenceRequirement("process_and_privilege_timeline", "agent_timeline"),
            EvidenceRequirement("privilege_and_integrity_state", "detection_evidence"),
            EvidenceRequirement("asset_identity", "agent_summary", required=False),
        ),
        summary="High-severity activity maps to a privilege-escalation technique.",
        root_cause=(
            "Wazuh observed activity mapped to privilege escalation; the exact "
            "exploit or administrative cause still requires host validation."
        ),
        mitre_prefixes=("T1068", "T1548"),
        required_field="process_name",
        investigation_steps=(
            "Review the process tree, effective user, and recent account changes.",
            "Check for newly created privileged sessions or persistence.",
        ),
        containment_recommendations=(
            "Isolate the affected host only after validating business impact.",
            "Disable a confirmed compromised account through an approved runbook.",
        ),
    ),
    AttackCapability(
        capability_id="persistence",
        incident_type="persistence_activity",
        evidence_profile="persistence_and_file_integrity",
        evidence_requirements=(
            EvidenceRequirement("related_persistence_events", "related_alerts"),
            EvidenceRequirement("file_integrity_state", "detection_evidence"),
            EvidenceRequirement("service_and_startup_activity", "archived_logs"),
            EvidenceRequirement(
                "process_inventory", "agent_inventory", required=False, component="processes"
            ),
        ),
        summary="High-severity endpoint activity maps to a persistence technique.",
        root_cause=(
            "Wazuh observed a persistence-related technique; the responsible "
            "binary, account, and change origin require endpoint validation."
        ),
        mitre_prefixes=("T1053", "T1136", "T1547"),
        investigation_steps=(
            "Inspect scheduled tasks, services, startup locations, and new accounts.",
            "Correlate file changes with process execution around the alert time.",
        ),
        containment_recommendations=(
            "Preserve the changed artifacts before removing confirmed persistence.",
        ),
    ),
    AttackCapability(
        capability_id="command-and-control",
        incident_type="command_and_control_activity",
        evidence_profile="network_and_process",
        evidence_requirements=(
            EvidenceRequirement(
                "network_destination", "primary_alert_field", alert_field="destination_ip"
            ),
            EvidenceRequirement("initiating_process_timeline", "agent_timeline"),
            EvidenceRequirement("listening_port_context", "agent_inventory", component="ports"),
            EvidenceRequirement("archived_network_activity", "archived_logs", required=False),
        ),
        summary="High-severity network activity maps to command and control.",
        root_cause=(
            "Wazuh observed a command-and-control technique; destination ownership "
            "and the initiating process require confirmation."
        ),
        mitre_prefixes=("T1071", "T1105"),
        required_field="destination_ip",
        investigation_steps=(
            "Identify the initiating process and all contacted destinations.",
            "Hunt for the same indicator across other agents and archived logs.",
        ),
        containment_recommendations=(
            "Block a confirmed malicious destination through a reviewed network runbook.",
            "Isolate a confirmed compromised endpoint.",
        ),
    ),
    AttackCapability(
        capability_id="exfiltration",
        incident_type="possible_data_exfiltration",
        evidence_profile="network_and_data_access",
        evidence_requirements=(
            EvidenceRequirement(
                "network_destination", "primary_alert_field", alert_field="destination_ip"
            ),
            EvidenceRequirement("process_and_transfer_timeline", "agent_timeline"),
            EvidenceRequirement("archived_data_access", "archived_logs"),
            EvidenceRequirement(
                "network_inventory", "agent_inventory", required=False, component="network"
            ),
        ),
        summary="High-severity network activity maps to an exfiltration technique.",
        root_cause=(
            "Wazuh observed an exfiltration-related technique; transferred content "
            "and destination intent are not established by this alert alone."
        ),
        mitre_prefixes=("T1041", "T1567"),
        required_field="destination_ip",
        investigation_steps=(
            "Measure destination, volume, duration, and the initiating identity.",
            "Review accessed files and related process activity before the transfer.",
        ),
        containment_recommendations=(
            "Restrict the confirmed channel and preserve endpoint/network evidence.",
        ),
    ),
    AttackCapability(
        capability_id="suspicious-process",
        incident_type="suspicious_process_execution",
        evidence_profile="process_and_parent",
        evidence_requirements=(
            EvidenceRequirement(
                "process_identity", "primary_alert_field", alert_field="process_name"
            ),
            EvidenceRequirement("process_parent_timeline", "agent_timeline"),
            EvidenceRequirement("process_inventory", "agent_inventory", component="processes"),
            EvidenceRequirement("file_integrity_state", "detection_evidence", required=False),
        ),
        summary="A high-severity process execution alert was observed.",
        root_cause=(
            "Wazuh detected suspicious process activity; authorization and process "
            "ancestry must be checked before declaring compromise."
        ),
        event_types=frozenset({"process_execution", "process_created"}),
        attack_families=frozenset({"execution", "endpoint_activity"}),
        required_field="process_name",
        investigation_steps=(
            "Validate the executable, parent process, user, and nearby file changes.",
            "Hunt for the executable or hash across other agents.",
        ),
        containment_recommendations=(
            "Stop or isolate only after confirming the process is malicious.",
        ),
    ),
    AttackCapability(
        capability_id="file-integrity",
        threat_bearing=False,
        incident_type="suspicious_file_change",
        evidence_profile="file_integrity_and_process",
        evidence_requirements=(
            EvidenceRequirement(
                "changed_file", "primary_alert_field", alert_field="file_path"
            ),
            EvidenceRequirement("file_integrity_state", "detection_evidence"),
            EvidenceRequirement("modifying_process_activity", "archived_logs"),
            EvidenceRequirement(
                "process_inventory", "agent_inventory", required=False, component="processes"
            ),
        ),
        summary="A high-severity file-integrity change was observed.",
        root_cause=(
            "Wazuh recorded a sensitive file change; the responsible process and "
            "whether the change was authorized require validation."
        ),
        event_types=frozenset({"file_created", "file_modified", "file_deleted"}),
        attack_families=frozenset({"file_change"}),
        required_field="file_path",
        investigation_steps=(
            "Compare before/after hashes and identify the modifying user and process.",
            "Check adjacent process, package, and persistence events.",
        ),
        containment_recommendations=(
            "Quarantine a confirmed malicious artifact using an approved host runbook.",
        ),
    ),
    AttackCapability(
        capability_id="vulnerability",
        threat_bearing=False,
        incident_type="high_risk_vulnerability_exposure",
        evidence_profile="vulnerability_and_asset",
        evidence_requirements=(
            EvidenceRequirement(
                "vulnerability_identity", "primary_alert_field", alert_field="cve_id"
            ),
            EvidenceRequirement("installed_vulnerability_state", "vulnerability_inventory"),
            EvidenceRequirement("service_exposure", "agent_inventory", component="ports"),
            EvidenceRequirement("exploitation_timeline", "agent_timeline", required=False),
        ),
        summary="A high-severity vulnerable package was identified.",
        root_cause=(
            "The installed package matches a high-severity vulnerability; this is "
            "exposure evidence and does not by itself prove exploitation."
        ),
        event_types=frozenset({"vulnerable_package"}),
        attack_families=frozenset({"vulnerability_management"}),
        required_field="cve_id",
        confidence=0.9,
        investigation_steps=(
            "Confirm the installed version, exposure, exploitability, and fixed version.",
            "Search for exploitation indicators before patching.",
        ),
        containment_recommendations=(
            "Reduce exposure and apply the approved patch during a reviewed window.",
        ),
    ),
    AttackCapability(
        capability_id="software-change",
        threat_bearing=False,
        incident_type="unauthorized_software_change",
        evidence_profile="package_and_process",
        evidence_requirements=(
            EvidenceRequirement(
                "package_identity", "primary_alert_field", alert_field="package_name"
            ),
            EvidenceRequirement("package_inventory", "agent_inventory", component="packages"),
            EvidenceRequirement("package_manager_activity", "archived_logs"),
            EvidenceRequirement("process_timeline", "agent_timeline", required=False),
        ),
        summary="A high-severity software package change was observed.",
        root_cause=(
            "Wazuh recorded a package state change; deployment records and the "
            "initiating identity must be checked to determine authorization."
        ),
        event_types=frozenset(
            {"package_installed", "package_removed", "package_state_changed"}
        ),
        attack_families=frozenset({"software_change"}),
        required_field="package_name",
        investigation_steps=(
            "Compare the package change with deployment and maintenance records.",
            "Review the initiating account and nearby process execution.",
        ),
        containment_recommendations=(
            "Revert an unauthorized package change through the normal change process.",
        ),
    ),
)


SSH_EVIDENCE_REQUIREMENTS: tuple[EvidenceRequirement, ...] = (
    EvidenceRequirement(
        "authentication_timeline",
        "related_alerts",
        purpose="Confirm failures, successes, source, user, and timing.",
    ),
    EvidenceRequirement(
        "post_login_activity",
        "agent_timeline",
        purpose="Find process, sudo, and other endpoint activity around the login.",
        minimum_pass=2,
    ),
    EvidenceRequirement(
        "session_archives",
        "archived_logs",
        purpose="Search archived telemetry for session activity.",
        minimum_pass=2,
    ),
    EvidenceRequirement(
        "file_integrity_state",
        "detection_evidence",
        required=False,
        minimum_pass=2,
    ),
    EvidenceRequirement(
        "source_asset_identity",
        "source_identity",
        required=False,
        purpose="Map the source IP to an approved administrator, VPN, or asset.",
    ),
)


GENERIC_EVIDENCE_REQUIREMENTS: tuple[EvidenceRequirement, ...] = (
    EvidenceRequirement(
        "related_security_events",
        "related_alerts",
        purpose="Establish the bounded event sequence around the alert.",
    ),
    EvidenceRequirement(
        "endpoint_activity_timeline",
        "agent_timeline",
        purpose="Collect nearby process, identity, file, and network alerts.",
    ),
    EvidenceRequirement(
        "asset_identity",
        "agent_summary",
        purpose="Confirm the monitored endpoint and its current connection state.",
    ),
    EvidenceRequirement(
        "process_inventory",
        "agent_inventory",
        required=False,
        component="processes",
    ),
)


def capability_for_alert(alert: Any) -> AttackCapability | None:
    return next(
        (capability for capability in CAPABILITIES if capability.matches(alert)),
        None,
    )


def capability_for_incident(incident_type: str) -> AttackCapability | None:
    return next(
        (
            capability
            for capability in CAPABILITIES
            if capability.incident_type == incident_type
        ),
        None,
    )


def diagnose_with_capabilities(
    state: IncidentWorkflowState,
) -> Diagnosis | None:
    matches = [
        (alert, capability_for_alert(alert))
        for alert in state.normalized_alerts
    ]
    matches = [
        (alert, capability)
        for alert, capability in matches
        if capability is not None
    ]
    if not matches:
        return None
    alert, capability = max(
        matches,
        key=lambda item: (
            int(item[0].rule_level or 0),
            len(item[0].mitre_techniques),
        ),
    )
    relevant = [
        candidate
        for candidate in state.normalized_alerts
        if capability.matches(candidate)
    ]
    source_refs = {
        f"wazuh:alert:{candidate.alert_id}" for candidate in relevant
    }
    evidence_ids = [
        item.evidence_id
        for item in state.evidence
        if item.source_ref in source_refs
    ]
    if not evidence_ids:
        return None
    assets = list(
        dict.fromkeys(
            candidate.hostname or candidate.agent_name or candidate.agent_id
            for candidate in relevant
            if candidate.hostname or candidate.agent_name or candidate.agent_id
        )
    )
    field_value = (
        getattr(alert, capability.required_field)
        if capability.required_field
        else None
    )
    monitor_context = getattr(state, "monitor_context", {}) or {}
    truncated = bool(monitor_context.get("related_alerts_truncated"))
    applicable_types = {
        item.evidence_type for item in capability.evidence_requirements
    }
    collection_results = [
        item
        for item in state.evidence_collection_results
        if item.evidence_type in applicable_types
    ]
    required_results = [item for item in collection_results if item.required]
    complete_results = [
        item
        for item in required_results
        if item.status in ANSWERED_COLLECTION_STATUSES
    ]
    completeness = (
        len(complete_results) / len(required_results)
        if required_results
        else 0.0
    )
    missing_evidence = [
        item.evidence_type
        for item in required_results
        if item.status not in ANSWERED_COLLECTION_STATUSES
    ]
    supporting_evidence_ids = list(
        dict.fromkeys(
            [
                *evidence_ids,
                *(
                    evidence_id
                    for item in collection_results
                    if item.status == "collected"
                    for evidence_id in item.evidence_ids
                ),
            ]
        )
    )
    needs_more_evidence = bool(
        truncated
        or completeness < 0.8
        or (
            capability.required_field is not None
            and not field_value
        )
    )
    return Diagnosis(
        incident_type=capability.incident_type,
        summary=capability.summary,
        root_cause=capability.root_cause,
        attack_techniques=list(
            dict.fromkeys(
                technique
                for candidate in relevant
                for technique in candidate.mitre_techniques
            )
        ),
        affected_assets=assets,
        affected_entities={
            "source_ip": alert.source_ip,
            "destination_ip": alert.destination_ip,
            "users": list(
                dict.fromkeys(
                    candidate.target_user
                    for candidate in relevant
                    if candidate.target_user
                )
            ),
            "process_name": alert.process_name,
            "file_path": alert.file_path,
            "package_name": alert.package_name,
            "cve_id": alert.cve_id,
            "capability_id": capability.capability_id,
            "evidence_profile": capability.evidence_profile,
        },
        evidence_ids=evidence_ids,
        confidence=min(
            capability.confidence,
            0.5 + (0.4 * completeness),
        ),
        needs_more_evidence=needs_more_evidence,
        deterministic=True,
        supporting_evidence_ids=supporting_evidence_ids,
        missing_evidence=missing_evidence,
        evidence_completeness=completeness,
    )
