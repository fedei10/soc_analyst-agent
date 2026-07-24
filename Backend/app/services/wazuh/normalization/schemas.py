"""Canonical Wazuh alert, aggregation, and finding schemas."""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


Outcome = Literal["success", "failure", "blocked", "unknown"]
NormalizationQuality = Literal["complete", "partial", "generic"]
FindingSeverity = Literal["informational", "low", "medium", "high", "critical"]


class NormalizedAlert(BaseModel):
    schema_version: str = "1.0"
    alert_id: str
    timestamp: datetime
    agent_id: str | None = None
    agent_name: str | None = None
    hostname: str | None = None
    rule_id: str | None = None
    rule_level: int = Field(default=0, ge=0)
    rule_description: str | None = None
    rule_groups: list[str] = Field(default_factory=list)
    decoder_name: str | None = None
    category: str
    attack_family: str
    event_type: str
    outcome: Outcome = "unknown"
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    source_user: str | None = None
    target_user: str | None = None
    process_name: str | None = None
    parent_process_name: str | None = None
    file_path: str | None = None
    package_name: str | None = None
    cve_id: str | None = None
    mitre_techniques: list[str] = Field(default_factory=list)
    summary: str
    evidence_ref: str
    normalization_quality: NormalizationQuality
    missing_fields: list[str] = Field(default_factory=list)

    @field_validator("timestamp")
    @classmethod
    def timestamp_is_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    @field_validator("source_ip", "destination_ip", mode="before")
    @classmethod
    def valid_ip_or_none(cls, value: Any) -> str | None:
        if value in (None, ""):
            return None
        try:
            return str(ipaddress.ip_address(str(value).strip("[]")))
        except ValueError:
            return None


class AuthenticationDetails(BaseModel):
    protocol: str | None = None
    attempt_count: int = Field(default=1, ge=0)
    unique_user_count: int | None = Field(default=None, ge=0)
    source_is_internal: bool | None = None
    successful_login_after_failures: bool | None = None
    authentication_method: str | None = None
    failure_reason: str | None = None


class ProcessExecutionDetails(BaseModel):
    executable: str | None = None
    parent_process: str | None = None
    command_line_hash: str | None = None
    user: str | None = None
    privilege_level: str | None = None
    suspicious_interpreter: bool = False
    execution_count: int = Field(default=1, ge=0)


class NetworkDetails(BaseModel):
    protocol: str | None = None
    connection_count: int = Field(default=1, ge=0)
    unique_destination_count: int | None = Field(default=None, ge=0)
    bytes_sent: int | None = Field(default=None, ge=0)
    bytes_received: int | None = Field(default=None, ge=0)
    destination_ports: list[int] = Field(default_factory=list)


class VulnerabilityDetails(BaseModel):
    cve_id: str | None = None
    package: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    severity_label: str | None = None
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    remediation_available: bool | None = None


class FileIntegrityDetails(BaseModel):
    path: str | None = None
    operation: str | None = None
    previous_hash: str | None = None
    current_hash: str | None = None
    user: str | None = None
    process: str | None = None
    file_type: str | None = None


class ComplianceDetails(BaseModel):
    benchmark: str | None = None
    control_id: str | None = None
    control_title: str | None = None
    previous_status: str | None = None
    current_status: str | None = None
    score: float | None = None


class PackageChangeDetails(BaseModel):
    package: str | None = None
    version: str | None = None
    operation: str | None = None
    package_status: str | None = None


class AlertEnvelope(BaseModel):
    schema_version: str = "1.0"
    normalized: NormalizedAlert
    attack_details: dict[str, Any] = Field(default_factory=dict)
    evidence_refs: list[str] = Field(default_factory=list)
    raw_document_ref: str | None = None
    normalization_quality: NormalizationQuality
    missing_fields: list[str] = Field(default_factory=list)


class AlertGroup(BaseModel):
    group_id: str
    group_key: str
    category: str
    attack_family: str
    event_type: str
    first_seen: datetime
    last_seen: datetime
    alert_count: int = Field(ge=1)
    event_count: int | None = Field(default=None, ge=0)
    highest_severity: int = Field(ge=0)
    source_ips: list[str] = Field(default_factory=list)
    destination_ips: list[str] = Field(default_factory=list)
    target_hosts: list[str] = Field(default_factory=list)
    target_users: list[str] = Field(default_factory=list)
    outcomes: dict[str, int] = Field(default_factory=dict)
    mitre_techniques: list[str] = Field(default_factory=list)
    summary: str
    evidence_refs: list[str] = Field(default_factory=list)
    representative_alert_id: str
    truncated_evidence_refs: bool = False


class SecurityFinding(BaseModel):
    finding_id: str
    title: str
    summary: str
    category: str
    attack_family: str
    event_type: str
    severity: FindingSeverity
    severity_score: int = Field(ge=0, le=15)
    confidence: float = Field(ge=0, le=1)
    first_seen: datetime
    last_seen: datetime
    affected_assets: list[str] = Field(default_factory=list)
    source_ips: list[str] = Field(default_factory=list)
    target_users: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    alert_count: int = Field(ge=1)
    representative_alert_id: str
    evidence_refs: list[str] = Field(min_length=1)
    investigation_recommended: bool
    recommendation_reason_code: str | None = None
