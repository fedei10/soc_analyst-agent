"""Normalized evidence returned by the Wazuh application gateway."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class AlertEvidence(BaseModel):
    alert_id: str
    timestamp: datetime
    agent_id: str | None = None
    agent_name: str | None = None
    rule_id: str
    rule_level: int = Field(ge=0)
    description: str
    source_ip: str | None = None
    target_user: str | None = None
    hostname: str | None = None
    decoder_name: str | None = None
    full_log: str | None = None
    rule_groups: list[str] = Field(default_factory=list)
    mitre_ids: list[str] = Field(default_factory=list)
    event_outcome: Literal["success", "failure", "unknown"] = "unknown"


class RawAlertDocument(BaseModel):
    """Bounded raw Wazuh fields plus their normalized alert representation."""

    alert_id: str
    normalized: AlertEvidence
    raw_document: dict[str, Any]


class AlertIngestionDocument(BaseModel):
    """One stable, sortable Wazuh document returned to the ingestion worker."""

    document_id: str
    index_name: str
    sort_values: list[Any] = Field(default_factory=list)
    normalized: AlertEvidence
    raw_document: dict[str, Any]


class AlertIngestionPage(BaseModel):
    documents: list[AlertIngestionDocument]
    search_after: list[Any] | None = None
    total: int = Field(ge=0)


class ArchivedLogSearchResult(BaseModel):
    index_pattern: str
    archive_status: Literal[
        "available",
        "unavailable",
        "partial",
        "unknown",
    ] = "unknown"
    query_scope: dict[str, Any] = Field(default_factory=dict)
    total: int = Field(ge=0)
    returned: int = Field(ge=0)
    truncated: bool
    events: list[RawAlertDocument]


class AlertSearchResult(BaseModel):
    total: int = Field(ge=0)
    returned: int = Field(ge=0)
    truncated: bool
    alerts: list[AlertEvidence]


class AgentSummary(BaseModel):
    agent_id: str
    name: str | None = None
    ip: str | None = None
    status: str | None = None
    version: str | None = None
    os_name: str | None = None
    last_keep_alive: datetime | None = None


class AuthenticationTimeline(BaseModel):
    total: int = Field(ge=0)
    returned: int = Field(ge=0)
    truncated: bool
    events: list[AlertEvidence]


class SuccessfulLoginAnalysis(BaseModel):
    successful_login_search_completed: bool = True
    search_scope: dict[str, Any] = Field(default_factory=dict)
    returned_authentication_events: int = Field(default=0, ge=0)
    failed_attempt_count: int = Field(ge=0)
    first_failure: datetime | None = None
    last_failure: datetime | None = None
    successful_login_found: bool
    successful_login_observed: bool = False
    successful_login_timestamp: datetime | None = None
    conclusion: Literal[
        "successful_login_observed",
        "no_success_in_returned_alerts",
        "no_failures_in_returned_alerts",
    ] = "no_success_in_returned_alerts"
    evidence_alert_ids: list[str]
    confidence: float = Field(ge=0.0, le=1.0)
    truncated: bool


class AttributionResult(BaseModel):
    alert_id: str
    status: Literal[
        "identified",
        "partially_identified",
        "not_identified",
        "insufficient_telemetry",
    ]
    source_ip: str | None = None
    source_address_scope: Literal[
        "private",
        "public",
        "reserved_or_unknown",
    ] = "reserved_or_unknown"
    target_user: str | None = None
    attributed_person: None = None
    confidence: float = Field(ge=0.0, le=1.0)
    disposition: Literal["investigate_and_monitor"] = "investigate_and_monitor"
    containment_recommended: bool = False
    successful_login_after_failures: bool | None = None
    successful_login_search_completed: bool = False
    authentication_search_truncated: bool = False
    known_facts: list[str] = Field(default_factory=list)
    evidence_checked: list[dict[str, Any]] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    tool_errors: list[dict[str, Any]] = Field(default_factory=list)
    steps_completed: int = Field(ge=0, le=8)
    complete: bool
    reason: str


class RuleMitreContext(BaseModel):
    rule_id: str
    description: str | None = None
    level: int | None = None
    groups: list[str] = Field(default_factory=list)
    mitre_ids: list[str] = Field(default_factory=list)
    techniques: list[dict] = Field(default_factory=list)


class EndpointInventory(BaseModel):
    agent_id: str
    component: Literal[
        "processes",
        "ports",
        "packages",
        "os",
        "network",
        "hotfixes",
    ]
    total: int = Field(ge=0)
    returned: int = Field(ge=0)
    truncated: bool
    items: list[dict[str, Any]]


class DetectionEvidence(BaseModel):
    agent_id: str
    fim_findings: list[dict]
    sca_findings: list[dict]
    rootcheck_findings: list[dict] = Field(default_factory=list)
    fim_total: int = Field(ge=0)
    sca_total: int = Field(ge=0)
    rootcheck_total: int = Field(default=0, ge=0)
    truncated: bool


class EndpointForensics(BaseModel):
    """Bounded endpoint evidence bundle for advanced L2 investigation."""

    agent_id: str
    agent: AgentSummary | None = None
    inventories: dict[str, EndpointInventory] = Field(default_factory=dict)
    detection_evidence: DetectionEvidence | None = None
    vulnerabilities: list[dict[str, Any]] = Field(default_factory=list)
    vulnerability_total: int = Field(default=0, ge=0)
    truncated: bool = False
    source_errors: list[dict[str, str]] = Field(default_factory=list)
    telemetry_limitations: list[str] = Field(default_factory=list)


class IOCHuntResult(BaseModel):
    """Local Wazuh evidence for one indicator, with explicit source coverage."""

    indicator: str
    indicator_type: Literal[
        "ip",
        "domain",
        "hash",
        "process",
        "user",
        "path",
        "other",
    ]
    alerts: AlertSearchResult | None = None
    archived_logs: ArchivedLogSearchResult | None = None
    source_errors: list[dict[str, str]] = Field(default_factory=list)
    intelligence_scope: list[str] = Field(default_factory=list)
    external_intelligence_status: Literal["not_configured"] = "not_configured"


class ToolError(BaseModel):
    code: str
    message: str
    retryable: bool
