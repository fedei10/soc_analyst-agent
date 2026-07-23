"""Normalized evidence returned by the Wazuh application gateway."""

from datetime import datetime
from typing import Literal

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
    mitre_ids: list[str] = Field(default_factory=list)
    event_outcome: Literal["success", "failure", "unknown"] = "unknown"


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
    failed_attempt_count: int = Field(ge=0)
    first_failure: datetime | None = None
    last_failure: datetime | None = None
    successful_login_found: bool
    successful_login_timestamp: datetime | None = None
    evidence_alert_ids: list[str]
    confidence: float = Field(ge=0.0, le=1.0)
    truncated: bool


class RuleMitreContext(BaseModel):
    rule_id: str
    description: str | None = None
    level: int | None = None
    groups: list[str] = Field(default_factory=list)
    mitre_ids: list[str] = Field(default_factory=list)
    techniques: list[dict] = Field(default_factory=list)


class DetectionEvidence(BaseModel):
    agent_id: str
    fim_findings: list[dict]
    sca_findings: list[dict]
    fim_total: int = Field(ge=0)
    sca_total: int = Field(ge=0)
    truncated: bool


class ToolError(BaseModel):
    code: str
    message: str
    retryable: bool
