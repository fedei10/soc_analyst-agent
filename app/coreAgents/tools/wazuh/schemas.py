"""Strict input schemas for the allowlisted SOC agent tools."""

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress


class ToolInput(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HighSeverityAlertsInput(ToolInput):
    min_level: int = Field(default=10, ge=0, le=15)
    hours: int = Field(default=24, ge=1, le=168)
    limit: int = Field(default=50, ge=1, le=100)


class AlertByIdInput(ToolInput):
    alert_id: str = Field(min_length=1, max_length=128, pattern=r"^[\w.-]+$")


class AgentSummaryInput(ToolInput):
    agent_id: str = Field(pattern=r"^\d+$", max_length=16)


class RelatedAlertsInput(AlertByIdInput):
    hours: int = Field(default=24, ge=1, le=168)
    limit: int = Field(default=100, ge=1, le=200)


class AuthenticationTimelineInput(ToolInput):
    source_ip: IPvAnyAddress
    target_user: str | None = Field(default=None, max_length=128)
    agent_id: str | None = Field(default=None, pattern=r"^\d+$", max_length=16)
    hours: int = Field(default=24, ge=1, le=168)
    limit: int = Field(default=100, ge=1, le=200)


class SuccessfulLoginInput(AuthenticationTimelineInput):
    limit: int = Field(default=200, ge=1, le=200)


class RuleMitreContextInput(ToolInput):
    rule_id: str = Field(pattern=r"^\d+$", max_length=16)


class DetectionEvidenceInput(ToolInput):
    agent_id: str = Field(pattern=r"^\d+$", max_length=16)
    limit: int = Field(default=100, ge=1, le=200)
