"""Strict input schemas for the allowlisted SOC agent tools."""

from datetime import datetime
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    model_validator,
)


class ToolInput(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HighSeverityAlertsInput(ToolInput):
    min_level: int = Field(default=10, ge=0, le=15)
    hours: int = Field(default=24, ge=1, le=168)
    limit: int = Field(default=50, ge=1, le=100)


class RecentAlertsInput(ToolInput):
    min_level: int = Field(default=0, ge=0, le=15)
    hours: int = Field(default=24, ge=1, le=168)
    limit: int = Field(default=50, ge=1, le=100)
    agent_id: str | None = Field(
        default=None,
        pattern=r"^\d+$",
        max_length=16,
    )
    rule_id: str | None = Field(
        default=None,
        pattern=r"^\d+$",
        max_length=16,
    )
    text: str | None = Field(default=None, min_length=2, max_length=128)


class AlertByIdInput(ToolInput):
    alert_id: str = Field(min_length=1, max_length=128, pattern=r"^[\w.-]+$")


class AgentSummaryInput(ToolInput):
    agent_id: str = Field(pattern=r"^\d+$", max_length=16)


class RelatedAlertsInput(AlertByIdInput):
    hours: int = Field(default=24, ge=1, le=168)
    limit: int = Field(default=25, ge=1, le=50)


class AuthenticationTimelineInput(ToolInput):
    source_ip: IPvAnyAddress | None = None
    target_user: str | None = Field(default=None, max_length=128)
    agent_id: str | None = Field(default=None, pattern=r"^\d+$", max_length=16)
    hours: int = Field(default=24, ge=1, le=168)
    limit: int = Field(default=25, ge=1, le=50)
    center_time: datetime | None = None
    window_minutes: int = Field(default=30, ge=1, le=1440)

    @model_validator(mode="after")
    def require_source_or_agent(self):
        if self.source_ip is None and self.agent_id is None:
            raise ValueError("source_ip or agent_id is required.")
        return self


class SuccessfulLoginInput(AuthenticationTimelineInput):
    limit: int = Field(default=50, ge=1, le=50)


class AgentTimeWindowInput(ToolInput):
    agent_id: str = Field(pattern=r"^\d+$", max_length=16)
    center_time: datetime
    window_minutes: int = Field(default=30, ge=1, le=1440)
    limit: int = Field(default=100, ge=1, le=200)


class AttributionInvestigationInput(AlertByIdInput):
    window_minutes: int = Field(default=30, ge=1, le=1440)
    limit: int = Field(default=100, ge=1, le=200)


class ArchivedLogSearchInput(ToolInput):
    text: str = Field(min_length=2, max_length=256)
    hours: int = Field(default=24, ge=1, le=168)
    limit: int = Field(default=50, ge=1, le=100)
    agent_id: str | None = Field(default=None, pattern=r"^\d+$", max_length=16)


class LogStatisticsInput(ToolInput):
    hours: int = Field(default=24, ge=1, le=168)


class RuleMitreContextInput(ToolInput):
    rule_id: str = Field(pattern=r"^\d+$", max_length=16)


class DetectionEvidenceInput(ToolInput):
    agent_id: str = Field(pattern=r"^\d+$", max_length=16)
    limit: int = Field(default=20, ge=1, le=200)


class EndpointInventoryInput(ToolInput):
    agent_id: str = Field(pattern=r"^\d+$", max_length=16)
    component: Literal[
        "processes",
        "ports",
        "packages",
        "os",
        "network",
        "hotfixes",
    ]
    limit: int = Field(default=20, ge=1, le=100)
    text: str | None = Field(default=None, min_length=2, max_length=128)


class VulnerabilitySearchInput(ToolInput):
    severity: Literal["Low", "Medium", "High", "Critical"] | None = None
    agent_id: str | None = Field(
        default=None,
        pattern=r"^\d+$",
        max_length=16,
    )
    limit: int = Field(default=20, ge=1, le=100)


# ToolRuntime is injected by LangGraph after model arguments are generated.
# These variants retain field validation while allowing that trusted hidden key.
class RuntimeAlertByIdInput(AlertByIdInput):
    model_config = ConfigDict(extra="ignore")


class RuntimeAttributionInvestigationInput(AttributionInvestigationInput):
    model_config = ConfigDict(extra="ignore")


class RuntimeAgentSummaryInput(AgentSummaryInput):
    model_config = ConfigDict(extra="ignore")
