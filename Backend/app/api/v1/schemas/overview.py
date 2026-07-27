"""HTTP contract for the SOC operations overview."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class APIModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class OverviewMetric(APIModel):
    value: int | float | None
    trend: str | None = None


class PipelineStage(APIModel):
    stage: Literal[
        "monitor",
        "analyze",
        "plan",
        "approval",
        "execute",
        "verify",
        "complete",
        "failed",
    ]
    count: int = Field(ge=0)


class AlertReduction(APIModel):
    raw_alerts: int | None = Field(default=None, ge=0)
    represented_alerts: int = Field(ge=0)
    findings: int = Field(ge=0)
    reduction_percent: float | None = Field(default=None, ge=0, le=100)


class SOCOverview(APIModel):
    generated_at: str
    window_hours: int = Field(ge=1, le=168)
    wazuh_status: Literal["available", "unavailable"]
    metrics: dict[str, OverviewMetric]
    pipeline: list[PipelineStage]
    severity_distribution: dict[str, int]
    alert_reduction: AlertReduction
    recent_investigations: list[dict]
    recent_findings: list[dict]


class ModelAssignment(APIModel):
    role: str
    provider: str
    model: str | None = None


class SOCPlatform(APIModel):
    generated_at: str
    pending_approvals: list[dict]
    response_actions: list[dict]
    audit_events: list[dict]
    model_assignments: list[ModelAssignment]
    response_policy: dict[str, bool | int | str]
    retention: dict[str, int | str]
    wazuh_dashboard_url: str | None = None
