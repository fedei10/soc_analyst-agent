"""Evidence-backed triage verdict and enrichment contracts."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.services.wazuh.normalization.schemas import FindingSeverity, SecurityFinding


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


VerdictLabel = Literal["benign", "suspicious", "malicious", "inconclusive"]
Reputation = Literal["unknown", "malicious", "suspicious", "clean"]
IndicatorType = Literal["ip", "domain", "hash"]


class TriageVerdict(StrictModel):
    verdict: VerdictLabel
    confidence: float = Field(ge=0, le=1)
    severity: FindingSeverity
    summary: str
    evidence_refs: list[str] = Field(min_length=1)
    false_positive_indicators: list[str] = Field(default_factory=list)
    escalation_recommended: bool
    missing_evidence: list[str] = Field(default_factory=list)
    deterministic: bool = False
    reason_code: str | None = None


class EnrichmentResult(StrictModel):
    indicator: str
    indicator_type: IndicatorType
    is_internal: bool
    reputation: Reputation = "unknown"
    known_asset: bool = False
    asset_owner: str | None = None
    allowlisted: bool = False
    previous_incidents: int = Field(default=0, ge=0)
    source: str


class TriagedFinding(StrictModel):
    finding: SecurityFinding
    verdict: TriageVerdict
    enrichment: list[EnrichmentResult] = Field(default_factory=list)
