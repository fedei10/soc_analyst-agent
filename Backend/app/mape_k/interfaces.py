"""Dependency-injection interfaces for controlled MAPE-K stages."""

from __future__ import annotations

from typing import Any, Protocol

from app.mape_k.schemas import (
    Diagnosis,
    IncidentWorkflowState,
    RemediationPlan,
)


class MonitorStage(Protocol):
    def run(self, state: IncidentWorkflowState) -> dict[str, Any]: ...


class AnalyzeStage(Protocol):
    def run(self, state: IncidentWorkflowState) -> Diagnosis: ...


class PlanStage(Protocol):
    def run(self, state: IncidentWorkflowState) -> RemediationPlan: ...


class PolicyStage(Protocol):
    def evaluate(self, state: IncidentWorkflowState) -> dict[str, Any]: ...


class ExecuteStage(Protocol):
    def run(self, state: IncidentWorkflowState) -> dict[str, Any]: ...


class VerifyStage(Protocol):
    def run(self, state: IncidentWorkflowState) -> dict[str, Any]: ...
