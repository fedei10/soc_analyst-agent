"""Typed contracts for SOC assistant commands and responses."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AssistantCommandName(StrEnum):
    CHAT = "chat"
    HELP = "help"
    ALERTS = "alerts"
    SUMMARY = "summary"
    HUNT = "hunt"
    TRIAGE = "triage"
    INVESTIGATE = "investigate"
    STATUS = "status"
    PLAN = "plan"
    COLLECT = "collect"
    CONTINUE = "continue"
    HEALTH = "health"
    EXPLAIN = "explain"


class AssistantIntent(StrictModel):
    command: AssistantCommandName
    arguments: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=1.0, ge=0, le=1)
    source: str = "deterministic"


class QuestionAnswer(StrictModel):
    answer: str = Field(min_length=1, max_length=4000)
    confidence: float = Field(default=0.7, ge=0, le=1)
    references: list[str] = Field(default_factory=list, max_length=10)
    limitations: list[str] = Field(default_factory=list, max_length=5)


class AssistantCommand(StrictModel):
    name: AssistantCommandName
    slash: str
    aliases: list[str] = Field(default_factory=list)
    title: str
    description: str
    usage: str
    category: str
    examples: list[str] = Field(default_factory=list)


class AssistantActivity(StrictModel):
    id: str
    tool: str | None = None
    label: str
    status: str


class AssistantResponse(StrictModel):
    conversation_id: str
    assistant_message: str
    response: dict[str, Any] = Field(default_factory=dict)
    tools_used: list[str] = Field(default_factory=list)
    activities: list[AssistantActivity] = Field(default_factory=list)
    selected_command: AssistantCommandName
    active_investigation_id: str | None = None
    active_alert_id: str | None = None
    active_agent_id: str | None = None
    investigation: dict[str, Any] | None = None


class AssistantRequest(StrictModel):
    message: str = Field(min_length=1, max_length=8000)
    conversation_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$",
    )
