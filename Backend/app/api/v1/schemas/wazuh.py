"""
Request schemas for the state-changing Wazuh endpoints (wazuh:write scope).

Both models reject unknown fields and require `approved_by`: response actions
are only executed after a named human approves them, and that name is logged
with the request_id for the audit trail.
"""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

# Commands Wazuh ships with. Custom AR scripts (isolate-host, quarantine-file,
# disable-user, kill-process, unblock variants) must be added on the manager
# first, then listed here — the enum is the API-side whitelist.
ActiveResponseCommand = Literal["firewall-drop", "host-deny", "restart-wazuh"]


class ActiveResponseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command: ActiveResponseCommand
    arguments: list[str] = Field(default_factory=list, max_length=10)
    alert: dict | None = Field(
        default=None, description="Original alert JSON, passed to the AR script for context."
    )
    approved_by: str = Field(
        min_length=1, max_length=100,
        description="Name of the human who approved this action.",
    )


class RestartAgentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approved_by: str = Field(min_length=1, max_length=100)
