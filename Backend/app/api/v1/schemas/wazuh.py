"""
Request schemas for state-changing Wazuh endpoints.

The approving/executing actor is always derived from the verified Clerk
principal and is never accepted from the client body.
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


class RestartAgentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
