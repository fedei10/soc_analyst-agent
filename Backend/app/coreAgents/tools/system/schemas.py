"""Strict inputs for API-host diagnostic tools."""

from typing import Literal

from pydantic import BaseModel, ConfigDict


class SystemDiagnosticInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    diagnostic: Literal[
        "listening_ports",
        "network_connections",
        "routing_table",
        "firewall_status",
        "failed_services",
        "process_snapshot",
    ]
