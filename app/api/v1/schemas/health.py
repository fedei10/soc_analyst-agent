"""
Response schemas for health endpoints.

One consistent shape for every check: `status`, plus healthy details
(cluster_status/nodes/agents_total) or error details (error_code/meaning/
fix/detail). None fields are dropped from responses.
"""
from typing import Literal

from pydantic import BaseModel


class ServiceCheck(BaseModel):
    status: Literal["healthy", "unhealthy"]
    # present when healthy
    cluster_status: str | None = None
    nodes: int | None = None
    agents_total: int | None = None
    # present when unhealthy
    error_code: int | str | None = None
    meaning: str | None = None
    fix: str | None = None
    detail: str | None = None


class WazuhHealthResponse(BaseModel):
    service: Literal["wazuh"] = "wazuh"
    status: Literal["healthy", "unhealthy"]
    checks: dict[str, ServiceCheck]


class ServicesHealthResponse(BaseModel):
    status: Literal["healthy", "unhealthy"]
    services: dict[str, ServiceCheck]
