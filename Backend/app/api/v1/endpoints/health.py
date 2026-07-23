"""
Service health diagnostics (auth required — see router comment below).

GET /api/v1/health/services -> quick up/down status of every external service
GET /api/v1/health/wazuh    -> detailed Wazuh check (indexer + server API) with
                               a human explanation and fix for every error code

Responses are validated against the schemas in app/api/v1/schemas/health.py,
so /docs always shows the exact shape of both the 200 and 503 cases.
"""
import time
from typing import Annotated, Callable

import httpx
import requests
from fastapi import APIRouter, Depends, Response, status
from opensearchpy import exceptions as opensearch_exc

from app.api.auth.deps import require_read
from app.api.v1.schemas.health import (
    ServiceCheck,
    ServicesHealthResponse,
    WazuhHealthResponse,
)
from app.services.cerebras.connection import test_cerebras_connection
from app.services.groq.connection import test_groq_connection
from app.services.oxy.connection import oxy_connection
from app.services.wazuh.dependencies import get_wazuh_gateway
from app.services.wazuh.exceptions import WazuhAPIError, WazuhAuthError, WazuhPermissionError
from app.services.wazuh.gateway import WazuhGateway

# Diagnostics require auth: the meaning/fix strings below describe internal
# topology and must not be readable anonymously. Bare liveness is GET /health
# in main.py. Results are cached so callers can't burn LLM quotas or trip
# Wazuh's auth rate limit by hammering these endpoints.
router = APIRouter(prefix="/health", tags=["health"], dependencies=[Depends(require_read)])
GatewayDep = Annotated[WazuhGateway, Depends(get_wazuh_gateway)]

_CACHE_TTL = 30.0
_cache: dict[str, tuple[float, object, int]] = {}


def _cached(key: str, build: Callable[[], tuple[object, int]]) -> tuple[object, int]:
    hit = _cache.get(key)
    if hit is None or hit[0] <= time.monotonic():
        body, code = build()
        hit = (time.monotonic() + _CACHE_TTL, body, code)
        _cache[key] = hit
    return hit[1], hit[2]

# What each Wazuh/indexer error code means and how to fix it.
HTTP_CODE_EXPLANATIONS = {
    401: {
        "meaning": "Unauthorized — Wazuh rejected the username/password.",
        "fix": "Check WAZUH_INDEXER_USER/PASSWORD and WAZUH_USERNAME/WAZUH_PASSWORD in .env "
               "against the values in PC1's docker-compose.yml.",
    },
    403: {
        "meaning": "Forbidden — credentials are valid but the user lacks RBAC "
                   "permission for this endpoint or index.",
        "fix": "Grant the user read permission in Wazuh RBAC (or use the admin/wazuh-wui "
               "lab users until the read-only soc_agent_reader user is created).",
    },
    404: {
        "meaning": "Not found — wrong URL path, or the wazuh-alerts-* index does not "
                   "exist yet (no alerts have been indexed).",
        "fix": "Verify WAZUH_BASE_URL in .env; if it is the index, generate at least one "
               "alert (e.g. a failed SSH login on a monitored agent).",
    },
    405: {
        "meaning": "Method not allowed — the configured endpoint is not accepting the "
                   "documented POST authentication method.",
        "fix": "Verify WAZUH_BASE_URL and confirm the manager API version and route.",
    },
    408: {
        "meaning": "Request timeout — Wazuh accepted the connection but was too slow.",
        "fix": "Check load on PC1; the indexer may still be starting up.",
    },
    429: {
        "meaning": "Too many requests — the Wazuh API rate-limits authentication "
                   "attempts.",
        "fix": "Wait a minute and retry; avoid re-authenticating on every request "
               "(the service caches the JWT for ~13 minutes).",
    },
    500: {
        "meaning": "Internal Wazuh error.",
        "fix": "On PC1: docker compose logs wazuh.manager / wazuh.indexer.",
    },
    503: {
        "meaning": "Service unavailable — the container is up but the service inside "
                   "is still initializing (common right after docker compose up).",
        "fix": "Wait 1-2 minutes for the indexer/manager to finish starting, then retry.",
    },
}

NETWORK_EXPLANATIONS = {
    "connection_refused": {
        "meaning": "Nothing is listening on the target host:port.",
        "fix": "The SSH tunnel to PC1 is not running, or the Wazuh containers are down. "
               "Start: ssh -N -L 9200:127.0.0.1:9200 -L 55000:127.0.0.1:55000 "
               "soclab@192.168.100.15 — and on PC1 check: docker compose ps.",
    },
    "timeout": {
        "meaning": "The host did not answer at all (packets dropped).",
        "fix": "Check the network route/VPN to PC1 and any firewall on 9200/55000.",
    },
    "ssl_error": {
        "meaning": "TLS verification failed — the server certificate is not signed by "
                   "the CA the client trusts.",
        "fix": "Copy root-ca.pem from PC1 and point WAZUH_CA_CERT at it, or set "
               "WAZUH_VERIFY_SSL=false for lab use only.",
    },
}


def explain_failure(exc: Exception) -> dict:
    """Turn an exception into {error_code, meaning, fix, detail}."""
    status_code = None
    if isinstance(exc, httpx.HTTPStatusError):
        status_code = exc.response.status_code
    elif isinstance(exc, WazuhAuthError):
        status_code = 401
    elif isinstance(exc, WazuhPermissionError):
        status_code = 403
    elif isinstance(exc, WazuhAPIError):
        status_code = exc.status_code
    elif isinstance(exc, opensearch_exc.TransportError) and isinstance(exc.status_code, int):
        status_code = exc.status_code

    if status_code is not None:
        info = HTTP_CODE_EXPLANATIONS.get(status_code, {
            "meaning": "Unexpected HTTP error from Wazuh.",
            "fix": "See detail below and the Wazuh container logs on PC1.",
        })
        return {"error_code": status_code, **info, "detail": str(exc)}

    if isinstance(exc, (opensearch_exc.ConnectionTimeout, httpx.TimeoutException)):
        kind = "timeout"
    elif isinstance(exc, opensearch_exc.SSLError) or "SSL" in str(exc) or "certificate" in str(exc):
        kind = "ssl_error"
    else:  # opensearch ConnectionError, httpx ConnectError, refused, etc.
        kind = "connection_refused"

    return {"error_code": kind, **NETWORK_EXPLANATIONS[kind], "detail": str(exc)}


@router.get(
    "/wazuh",
    response_model=WazuhHealthResponse,
    response_model_exclude_none=True,
    responses={503: {"model": WazuhHealthResponse,
                     "description": "One or more Wazuh components are unhealthy"}},
)
def wazuh_health(response: Response, gateway: GatewayDep) -> WazuhHealthResponse:
    """Detailed Wazuh health: indexer and server API checked separately. Cached 30s."""
    body, response.status_code = _cached("wazuh", lambda: _build_wazuh_health(gateway))
    return body


def _build_wazuh_health(gateway: WazuhGateway) -> tuple[WazuhHealthResponse, int]:
    checks: dict[str, ServiceCheck] = {}

    try:
        cluster = gateway.indexer_health()
        checks["indexer"] = ServiceCheck(
            status="healthy",
            cluster_status=cluster.get("status"),
            nodes=cluster.get("number_of_nodes"),
        )
    except Exception as e:
        checks["indexer"] = ServiceCheck(status="unhealthy", **explain_failure(e))

    try:
        agents = gateway.server_get("/agents", params={"limit": 1})
        checks["server_api"] = ServiceCheck(
            status="healthy",
            agents_total=agents.get("data", {}).get("total_affected_items"),
        )
    except Exception as e:
        checks["server_api"] = ServiceCheck(status="unhealthy", **explain_failure(e))

    healthy = all(c.status == "healthy" for c in checks.values())
    code = status.HTTP_200_OK if healthy else status.HTTP_503_SERVICE_UNAVAILABLE
    return WazuhHealthResponse(status="healthy" if healthy else "unhealthy", checks=checks), code


@router.get(
    "/services",
    response_model=ServicesHealthResponse,
    response_model_exclude_none=True,
    responses={503: {"model": ServicesHealthResponse,
                     "description": "One or more services are unhealthy"}},
)
def services_health(response: Response, gateway: GatewayDep) -> ServicesHealthResponse:
    """Quick up/down status of every external service. Cached 30s."""
    body, response.status_code = _cached("services", lambda: _build_services_health(gateway))
    return body


def _build_services_health(gateway: WazuhGateway) -> tuple[ServicesHealthResponse, int]:
    results: dict[str, ServiceCheck] = {}

    for name, check in {
        "groq": test_groq_connection,
        "cerebras": test_cerebras_connection,
    }.items():
        try:
            check()
            results[name] = ServiceCheck(status="healthy")
        except requests.HTTPError as e:
            results[name] = ServiceCheck(
                status="unhealthy",
                error_code=e.response.status_code,
                detail="401 = bad API key in .env" if e.response.status_code == 401 else str(e),
            )
        except Exception as e:
            results[name] = ServiceCheck(status="unhealthy", detail=str(e))

    # ponytail: oxy_connection swallows its own errors and returns bool
    results["oxy"] = ServiceCheck(status="healthy" if oxy_connection() else "unhealthy")

    try:
        gateway.indexer_health()
        gateway.validate_server()
        results["wazuh"] = ServiceCheck(status="healthy")
    except Exception as e:
        results["wazuh"] = ServiceCheck(status="unhealthy", **explain_failure(e))

    healthy = all(r.status == "healthy" for r in results.values())
    code = status.HTTP_200_OK if healthy else status.HTTP_503_SERVICE_UNAVAILABLE
    return ServicesHealthResponse(status="healthy" if healthy else "unhealthy", services=results), code
