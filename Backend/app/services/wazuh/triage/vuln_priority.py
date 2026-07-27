"""Re-rank detected CVEs by real-world exploitability, not just CVSS.

Deterministic scoring: CISA KEV membership (actively exploited) dominates,
then EPSS exploitation probability, then CVSS base score. Both feeds are
free, unauthenticated, and optional - offline the ranking degrades to CVSS.
"""

from __future__ import annotations

import time
from typing import Any

import httpx
import structlog

logger = structlog.get_logger("tsage.vuln_priority")

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
EPSS_URL = "https://api.first.org/data/v1/epss"
FEED_TIMEOUT_SECONDS = 5.0
KEV_CACHE_SECONDS = 86_400
_kev_cache: tuple[float, frozenset[str]] | None = None

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}


def fetch_kev_cves() -> frozenset[str]:
    global _kev_cache
    if _kev_cache and time.monotonic() - _kev_cache[0] < KEV_CACHE_SECONDS:
        return _kev_cache[1]
    try:
        response = httpx.get(KEV_URL, timeout=FEED_TIMEOUT_SECONDS)
        response.raise_for_status()
        cves = frozenset(
            str(item.get("cveID"))
            for item in response.json().get("vulnerabilities", [])
            if item.get("cveID")
        )
        _kev_cache = (time.monotonic(), cves)
        return cves
    except Exception as exc:
        logger.warning("kev_feed_unavailable", error_type=type(exc).__name__)
        return _kev_cache[1] if _kev_cache else frozenset()


def fetch_epss_scores(cves: list[str]) -> dict[str, float]:
    if not cves:
        return {}
    try:
        response = httpx.get(
            EPSS_URL,
            params={"cve": ",".join(cves[:100])},
            timeout=FEED_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        return {
            str(item["cve"]): float(item["epss"])
            for item in response.json().get("data", [])
            if item.get("cve")
        }
    except Exception as exc:
        logger.warning("epss_feed_unavailable", error_type=type(exc).__name__)
        return {}


def _field(source: dict[str, Any], *path: str) -> Any:
    value: Any = source
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def prioritize_vulnerabilities(
    items: list[dict[str, Any]],
    *,
    kev_cves: frozenset[str],
    epss_scores: dict[str, float],
) -> list[dict[str, Any]]:
    ranked = []
    for source in items:
        cve = str(_field(source, "vulnerability", "id") or "")
        severity = str(_field(source, "vulnerability", "severity") or "-")
        cvss = _field(source, "vulnerability", "score", "base")
        cvss_value = float(cvss) if cvss is not None else 0.0
        epss = float(epss_scores.get(cve, 0.0))
        in_kev = cve in kev_cves
        reasons = []
        if in_kev:
            reasons.append("Listed in CISA KEV: known active exploitation")
        if epss > 0:
            reasons.append(f"EPSS exploitation probability {epss:.1%}")
        if cvss is not None:
            reasons.append(f"CVSS base score {cvss_value:g}")
        if not reasons:
            reasons.append("No exploitability signal; ranked by severity only")
        ranked.append(
            {
                "cve": cve or "unknown",
                "severity": severity,
                "cvss": cvss_value if cvss is not None else None,
                "epss": epss if epss > 0 else None,
                "known_exploited": in_kev,
                "priority_score": round(
                    (1000.0 if in_kev else 0.0)
                    + epss * 100.0
                    + cvss_value
                    + SEVERITY_ORDER.get(severity, 0) * 0.1,
                    3,
                ),
                "reasons": reasons,
                "agent_id": _field(source, "agent", "id"),
                "agent_name": _field(source, "agent", "name"),
                "package": _field(source, "package", "name"),
                "description": str(
                    _field(source, "vulnerability", "description") or ""
                )[:300]
                or None,
            }
        )
    ranked.sort(key=lambda item: item["priority_score"], reverse=True)
    return ranked


def rank_detected_vulnerabilities(
    items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    cves = [
        str(_field(source, "vulnerability", "id"))
        for source in items
        if _field(source, "vulnerability", "id")
    ]
    return prioritize_vulnerabilities(
        items,
        kev_cves=fetch_kev_cves(),
        epss_scores=fetch_epss_scores(cves),
    )
