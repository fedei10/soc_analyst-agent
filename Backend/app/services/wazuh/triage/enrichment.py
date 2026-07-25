"""Pluggable indicator enrichment: one real internal adapter, vendor stubs behind the same seam."""

from __future__ import annotations

import ipaddress
from typing import Protocol

from app.config import settings
from app.services.wazuh.triage.schemas import EnrichmentResult, IndicatorType


def _csv_set(value: str) -> set[str]:
    return {item.strip() for item in value.split(",") if item.strip()}


class EnrichmentAdapter(Protocol):
    def enrich(self, indicator: str, indicator_type: IndicatorType) -> EnrichmentResult: ...


def _is_private_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


class InternalAssetAdapter:
    """Checks an indicator against configured internal allowlists. No external calls."""

    def enrich(self, indicator: str, indicator_type: IndicatorType) -> EnrichmentResult:
        if indicator_type != "ip":
            return EnrichmentResult(
                indicator=indicator,
                indicator_type=indicator_type,
                is_internal=False,
                source="internal_asset_inventory",
            )
        is_internal = _is_private_ip(indicator)
        allowlisted = indicator in _csv_set(settings.MAPEK_APPROVED_ADMIN_IPS)
        protected = indicator in _csv_set(settings.MAPEK_PROTECTED_IPS)
        return EnrichmentResult(
            indicator=indicator,
            indicator_type=indicator_type,
            is_internal=is_internal,
            reputation="clean" if allowlisted else "unknown",
            known_asset=is_internal,
            allowlisted=allowlisted or protected,
            source="internal_asset_inventory",
        )


class ExternalNotConfiguredAdapter:
    """Stub for a vendor threat-intel source with no credentials configured yet.

    ponytail: no VirusTotal/MISP/AbuseIPDB API keys in this environment. Swap
    this for a real HTTP client behind the same EnrichmentAdapter protocol
    once credentials exist — no other call site changes.
    """

    def __init__(self, vendor: str) -> None:
        self.vendor = vendor

    def enrich(self, indicator: str, indicator_type: IndicatorType) -> EnrichmentResult:
        return EnrichmentResult(
            indicator=indicator,
            indicator_type=indicator_type,
            is_internal=False,
            reputation="unknown",
            source=f"{self.vendor}:not_configured",
        )


VENDOR_ADAPTERS: dict[str, EnrichmentAdapter] = {
    "virustotal": ExternalNotConfiguredAdapter("virustotal"),
    "misp": ExternalNotConfiguredAdapter("misp"),
    "abuseipdb": ExternalNotConfiguredAdapter("abuseipdb"),
}
