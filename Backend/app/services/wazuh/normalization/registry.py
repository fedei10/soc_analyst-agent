"""Prioritized registry for deterministic Wazuh normalizers."""

from __future__ import annotations

import time
from typing import Any

import structlog

from app.services.wazuh.normalization.auditd import AuditdNormalizer
from app.services.wazuh.normalization.authentication import AuthenticationNormalizer
from app.services.wazuh.normalization.compliance import ComplianceNormalizer
from app.services.wazuh.normalization.file_integrity import FileIntegrityNormalizer
from app.services.wazuh.normalization.generic import GenericNormalizer
from app.services.wazuh.normalization.network import NetworkNormalizer
from app.services.wazuh.normalization.package import PackageNormalizer
from app.services.wazuh.normalization.schemas import AlertEnvelope
from app.services.wazuh.normalization.sysmon import SysmonNormalizer
from app.services.wazuh.normalization.vulnerability import VulnerabilityNormalizer


logger = structlog.get_logger("tsage.wazuh.normalization")

NORMALIZERS = sorted(
    [
        AuthenticationNormalizer(),
        AuditdNormalizer(),
        SysmonNormalizer(),
        VulnerabilityNormalizer(),
        ComplianceNormalizer(),
        PackageNormalizer(),
        FileIntegrityNormalizer(),
        NetworkNormalizer(),
        GenericNormalizer(),
    ],
    key=lambda normalizer: normalizer.priority,
)


def normalize_alert(raw: dict[str, Any]) -> AlertEnvelope:
    started = time.perf_counter()
    for normalizer in NORMALIZERS:
        if not normalizer.matches(raw):
            continue
        try:
            result = normalizer.normalize(raw)
        except Exception as exc:
            logger.warning(
                "alert_normalization_failed",
                normalizer=type(normalizer).__name__,
                error_type=type(exc).__name__,
            )
            result = GenericNormalizer().normalize(raw)
        logger.info(
            "alert_normalization_completed",
            decoder=result.normalized.decoder_name,
            rule_id=result.normalized.rule_id,
            attack_family=result.normalized.attack_family,
            event_type=result.normalized.event_type,
            normalization_quality=result.normalization_quality,
            duration_ms=round((time.perf_counter() - started) * 1000, 2),
        )
        return result
    return GenericNormalizer().normalize(raw)


def normalize_alerts(alerts: list[dict[str, Any]]) -> list[AlertEnvelope]:
    return [normalize_alert(alert) for alert in alerts]
