"""Deterministic Wazuh normalization and compact-context API."""

from app.services.wazuh.normalization.aggregation import (
    aggregate_alerts,
    build_findings,
)
from app.services.wazuh.normalization.registry import (
    NORMALIZERS,
    normalize_alert,
    normalize_alerts,
)
from app.services.wazuh.normalization.schemas import (
    AlertEnvelope,
    AlertGroup,
    NormalizedAlert,
    SecurityFinding,
)

__all__ = [
    "AlertEnvelope",
    "AlertGroup",
    "NORMALIZERS",
    "NormalizedAlert",
    "SecurityFinding",
    "aggregate_alerts",
    "build_findings",
    "normalize_alert",
    "normalize_alerts",
]
