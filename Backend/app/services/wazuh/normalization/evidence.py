"""Validated evidence-reference resolution back to unchanged Wazuh documents."""

from __future__ import annotations

import re

import structlog

from app.services.wazuh.gateway import WazuhGateway
from app.services.wazuh.models import RawAlertDocument


logger = structlog.get_logger("tsage.wazuh.normalization")
EVIDENCE_REF_PATTERN = re.compile(r"^wazuh:alert:(?P<alert_id>[\w.-]{1,128})$")


def alert_id_from_evidence_ref(reference: str) -> str:
    match = EVIDENCE_REF_PATTERN.fullmatch(reference)
    if not match:
        raise ValueError("Invalid Wazuh evidence reference.")
    return match.group("alert_id")


def resolve_evidence_ref(
    reference: str,
    gateway: WazuhGateway,
) -> RawAlertDocument | None:
    alert_id = alert_id_from_evidence_ref(reference)
    document = gateway.get_raw_alert_by_id(alert_id)
    logger.info(
        "raw_evidence_retrieved",
        alert_id=alert_id,
        found=document is not None,
    )
    return document
