"""Base class and shared canonical-field construction for Wazuh normalizers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from app.services.wazuh.normalization.field_extractors import (
    alert_id,
    authentication_log_fields,
    evidence_ref,
    first,
    integer,
    ip,
    port,
    string_list,
    text,
    timestamp,
)
from app.services.wazuh.normalization.schemas import AlertEnvelope, NormalizedAlert


class AlertNormalizer(ABC):
    priority = 100
    category = "uncategorized"
    attack_family = "unknown"

    @abstractmethod
    def matches(self, raw: dict[str, Any]) -> bool:
        raise NotImplementedError

    @abstractmethod
    def normalize(self, raw: dict[str, Any]) -> AlertEnvelope:
        raise NotImplementedError

    def build(
        self,
        raw: dict[str, Any],
        *,
        event_type: str,
        summary: str,
        outcome: str = "unknown",
        attack_details: dict[str, Any] | None = None,
        category: str | None = None,
        attack_family: str | None = None,
        process_name: str | None = None,
        parent_process_name: str | None = None,
        file_path: str | None = None,
        package_name: str | None = None,
        cve_id: str | None = None,
        generic: bool = False,
    ) -> AlertEnvelope:
        identifier = alert_id(raw)
        parsed_timestamp, timestamp_valid = timestamp(raw)
        rule_id = text(raw, "rule.id", "rule_id")
        rule_description = text(
            raw,
            "rule.description",
            "description",
            "rule_description",
        )
        source_ip = ip(
            raw,
            "source.ip",
            "source_ip",
            "data.srcip",
            "data.src_ip",
            "data.source_ip",
            "data.remote_ip",
        )
        log_source_ip, log_user, log_source_port = authentication_log_fields(raw)
        source_ip = source_ip or log_source_ip
        destination_ip = ip(
            raw,
            "destination.ip",
            "destination_ip",
            "data.dstip",
            "data.dst_ip",
            "data.destination_ip",
        )
        missing = []
        if identifier == "unknown-alert":
            missing.append("alert_id")
        if not timestamp_valid:
            missing.append("timestamp")
        if not rule_id:
            missing.append("rule_id")
        if not rule_description:
            missing.append("rule_description")
        quality = "generic" if generic else ("partial" if missing else "complete")
        normalized = NormalizedAlert(
            alert_id=identifier,
            timestamp=parsed_timestamp,
            agent_id=text(raw, "agent.id", "agent_id"),
            agent_name=text(raw, "agent.name", "agent_name"),
            hostname=text(
                raw,
                "predecoder.hostname",
                "hostname",
                "agent.name",
                "agent_name",
            ),
            rule_id=rule_id,
            rule_level=integer(raw, "rule.level", "rule_level", default=0) or 0,
            rule_description=rule_description,
            rule_groups=string_list(raw, "rule.groups", "rule_groups"),
            decoder_name=text(raw, "decoder.name", "decoder_name"),
            category=category or self.category,
            attack_family=attack_family or self.attack_family,
            event_type=event_type,
            outcome=outcome,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=(
                port(raw, "source.port", "source_port", "data.srcport")
                or log_source_port
            ),
            destination_port=port(
                raw,
                "destination.port",
                "destination_port",
                "data.dstport",
            ),
            source_user=text(raw, "source.user.name", "source_user", "data.srcuser"),
            target_user=(
                text(
                    raw,
                    "user.name",
                    "target_user",
                    "data.dstuser",
                    "data.srcuser",
                    "data.user",
                    "data.username",
                )
                or log_user
            ),
            process_name=process_name,
            parent_process_name=parent_process_name,
            file_path=file_path,
            package_name=package_name,
            cve_id=cve_id,
            mitre_techniques=string_list(
                raw,
                "rule.mitre.id",
                "mitre_ids",
                "mitre_techniques",
            ),
            summary=summary,
            evidence_ref=evidence_ref(identifier),
            normalization_quality=quality,
            missing_fields=missing,
        )
        details = {
            key: value
            for key, value in (attack_details or {}).items()
            if value is not None
            and value != []
            and key not in type(normalized).model_fields
        }
        return AlertEnvelope(
            normalized=normalized,
            attack_details=details,
            evidence_refs=[normalized.evidence_ref],
            raw_document_ref=normalized.evidence_ref,
            normalizer_name=type(self).__name__,
            normalization_quality=quality,
            missing_fields=missing,
        )


def outcome_from_text(value: str) -> str:
    if any(word in value for word in ("blocked", "denied", "dropped")):
        return "blocked"
    if any(word in value for word in ("success", "accepted", "logged in")):
        return "success"
    if any(word in value for word in ("fail", "invalid user", "authentication error")):
        return "failure"
    return "unknown"
