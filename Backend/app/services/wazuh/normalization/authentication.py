"""SSH and authentication alert normalization."""

from __future__ import annotations

import ipaddress
from typing import Any

from app.services.wazuh.normalization.base import AlertNormalizer, outcome_from_text
from app.services.wazuh.normalization.field_extractors import (
    combined_text,
    integer,
    ip,
    text,
)
from app.services.wazuh.normalization.schemas import AuthenticationDetails


class AuthenticationNormalizer(AlertNormalizer):
    priority = 10
    category = "authentication"
    attack_family = "credential_access"

    def matches(self, raw: dict[str, Any]) -> bool:
        value = combined_text(raw)
        return any(
            marker in value
            for marker in (
                "sshd",
                "authentication_fail",
                "authentication_success",
                "failed password",
                "accepted password",
                "brute force",
                "t1110",
            )
        )

    def normalize(self, raw: dict[str, Any]):
        value = combined_text(raw)
        outcome = outcome_from_text(value)
        repeated = any(
            marker in value
            for marker in ("brute force", "multiple", "more than one time", "t1110")
        )
        if outcome == "success":
            event_type = "ssh_login_success"
            attack_family = "initial_access"
        elif repeated:
            event_type = "ssh_brute_force"
            attack_family = "credential_access"
        else:
            event_type = "ssh_login_failure"
            attack_family = "credential_access"
        source_ip = ip(
            raw,
            "source.ip",
            "source_ip",
            "data.srcip",
            "data.remote_ip",
        )
        internal = None
        if source_ip:
            internal = ipaddress.ip_address(source_ip).is_private
        details = AuthenticationDetails(
            protocol="ssh" if "ssh" in value else text(raw, "data.protocol"),
            attempt_count=integer(
                raw,
                "data.attempt_count",
                "rule.firedtimes",
                "event_count",
                default=1,
            )
            or 1,
            source_is_internal=internal,
            authentication_method=(
                "password"
                if "password" in value
                else text(raw, "data.authentication_method")
            ),
            failure_reason=(
                "invalid_user"
                if "invalid user" in value or "non-existent user" in value
                else ("authentication_failed" if outcome == "failure" else None)
            ),
        ).model_dump(mode="json", exclude_none=True)
        description = text(raw, "rule.description", "description") or "authentication event"
        return self.build(
            raw,
            event_type=event_type,
            summary=f"{event_type.replace('_', ' ')}: {description}.",
            outcome=outcome,
            attack_family=attack_family,
            attack_details=details,
        )
