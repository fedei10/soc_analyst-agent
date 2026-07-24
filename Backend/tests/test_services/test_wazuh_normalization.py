import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest

from app.coreAgents.orchestration.conversation_tools import build_soc_chat_tools
from app.services.wazuh.models import AlertEvidence, AlertSearchResult
from app.services.wazuh.normalization.aggregation import (
    aggregate_alerts,
    build_findings,
    severity_for_level,
)
from app.services.wazuh.normalization.evidence import (
    alert_id_from_evidence_ref,
    resolve_evidence_ref,
)
from app.services.wazuh.normalization.registry import normalize_alert
from app.services.wazuh.normalization.serializers import (
    compact_alert_search_result,
    compact_tool_result,
    serialize_for_api,
    serialize_for_trace,
)


BASE_TIME = datetime(2026, 7, 24, 19, 0, tzinfo=UTC)


def raw_alert(
    alert_id: str,
    *,
    timestamp: str = "2026-07-24T19:00:00Z",
    decoder: str = "json",
    groups: list[str] | None = None,
    description: str = "Synthetic alert",
    level: int = 7,
    data: dict | None = None,
    full_log: str = "synthetic log",
) -> dict:
    return {
        "_id": alert_id,
        "_source": {
            "@timestamp": timestamp,
            "agent": {"id": "001", "name": "servervb"},
            "rule": {
                "id": "100001",
                "level": level,
                "description": description,
                "groups": groups or [],
            },
            "decoder": {"name": decoder},
            "data": data or {},
            "full_log": full_log,
        },
    }


def auth_raw(alert_id: str, *, success: bool = False, offset: int = 0) -> dict:
    description = (
        "sshd: successful authentication"
        if success
        else "sshd: brute force trying to get access to the system"
    )
    full_log = (
        "Accepted password for analyst from 192.168.100.9 port 4422 ssh2"
        if success
        else "Failed password for invalid user lab from 192.168.100.9 port 4422 ssh2"
    )
    raw = raw_alert(
        alert_id,
        timestamp=(BASE_TIME + timedelta(seconds=offset)).isoformat(),
        decoder="sshd",
        groups=["sshd", "authentication_success" if success else "authentication_failures"],
        description=description,
        level=10,
        data={"srcip": "192.168.100.9", "srcuser": "analyst" if success else "lab"},
        full_log=full_log,
    )
    raw["_source"]["rule"]["id"] = "5715" if success else "5712"
    raw["_source"]["rule"]["mitre"] = {"id": ["T1110"]}
    return raw


def test_ssh_brute_force_normalization():
    envelope = normalize_alert(auth_raw("ssh-1"))
    alert = envelope.normalized
    assert alert.category == "authentication"
    assert alert.attack_family == "credential_access"
    assert alert.event_type == "ssh_brute_force"
    assert alert.outcome == "failure"
    assert alert.source_ip == "192.168.100.9"
    assert alert.mitre_techniques == ["T1110"]
    assert envelope.evidence_refs == ["wazuh:alert:ssh-1"]
    assert "full_log" not in envelope.model_dump()


def test_ssh_success_normalization():
    alert = normalize_alert(auth_raw("ssh-success", success=True)).normalized
    assert alert.attack_family == "initial_access"
    assert alert.event_type == "ssh_login_success"
    assert alert.outcome == "success"


@pytest.mark.parametrize(
    ("fixture", "event_type", "family"),
    [
        (
            raw_alert(
                "sca-1",
                groups=["sca"],
                description="Security Configuration Assessment failed",
                data={
                    "sca": {
                        "policy": "CIS Ubuntu",
                        "check": {"id": "cis-1", "result": "failed"},
                    }
                },
            ),
            "compliance_control_failed",
            "security_posture",
        ),
        (
            raw_alert(
                "vuln-1",
                groups=["vulnerability-detector"],
                description="Vulnerability detected",
                data={
                    "vulnerability": {
                        "id": "CVE-2026-0001",
                        "severity": "High",
                        "package": {"name": "openssl", "version": "1.0"},
                    }
                },
            ),
            "vulnerable_package",
            "vulnerability_management",
        ),
        (
            raw_alert(
                "pkg-1",
                decoder="dpkg",
                groups=["syslog", "dpkg"],
                description="Package installed",
                data={"package": "curl", "version": "8.0"},
            ),
            "package_installed",
            "software_change",
        ),
        (
            raw_alert(
                "audit-1",
                decoder="auditd",
                groups=["audit", "auditd"],
                description="Auditd execve command execution",
                data={
                    "audit": {
                        "exe": "/usr/bin/bash",
                        "command": "bash -c sensitive argument",
                        "uid": "1000",
                    }
                },
            ),
            "process_execution",
            "execution",
        ),
        (
            raw_alert(
                "fim-1",
                groups=["syscheck"],
                description="File modified",
                data={"path": "/etc/ssh/sshd_config"},
            ),
            "file_modified",
            "file_change",
        ),
        (
            raw_alert(
                "net-1",
                groups=["firewall"],
                description="Firewall blocked connection",
                data={"srcip": "203.0.113.2", "dstip": "192.0.2.2", "dstport": "22"},
            ),
            "network_connection",
            "network_activity",
        ),
    ],
)
def test_family_normalization(fixture, event_type, family):
    alert = normalize_alert(fixture).normalized
    assert alert.event_type == event_type
    assert alert.attack_family == family


def test_auditd_hashes_command_line():
    envelope = normalize_alert(
        raw_alert(
            "audit-hash",
            decoder="auditd",
            description="execve",
            data={"audit": {"exe": "/bin/bash", "command": "secret command"}},
        )
    )
    assert envelope.attack_details["command_line_hash"].startswith("sha256:")
    assert "secret command" not in json.dumps(envelope.model_dump(), default=str)


def test_generic_missing_fields_invalid_timestamp_and_malformed_ip_are_safe():
    raw = {
        "_id": "generic-1",
        "_source": {
            "@timestamp": "not-a-timestamp",
            "data": {"srcip": "999.1.1.1"},
        },
    }
    envelope = normalize_alert(raw)
    assert envelope.normalization_quality == "generic"
    assert envelope.normalized.timestamp == datetime(1970, 1, 1, tzinfo=UTC)
    assert envelope.normalized.source_ip is None
    assert {"timestamp", "rule_id", "rule_description"} <= set(
        envelope.missing_fields
    )


def test_authentication_deduplication_and_finding_generation():
    envelopes = [
        normalize_alert(auth_raw(f"ssh-{index}", offset=index * 10))
        for index in range(20)
    ]
    groups = aggregate_alerts(envelopes)
    findings = build_findings(groups)
    assert len(groups) == 1
    assert groups[0].alert_count == 20
    assert groups[0].representative_alert_id in {
        f"ssh-{index}" for index in range(20)
    }
    assert len(findings) == 1
    assert findings[0].alert_count == 20
    assert findings[0].severity == "high"
    assert findings[0].evidence_refs


def test_attack_specific_grouping_keeps_vulnerabilities_and_compliance_separate():
    vulnerability_a = raw_alert(
        "vuln-a",
        groups=["vulnerability-detector"],
        description="Vulnerability detected",
        data={"vulnerability": {"id": "CVE-1", "package": {"name": "openssl"}}},
    )
    vulnerability_b = deepcopy(vulnerability_a)
    vulnerability_b["_id"] = "vuln-b"
    vulnerability_b["_source"]["data"]["vulnerability"]["id"] = "CVE-2"
    compliance_a = raw_alert(
        "sca-a",
        groups=["sca"],
        description="SCA failed",
        data={"sca": {"policy": "CIS", "check": {"id": "1", "result": "failed"}}},
    )
    compliance_b = deepcopy(compliance_a)
    compliance_b["_id"] = "sca-b"
    compliance_b["_source"]["data"]["sca"]["check"]["id"] = "2"
    groups = aggregate_alerts(
        [
            normalize_alert(item)
            for item in (
                vulnerability_a,
                vulnerability_b,
                compliance_a,
                compliance_b,
            )
        ]
    )
    assert len(groups) == 4


@pytest.mark.parametrize(
    ("level", "severity"),
    [(0, "informational"), (4, "low"), (7, "medium"), (10, "high"), (13, "critical")],
)
def test_severity_mapping(level, severity):
    assert severity_for_level(level) == severity


def test_evidence_reference_validation_and_resolution():
    expected = object()

    class Gateway:
        def get_raw_alert_by_id(self, alert_id):
            assert alert_id == "alert-1"
            return expected

    assert alert_id_from_evidence_ref("wazuh:alert:alert-1") == "alert-1"
    assert resolve_evidence_ref("wazuh:alert:alert-1", Gateway()) is expected
    with pytest.raises(ValueError):
        alert_id_from_evidence_ref("file:///etc/passwd")


def test_compact_serializer_and_tool_result_drop_raw_fields():
    result = AlertSearchResult(
        total=2,
        returned=2,
        truncated=False,
        alerts=[
            AlertEvidence(
                alert_id=f"alert-{index}",
                timestamp=BASE_TIME + timedelta(seconds=index),
                agent_id="001",
                agent_name="servervb",
                rule_id="5712",
                rule_level=10,
                description="sshd brute force",
                source_ip="192.168.100.9",
                target_user="lab",
                decoder_name="sshd",
                full_log="sensitive exact log " * 100,
                rule_groups=["sshd", "authentication_failures"],
                mitre_ids=["T1110"],
                event_outcome="failure",
            )
            for index in range(2)
        ],
    )
    compact = compact_alert_search_result(result)
    tool = compact_tool_result(
        "get_recent_wazuh_alerts",
        {"ok": True, "data": result.model_dump(mode="json")},
    )
    rendered = json.dumps({"compact": compact, "tool": tool}, default=str)
    assert compact["finding_count"] == 1
    assert "alerts" not in compact
    assert "full_log" not in rendered
    assert "sensitive exact log" not in rendered


def test_raw_api_serializer_is_explicit_but_agent_trace_is_sanitized():
    raw = {
        "raw_document": {"full_log": "exact evidence"},
        "authorization": "Bearer secret",
        "password": "secret",
        "__gemini_function_call_thought_signatures__": ["signature"],
        "extras": {"signature": "provider-signature"},
    }
    assert serialize_for_api(mode="raw", raw=raw)["raw_document"]["full_log"] == (
        "exact evidence"
    )
    trace = json.dumps(serialize_for_trace(raw))
    assert "exact evidence" not in trace
    assert "provider-signature" not in trace
    assert "Bearer secret" not in trace
    assert '"secret"' not in trace


def test_conversation_alert_tool_defaults_to_compact_findings():
    result = AlertSearchResult(
        total=1,
        returned=1,
        truncated=False,
        alerts=[
            AlertEvidence(
                alert_id="alert-1",
                timestamp=BASE_TIME,
                agent_id="001",
                rule_id="5712",
                rule_level=10,
                description="sshd brute force",
                decoder_name="sshd",
                full_log="must not reach state",
                rule_groups=["sshd", "authentication_failures"],
                event_outcome="failure",
            )
        ],
    )

    class Gateway:
        def search_alerts(self, **kwargs):
            return result

    tools = {
        item.name: item
        for item in build_soc_chat_tools(gateway=Gateway())
    }
    payload = tools["get_recent_wazuh_alerts"].invoke({})
    assert payload["ok"] is True
    assert payload["data"]["finding_count"] == 1
    assert "alerts" not in payload["data"]
    assert "must not reach state" not in json.dumps(payload)


def test_compact_payload_is_at_least_seventy_percent_smaller():
    alerts = []
    for index in range(70):
        family_index = index % 7
        alert = AlertEvidence(
            alert_id=f"alert-{index}",
            timestamp=BASE_TIME + timedelta(seconds=family_index),
            agent_id="001",
            agent_name="servervb",
            rule_id="5712",
            rule_level=10,
            description="sshd brute force repeated authentication failure",
            source_ip="192.168.100.9",
            target_user="lab",
            decoder_name="sshd",
            full_log=("Failed password with verbose duplicated context " * 40),
            rule_groups=["sshd", "authentication_failures"],
            mitre_ids=["T1110"],
            event_outcome="failure",
        )
        alerts.append(alert)
    result = AlertSearchResult(
        total=70,
        returned=70,
        truncated=False,
        alerts=alerts,
    )
    before = len(json.dumps(result.model_dump(mode="json"), default=str))
    compact = compact_alert_search_result(result)
    after = len(json.dumps(compact, default=str))
    assert after <= before * 0.30
    assert compact["finding_count"] == 1
    assert compact["findings"][0]["alert_count"] == 70
    assert "full_log" not in json.dumps(compact)
