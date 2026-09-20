"""Unit tests for Sysmon alert normalization.

Sysmon carries process, network, file, and registry activity under one decoder,
so the event-type branch decides which category downstream analysis sees.
"""

import pytest

from app.services.wazuh.normalization.registry import normalize_alert
from app.services.wazuh.normalization.sysmon import SysmonNormalizer


def raw_alert(
    *,
    description: str = "Sysmon - Event 1: Process creation",
    groups: list[str] | None = None,
    full_log: str = "",
    event_id: str = "1",
    image: str | None = None,
    parent_image: str | None = None,
    target_filename: str | None = None,
) -> dict:
    eventdata: dict[str, str] = {}
    if image is not None:
        eventdata["image"] = image
    if parent_image is not None:
        eventdata["parentImage"] = parent_image
    if target_filename is not None:
        eventdata["targetFilename"] = target_filename
    return {
        "id": "alert-sysmon-1",
        "timestamp": "2026-07-24T19:00:00Z",
        "agent": {"id": "004", "name": "win-endpoint"},
        "rule": {
            "id": "61603",
            "level": 7,
            "description": description,
            "groups": groups if groups is not None else ["windows", "sysmon"],
        },
        "decoder": {"name": "windows_eventchannel"},
        "full_log": full_log,
        "data": {
            "win": {
                "system": {"eventID": event_id},
                "eventdata": eventdata,
            }
        },
    }


def test_normalizer_matches_only_sysmon_alerts():
    normalizer = SysmonNormalizer()

    assert normalizer.matches(raw_alert()) is True
    assert normalizer.matches({"rule": {"description": "SSH login failed"}}) is False


@pytest.mark.parametrize(
    ("description", "event_id", "event_type", "category"),
    [
        (
            "Sysmon - Event 3: Network connection detected",
            "3",
            "network_connection",
            "network",
        ),
        ("Sysmon - Event 11: File create", "11", "file_created", "file_integrity"),
        (
            "Sysmon - Event 13: Registry value set",
            "13",
            "registry_changed",
            "configuration_change",
        ),
        (
            "Sysmon - Event 1: Process creation",
            "1",
            "process_created",
            "process_execution",
        ),
    ],
)
def test_event_type_branches(description, event_id, event_type, category):
    result = SysmonNormalizer().normalize(
        raw_alert(description=description, event_id=event_id)
    )

    assert result.normalized.event_type == event_type
    assert result.normalized.category == category


def test_event_id_alone_selects_the_branch_without_a_matching_description():
    """The `event id: N` form in full_log must drive classification too."""
    result = SysmonNormalizer().normalize(
        raw_alert(
            description="Sysmon alert",
            full_log="sysmon event id: 3",
            event_id="3",
        )
    )

    assert result.normalized.event_type == "network_connection"


def test_unrecognised_sysmon_event_falls_back_to_process_creation():
    result = SysmonNormalizer().normalize(
        raw_alert(description="Sysmon - Event 255: Something new", event_id="255")
    )

    assert result.normalized.event_type == "process_created"
    assert result.normalized.category == "process_execution"


def test_process_fields_are_extracted():
    result = SysmonNormalizer().normalize(
        raw_alert(
            image="C:\\Windows\\System32\\cmd.exe",
            parent_image="C:\\Windows\\explorer.exe",
        )
    )

    assert result.normalized.process_name == "C:\\Windows\\System32\\cmd.exe"
    assert result.normalized.parent_process_name == "C:\\Windows\\explorer.exe"


def test_file_path_is_extracted_for_file_events():
    result = SysmonNormalizer().normalize(
        raw_alert(
            description="Sysmon - Event 11: File create",
            event_id="11",
            target_filename="C:\\Users\\public\\payload.dll",
        )
    )

    assert result.normalized.file_path == "C:\\Users\\public\\payload.dll"


def test_missing_eventdata_leaves_fields_unset():
    result = SysmonNormalizer().normalize(raw_alert())

    assert result.normalized.process_name is None
    assert result.normalized.parent_process_name is None
    assert result.normalized.file_path is None


def test_attack_details_record_the_provider_and_event_id():
    result = SysmonNormalizer().normalize(raw_alert(event_id="7"))

    assert result.attack_details["provider"] == "sysmon"
    assert result.attack_details["event_id"] == "7"


def test_attack_family_and_summary():
    result = SysmonNormalizer().normalize(raw_alert())

    assert result.normalized.attack_family == "endpoint_activity"
    assert result.normalized.summary == "Sysmon process created event."


def test_blocked_outcome_is_derived_from_the_text():
    result = SysmonNormalizer().normalize(
        raw_alert(description="Sysmon - Event 3: Network connection blocked")
    )

    assert result.normalized.outcome == "blocked"


def test_registry_dispatches_sysmon_alerts_to_this_normalizer():
    """Guards the priority ordering, not just the normalizer in isolation."""
    result = normalize_alert(raw_alert())

    assert result.normalizer_name == "SysmonNormalizer"
    assert result.attack_details["provider"] == "sysmon"
    assert result.normalized.event_type == "process_created"
