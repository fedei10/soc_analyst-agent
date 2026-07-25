from app.soc_assistant.overview import build_soc_overview, build_soc_platform


def test_overview_aggregates_real_workflow_data():
    investigations = [
        {
            "investigation_id": "INV-1",
            "alert_id": "alert-1",
            "status": "awaiting_approval",
            "current_stage": "human_approval",
            "severity": "high",
            "confidence": 0.9,
            "pending_nodes": ["human_approval"],
            "executed_actions": [],
            "audit_events": [
                {"timestamp": "2026-07-25T10:00:00Z"},
            ],
        },
        {
            "investigation_id": "INV-2",
            "alert_id": "alert-2",
            "status": "completed",
            "current_stage": "final_report",
            "severity": "critical",
            "executed_actions": [{"action_id": "ACT-1"}],
        },
    ]
    findings = [
        {
            "finding_id": "FND-1",
            "severity": "high",
            "alert_count": 8,
            "last_seen": "2026-07-25T10:00:00Z",
            "finding": {"title": "SSH brute force"},
            "verdict": {"verdict": "malicious", "confidence": 0.92},
        },
        {
            "finding_id": "FND-2",
            "severity": "low",
            "alert_count": 2,
            "finding": {"title": "Expected scan"},
            "verdict": {"verdict": "benign", "confidence": 0.8},
        },
    ]

    overview = build_soc_overview(
        investigations=investigations,
        investigation_total=2,
        findings=findings,
        alert_summary={"total_alerts": 20},
        window_hours=24,
    )

    assert overview.metrics["active_investigations"].value == 1
    assert overview.metrics["pending_approvals"].value == 1
    assert overview.metrics["executed_actions"].value == 1
    assert overview.metrics["malicious_findings"].value == 1
    assert overview.alert_reduction.represented_alerts == 10
    assert overview.alert_reduction.reduction_percent == 90.0
    assert {item.stage: item.count for item in overview.pipeline}["approval"] == 1
    assert {item.stage: item.count for item in overview.pipeline}["complete"] == 1


def test_overview_degrades_when_wazuh_is_unavailable():
    overview = build_soc_overview(
        investigations=[],
        investigation_total=0,
        findings=[],
        alert_summary=None,
        window_hours=24,
    )

    assert overview.wazuh_status == "unavailable"
    assert overview.metrics["wazuh_alerts"].value is None
    assert overview.alert_reduction.reduction_percent is None


def test_platform_aggregates_approvals_actions_and_audit_events():
    platform = build_soc_platform(
        investigations=[
            {
                "investigation_id": "INV-1",
                "status": "awaiting_approval",
                "approval_request": {
                    "approval_id": "APR-1",
                    "incident_id": "INC-1",
                    "expires_at": "2026-07-25T15:00:00Z",
                    "required_role": "soc_l3",
                    "proposed_actions": [
                        {
                            "action_id": "ACT-1",
                            "action_type": "block_ip",
                            "target": "192.0.2.10",
                            "risk_level": 3,
                            "evidence_refs": ["alert:1"],
                        }
                    ],
                },
                "audit_events": [
                    {
                        "event": "approval_required",
                        "stage": "human_approval",
                        "timestamp": "2026-07-25T14:00:00Z",
                    }
                ],
            }
        ],
        model_assignments=[
            {"role": "l1", "provider": "cerebras", "model": "test-model"}
        ],
        response_policy={"wazuh_read_only": True},
        retention={"messages_days": 90},
    )

    assert platform.pending_approvals[0]["status"] == "pending"
    assert platform.response_actions[0]["status"] == "awaiting_approval"
    assert platform.audit_events[0]["investigation_id"] == "INV-1"
    assert platform.model_assignments[0].provider == "cerebras"
