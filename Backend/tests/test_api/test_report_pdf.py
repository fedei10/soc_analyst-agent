"""Checks for the PDF incident-report renderer."""

from app.orchestration.report_pdf import build_investigation_pdf


def test_pdf_renders_snapshot_sections():
    pdf = build_investigation_pdf(
        {
            "investigation_id": "INV-TEST",
            "incident_id": "INC-TEST",
            "alert_id": "AL-1",
            "agent_id": "001",
            "status": "completed",
            "current_stage": "final_report",
            "severity": "high",
            "confidence": 0.91,
            "initiated_by": "api",
            "diagnosis": {"summary": "SSH brute force from 203.0.113.9."},
            "remediation_plan": {"summary": "Block the source IP."},
            "proposed_actions": [
                {
                    "action_type": "block_ip",
                    "target": "203.0.113.9",
                    "risk_level": 2,
                    "ttl_seconds": 3600,
                }
            ],
            "tier_reports": [
                {"tier": "l1", "summary": "Initial triage confirmed hostile."}
            ],
            "audit_events": [
                {
                    "timestamp": "2026-07-26T10:00:00Z",
                    "stage": "monitor",
                    "event": "workflow_started",
                }
            ],
        }
    )
    assert pdf.startswith(b"%PDF")
    assert len(pdf) > 1500


def test_analyst_report_pdf_renders_markdown_sections():
    from app.orchestration.report_pdf import build_analyst_report_pdf

    pdf = build_analyst_report_pdf(
        {
            "report_id": "RPT-TEST",
            "title": "SSH brute force write-up",
            "summary": "Repeated failed logins from one source.",
            "severity": "high",
            "created_by": "user_1",
            "body_markdown": (
                "## Evidence\n"
                "- 12 failed logins from 203.0.113.9\n"
                "## Recommendations\n"
                "- Block the source IP\n"
                "- Confirm the target account is not expected to log in remotely"
            ),
            "related_alert_ids": ["ssh-1", "ssh-2"],
            "related_finding_ids": ["FND-1"],
        }
    )
    assert pdf.startswith(b"%PDF")
    assert len(pdf) > 1500
