"""Render an investigation snapshot as a PDF incident report."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fpdf import FPDF

# ponytail: direct PDF via fpdf2; a LaTeX pipeline can replace this if
# typeset-quality reports are ever required.

MARGIN = 14


def _text(value: Any) -> str:
    if value is None:
        return "-"
    return str(value).encode("latin-1", "replace").decode("latin-1")


class _ReportPDF(FPDF):
    def header(self) -> None:
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(110, 110, 110)
        self.cell(90, 6, "TSAGE SOC - Incident report", align="L")
        self.cell(0, 6, datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"), align="R")
        self.ln(10)

    def footer(self) -> None:
        self.set_y(-12)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(110, 110, 110)
        self.cell(0, 6, f"Page {self.page_no()}/{{nb}}", align="C")

    def section(self, title: str) -> None:
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(20, 20, 20)
        self.ln(3)
        self.cell(0, 8, _text(title))
        self.ln(9)
        self.set_draw_color(180, 180, 180)
        self.line(MARGIN, self.get_y() - 2, 210 - MARGIN, self.get_y() - 2)

    def fact(self, label: str, value: Any) -> None:
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(90, 90, 90)
        self.cell(52, 6, _text(label))
        self.set_font("Helvetica", "", 9)
        self.set_text_color(20, 20, 20)
        self.multi_cell(0, 6, _text(value), new_x="LMARGIN", new_y="NEXT")

    def paragraph(self, value: Any) -> None:
        self.set_font("Helvetica", "", 9)
        self.set_text_color(20, 20, 20)
        self.multi_cell(0, 5.5, _text(value), new_x="LMARGIN", new_y="NEXT")
        self.ln(1)


def _result_summary(result: dict[str, Any] | None) -> str | None:
    if not isinstance(result, dict):
        return None
    summary = result.get("summary")
    return str(summary) if summary else None


def build_investigation_pdf(snapshot: dict[str, Any]) -> bytes:
    pdf = _ReportPDF()
    pdf.set_margins(MARGIN, MARGIN, MARGIN)
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.alias_nb_pages()
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, _text(f"Investigation {snapshot.get('investigation_id')}"))
    pdf.ln(12)

    pdf.section("Overview")
    for label, key in (
        ("Incident", "incident_id"),
        ("Alert", "alert_id"),
        ("Agent", "agent_id"),
        ("Status", "status"),
        ("Stage", "current_stage"),
        ("Severity", "severity"),
        ("Initiated by", "initiated_by"),
    ):
        pdf.fact(label, snapshot.get(key))
    confidence = snapshot.get("confidence")
    pdf.fact(
        "Confidence",
        f"{round(float(confidence) * 100)}%" if confidence is not None else "-",
    )

    for title, key in (
        ("Diagnosis", "diagnosis"),
        ("Remediation plan", "remediation_plan"),
        ("Policy decision", "policy_decision"),
        ("Verification", "verification"),
        ("Rollback", "rollback"),
    ):
        summary = _result_summary(snapshot.get(key))
        if summary:
            pdf.section(title)
            pdf.paragraph(summary)

    actions = snapshot.get("proposed_actions") or []
    if actions:
        pdf.section("Proposed response actions")
        for action in actions:
            if isinstance(action, dict):
                pdf.paragraph(
                    f"- {action.get('action_type')} on {action.get('target')} "
                    f"(risk {action.get('risk_level')}, "
                    f"TTL {action.get('ttl_seconds') or 'n/a'}s)"
                )

    executed = snapshot.get("executed_actions") or []
    if executed:
        pdf.section("Executed actions")
        for action in executed:
            if isinstance(action, dict):
                pdf.paragraph(
                    f"- {action.get('action_type') or action.get('action_id')} "
                    f"on {action.get('target')} -> {action.get('status')}"
                )

    for report in snapshot.get("tier_reports") or []:
        if not isinstance(report, dict):
            continue
        pdf.section(f"{str(report.get('tier', '')).upper()} analyst report")
        summary = report.get("summary")
        if summary:
            pdf.paragraph(summary)

    events = snapshot.get("audit_events") or []
    if events:
        pdf.section("Audit trail")
        for event in events[-30:]:
            if isinstance(event, dict):
                pdf.paragraph(
                    f"{event.get('timestamp')}  {event.get('stage')}: "
                    f"{event.get('event')}"
                )

    return bytes(pdf.output())


def build_analyst_report_pdf(report: dict[str, Any]) -> bytes:
    """Render a chat-saved analyst report. Minimal markdown: '## ' starts a
    section, '- ' starts a bullet, everything else is a paragraph."""
    pdf = _ReportPDF()
    pdf.set_margins(MARGIN, MARGIN, MARGIN)
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.alias_nb_pages()
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 16)
    pdf.multi_cell(0, 10, _text(report.get("title")), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    pdf.fact("Severity", report.get("severity") or "Not classified")
    pdf.fact("Created by", report.get("created_by"))
    pdf.fact("Report ID", report.get("report_id"))

    pdf.section("Summary")
    pdf.paragraph(report.get("summary"))

    for line in str(report.get("body_markdown") or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("## "):
            pdf.section(stripped[3:])
        elif stripped.startswith("# "):
            pdf.section(stripped[2:])
        elif stripped.startswith(("- ", "* ")):
            pdf.paragraph(f"• {stripped[2:]}")
        else:
            pdf.paragraph(stripped)

    related_alerts = report.get("related_alert_ids") or []
    related_findings = report.get("related_finding_ids") or []
    if related_alerts or related_findings:
        pdf.section("References")
        if related_alerts:
            pdf.fact("Alerts", ", ".join(str(item) for item in related_alerts))
        if related_findings:
            pdf.fact(
                "Findings", ", ".join(str(item) for item in related_findings)
            )

    return bytes(pdf.output())
