"""
Professional forensic PDF report generator using ReportLab.

Pulls a completed scan's full record set out of SQLite (USB info, every
file scanned with its risk score/reasons, sandbox results, registry and
network activity, and the quarantine list) and lays it out as a
structured, readable forensic report with an overall verdict section.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

import config
import database
from utils.logger import get_logger

logger = get_logger(__name__)

_styles = getSampleStyleSheet()
_TITLE = ParagraphStyle("ReportTitle", parent=_styles["Title"], textColor=colors.HexColor("#0B1F3A"))
_H2 = ParagraphStyle("H2", parent=_styles["Heading2"], textColor=colors.HexColor("#12335B"), spaceBefore=14)
_BODY = ParagraphStyle("Body", parent=_styles["BodyText"], leading=14)
_SMALL = ParagraphStyle("Small", parent=_styles["BodyText"], fontSize=8, leading=10)

_RISK_COLORS = {
    "Low": colors.HexColor("#2ecc71"), "Medium": colors.HexColor("#f1c40f"),
    "High": colors.HexColor("#e67e22"), "Critical": colors.HexColor("#e74c3c"),
}


def _overall_verdict(scan: dict, files: list[dict]) -> str:
    highest = scan.get("highest_risk", 0)
    if highest >= 80:
        level = "CRITICAL"
        text = ("One or more files on this device show a Critical risk profile with multiple "
                "strong indicators (disguised executables, dangerous API usage, or confirmed "
                "runtime persistence/network behavior). Do not open unquarantined files from "
                "this device on a production machine.")
    elif highest >= 60:
        level = "HIGH"
        text = ("This device contains files with High risk indicators. Review the flagged files "
                "and sandbox results below before using this device further.")
    elif highest >= 30:
        level = "MEDIUM"
        text = ("This device contains files with Medium risk indicators. No confirmed malicious "
                "behavior was observed, but the flagged items warrant a manual review.")
    else:
        level = "LOW"
        text = "No significant risk indicators were found across the files scanned on this device."
    return f"Overall Verdict: {level}\n\n{text}"


def generate_report(scan_id: str) -> str:
    """Build the full forensic PDF for a completed scan and return its file path."""
    scan = database.get_scan(scan_id)
    if not scan:
        raise ValueError(f"No scan found with id {scan_id}")

    files = database.list_files_for_scan(scan_id)
    quarantine_items = [q for q in database.list_quarantine() if q["scan_id"] == scan_id]
    sandbox_runs = database.list_sandbox_runs_for_scan(scan_id)

    report_path = config.REPORTS_DIR / f"{scan_id}_forensic_report.pdf"
    doc = SimpleDocTemplate(
        str(report_path), pagesize=A4,
        leftMargin=1.8 * cm, rightMargin=1.8 * cm, topMargin=1.8 * cm, bottomMargin=1.8 * cm,
    )
    story = []

    # --- Title & USB info ---------------------------------------------------
    story.append(Paragraph("USB Threat Analyzer", _TITLE))
    story.append(Paragraph("Digital Forensic Report", _styles["Heading3"]))
    story.append(Spacer(1, 10))

    usb_table_data = [
        ["Scan ID", scan_id],
        ["USB Name / Label", scan.get("usb_name") or "Unknown"],
        ["Drive Letter", scan.get("drive_letter") or "-"],
        ["Capacity", f"{scan.get('capacity_bytes', 0) / (1024**3):.2f} GB"],
        ["File System", scan.get("file_system") or "-"],
        ["Scan Started", scan.get("started_at") or "-"],
        ["Scan Finished", scan.get("finished_at") or "-"],
        ["Files Scanned", str(scan.get("files_scanned", 0))],
        ["Suspicious Files", str(scan.get("suspicious_files", 0))],
        ["Highest Risk Score", str(scan.get("highest_risk", 0))],
        ["Sandbox Used", scan.get("sandbox_used") or "None"],
    ]
    t = Table(usb_table_data, colWidths=[5 * cm, 10.5 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EAF1FB")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t)

    # --- Overall verdict ------------------------------------------------------
    story.append(Paragraph("Overall Verdict", _H2))
    story.append(Paragraph(_overall_verdict(scan, files).replace("\n\n", "<br/><br/>"), _BODY))

    # --- All files & risk scores -----------------------------------------
    story.append(Paragraph("Scanned Files & Risk Scores", _H2))
    file_rows = [["File", "Ext", "Level", "Size", "Risk", "Reasons"]]
    for f in files:
        reasons = "; ".join(f.get("reasons", [])[:4]) or "None"
        file_rows.append([
            Paragraph(f.get("file_name", ""), _SMALL),
            f.get("extension", ""),
            str(f.get("level", "")),
            f"{(f.get('size_bytes') or 0) / 1024:.1f} KB",
            f"{f.get('risk_score', 0)} ({f.get('risk_level', '')})",
            Paragraph(reasons, _SMALL),
        ])
    if len(file_rows) == 1:
        file_rows.append(["No files recorded", "", "", "", "", ""])
    ft = Table(file_rows, colWidths=[3.3 * cm, 1.3 * cm, 1.3 * cm, 1.8 * cm, 2.3 * cm, 5.5 * cm], repeatRows=1)
    ft.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#12335B")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F4F7FB")]),
    ]))
    story.append(ft)

    # --- Sandbox results ---------------------------------------------------
    if sandbox_runs:
        story.append(PageBreak())
        story.append(Paragraph("Sandbox Runtime Analysis", _H2))
        for run in sandbox_runs:
            story.append(Paragraph(f"Sandbox: {run['sandbox_type']} | Sample SHA-256: {run['file_sha256']}", _styles["Heading4"]))
            diff = run.get("diff", {})
            summary = diff.get("summary", {})
            story.append(Paragraph(
                f"Registry +{summary.get('registry', 0)} | Files +{summary.get('files', 0)} | "
                f"Network {summary.get('network', 0)} connections | Startup +{summary.get('startup', 0)} | "
                f"Services +{summary.get('services', 0)} | Scheduled Tasks +{summary.get('scheduled_tasks', 0)}",
                _BODY,
            ))
            story.append(Paragraph(f"Verdict Notes: {run.get('verdict_notes', '')}", _BODY))

            if diff.get("registry_changes"):
                story.append(Paragraph("Registry Changes:", _styles["Heading4"]))
                story.append(Paragraph("<br/>".join(diff["registry_changes"][:25]), _SMALL))
            if diff.get("new_network_connections"):
                story.append(Paragraph("Network Activity:", _styles["Heading4"]))
                story.append(Paragraph("<br/>".join(diff["new_network_connections"][:25]), _SMALL))
            story.append(Spacer(1, 10))

    # --- Quarantine list -----------------------------------------------------
    story.append(Paragraph("Quarantine List", _H2))
    q_rows = [["Original Path", "SHA-256", "Risk", "Status"]]
    for q in quarantine_items:
        q_rows.append([
            Paragraph(q["original_path"], _SMALL), q["sha256"][:16] + "...",
            str(q["risk_score"]), q["status"],
        ])
    if len(q_rows) == 1:
        q_rows.append(["No files quarantined", "", "", ""])
    qt = Table(q_rows, colWidths=[7 * cm, 4 * cm, 1.5 * cm, 2.5 * cm], repeatRows=1)
    qt.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#12335B")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
    ]))
    story.append(qt)

    story.append(Spacer(1, 16))
    story.append(Paragraph(
        f"Report generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} by USB Threat Analyzer.",
        _styles["Italic"],
    ))

    doc.build(story)
    logger.info("Forensic PDF report generated: %s", report_path)
    return str(report_path)
