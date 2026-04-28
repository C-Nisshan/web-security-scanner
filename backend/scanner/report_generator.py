"""
report_generator.py — Report Generation Engine (FINAL STABLE)
"""

import os
import html
import logging
from datetime import datetime
from typing import Dict, List, Tuple, Optional

logger = logging.getLogger("report_generator")


# ─────────────────────────────────────────────
# Colours
# ─────────────────────────────────────────────

SEVERITY_COLORS = {
    "Critical": "#ff4757",
    "High": "#ff6b35",
    "Medium": "#ffd32a",
    "Low": "#00d4ff",
    "Informational": "#6b7a99",
    "Clean": "#00ff88",
}

RISK_COLORS = SEVERITY_COLORS.copy()


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _h(text) -> str:
    return html.escape(str(text) if text else "")


def _severity_badge_html(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, "#6b7a99")
    return (
        f'<span style="background:{color}22;color:{color};'
        f'border:1px solid {color}44;padding:3px 10px;'
        f'border-radius:20px;font-size:.72rem;font-weight:700">'
        f'{_h(severity)}</span>'
    )


# ─────────────────────────────────────────────
# Main Class
# ─────────────────────────────────────────────

class ReportGenerator:

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    # =========================================================
    # MASTER METHOD (NEW - Recommended)
    # =========================================================
    def generate_reports(
        self,
        analysis: Dict,
        scan_meta: Dict,
        report_id: str
    ) -> Dict[str, Optional[str]]:
        """
        Generate both HTML + PDF safely.
        Returns paths for frontend use.
        """

        html_path = self.generate_html(analysis, scan_meta, report_id)

        pdf_path = None
        try:
            pdf_path = self.generate_pdf(analysis, scan_meta, report_id)
        except Exception as e:
            logger.exception("PDF generation failed: %s", e)

        return {
            "html_report": html_path,
            "pdf_report": pdf_path
        }

    # =========================================================
    # HTML REPORT
    # =========================================================

    def generate_html(self, analysis: Dict, scan_meta: Dict, report_id: str) -> str:
        path = os.path.join(self.output_dir, f"{report_id}.html")

        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self._render_html(analysis, scan_meta))

        logger.info("HTML report generated → %s", path)
        return path

    def _render_html(self, analysis: Dict, meta: Dict) -> str:

        target = _h(meta.get("target_url", "Unknown"))
        scan_date = _h(meta.get("scan_date", datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        risk = _h(analysis.get("overall_risk", "Unknown"))

        findings = analysis.get("findings", [])
        recs = analysis.get("recommendations", [])

        html_parts = [
            "<html><head><meta charset='UTF-8'>",
            "<title>Security Report</title>",
            "</head><body>",
            f"<h1>Security Report</h1>",
            f"<p><b>Target:</b> {target}</p>",
            f"<p><b>Date:</b> {scan_date}</p>",
            f"<p><b>Risk:</b> {risk}</p>",
            "<hr>",
        ]

        if not findings:
            html_parts.append("<h3>✅ No vulnerabilities found</h3>")
        else:
            for f in findings:
                html_parts.append("<div style='margin-bottom:20px'>")
                html_parts.append(f"<h3>{_h(f.get('vulnerability'))}</h3>")
                html_parts.append(_severity_badge_html(f.get("severity_label")))
                html_parts.append(f"<p>{_h(f.get('description'))}</p>")
                html_parts.append("</div>")

        html_parts.append("<h2>Recommendations</h2><ul>")
        for r in recs:
            html_parts.append(f"<li>{_h(r)}</li>")
        html_parts.append("</ul></body></html>")

        return "".join(html_parts)

    # =========================================================
    # PDF REPORT (SAFE)
    # =========================================================

    def generate_pdf(self, analysis: Dict, scan_meta: Dict, report_id: str) -> str:
        """
        Professional styled PDF report
        """

        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
            )
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib import colors
            from reportlab.lib.units import cm
        except ImportError:
            raise ImportError("Install reportlab: pip install reportlab")

        path = os.path.join(self.output_dir, f"{report_id}.pdf")

        doc = SimpleDocTemplate(
            path,
            pagesize=A4,
            leftMargin=2 * cm,
            rightMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
        )

        styles = getSampleStyleSheet()

        # Custom styles
        title_style = ParagraphStyle(
            "title",
            parent=styles["Title"],
            fontSize=20,
            spaceAfter=10
        )

        section_style = ParagraphStyle(
            "section",
            parent=styles["Heading2"],
            fontSize=13,
            spaceBefore=12,
            spaceAfter=6
        )

        normal_style = styles["Normal"]

        story: List = []

        # ─────────────────────────────
        # COVER
        # ─────────────────────────────
        story.append(Paragraph("🛡 Security Assessment Report", title_style))
        story.append(Spacer(1, 10))

        meta_table = Table([
            ["Target URL", scan_meta.get("target_url", "N/A")],
            ["Scan Date", scan_meta.get("scan_date", "N/A")],
            ["Duration", scan_meta.get("duration", "N/A")],
            ["Pages Crawled", str(scan_meta.get("pages_crawled", "N/A"))],
            ["Auth Mode", scan_meta.get("auth_type", "N/A")],
            ["Overall Risk", analysis.get("overall_risk", "N/A")],
        ], colWidths=[5 * cm, 10 * cm])

        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("PADDING", (0, 0), (-1, -1), 6),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ]))

        story.append(meta_table)
        story.append(Spacer(1, 20))

        # ─────────────────────────────
        # EXEC SUMMARY
        # ─────────────────────────────
        story.append(Paragraph("Executive Summary", section_style))

        summary_table = Table([
            ["Total", "Critical", "High", "Medium", "Low"],
            [
                analysis.get("total_findings", 0),
                analysis.get("critical_count", 0),
                analysis.get("high_count", 0),
                analysis.get("medium_count", 0),
                analysis.get("low_count", 0),
            ]
        ])

        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 8),
        ]))

        story.append(summary_table)
        story.append(Spacer(1, 15))

        # ─────────────────────────────
        # FINDINGS
        # ─────────────────────────────
        findings = analysis.get("findings", [])

        if findings:
            story.append(Paragraph("Detailed Findings", section_style))

            for f in findings:
                severity = f.get("severity_label", "Unknown")

                sev_color = {
                    "Critical": colors.red,
                    "High": colors.orange,
                    "Medium": colors.gold,
                    "Low": colors.blue,
                }.get(severity, colors.black)

                header = Table([[f"#{f.get('id')} - {f.get('vulnerability')}"]],
                            colWidths=[16 * cm])

                header.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), colors.whitesmoke),
                    ("TEXTCOLOR", (0, 0), (-1, -1), sev_color),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                    ("PADDING", (0, 0), (-1, -1), 8),
                    ("BOX", (0, 0), (-1, -1), 1, sev_color),
                ]))

                story.append(header)

                story.append(Paragraph(f"<b>Severity:</b> {severity}", normal_style))
                story.append(Paragraph(f"<b>URL:</b> {f.get('url')}", normal_style))
                story.append(Paragraph(f"<b>Parameter:</b> {f.get('param')}", normal_style))
                story.append(Paragraph(f.get("description", ""), normal_style))

                # Remediation
                story.append(Paragraph("<b>Remediation:</b>", normal_style))
                for step in f.get("remediation_steps", []):
                    story.append(Paragraph(f"• {step}", normal_style))

                story.append(Spacer(1, 12))

        else:
            story.append(Paragraph("No vulnerabilities detected.", normal_style))

        # ─────────────────────────────
        # RECOMMENDATIONS
        # ─────────────────────────────
        story.append(PageBreak())
        story.append(Paragraph("Recommendations", section_style))

        for r in analysis.get("recommendations", []):
            story.append(Paragraph(f"• {r}", normal_style))

        # Build PDF
        doc.build(story)

        logger.info("Professional PDF generated → %s", path)
        return path