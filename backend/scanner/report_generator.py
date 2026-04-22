"""
report_generator.py — Report Generation Engine
===============================================
Generates a polished, standalone HTML report and a PDF report
from the structured findings produced by ResponseAnalyzer.

HTML report : fully self-contained (inline CSS, no external deps)
PDF report  : generated with ReportLab Platypus

Layer : Reporting Layer
"""

import os
import html
import logging
from datetime import datetime
from typing import Dict, List

logger = logging.getLogger("report_generator")

# ─────────────────────────────────────────────────────────────
# Colour / severity maps (shared across HTML + PDF)
# ─────────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "Critical"     : "#ff4757",
    "High"         : "#ff6b35",
    "Medium"       : "#ffd32a",
    "Low"          : "#00d4ff",
    "Informational": "#6b7a99",
    "Clean"        : "#00ff88",
}

RISK_COLORS = {
    "Critical": "#ff4757",
    "High"    : "#ff6b35",
    "Medium"  : "#ffd32a",
    "Low"     : "#00d4ff",
    "Clean"   : "#00ff88",
}

# ─────────────────────────────────────────────────────────────
# HTML Report Template
# ─────────────────────────────────────────────────────────────

HTML_STYLE = """
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#070b14;color:#e8edf5;line-height:1.65}
a{color:#00d4ff;text-decoration:none}
.container{max-width:1100px;margin:0 auto;padding:0 24px}
.cover{background:linear-gradient(135deg,#0a1020,#0d1526);border-bottom:3px solid #00d4ff;
  padding:60px 40px;text-align:center}
.cover-logo{font-size:2.5rem;color:#00d4ff;margin-bottom:8px}
.cover-title{font-size:2.2rem;font-weight:900;color:#fff;margin:12px 0}
.cover-subtitle{font-size:1rem;color:#6b7a99}
.cover-meta{display:flex;justify-content:center;gap:40px;margin-top:32px;flex-wrap:wrap}
.meta-item{text-align:center}
.meta-label{font-size:.7rem;text-transform:uppercase;letter-spacing:.1em;color:#6b7a99}
.meta-val{font-size:1rem;font-weight:700;color:#fff}
.section{padding:48px 0}
.section-title{font-size:1.4rem;font-weight:800;color:#fff;margin-bottom:24px;
  padding-bottom:12px;border-bottom:1px solid #1a2d50}
.exec-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:32px}
.exec-card{background:#0d1526;border:1px solid #1a2d50;border-radius:12px;padding:20px;text-align:center}
.exec-val{font-size:2.4rem;font-weight:900;line-height:1}
.exec-label{font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;color:#6b7a99;margin-top:6px}
.risk-badge{display:inline-block;padding:6px 18px;border-radius:100px;
  font-size:.85rem;font-weight:700;margin-bottom:24px}
table{width:100%;border-collapse:collapse;font-size:.85rem}
th{background:#0d1526;color:#6b7a99;text-transform:uppercase;letter-spacing:.06em;
  font-size:.7rem;padding:10px 14px;text-align:left}
td{padding:10px 14px;border-bottom:1px solid #1a2d50;vertical-align:top}
tr:hover td{background:#0a1020}
.sev-badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:.72rem;font-weight:700}
.finding-card{background:#0d1526;border:1px solid #1a2d50;border-radius:12px;
  margin-bottom:24px;overflow:hidden}
.finding-header{padding:18px 22px;display:flex;align-items:center;gap:12px;
  border-bottom:1px solid #1a2d50}
.finding-id{width:32px;height:32px;border-radius:8px;background:#1a2d50;
  display:flex;align-items:center;justify-content:center;font-size:.8rem;
  font-weight:700;flex-shrink:0}
.finding-title{font-size:1rem;font-weight:700;color:#fff;flex:1}
.finding-body{padding:22px}
.detail-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:18px}
.detail-item{}
.detail-label{font-size:.7rem;text-transform:uppercase;letter-spacing:.06em;
  color:#6b7a99;margin-bottom:4px}
.detail-val{font-size:.85rem;color:#e8edf5;word-break:break-all}
.detail-val code{background:#070b14;border:1px solid #1a2d50;border-radius:5px;
  padding:1px 6px;font-family:monospace;color:#00d4ff;font-size:.82rem}
.desc-block{font-size:.875rem;color:#a0aec0;line-height:1.7;margin-bottom:18px}
.remediation h4{font-size:.85rem;font-weight:700;color:#00ff88;margin-bottom:10px}
.remediation ol{padding-left:20px}
.remediation li{font-size:.85rem;color:#a0aec0;margin-bottom:6px;line-height:1.65}
.code-block{background:#070b14;border:1px solid #1a2d50;border-radius:8px;
  padding:14px 16px;font-family:monospace;font-size:.8rem;
  line-height:1.8;white-space:pre-wrap;word-break:break-all;margin-top:8px}
.code-bad{border-left:3px solid #ff4757;color:#ffa198}
.code-good{border-left:3px solid #00ff88;color:#a7f3d0}
.code-label{font-size:.7rem;text-transform:uppercase;letter-spacing:.08em;
  color:#6b7a99;margin-top:14px;margin-bottom:4px}
.evidence-block{background:#070b14;border:1px solid #ff475730;border-radius:8px;
  padding:10px 14px;font-family:monospace;font-size:.78rem;
  color:#ffa198;margin-top:8px;word-break:break-all}
.technique-tag{display:inline-block;background:#00d4ff15;border:1px solid #00d4ff30;
  border-radius:20px;padding:2px 10px;font-size:.7rem;color:#00d4ff;margin-right:4px}
.recs-list{list-style:none}
.recs-list li{padding:10px 14px;border-left:3px solid #00d4ff;
  background:#0d1526;border-radius:0 8px 8px 0;margin-bottom:8px;
  font-size:.875rem;color:#a0aec0}
.footer-bar{background:#0a1020;border-top:1px solid #1a2d50;
  padding:20px 40px;text-align:center;font-size:.78rem;color:#3d4f70;margin-top:60px}
.clean-banner{text-align:center;padding:60px 20px}
.clean-icon{font-size:3rem;color:#00ff88}
.clean-text{font-size:1.1rem;color:#a0aec0;margin-top:16px}
@media(max-width:640px){.detail-grid{grid-template-columns:1fr}.cover-meta{flex-direction:column}}
</style>
"""


def _severity_badge_html(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, "#6b7a99")
    return (
        f'<span class="sev-badge" '
        f'style="background:{color}22;color:{color};border:1px solid {color}44">'
        f'{html.escape(severity)}</span>'
    )


def _h(text) -> str:
    """HTML-escape a value."""
    return html.escape(str(text) if text else "")


class ReportGenerator:
    """
    Generates HTML and (optionally) PDF assessment reports.

    Parameters
    ----------
    output_dir : directory where reports are written (created if absent)
    """

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    # ── HTML report ───────────────────────────────────────────

    def generate_html(
        self,
        analysis:    Dict,
        scan_meta:   Dict,
        report_id:   str,
    ) -> str:
        """
        Build a standalone HTML report and write it to disk.

        Returns the file path.
        """
        path = os.path.join(self.output_dir, f"{report_id}.html")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self._render_html(analysis, scan_meta))
        logger.info("[ReportGenerator] HTML report → %s", path)
        return path

    def _render_html(self, analysis: Dict, meta: Dict) -> str:
        target     = _h(meta.get("target_url", "Unknown"))
        scan_date  = _h(meta.get("scan_date",  datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        duration   = _h(meta.get("duration",   "N/A"))
        pages      = _h(meta.get("pages_crawled", "N/A"))
        risk       = _h(analysis.get("overall_risk", "Unknown"))
        risk_color = RISK_COLORS.get(risk, "#6b7a99")

        total    = analysis.get("total_findings", 0)
        critical = analysis.get("critical_count",  0)
        high     = analysis.get("high_count",      0)
        medium   = analysis.get("medium_count",    0)
        low      = analysis.get("low_count",       0)
        findings = analysis.get("findings",        [])
        recs     = analysis.get("recommendations", [])

        # ── Cover ────────────────────────────────────────────
        html_parts = [
            "<!DOCTYPE html><html lang='en'><head>",
            "<meta charset='UTF-8'>",
            "<meta name='viewport' content='width=device-width,initial-scale=1'>",
            "<title>Aegis Security Assessment Report</title>",
            HTML_STYLE,
            "</head><body>",
            # Cover
            "<div class='cover'>",
            "<div class='cover-logo'>🛡</div>",
            "<div class='cover-title'>Security Assessment Report</div>",
            f"<div class='cover-subtitle'>Aegis Security Platform &mdash; Automated Web Application Assessment</div>",
            "<div class='cover-meta'>",
            f"<div class='meta-item'><div class='meta-label'>Target</div><div class='meta-val'>{target}</div></div>",
            f"<div class='meta-item'><div class='meta-label'>Scan Date</div><div class='meta-val'>{scan_date}</div></div>",
            f"<div class='meta-item'><div class='meta-label'>Duration</div><div class='meta-val'>{duration}</div></div>",
            f"<div class='meta-item'><div class='meta-label'>Pages Crawled</div><div class='meta-val'>{pages}</div></div>",
            "</div>",
            "</div>",  # /cover
            "<div class='container'>",

            # ── Executive Summary ────────────────────────────
            "<div class='section'>",
            "<div class='section-title'>Executive Summary</div>",
            f"<span class='risk-badge' style='background:{risk_color}22;color:{risk_color};border:1px solid {risk_color}44'>",
            f"Overall Risk: {risk}</span>",
            "<div class='exec-grid'>",
            self._exec_card(str(total),    "Total Findings",  "#00d4ff"),
            self._exec_card(str(critical), "Critical",        "#ff4757"),
            self._exec_card(str(high),     "High",            "#ff6b35"),
            self._exec_card(str(medium),   "Medium",          "#ffd32a"),
            self._exec_card(str(low),      "Low",             "#00d4ff"),
            "</div>",
        ]

        if total == 0:
            html_parts += [
                "<div class='clean-banner'>",
                "<div class='clean-icon'>✅</div>",
                "<div class='clean-text'>No vulnerabilities were detected in this scan pass. "
                "Continue regular assessments as part of your security programme.</div>",
                "</div>",
            ]
        else:
            # ── Summary Table ──────────────────────────────
            html_parts += [
                "<div class='section-title' style='margin-top:32px'>Vulnerability Summary</div>",
                "<table><thead><tr>",
                "<th>#</th><th>Vulnerability</th><th>Severity</th>",
                "<th>Parameter</th><th>Detection Technique</th>",
                "</tr></thead><tbody>",
            ]
            for row in analysis.get("summary_table", []):
                sev_badge = _severity_badge_html(row["severity"])
                html_parts.append(
                    f"<tr>"
                    f"<td>{_h(row['id'])}</td>"
                    f"<td>{_h(row['vulnerability'])}</td>"
                    f"<td>{sev_badge}</td>"
                    f"<td><code style='background:#070b14;padding:2px 6px;border-radius:4px;"
                    f"color:#00d4ff;font-size:.82rem'>{_h(row['param'])}</code></td>"
                    f"<td>{_h(row['techniques'])}</td>"
                    f"</tr>"
                )
            html_parts.append("</tbody></table>")

            # ── Detailed Findings ──────────────────────────
            html_parts.append("<div class='section-title' style='margin-top:40px'>Detailed Findings</div>")
            for f in findings:
                html_parts.append(self._render_finding_card(f))

        # ── Recommendations ──────────────────────────────────
        html_parts += [
            "</div>",  # /section
            "<div class='section'>",
            "<div class='section-title'>Recommendations</div>",
            "<ul class='recs-list'>",
        ]
        for rec in recs:
            html_parts.append(f"<li>{_h(rec)}</li>")
        html_parts += [
            "</ul>",
            "</div>",  # /section
            "</div>",  # /container

            # Footer
            "<div class='footer-bar'>",
            f"Generated by Aegis Security Platform &mdash; {scan_date} &mdash; "
            "For authorised use only",
            "</div>",
            "</body></html>",
        ]
        return "".join(html_parts)

    def _exec_card(self, val: str, label: str, color: str) -> str:
        return (
            f"<div class='exec-card'>"
            f"<div class='exec-val' style='color:{color}'>{val}</div>"
            f"<div class='exec-label'>{label}</div>"
            f"</div>"
        )

    def _render_finding_card(self, f: Dict) -> str:
        sev_color = SEVERITY_COLORS.get(f["severity_label"], "#6b7a99")
        sev_badge = _severity_badge_html(f["severity_label"])
        techniques_html = "".join(
            f"<span class='technique-tag'>{_h(t)}</span>"
            for t in f.get("techniques", [])
        )

        # First evidence from findings_detail
        evidence_html = ""
        for fd in f.get("findings_detail", [])[:1]:
            ev = fd.get("evidence", "")
            if ev:
                evidence_html = (
                    f"<div class='detail-label'>Evidence</div>"
                    f"<div class='evidence-block'>{_h(ev)}</div>"
                )

        code_html = ""
        if f.get("code_bad") and f.get("code_good"):
            code_html = (
                "<div class='code-label'>Vulnerable Pattern</div>"
                f"<div class='code-block code-bad'>{_h(f['code_bad'])}</div>"
                "<div class='code-label'>Secure Pattern</div>"
                f"<div class='code-block code-good'>{_h(f['code_good'])}</div>"
            )

        steps_html = "".join(
            f"<li>{_h(s)}</li>"
            for s in f.get("remediation_steps", [])
        )

        return (
            f"<div class='finding-card' style='border-color:{sev_color}33'>"
            f"<div class='finding-header' style='background:{sev_color}0a'>"
            f"<div class='finding-id' style='color:{sev_color}'>{_h(f['id'])}</div>"
            f"<div class='finding-title'>{_h(f['vulnerability'])}</div>"
            f"{sev_badge}"
            f"</div>"
            f"<div class='finding-body'>"
            f"<p class='desc-block'>{_h(f.get('description', ''))}</p>"
            f"<div class='detail-grid'>"
            f"<div class='detail-item'><div class='detail-label'>Affected URL</div>"
            f"<div class='detail-val'><a href='{_h(f['url'])}'>{_h(f['url'])}</a></div></div>"
            f"<div class='detail-item'><div class='detail-label'>Parameter</div>"
            f"<div class='detail-val'><code>{_h(f['param'])}</code></div></div>"
            f"<div class='detail-item'><div class='detail-label'>Detection Techniques</div>"
            f"<div class='detail-val'>{techniques_html}</div></div>"
            f"<div class='detail-item'><div class='detail-label'>OWASP / CWE</div>"
            f"<div class='detail-val'>"
            f"<a href='{_h(f.get('owasp_url',''))}' target='_blank'>{_h(f.get('owasp_ref',''))}</a>"
            f" &mdash; {_h(f.get('cwe',''))}</div></div>"
            f"</div>"
            f"{evidence_html}"
            f"<div class='remediation'>"
            f"<h4>Remediation Steps</h4>"
            f"<ol>{steps_html}</ol>"
            f"</div>"
            f"{code_html}"
            f"</div>"  # /finding-body
            f"</div>"  # /finding-card
        )

    # ── PDF report ────────────────────────────────────────────

    def generate_pdf(
        self,
        analysis:  Dict,
        scan_meta: Dict,
        report_id: str,
    ) -> str:
        """
        Build a PDF report using ReportLab and write it to disk.

        Returns the file path, or raises ImportError if ReportLab
        is not installed.
        """
        try:
            from reportlab.lib              import colors
            from reportlab.lib.pagesizes    import A4
            from reportlab.lib.styles       import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units        import cm
            from reportlab.platypus         import (
                SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
                HRFlowable, PageBreak,
            )
        except ImportError:
            raise ImportError(
                "ReportLab is required for PDF generation. "
                "Install it with: pip install reportlab"
            )

        path = os.path.join(self.output_dir, f"{report_id}.pdf")
        doc  = SimpleDocTemplate(
            path,
            pagesize=A4,
            leftMargin=2*cm, rightMargin=2*cm,
            topMargin=2*cm,  bottomMargin=2*cm,
            title="Aegis Security Assessment Report",
        )

        W, H = A4
        styles   = getSampleStyleSheet()
        story    = []
        C_CYAN   = colors.HexColor("#00d4ff")
        C_RED    = colors.HexColor("#ff4757")
        C_ORANGE = colors.HexColor("#ff6b35")
        C_YELLOW = colors.HexColor("#ffd32a")
        C_GREEN  = colors.HexColor("#00ff88")
        C_BG     = colors.HexColor("#070b14")
        C_SURF   = colors.HexColor("#0d1526")
        C_BORDER = colors.HexColor("#1a2d50")
        C_TEXT   = colors.HexColor("#e8edf5")
        C_DIM    = colors.HexColor("#6b7a99")

        def sev_color(sev: str):
            return {
                "Critical"     : C_RED,
                "High"         : C_ORANGE,
                "Medium"       : C_YELLOW,
                "Low"          : C_CYAN,
                "Clean"        : C_GREEN,
            }.get(sev, C_DIM)

        # ── Styles ────────────────────────────────────────────
        heading1 = ParagraphStyle("H1", parent=styles["Normal"],
            fontSize=22, fontName="Helvetica-Bold",
            textColor=colors.white, spaceAfter=6)
        heading2 = ParagraphStyle("H2", parent=styles["Normal"],
            fontSize=14, fontName="Helvetica-Bold",
            textColor=colors.white, spaceBefore=16, spaceAfter=6)
        heading3 = ParagraphStyle("H3", parent=styles["Normal"],
            fontSize=11, fontName="Helvetica-Bold",
            textColor=C_CYAN, spaceBefore=10, spaceAfter=4)
        body_style = ParagraphStyle("Body", parent=styles["Normal"],
            fontSize=9, textColor=C_TEXT, leading=14, spaceAfter=4)
        dim_style  = ParagraphStyle("Dim", parent=styles["Normal"],
            fontSize=8, textColor=C_DIM,  leading=12)
        mono_style = ParagraphStyle("Mono", parent=styles["Normal"],
            fontSize=8, fontName="Courier", textColor=C_CYAN,
            leading=12, spaceAfter=4)
        label_style = ParagraphStyle("Label", parent=styles["Normal"],
            fontSize=7, fontName="Helvetica-Bold",
            textColor=C_DIM, spaceBefore=8, spaceAfter=2)

        target    = scan_meta.get("target_url", "Unknown")
        scan_date = scan_meta.get("scan_date",  datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        duration  = scan_meta.get("duration",   "N/A")
        pages     = scan_meta.get("pages_crawled", "N/A")
        risk      = analysis.get("overall_risk", "Unknown")
        total     = analysis.get("total_findings", 0)
        critical  = analysis.get("critical_count",  0)
        high      = analysis.get("high_count",      0)
        medium    = analysis.get("medium_count",    0)
        low       = analysis.get("low_count",       0)
        findings  = analysis.get("findings",        [])
        recs      = analysis.get("recommendations", [])

        # ── Cover Page ────────────────────────────────────────
        story.append(Spacer(1, 2*cm))
        story.append(Paragraph("Aegis Security", heading1))
        story.append(Paragraph("Web Application Assessment Report", heading2))
        story.append(HRFlowable(width="100%", thickness=2, color=C_CYAN, spaceAfter=16))

        meta_data = [
            ["Target URL",     target],
            ["Scan Date",      scan_date],
            ["Duration",       duration],
            ["Pages Crawled",  str(pages)],
            ["Overall Risk",   risk],
        ]
        meta_table = Table(meta_data, colWidths=[4*cm, 14*cm])
        meta_table.setStyle(TableStyle([
            ("FONTNAME",  (0,0), (0,-1), "Helvetica-Bold"),
            ("FONTSIZE",  (0,0), (-1,-1), 9),
            ("TEXTCOLOR", (0,0), (0,-1),  C_DIM),
            ("TEXTCOLOR", (1,0), (1,-1),  C_TEXT),
            ("ROWBACKGROUNDS", (0,0), (-1,-1), [C_SURF, C_BG]),
            ("TOPPADDING",    (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ]))
        story.append(meta_table)
        story.append(PageBreak())

        # ── Executive Summary ─────────────────────────────────
        story.append(Paragraph("Executive Summary", heading2))
        story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER, spaceAfter=10))

        summary_data = [
            ["Total Findings", "Critical", "High", "Medium", "Low"],
            [str(total), str(critical), str(high), str(medium), str(low)],
        ]
        summary_table = Table(summary_data, colWidths=[3.6*cm]*5)
        summary_table.setStyle(TableStyle([
            ("FONTNAME",  (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",  (0,0), (-1,-1), 9),
            ("TEXTCOLOR", (0,0), (-1,0), C_DIM),
            ("TEXTCOLOR", (0,1), (0,1),  C_CYAN),
            ("TEXTCOLOR", (1,1), (1,1),  C_RED),
            ("TEXTCOLOR", (2,1), (2,1),  C_ORANGE),
            ("TEXTCOLOR", (3,1), (3,1),  C_YELLOW),
            ("TEXTCOLOR", (4,1), (4,1),  C_CYAN),
            ("FONTNAME",  (0,1), (-1,1), "Helvetica-Bold"),
            ("FONTSIZE",  (0,1), (-1,1), 16),
            ("ALIGN",     (0,0), (-1,-1), "CENTER"),
            ("ROWBACKGROUNDS", (0,0), (-1,-1), [C_SURF, C_BG]),
            ("TOPPADDING",    (0,0), (-1,-1), 8),
            ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.4*cm))
        story.append(Paragraph(
            f"Overall Risk Assessment: <b>{risk}</b>",
            ParagraphStyle("RiskP", parent=body_style, textColor=sev_color(risk))
        ))

        # ── Vulnerability Summary Table ───────────────────────
        if total > 0:
            story.append(Spacer(1, 0.6*cm))
            story.append(Paragraph("Vulnerability Summary", heading2))
            story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER, spaceAfter=10))

            tbl_data  = [["#", "Vulnerability", "Severity", "Parameter", "Techniques"]]
            tbl_style = [
                ("FONTNAME",  (0,0), (-1,0), "Helvetica-Bold"),
                ("FONTSIZE",  (0,0), (-1,-1), 8),
                ("TEXTCOLOR", (0,0), (-1,0), C_DIM),
                ("TEXTCOLOR", (0,1), (-1,-1), C_TEXT),
                ("BACKGROUND",(0,0), (-1,0), C_SURF),
                ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_BG, C_SURF]),
                ("TOPPADDING",    (0,0), (-1,-1), 6),
                ("BOTTOMPADDING", (0,0), (-1,-1), 6),
                ("LEFTPADDING",   (0,0), (-1,-1), 6),
            ]
            for i, row in enumerate(analysis.get("summary_table", []), start=1):
                tbl_data.append([
                    str(row["id"]),
                    row["vulnerability"],
                    row["severity"],
                    row["param"],
                    row["techniques"],
                ])
                sc = sev_color(row["severity"])
                tbl_style.append(("TEXTCOLOR", (2, i), (2, i), sc))

            vtable = Table(tbl_data, colWidths=[1*cm, 5.5*cm, 2*cm, 3*cm, 6.5*cm])
            vtable.setStyle(TableStyle(tbl_style))
            story.append(vtable)

            # ── Detailed Findings ──────────────────────────────
            story.append(PageBreak())
            story.append(Paragraph("Detailed Findings", heading2))
            story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER, spaceAfter=10))

            for f in findings:
                sc = sev_color(f["severity_label"])
                story.append(Paragraph(
                    f"Finding #{f['id']}: {f['vulnerability']}",
                    ParagraphStyle("FH", parent=heading3, textColor=sc)
                ))

                details = [
                    ["Severity",  f["severity_label"]],
                    ["URL",       f["url"]],
                    ["Parameter", f["param"]],
                    ["OWASP",     f.get("owasp_ref", "")],
                    ["CWE",       f.get("cwe", "")],
                    ["Techniques",", ".join(f.get("techniques", []))],
                ]
                dtable = Table(details, colWidths=[3*cm, 15*cm])
                dtable.setStyle(TableStyle([
                    ("FONTNAME",  (0,0), (0,-1), "Helvetica-Bold"),
                    ("FONTSIZE",  (0,0), (-1,-1), 8),
                    ("TEXTCOLOR", (0,0), (0,-1), C_DIM),
                    ("TEXTCOLOR", (1,0), (1,0),  sc),
                    ("TEXTCOLOR", (1,1), (1,-1), C_TEXT),
                    ("ROWBACKGROUNDS", (0,0), (-1,-1), [C_SURF, C_BG]),
                    ("TOPPADDING",    (0,0), (-1,-1), 5),
                    ("BOTTOMPADDING", (0,0), (-1,-1), 5),
                    ("LEFTPADDING",   (0,0), (-1,-1), 6),
                ]))
                story.append(dtable)
                story.append(Spacer(1, 0.2*cm))

                if f.get("description"):
                    story.append(Paragraph(f["description"], body_style))

                # Evidence from first finding detail
                for fd in f.get("findings_detail", [])[:1]:
                    ev = fd.get("evidence", "")
                    if ev:
                        story.append(Paragraph("Evidence:", label_style))
                        story.append(Paragraph(str(ev)[:200], mono_style))

                story.append(Paragraph("Remediation:", label_style))
                for step in f.get("remediation_steps", []):
                    story.append(Paragraph(f"• {step}", body_style))

                story.append(Spacer(1, 0.5*cm))
                story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
                story.append(Spacer(1, 0.3*cm))

        # ── Recommendations ───────────────────────────────────
        story.append(Paragraph("Recommendations", heading2))
        story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER, spaceAfter=10))
        for rec in recs:
            story.append(Paragraph(f"• {rec}", body_style))

        story.append(Spacer(1, cm))
        story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER))
        story.append(Paragraph(
            f"Generated by Aegis Security Platform | {scan_date} | Authorised use only",
            dim_style
        ))

        doc.build(story)
        logger.info("[ReportGenerator] PDF report → %s", path)
        return path