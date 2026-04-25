"""
report_generator.py — Report Generation Engine
===============================================
Generates a polished, standalone HTML report and a professional
PDF report from the structured findings produced by ResponseAnalyzer.

HTML report : fully self-contained (inline CSS, no external deps)
PDF report  : ReportLab Platypus — professional light theme with
              cover page, colour-coded findings, severity dashboard,
              code blocks, page numbers.

Layer : Reporting Layer

PDF Changes (v3)
----------------
- Replaced broken colour operations (risk_color.hexval(), sc.rgb())
  with explicit lookup dictionaries for every severity / risk level.
- Switched to a clean white / light-grey professional theme so the
  PDF renders correctly in all viewers and prints legibly.
- Fixed column widths and padding for all tables.
- Removed unused imports (BalancedColumns).
- Added a proper page-number footer via onFirstPage / onLaterPages.
"""

import os
import html
import logging
from datetime import datetime
from typing import Dict, List

logger = logging.getLogger("report_generator")

# ─────────────────────────────────────────────────────────────
# Colour / severity maps
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
    return html.escape(str(text) if text else "")


class ReportGenerator:
    """
    Generates HTML and PDF assessment reports.

    Parameters
    ----------
    output_dir : directory where reports are written (created if absent)
    """

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    # ── HTML report ───────────────────────────────────────────

    def generate_html(self, analysis: Dict, scan_meta: Dict, report_id: str) -> str:
        path = os.path.join(self.output_dir, f"{report_id}.html")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self._render_html(analysis, scan_meta))
        logger.info("[ReportGenerator] HTML report → %s", path)
        return path

    def _render_html(self, analysis: Dict, meta: Dict) -> str:
        target    = _h(meta.get("target_url", "Unknown"))
        scan_date = _h(meta.get("scan_date",  datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        duration  = _h(meta.get("duration",   "N/A"))
        pages     = _h(meta.get("pages_crawled", "N/A"))
        auth_type = _h(meta.get("auth_type", "none"))
        risk      = _h(analysis.get("overall_risk", "Unknown"))
        risk_color = RISK_COLORS.get(risk, "#6b7a99")

        total    = analysis.get("total_findings", 0)
        critical = analysis.get("critical_count",  0)
        high     = analysis.get("high_count",      0)
        medium   = analysis.get("medium_count",    0)
        low      = analysis.get("low_count",       0)
        findings = analysis.get("findings",        [])
        recs     = analysis.get("recommendations", [])

        html_parts = [
            "<!DOCTYPE html><html lang='en'><head>",
            "<meta charset='UTF-8'>",
            "<meta name='viewport' content='width=device-width,initial-scale=1'>",
            "<title>Aegis Security Assessment Report</title>",
            HTML_STYLE,
            "</head><body>",
            "<div class='cover'>",
            "<div class='cover-logo'>🛡</div>",
            "<div class='cover-title'>Security Assessment Report</div>",
            "<div class='cover-subtitle'>Aegis Security Platform &mdash; Automated Web Application Assessment</div>",
            "<div class='cover-meta'>",
            f"<div class='meta-item'><div class='meta-label'>Target</div><div class='meta-val'>{target}</div></div>",
            f"<div class='meta-item'><div class='meta-label'>Scan Date</div><div class='meta-val'>{scan_date}</div></div>",
            f"<div class='meta-item'><div class='meta-label'>Duration</div><div class='meta-val'>{duration}</div></div>",
            f"<div class='meta-item'><div class='meta-label'>Pages Crawled</div><div class='meta-val'>{pages}</div></div>",
            f"<div class='meta-item'><div class='meta-label'>Auth Mode</div><div class='meta-val'>{auth_type}</div></div>",
            "</div></div>",
            "<div class='container'>",
            "<div class='section'>",
            "<div class='section-title'>Executive Summary</div>",
            f"<span class='risk-badge' style='background:{risk_color}22;color:{risk_color};border:1px solid {risk_color}44'>Overall Risk: {risk}</span>",
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
                "<div class='clean-text'>No vulnerabilities were detected in this scan pass.</div>",
                "</div>",
            ]
        else:
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
            html_parts.append("<div class='section-title' style='margin-top:40px'>Detailed Findings</div>")
            for f in findings:
                html_parts.append(self._render_finding_card(f))

        html_parts += [
            "</div>",
            "<div class='section'>",
            "<div class='section-title'>Recommendations</div>",
            "<ul class='recs-list'>",
        ]
        for rec in recs:
            html_parts.append(f"<li>{_h(rec)}</li>")
        html_parts += [
            "</ul></div></div>",
            "<div class='footer-bar'>",
            f"Generated by Aegis Security Platform &mdash; {scan_date} &mdash; For authorised use only",
            "</div></body></html>",
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
        steps_html = "".join(f"<li>{_h(s)}</li>" for s in f.get("remediation_steps", []))

        return (
            f"<div class='finding-card' style='border-color:{sev_color}33'>"
            f"<div class='finding-header' style='background:{sev_color}0a'>"
            f"<div class='finding-id' style='color:{sev_color}'>{_h(f['id'])}</div>"
            f"<div class='finding-title'>{_h(f['vulnerability'])}</div>"
            f"{sev_badge}</div>"
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
            f"<div class='remediation'><h4>Remediation Steps</h4><ol>{steps_html}</ol></div>"
            f"{code_html}"
            f"</div></div>"
        )

    # ─────────────────────────────────────────────────────────
    # PDF report — clean professional light theme
    # ─────────────────────────────────────────────────────────

    def generate_pdf(self, analysis: Dict, scan_meta: Dict, report_id: str) -> str:
        """
        Build a professional PDF report using ReportLab Platypus.
        Light theme (white background, dark text) for maximum readability
        in all PDF viewers and when printed.
        """
        try:
            from reportlab.lib              import colors
            from reportlab.lib.pagesizes    import A4
            from reportlab.lib.styles       import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units        import cm
            from reportlab.lib.enums        import TA_CENTER, TA_LEFT, TA_RIGHT
            from reportlab.lib.colors       import HexColor
            from reportlab.platypus         import (
                SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
                HRFlowable, PageBreak, KeepTogether,
            )
        except ImportError:
            raise ImportError(
                "ReportLab is required for PDF generation. "
                "Install it with: pip install reportlab"
            )

        # ── Palette (light professional theme) ────────────────
        # All colours are simple HexColor lookups — no runtime colour maths.

        C_WHITE    = colors.white
        C_NEAR_W   = HexColor("#f7f8fa")   # alternating row tint
        C_LIGHT    = HexColor("#eef0f5")   # table header background
        C_COVER    = HexColor("#0a1020")   # dark cover page background
        C_COVER_AC = HexColor("#00d4ff")   # cover accent / rule
        C_TEXT     = HexColor("#1a2035")   # primary dark text
        C_DIM      = HexColor("#4a5568")   # secondary text
        C_MUTED    = HexColor("#8896ad")   # footer / caption text
        C_BORDER   = HexColor("#d1d8e8")   # table borders
        C_ACCENT   = HexColor("#0077cc")   # hyperlinks / labels

        # Severity foreground colours (readable on white background)
        SEV_FG: Dict[str, HexColor] = {
            "Critical": HexColor("#cc1122"),
            "High"    : HexColor("#cc4400"),
            "Medium"  : HexColor("#997700"),
            "Low"     : HexColor("#0077cc"),
            "Clean"   : HexColor("#007744"),
            "Unknown" : HexColor("#556688"),
        }
        # Severity light background tints
        SEV_BG: Dict[str, HexColor] = {
            "Critical": HexColor("#fff0f0"),
            "High"    : HexColor("#fff4ee"),
            "Medium"  : HexColor("#fffbee"),
            "Low"     : HexColor("#eef6ff"),
            "Clean"   : HexColor("#eefff6"),
            "Unknown" : HexColor("#f3f4f8"),
        }
        # Risk-level foreground colours (same set as severity)
        RISK_FG = SEV_FG

        def sev_fg(label: str) -> HexColor:
            return SEV_FG.get(label, SEV_FG["Unknown"])

        def sev_bg(label: str) -> HexColor:
            return SEV_BG.get(label, SEV_BG["Unknown"])

        # ── Document ──────────────────────────────────────────
        path = os.path.join(self.output_dir, f"{report_id}.pdf")
        W, H = A4

        story: List = []

        def _draw_footer(canvas, doc):
            """Page number footer on every page."""
            canvas.saveState()
            canvas.setFont("Helvetica", 7)
            canvas.setFillColor(C_MUTED)
            footer_text = (
                f"Aegis Security Platform  ·  Confidential — Authorised Use Only  ·  "
                f"Page {doc.page}"
            )
            canvas.drawCentredString(W / 2, 1.1 * cm, footer_text)
            canvas.restoreState()

        doc = SimpleDocTemplate(
            path,
            pagesize=A4,
            leftMargin=2.0 * cm, rightMargin=2.0 * cm,
            topMargin=2.0 * cm,  bottomMargin=2.2 * cm,
            title="Aegis Security Assessment Report",
            author="Aegis Security Platform",
        )

        # ── Style helpers ─────────────────────────────────────

        def _ps(name, **kw) -> ParagraphStyle:
            base = getSampleStyleSheet()["Normal"]
            return ParagraphStyle(name, parent=base, **kw)

        W_CONTENT = W - 4.0 * cm   # usable width

        S_TITLE   = _ps("title",   fontSize=22, fontName="Helvetica-Bold",
                         textColor=C_WHITE,  alignment=TA_CENTER, spaceAfter=6)
        S_SUB     = _ps("sub",     fontSize=11, textColor=HexColor("#99aabb"),
                         alignment=TA_CENTER, spaceAfter=14)
        S_SECTION = _ps("section", fontSize=13, fontName="Helvetica-Bold",
                         textColor=C_TEXT,   spaceBefore=16, spaceAfter=6)
        S_BODY    = _ps("body",    fontSize=9,  textColor=C_DIM,
                         leading=14, spaceAfter=4)
        S_MONO    = _ps("mono",    fontSize=8,  fontName="Courier",
                         textColor=C_ACCENT, leading=12, spaceAfter=4)
        S_MONO_BAD  = _ps("mono_bad",  fontSize=8, fontName="Courier",
                           textColor=HexColor("#aa2222"), leading=13,
                           backColor=HexColor("#fff8f8"), spaceAfter=4)
        S_MONO_GOOD = _ps("mono_good", fontSize=8, fontName="Courier",
                           textColor=HexColor("#117733"), leading=13,
                           backColor=HexColor("#f6fff9"), spaceAfter=4)
        S_LABEL   = _ps("label",   fontSize=7, fontName="Helvetica-Bold",
                         textColor=C_MUTED,  spaceBefore=6, spaceAfter=2)
        S_CENTER  = _ps("center",  fontSize=9, textColor=C_DIM,
                         alignment=TA_CENTER)
        S_FOOTER  = _ps("footer",  fontSize=7, textColor=C_MUTED,
                         alignment=TA_CENTER)

        # ── Scan metadata ─────────────────────────────────────
        target    = scan_meta.get("target_url",    "Unknown")
        scan_date = scan_meta.get("scan_date",     datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        duration  = scan_meta.get("duration",      "N/A")
        pages     = str(scan_meta.get("pages_crawled", "N/A"))
        forms_fnd = str(scan_meta.get("forms_found",   "N/A"))
        auth_type = scan_meta.get("auth_type",     "none")
        risk      = analysis.get("overall_risk",   "Unknown")
        total     = analysis.get("total_findings", 0)
        critical  = analysis.get("critical_count",  0)
        high      = analysis.get("high_count",      0)
        medium    = analysis.get("medium_count",    0)
        low       = analysis.get("low_count",       0)
        findings  = analysis.get("findings",        [])
        recs      = analysis.get("recommendations", [])

        # ══════════════════════════════════════════════════════
        # COVER PAGE
        # ══════════════════════════════════════════════════════

        # Dark cover panel
        cover_table_data = [
            [Paragraph("🛡  AEGIS SECURITY", S_TITLE)],
            [Paragraph("Web Application Security Assessment Report", S_SUB)],
        ]
        cover_t = Table(cover_table_data, colWidths=[W_CONTENT])
        cover_t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), C_COVER),
            ("TOPPADDING",    (0, 0), (-1, -1), 28),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 28),
            ("LEFTPADDING",   (0, 0), (-1, -1), 0),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ]))
        story.append(cover_t)
        story.append(HRFlowable(width="100%", thickness=2,
                                color=C_COVER_AC, spaceAfter=18))

        # Metadata table
        meta_rows = [
            ["TARGET URL",    target],
            ["SCAN DATE",     scan_date],
            ["DURATION",      duration],
            ["PAGES CRAWLED", pages],
            ["FORMS FOUND",   forms_fnd],
            ["AUTH MODE",     auth_type.upper()],
            ["OVERALL RISK",  risk.upper()],
        ]
        meta_t = Table(meta_rows, colWidths=[4.0 * cm, W_CONTENT - 4.0 * cm])
        meta_styles = [
            ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME",      (1, 0), (1, -1), "Helvetica"),
            ("FONTSIZE",      (0, 0), (-1, -1), 9),
            ("TEXTCOLOR",     (0, 0), (0, -1), C_MUTED),
            ("TEXTCOLOR",     (1, 0), (1, -2), C_TEXT),
            ("ROWBACKGROUNDS",(0, 0), (-1, -1), [C_WHITE, C_NEAR_W]),
            ("TOPPADDING",    (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
            ("LINEBELOW",     (0, 0), (-1, -2), 0.3, C_BORDER),
            ("BOX",           (0, 0), (-1, -1), 0.5, C_BORDER),
            # Highlight risk row
            ("TEXTCOLOR",     (1, -1), (1, -1), RISK_FG.get(risk, SEV_FG["Unknown"])),
            ("FONTNAME",      (1, -1), (1, -1), "Helvetica-Bold"),
            ("FONTSIZE",      (1, -1), (1, -1), 10),
        ]
        meta_t.setStyle(TableStyle(meta_styles))
        story.append(meta_t)
        story.append(Spacer(1, 0.6 * cm))

        # Confidentiality notice
        notice_t = Table(
            [["  ⚠  CONFIDENTIAL — FOR AUTHORISED USE ONLY  "]],
            colWidths=[W_CONTENT]
        )
        notice_t.setStyle(TableStyle([
            ("FONTNAME",      (0, 0), (-1, -1), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("TEXTCOLOR",     (0, 0), (-1, -1), HexColor("#996600")),
            ("BACKGROUND",    (0, 0), (-1, -1), HexColor("#fffbee")),
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING",    (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("BOX",           (0, 0), (-1, -1), 0.8, HexColor("#f0c060")),
        ]))
        story.append(notice_t)
        story.append(PageBreak())

        # ══════════════════════════════════════════════════════
        # EXECUTIVE SUMMARY
        # ══════════════════════════════════════════════════════
        story.append(Paragraph("Executive Summary", S_SECTION))
        story.append(HRFlowable(width="100%", thickness=1,
                                color=C_BORDER, spaceAfter=10))

        # Risk badge
        risk_fg = RISK_FG.get(risk, SEV_FG["Unknown"])
        risk_bg = SEV_BG.get(risk, SEV_BG["Unknown"])
        rb = Table([[f"  Overall Risk: {risk.upper()}  "]])
        rb.setStyle(TableStyle([
            ("FONTNAME",      (0, 0), (-1, -1), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 11),
            ("TEXTCOLOR",     (0, 0), (-1, -1), risk_fg),
            ("BACKGROUND",    (0, 0), (-1, -1), risk_bg),
            ("TOPPADDING",    (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LEFTPADDING",   (0, 0), (-1, -1), 14),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 14),
            ("BOX",           (0, 0), (-1, -1), 1.0, risk_fg),
        ]))
        story.append(rb)
        story.append(Spacer(1, 0.4 * cm))

        # Severity dashboard — 5 metric cards
        col_w = W_CONTENT / 5
        dash_labels = ["TOTAL",    "CRITICAL",  "HIGH",     "MEDIUM",   "LOW"]
        dash_values = [str(total), str(critical), str(high), str(medium), str(low)]
        dash_fg     = [C_ACCENT,   SEV_FG["Critical"], SEV_FG["High"],
                       SEV_FG["Medium"], SEV_FG["Low"]]
        dash_bg     = [C_NEAR_W,   SEV_BG["Critical"], SEV_BG["High"],
                       SEV_BG["Medium"], SEV_BG["Low"]]

        dash_t = Table(
            [dash_labels, dash_values],
            colWidths=[col_w] * 5
        )
        dash_style = [
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
            ("FONTSIZE",      (0, 0), (-1, 0), 7),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 1), (-1, 1), 20),
            ("FONTNAME",      (0, 1), (-1, 1), "Helvetica-Bold"),
            ("TOPPADDING",    (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("LINEBELOW",     (0, 0), (-1, 0), 0.5, C_BORDER),
            ("BOX",           (0, 0), (-1, -1), 0.5, C_BORDER),
            ("INNERGRID",     (0, 0), (-1, -1), 0.3, C_BORDER),
        ]
        for i in range(5):
            dash_style.append(("TEXTCOLOR",  (i, 0), (i, 0), C_MUTED))
            dash_style.append(("TEXTCOLOR",  (i, 1), (i, 1), dash_fg[i]))
            dash_style.append(("BACKGROUND", (i, 0), (i, -1), dash_bg[i]))
        dash_t.setStyle(TableStyle(dash_style))
        story.append(dash_t)
        story.append(Spacer(1, 0.6 * cm))

        if total == 0:
            ok_t = Table(
                [["✓  No vulnerabilities detected in this scan pass."]],
                colWidths=[W_CONTENT]
            )
            ok_t.setStyle(TableStyle([
                ("FONTNAME",      (0, 0), (-1, -1), "Helvetica-Bold"),
                ("FONTSIZE",      (0, 0), (-1, -1), 10),
                ("TEXTCOLOR",     (0, 0), (-1, -1), SEV_FG["Clean"]),
                ("BACKGROUND",    (0, 0), (-1, -1), SEV_BG["Clean"]),
                ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
                ("TOPPADDING",    (0, 0), (-1, -1), 14),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
                ("BOX",           (0, 0), (-1, -1), 0.8, SEV_FG["Clean"]),
            ]))
            story.append(ok_t)

        # ══════════════════════════════════════════════════════
        # VULNERABILITY SUMMARY TABLE
        # ══════════════════════════════════════════════════════
        if total > 0:
            story.append(Paragraph("Vulnerability Summary", S_SECTION))
            story.append(HRFlowable(width="100%", thickness=1,
                                    color=C_BORDER, spaceAfter=8))

            # Column widths: #, vulnerability, severity, param, techniques
            col_w_sum = [0.6*cm, 5.0*cm, 2.0*cm, 3.0*cm,
                         W_CONTENT - 0.6 - 5.0 - 2.0 - 3.0]
            sum_header = ["#", "VULNERABILITY", "SEVERITY", "PARAMETER", "TECHNIQUES"]
            sum_rows   = [sum_header]
            sum_style  = [
                ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",      (0, 0), (-1, 0), 7),
                ("TEXTCOLOR",     (0, 0), (-1, 0), C_MUTED),
                ("BACKGROUND",    (0, 0), (-1, 0), C_LIGHT),
                ("FONTSIZE",      (0, 1), (-1, -1), 8),
                ("TEXTCOLOR",     (0, 1), (-1, -1), C_TEXT),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_NEAR_W]),
                ("TOPPADDING",    (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING",   (0, 0), (-1, -1), 5),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
                ("ALIGN",         (0, 0), (0, -1), "CENTER"),
                ("LINEBELOW",     (0, 0), (-1, 0), 0.5, C_BORDER),
                ("INNERGRID",     (0, 1), (-1, -1), 0.2, C_BORDER),
                ("BOX",           (0, 0), (-1, -1), 0.5, C_BORDER),
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ]
            for i, row in enumerate(analysis.get("summary_table", []), start=1):
                fg = sev_fg(row["severity"])
                sum_rows.append([
                    str(row["id"]),
                    row["vulnerability"],
                    row["severity"],
                    row["param"],
                    row["techniques"],
                ])
                sum_style.append(("TEXTCOLOR", (2, i), (2, i), fg))
                sum_style.append(("FONTNAME",  (2, i), (2, i), "Helvetica-Bold"))
                sum_style.append(("BACKGROUND",(2, i), (2, i), sev_bg(row["severity"])))

            sum_t = Table(sum_rows, colWidths=col_w_sum)
            sum_t.setStyle(TableStyle(sum_style))
            story.append(sum_t)

            # ══════════════════════════════════════════════════
            # DETAILED FINDINGS
            # ══════════════════════════════════════════════════
            story.append(PageBreak())
            story.append(Paragraph("Detailed Findings", S_SECTION))
            story.append(HRFlowable(width="100%", thickness=1,
                                    color=C_BORDER, spaceAfter=12))

            for f in findings:
                fg_col = sev_fg(f["severity_label"])
                bg_col = sev_bg(f["severity_label"])

                # Header row: finding title + severity badge
                hdr = Table(
                    [[
                        Paragraph(
                            f"<b>#{f['id']}  {f['vulnerability']}</b>",
                            _ps("fhdr", fontSize=10, fontName="Helvetica-Bold",
                                textColor=C_TEXT)
                        ),
                        Paragraph(
                            f"<b>{f['severity_label'].upper()}</b>",
                            _ps("sev_p", fontSize=9, fontName="Helvetica-Bold",
                                textColor=fg_col, alignment=TA_CENTER)
                        ),
                    ]],
                    colWidths=[W_CONTENT - 2.5 * cm, 2.5 * cm]
                )
                hdr.setStyle(TableStyle([
                    ("BACKGROUND",    (0, 0), (0, 0), C_LIGHT),
                    ("BACKGROUND",    (1, 0), (1, 0), bg_col),
                    ("TOPPADDING",    (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
                    ("BOX",           (0, 0), (-1, -1), 0.8, fg_col),
                    ("LINEBEFORE",    (0, 0), (0, 0), 3, fg_col),
                    ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
                ]))

                # Evidence
                ev = ""
                for fd in f.get("findings_detail", [])[:1]:
                    ev = str(fd.get("evidence", ""))[:120]

                # Detail table
                detail_data = [
                    ["URL",         f["url"][:80] + ("…" if len(f["url"]) > 80 else "")],
                    ["Parameter",   f["param"]],
                    ["OWASP Ref",   f.get("owasp_ref", "N/A")],
                    ["CWE",         f.get("cwe", "N/A")],
                    ["Techniques",  ", ".join(f.get("techniques", []))],
                ]
                if ev:
                    detail_data.append(["Evidence", ev])

                det_t = Table(
                    detail_data,
                    colWidths=[2.5 * cm, W_CONTENT - 2.5 * cm]
                )
                det_style = [
                    ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE",      (0, 0), (-1, -1), 8),
                    ("TEXTCOLOR",     (0, 0), (0, -1), C_MUTED),
                    ("TEXTCOLOR",     (1, 0), (1, -1), C_TEXT),
                    ("ROWBACKGROUNDS",(0, 0), (-1, -1), [C_WHITE, C_NEAR_W]),
                    ("TOPPADDING",    (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
                    ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                    ("LINEBELOW",     (0, 0), (-1, -2), 0.2, C_BORDER),
                    ("BOX",           (0, 0), (-1, -1), 0.4, C_BORDER),
                ]
                if ev:
                    det_style += [
                        ("TEXTCOLOR",  (1, -1), (1, -1), HexColor("#996600")),
                        ("FONTNAME",   (1, -1), (1, -1), "Courier"),
                        ("FONTSIZE",   (1, -1), (1, -1), 7),
                        ("BACKGROUND", (0, -1), (-1, -1), HexColor("#fffbee")),
                    ]
                det_t.setStyle(TableStyle(det_style))

                # Description paragraph
                desc_p = Paragraph(
                    f.get("description", ""),
                    _ps("desc", fontSize=8, textColor=C_DIM, leading=13, spaceAfter=4)
                ) if f.get("description") else Spacer(1, 0.1 * cm)

                # Remediation steps
                rem_items = [
                    Paragraph(
                        f"• {step}",
                        _ps("rem", fontSize=8, textColor=C_DIM, leading=13)
                    )
                    for step in f.get("remediation_steps", [])
                ]

                # Code examples
                code_items = []
                if f.get("code_bad"):
                    code_items.append(Paragraph(
                        "⚠ Vulnerable Pattern:",
                        _ps("cl_bad", fontSize=7, fontName="Helvetica-Bold",
                            textColor=HexColor("#aa2222"), spaceAfter=2)
                    ))
                    code_items.append(Paragraph(
                        f.get("code_bad", "").replace("\n", "<br/>"),
                        S_MONO_BAD
                    ))
                if f.get("code_good"):
                    code_items.append(Paragraph(
                        "✓ Secure Pattern:",
                        _ps("cl_good", fontSize=7, fontName="Helvetica-Bold",
                            textColor=HexColor("#117733"), spaceAfter=2)
                    ))
                    code_items.append(Paragraph(
                        f.get("code_good", "").replace("\n", "<br/>"),
                        S_MONO_GOOD
                    ))

                story.append(KeepTogether(
                    [hdr, Spacer(1, 0.1 * cm), det_t, Spacer(1, 0.15 * cm)]
                ))
                story.append(desc_p)
                if rem_items:
                    story.append(Paragraph(
                        "Remediation Steps:",
                        _ps("rem_hdr", fontSize=8, fontName="Helvetica-Bold",
                            textColor=C_TEXT, spaceBefore=6, spaceAfter=3)
                    ))
                    story.extend(rem_items)
                story.extend(code_items)
                story.append(Spacer(1, 0.25 * cm))
                story.append(HRFlowable(
                    width="100%", thickness=0.3, color=C_BORDER, spaceAfter=0.25 * cm
                ))

        # ══════════════════════════════════════════════════════
        # RECOMMENDATIONS
        # ══════════════════════════════════════════════════════
        story.append(Paragraph("Recommendations", S_SECTION))
        story.append(HRFlowable(width="100%", thickness=1,
                                color=C_BORDER, spaceAfter=10))

        for i, rec in enumerate(recs):
            # First two recommendations get accent colours
            accent = (SEV_FG["Critical"] if i == 0 and "CRITICAL" in rec
                      else SEV_FG["High"] if i == 1
                      else C_ACCENT)
            rec_t = Table(
                [[f"  {i+1}", f"  {rec}"]],
                colWidths=[0.7 * cm, W_CONTENT - 0.7 * cm]
            )
            rec_t.setStyle(TableStyle([
                ("FONTSIZE",      (0, 0), (-1, -1), 8),
                ("TEXTCOLOR",     (0, 0), (0, 0), accent),
                ("FONTNAME",      (0, 0), (0, 0), "Helvetica-Bold"),
                ("TEXTCOLOR",     (1, 0), (1, 0), C_TEXT),
                ("BACKGROUND",    (0, 0), (-1, -1), C_NEAR_W),
                ("TOPPADDING",    (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("LEFTPADDING",   (0, 0), (-1, -1), 6),
                ("LINEBEFORE",    (0, 0), (0, 0), 3, accent),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                ("BOX",           (0, 0), (-1, -1), 0.3, C_BORDER),
            ]))
            story.append(rec_t)
            story.append(Spacer(1, 0.1 * cm))

        # ── Build ─────────────────────────────────────────────
        doc.build(story,
                  onFirstPage=_draw_footer,
                  onLaterPages=_draw_footer)
        logger.info("[ReportGenerator] PDF report → %s", path)
        return path