"""
response_analyzer.py — Response Analysis & Finding Aggregation
==============================================================
Takes raw results produced by SQLiDetector and XSSDetector,
de-duplicates them, assigns CVSS-inspired severity scores,
adds OWASP references, and appends actionable remediation
guidance for each finding type.

Layer : Analysis Layer
"""

import logging
from typing import Dict, List

logger = logging.getLogger("response_analyzer")

# ─────────────────────────────────────────────────────────────
# Remediation knowledge base
# ─────────────────────────────────────────────────────────────

REMEDIATIONS: Dict[str, Dict] = {
    "SQL Injection": {
        "owasp_ref"  : "OWASP A03:2021 – Injection",
        "owasp_url"  : "https://owasp.org/Top10/A03_2021-Injection/",
        "cwe"        : "CWE-89",
        "description": (
            "SQL Injection allows attackers to interfere with database queries, "
            "potentially exposing, modifying, or deleting data, and in some cases "
            "executing operating-system commands."
        ),
        "steps": [
            "Use parameterised queries / prepared statements for ALL database interactions.",
            "Employ an ORM (e.g. SQLAlchemy, Django ORM) that handles escaping by default.",
            "Apply an allowlist-based input validation strategy — reject unexpected characters.",
            "Enforce least-privilege database accounts; application users should not have "
            "DDL or admin permissions.",
            "Enable a Web Application Firewall (WAF) as a defence-in-depth layer.",
            "Regularly audit stored procedures and dynamic SQL for injection-prone patterns.",
        ],
        "code_bad": (
            '# VULNERABLE — string concatenation\n'
            'query = "SELECT * FROM users WHERE id = " + user_input\n'
            'cursor.execute(query)'
        ),
        "code_good": (
            '# SAFE — parameterised query\n'
            'query = "SELECT * FROM users WHERE id = %s"\n'
            'cursor.execute(query, (user_input,))'
        ),
    },
    "Cross-Site Scripting (XSS)": {
        "owasp_ref"  : "OWASP A03:2021 – Injection",
        "owasp_url"  : "https://owasp.org/Top10/A03_2021-Injection/",
        "cwe"        : "CWE-79",
        "description": (
            "XSS allows attackers to inject malicious scripts into pages viewed by other "
            "users, enabling session hijacking, credential theft, and defacement."
        ),
        "steps": [
            "HTML-encode all user-supplied output before rendering it in HTML context "
            "(use html.escape() in Python, or your framework's auto-escaping).",
            "Use a Content Security Policy (CSP) header to restrict executable script sources.",
            "Validate and sanitise input on the server side — reject unexpected HTML tags.",
            "Avoid inserting untrusted data into JavaScript, CSS, or URL contexts without "
            "context-appropriate encoding.",
            "Use the HttpOnly and Secure flags on session cookies to limit impact.",
            "Consider a sanitisation library (e.g. bleach) for rich-text fields.",
        ],
        "code_bad": (
            '# VULNERABLE — raw user input in template\n'
            'return f"<h1>Hello {request.args[\'name\']}</h1>"'
        ),
        "code_good": (
            '# SAFE — HTML-escaped output\n'
            'import html\n'
            'safe = html.escape(request.args["name"])\n'
            'return f"<h1>Hello {safe}</h1>"'
        ),
    },
}

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}

SEVERITY_LABELS = {
    "critical": "Critical",
    "high"    : "High",
    "medium"  : "Medium",
    "low"     : "Low",
    "none"    : "Informational",
}

CVSS_SCORES = {
    "critical": "9.0 – 10.0",
    "high"    : "7.0 – 8.9",
    "medium"  : "4.0 – 6.9",
    "low"     : "0.1 – 3.9",
    "none"    : "0.0",
}


# ─────────────────────────────────────────────────────────────
# ResponseAnalyzer
# ─────────────────────────────────────────────────────────────

class ResponseAnalyzer:
    """
    Aggregates raw detector results into a structured findings report.

    Usage
    -----
    analyzer = ResponseAnalyzer()
    report   = analyzer.analyze(sqli_results, xss_results)
    """

    def analyze(
        self,
        sqli_results: List[Dict],
        xss_results:  List[Dict],
    ) -> Dict:
        """
        Merge, de-duplicate, enrich, and rank all findings.

        Parameters
        ----------
        sqli_results : list of dicts returned by SQLiDetector.detect()
        xss_results  : list of dicts returned by XSSDetector.detect()

        Returns
        -------
        dict with keys:
            total_findings, critical_count, high_count, medium_count,
            low_count, overall_risk, findings (enriched list),
            summary_table, recommendations
        """
        enriched: List[Dict] = []

        for raw in sqli_results + xss_results:
            if not raw.get("confirmed"):
                continue

            vuln_type = raw["vulnerability"]
            kb        = REMEDIATIONS.get(vuln_type, {})
            severity  = raw.get("highest_severity", "low")

            enriched.append({
                "id"            : len(enriched) + 1,
                "vulnerability" : vuln_type,
                "severity"      : severity,
                "severity_label": SEVERITY_LABELS.get(severity, severity.title()),
                "cvss_range"    : CVSS_SCORES.get(severity, "N/A"),
                "url"           : raw["url"],
                "param"         : raw["param"],
                "techniques"    : raw.get("technique_summary", []),
                "total_hits"    : raw.get("total_hits", 0),
                "findings_detail": raw.get("findings", []),
                "owasp_ref"     : kb.get("owasp_ref", ""),
                "owasp_url"     : kb.get("owasp_url", ""),
                "cwe"           : kb.get("cwe", ""),
                "description"   : kb.get("description", ""),
                "remediation_steps": kb.get("steps", []),
                "code_bad"      : kb.get("code_bad", ""),
                "code_good"     : kb.get("code_good", ""),
            })

        enriched.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 0), reverse=True)

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in enriched:
            sev = f["severity"]
            if sev in counts:
                counts[sev] += 1

        overall_risk = (
            "Critical" if counts["critical"] > 0 else
            "High"     if counts["high"]     > 0 else
            "Medium"   if counts["medium"]   > 0 else
            "Low"      if counts["low"]      > 0 else
            "Clean"
        )

        summary_table = [
            {
                "id"           : f["id"],
                "vulnerability": f["vulnerability"],
                "severity"     : f["severity_label"],
                "url"          : f["url"],
                "param"        : f["param"],
                "techniques"   : ", ".join(f["techniques"]),
            }
            for f in enriched
        ]

        recommendations = _build_recommendations(enriched)

        logger.info(
            "[Analyzer] findings=%d  critical=%d  high=%d  medium=%d  low=%d  risk=%s",
            len(enriched), counts["critical"], counts["high"],
            counts["medium"], counts["low"], overall_risk
        )

        return {
            "total_findings" : len(enriched),
            "critical_count" : counts["critical"],
            "high_count"     : counts["high"],
            "medium_count"   : counts["medium"],
            "low_count"      : counts["low"],
            "overall_risk"   : overall_risk,
            "findings"       : enriched,
            "summary_table"  : summary_table,
            "recommendations": recommendations,
        }


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _build_recommendations(findings: List[Dict]) -> List[str]:
    """
    Produce a prioritised, de-duplicated list of top-level
    recommendations based on the confirmed finding types.
    """
    types_found = {f["vulnerability"] for f in findings}
    recs: List[str] = []

    if "SQL Injection" in types_found:
        recs.append(
            "CRITICAL: Migrate all database queries to parameterised statements "
            "or a trusted ORM immediately."
        )
    if "Cross-Site Scripting (XSS)" in types_found:
        recs.append(
            "HIGH: Implement output encoding for all user-controlled values "
            "and deploy a Content Security Policy header."
        )

    recs += [
        "Conduct a full manual code review of all input-handling routines.",
        "Integrate a Static Application Security Testing (SAST) tool into your CI/CD pipeline.",
        "Schedule regular automated scans to catch regressions after each release.",
        "Train development staff on OWASP Top 10 and secure coding practices.",
    ]
    return recs