"""
scanner/ai_advisor.py — AI-Powered Security Advisor  v1.0
==========================================================
Generates prioritised, context-aware security recommendations
from confirmed scan findings.

Two modes
---------
  AI mode   — Uses Google Gemini 1.5 Flash when GEMINI_API_KEY is set
              in the environment (or .env file). Produces recommendations
              tailored to the exact vulnerabilities, parameters, and URLs
              discovered in the scan.

  Rule mode — Built-in rule-based advisor used when no API key is
              configured, or when the Gemini call fails. Covers all
              vulnerability types the scanner can detect.

Configuration
-------------
  Set GEMINI_API_KEY in your .env file (see .env.example).
  No code changes are needed — the module detects the key automatically.

Layer : Analysis Layer
"""

import os
import re
import logging
from typing import Dict, List, Optional

logger = logging.getLogger("ai_advisor")


# ─────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────

def generate_recommendations(
    findings: List[Dict],
    scan_meta: Optional[Dict] = None,
) -> List[str]:
    """
    Return a prioritised list of security recommendation strings.

    Tries Gemini first if GEMINI_API_KEY is available; falls back
    to the rule-based advisor on any error.

    Parameters
    ----------
    findings  : enriched finding dicts from ResponseAnalyzer
    scan_meta : optional scan metadata dict (target_url, scan_date, …)
    """
    scan_meta = scan_meta or {}
    api_key   = os.getenv("GEMINI_API_KEY", "").strip()

    if api_key:
        logger.info("[AIAdvisor] GEMINI_API_KEY found — using Gemini 1.5 Flash")
        try:
            return _gemini_recommendations(findings, scan_meta, api_key)
        except Exception as exc:
            logger.warning(
                "[AIAdvisor] Gemini call failed (%s) — falling back to rule-based advisor",
                exc,
            )

    logger.info("[AIAdvisor] Using rule-based advisor")
    return _rule_based_recommendations(findings)


# ─────────────────────────────────────────────────────────────
# Gemini advisor
# ─────────────────────────────────────────────────────────────

def _build_prompt(findings: List[Dict], scan_meta: Dict) -> str:
    target   = scan_meta.get("target_url", "Unknown target")
    duration = scan_meta.get("duration",   "N/A")
    pages    = scan_meta.get("pages_crawled", "N/A")

    if findings:
        finding_lines = "\n".join(
            f"  [{f['severity_label'].upper()}] {f['vulnerability']} "
            f"— parameter: '{f['param']}' — URL: {f['url']}"
            for f in findings[:12]          # cap at 12 to stay within token budget
        )
    else:
        finding_lines = "  No vulnerabilities confirmed."

    return f"""You are a senior application security consultant writing the
recommendations section of a professional penetration-test report.

Scan context
------------
Target     : {target}
Pages crawled: {pages}
Duration   : {duration}
Confirmed findings:
{finding_lines}

Task
----
Write 7 to 9 specific, actionable security recommendations.
Rules:
- Order from highest to lowest urgency.
- Each recommendation must be one or two sentences.
- Reference the exact vulnerability type and (where relevant) the
  specific parameter or endpoint that was affected.
- Avoid generic filler advice ("keep software up to date") unless
  it directly relates to a confirmed finding.
- Do not number the items — return one recommendation per line,
  separated by a blank line.
- Do not include any heading, preamble, or closing remarks.
- Write in a formal, professional register suitable for a client report.
"""


def _gemini_recommendations(
    findings: List[Dict],
    scan_meta: Dict,
    api_key: str,
) -> List[str]:
    try:
        import google.generativeai as genai          # type: ignore
    except ImportError:
        raise RuntimeError(
            "google-generativeai is not installed. "
            "Add it to requirements.txt: google-generativeai>=0.7"
        )

    genai.configure(api_key=api_key)
    model    = genai.GenerativeModel("gemini-1.5-flash")
    prompt   = _build_prompt(findings, scan_meta)

    config = {
        "temperature"      : 0.3,     # low temp → consistent, professional output
        "top_p"            : 0.85,
        "max_output_tokens": 1024,
    }
    response = model.generate_content(prompt, generation_config=config)
    raw_text = (response.text or "").strip()

    if not raw_text:
        raise ValueError("Gemini returned an empty response")

    # Parse: split on blank lines, strip leading bullets / numbering
    paragraphs = [p.strip() for p in re.split(r"\n{2,}", raw_text) if p.strip()]
    recs: List[str] = []
    for para in paragraphs:
        # collapse internal newlines into spaces
        line = re.sub(r"\s+", " ", para)
        # strip leading numbers / bullets (e.g. "1. ", "• ", "- ")
        line = re.sub(r"^[\d]+[\.\)]\s*|^[-•*]\s*", "", line).strip()
        if len(line) > 20:
            recs.append(line)

    if not recs:
        raise ValueError("Could not parse any recommendations from Gemini response")

    logger.info("[AIAdvisor] Gemini returned %d recommendations", len(recs))
    return recs


# ─────────────────────────────────────────────────────────────
# Rule-based advisor (fallback)
# ─────────────────────────────────────────────────────────────

# Per-vulnerability remediation advice
_VULN_RECS: Dict[str, List[str]] = {
    "SQL Injection": [
        (
            "CRITICAL — Replace all string-concatenated database queries with "
            "parameterised statements or a trusted ORM (e.g. SQLAlchemy, Django ORM); "
            "this is the single highest-impact remediation available."
        ),
        (
            "Enforce a least-privilege database account for the application — "
            "the runtime user must not hold DDL, DROP, or administrative privileges."
        ),
        (
            "Deploy a Web Application Firewall (WAF) rule-set for SQL injection patterns "
            "as a defence-in-depth layer while parameterisation work is completed."
        ),
    ],
    "Cross-Site Scripting (XSS)": [
        (
            "HIGH — Apply context-aware output encoding (html.escape() in Python, "
            "or framework auto-escaping) to every user-controlled value before it is "
            "rendered in an HTML, attribute, JavaScript, or URL context."
        ),
        (
            "Implement a strict Content Security Policy (CSP) header that disallows "
            "inline scripts and restricts executable sources to your own origin; "
            "this eliminates the impact of any residual reflected-XSS surface."
        ),
        (
            "Set the HttpOnly and Secure flags on all session cookies to prevent "
            "JavaScript access and transmission over plain HTTP respectively."
        ),
    ],
}

# Generic recommendations appended after vulnerability-specific ones
_GENERIC_RECS: List[str] = [
    (
        "Integrate a Static Application Security Testing (SAST) tool "
        "(e.g. Semgrep, Bandit) into the CI/CD pipeline so injection-prone "
        "patterns are caught before code reaches production."
    ),
    (
        "Conduct a focused manual code review of every input-handling routine, "
        "paying particular attention to the parameters identified in this report."
    ),
    (
        "Schedule recurring automated scans against a staging environment after "
        "each release to detect security regressions before they reach production."
    ),
    (
        "Provide developers with targeted secure-coding training covering "
        "OWASP Top 10 A03:2021 (Injection), including hands-on exercises "
        "with the affected language and framework."
    ),
    (
        "Review and harden HTTP security headers across the application: "
        "X-Content-Type-Options, X-Frame-Options, Referrer-Policy, and "
        "Permissions-Policy are low-effort, high-value additions."
    ),
]


def _rule_based_recommendations(findings: List[Dict]) -> List[str]:
    """
    Build a prioritised, de-duplicated recommendation list from confirmed findings.
    """
    vuln_types = {f["vulnerability"] for f in findings}

    # Severity-ordered vuln types so the most severe lead
    priority_order = ["SQL Injection", "Cross-Site Scripting (XSS)"]
    ordered_types  = [v for v in priority_order if v in vuln_types] + \
                     [v for v in vuln_types if v not in priority_order]

    recs: List[str] = []
    seen: set       = set()

    for vtype in ordered_types:
        for rec in _VULN_RECS.get(vtype, []):
            if rec not in seen:
                recs.append(rec)
                seen.add(rec)

    # Always append generic hygiene recommendations
    for rec in _GENERIC_RECS:
        if rec not in seen:
            recs.append(rec)
            seen.add(rec)

    return recs