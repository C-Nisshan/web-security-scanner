"""
xss_detector.py — Cross-Site Scripting Detector
================================================
Context-aware XSS detection.  For each payload the detector:
  1. Injects it into the target parameter via GET or POST
  2. Checks whether the payload appears unencoded in the response
  3. Identifies the injection context (HTML body, attribute, script block)
  4. Tries encoding-bypass variants when the baseline is filtered

Changes from v2
---------------
- Added _post_form() helper for HTTP POST requests.
- Added detect_form(url, param, method, base_inputs) so the controller
  can test HTML form fields (both GET and POST).
- _build_result() extracted as shared helper.

Layer : Processing Layer
"""

import re
import logging
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests

logger = logging.getLogger("xss_detector")

# ─────────────────────────────────────────────────────────────
# Payload library
# ─────────────────────────────────────────────────────────────

HTML_BODY_PAYLOADS: List[Dict] = [
    {"payload": "<script>alert(1)</script>",           "context": "script_tag"},
    {"payload": "<img src=x onerror=alert(1)>",        "context": "event_handler"},
    {"payload": "<svg onload=alert(1)>",               "context": "svg"},
    {"payload": "<details open ontoggle=alert(1)>",    "context": "event_handler"},
    {"payload": "<body onload=alert(1)>",              "context": "event_handler"},
    {"payload": "<input onfocus=alert(1) autofocus>",  "context": "event_handler"},
]

ATTR_BREAK_PAYLOADS: List[Dict] = [
    {"payload": "\" onmouseover=\"alert(1)",           "context": "attr_double_quote"},
    {"payload": "' onmouseover='alert(1)",             "context": "attr_single_quote"},
    {"payload": "\"><script>alert(1)</script>",        "context": "attr_escape"},
    {"payload": "'><script>alert(1)</script>",         "context": "attr_escape"},
    {"payload": "\" autofocus onfocus=\"alert(1)",     "context": "attr_focus"},
]

SCRIPT_BREAK_PAYLOADS: List[Dict] = [
    {"payload": "'-alert(1)-'",                        "context": "script_string"},
    {"payload": "\"-alert(1)-\"",                      "context": "script_string"},
    {"payload": "</script><script>alert(1)</script>",  "context": "script_close"},
    {"payload": "${alert(1)}",                         "context": "template_literal"},
]

BYPASS_PAYLOADS: List[Dict] = [
    {"payload": "<ScRiPt>alert(1)</ScRiPt>",           "context": "case_bypass"},
    {"payload": "<img src=x OnErRoR=alert(1)>",        "context": "case_bypass"},
    {"payload": "<svg/onload=alert(1)>",               "context": "whitespace_bypass"},
    {"payload": "javascript:alert(1)",                 "context": "protocol_bypass"},
    {"payload": "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;", "context": "html_entity"},
    {"payload": "{{constructor.constructor('alert(1)')()}}", "context": "template_injection"},
]

ALL_PAYLOADS = (
    HTML_BODY_PAYLOADS
    + ATTR_BREAK_PAYLOADS
    + SCRIPT_BREAK_PAYLOADS
    + BYPASS_PAYLOADS
)

DANGER_PATTERNS: List[re.Pattern] = [
    re.compile(r"<script[^>]*>.*?alert\s*\(", re.IGNORECASE | re.DOTALL),
    re.compile(r"on\w+\s*=\s*['\"]?alert\s*\(",  re.IGNORECASE),
    re.compile(r"<svg[^>]*onload\s*=",         re.IGNORECASE),
    re.compile(r"javascript\s*:\s*alert",      re.IGNORECASE),
]

ENCODED_INDICATORS = ("&lt;", "&gt;", "&amp;", "&#", "%3C", "%3E")

_ENCODE_CHECK_WINDOW = 60


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
    idx = body.find(payload)
    if idx == -1:
        idx = body.lower().find(payload.lower())
    if idx == -1:
        return False
    start   = max(0, idx - _ENCODE_CHECK_WINDOW)
    end     = min(len(body), idx + len(payload) + _ENCODE_CHECK_WINDOW)
    snippet = body[start:end]
    return any(ind.lower() in snippet.lower() for ind in ENCODED_INDICATORS)


def _find_context(body: str, payload: str) -> str:
    idx = body.lower().find(payload.lower())
    if idx == -1:
        return "unknown"
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


def _analyse_response(body: str, payload: str, item: Dict) -> Optional[Dict]:
    """
    Shared reflection/encoding/context analysis used by both GET
    and POST scanning paths.  Returns a finding dict or None.
    """
    reflected = payload in body or payload.lower() in body.lower()
    if not reflected:
        return None
    if _is_encoded(body, payload):
        return None

    is_executable = any(p.search(body) for p in DANGER_PATTERNS)
    severity      = "high" if is_executable else "medium"
    context       = _find_context(body, payload)
    evidence      = _extract_evidence(body, payload)

    return {
        "technique"   : "reflected_xss",
        "payload"     : payload,
        "context"     : item["context"],
        "html_context": context,
        "executable"  : is_executable,
        "evidence"    : evidence,
        "severity"    : severity,
    }


def _build_result(url: str, param: str, findings: List[Dict]) -> Dict:
    confirmed        = len(findings) > 0
    executable_count = sum(1 for f in findings if f["executable"])
    severities       = [f["severity"] for f in findings]
    highest          = (
        "high"   if "high"   in severities else
        "medium" if "medium" in severities else
        "low"    if severities else "none"
    )
    return {
        "url"              : url,
        "param"            : param,
        "vulnerability"    : "Cross-Site Scripting (XSS)",
        "findings"         : findings,
        "confirmed"        : confirmed,
        "technique_summary": ["reflected_xss"] if confirmed else [],
        "highest_severity" : highest,
        "executable_count" : executable_count,
        "total_hits"       : len(findings),
    }


# ─────────────────────────────────────────────────────────────
# XSSDetector
# ─────────────────────────────────────────────────────────────

class XSSDetector:
    """
    Context-aware cross-site scripting detector with GET and POST support.

    Parameters
    ----------
    timeout    : per-request HTTP timeout (seconds)
    user_agent : User-Agent header value
    session    : optional pre-configured requests.Session
    """

    def __init__(
        self,
        timeout:    int                        = 8,
        user_agent: str                        = "AegisSecurity/1.0 Web Application Assessment",
        session:    Optional[requests.Session] = None,
    ):
        self.timeout = timeout
        if session is not None:
            self._session = session
        else:
            self._session = requests.Session()
            self._session.headers.update({"User-Agent": user_agent})

    # ── HTTP helpers ──────────────────────────────────────────

    def _get(self, url: str) -> Optional[requests.Response]:
        try:
            return self._session.get(
                url, timeout=self.timeout,
                allow_redirects=True, verify=False,
            )
        except requests.exceptions.RequestException:
            return None

    def _post_form(self, url: str, data: Dict[str, str]) -> Optional[requests.Response]:
        """Send a POST application/x-www-form-urlencoded request."""
        try:
            return self._session.post(
                url, data=data, timeout=self.timeout,
                allow_redirects=True, verify=False,
            )
        except requests.exceptions.RequestException:
            return None

    # ── GET param payload test ────────────────────────────────

    def _test_payload_get(self, url: str, param: str, item: Dict) -> Optional[Dict]:
        payload  = item["payload"]
        injected = _inject_param(url, param, payload)
        resp     = self._get(injected)
        if resp is None:
            return None
        result = _analyse_response(resp.text, payload, item)
        if result:
            result["injected_url"] = injected
            result["status_code"]  = resp.status_code
            logger.warning("[XSS-GET] param=%s context=%s executable=%s",
                           param, result["html_context"], result["executable"])
        return result

    # ── POST form payload test ────────────────────────────────

    def _test_payload_form(
        self, url: str, param: str, item: Dict,
        method: str, base_inputs: Dict[str, str]
    ) -> Optional[Dict]:
        payload = item["payload"]
        data    = {**base_inputs, param: payload}

        if method == "POST":
            resp = self._post_form(url, data)
        else:
            resp = self._get(_inject_param(url, param, payload))

        if resp is None:
            return None
        result = _analyse_response(resp.text, payload, item)
        if result:
            result["injected_url"] = url
            result["status_code"]  = resp.status_code
            logger.warning("[XSS-FORM] url=%s param=%s context=%s executable=%s",
                           url, param, result["html_context"], result["executable"])
        return result

    # ── public API — URL param detection ─────────────────────

    def detect(self, url: str, param: str) -> Dict:
        """Run the full XSS payload suite against *url* / *param* (GET)."""
        logger.info("[XSSDetector] URL param test %s  param=%s", url, param)

        findings:      List[Dict] = []
        seen_contexts: set        = set()

        for item in ALL_PAYLOADS:
            result = self._test_payload_get(url, param, item)
            if result and result["context"] not in seen_contexts:
                seen_contexts.add(result["context"])
                findings.append(result)

        return _build_result(url, param, findings)

    # ── public API — Form field detection  ← NEW ─────────────

    def detect_form(
        self,
        url:         str,
        param:       str,
        method:      str           = "POST",
        base_inputs: Optional[Dict[str, str]] = None,
    ) -> Dict:
        """
        Test a single form field for reflected XSS.

        Parameters
        ----------
        url         : form action URL
        param       : field name to inject payloads into
        method      : "POST" or "GET"
        base_inputs : all other form fields with their default values
        """
        logger.info("[XSSDetector] Form test %s  param=%s  method=%s",
                    url, param, method)
        base = dict(base_inputs or {})
        if param not in base:
            base[param] = "test"

        findings:      List[Dict] = []
        seen_contexts: set        = set()

        for item in ALL_PAYLOADS:
            result = self._test_payload_form(url, param, item, method, base)
            if result and result["context"] not in seen_contexts:
                seen_contexts.add(result["context"])
                findings.append(result)

        return _build_result(url, param, findings)