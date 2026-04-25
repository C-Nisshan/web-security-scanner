"""
sqli_detector.py — SQL Injection Detector
==========================================
Advanced SQL injection detection using three techniques:
  1. Error-based  — database error strings in the response body
  2. Boolean-based — response-length difference on true vs false conditions
  3. Time-based   — measured response delay with SLEEP/WAITFOR payloads

Changes from v2
---------------
- Added _post_form() helper for HTTP POST requests.
- Added detect_form(url, param, method, base_inputs) so the controller
  can test HTML form fields (both GET and POST) in addition to URL params.
- _build_result() extracted as shared helper to avoid code duplication
  between detect() and detect_form().

Layer : Processing Layer
"""

import time
import logging
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests

logger = logging.getLogger("sqli_detector")

# ─────────────────────────────────────────────────────────────
# Payload sets
# ─────────────────────────────────────────────────────────────

ERROR_PAYLOADS: List[str] = [
    "'",
    "''",
    "\"",
    "\\",
    "1'",
    "1\"",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1 --",
    "' OR 1=1#",
    "\" OR \"1\"=\"1",
    "'; SELECT 1 --",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION())) --",
    "' || '1'='1",
    "a' OR 'a'='a",
]

BOOLEAN_PAYLOAD_PAIRS: List[Tuple[str, str]] = [
    ("1 AND 1=1",        "1 AND 1=2"),
    ("1' AND '1'='1",    "1' AND '1'='2"),
    ("1 AND 2>1",        "1 AND 2<1"),
    ("' OR 'x'='x",     "' OR 'x'='y"),
]

TIME_PAYLOADS: List[Dict] = [
    {"payload": "'; WAITFOR DELAY '0:0:5' --", "db": "mssql", "delay": 5},
    {"payload": "' OR SLEEP(5) --",             "db": "mysql", "delay": 5},
    {"payload": "1; SELECT pg_sleep(5) --",     "db": "pgsql", "delay": 5},
    {"payload": "' OR 1=1; WAITFOR DELAY '0:0:5' --", "db": "mssql", "delay": 5},
    {"payload": "1 AND SLEEP(5)",               "db": "mysql", "delay": 5},
]

ERROR_SIGNATURES: List[str] = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "mysql_num_rows",
    "mysql_query",
    "supplied argument is not a valid mysql",
    "pg_query()",
    "pg_exec()",
    "postgresql query failed",
    "pgsql error",
    "pg_result",
    "sqlite error",
    "sqlite3.operationalerror",
    "sqlite_master",
    "microsoft ole db provider for sql server",
    "microsoft odbc sql server driver",
    "[sql server]",
    "unclosed quotation mark after the character string",
    "incorrect syntax near",
    "mssql_query()",
    "oracle error",
    "ora-",
    "oracle odbc",
    "quoted string not properly terminated",
    "sql syntax",
    "database error",
    "db error",
    "sqlexception",
    "invalid query",
    "unterminated string",
    "syntax error",
    "unexpected end of sql command",
]

BOOLEAN_LENGTH_THRESHOLD = 0.20
TIME_THRESHOLD_FACTOR    = 0.85


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _inject_param(url: str, param: str, value: str) -> str:
    parsed    = urlparse(url)
    qs        = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _has_error_sig(body: str) -> Tuple[bool, str]:
    lower = body.lower()
    for sig in ERROR_SIGNATURES:
        if sig.lower() in lower:
            return True, sig
    return False, ""


def _highest_severity(severities: List[str]) -> str:
    if "critical" in severities: return "critical"
    if "high"     in severities: return "high"
    if "medium"   in severities: return "medium"
    if "low"      in severities: return "low"
    return "none"


def _build_result(url: str, param: str, all_findings: List[Dict]) -> Dict:
    """Deduplicate findings per technique and build the standard result dict."""
    seen, unique = set(), []
    for f in all_findings:
        if f["technique"] not in seen:
            seen.add(f["technique"])
            unique.append(f)

    severities = [f["severity"] for f in unique]
    return {
        "url"              : url,
        "param"            : param,
        "vulnerability"    : "SQL Injection",
        "findings"         : unique,
        "confirmed"        : len(unique) > 0,
        "technique_summary": list(seen),
        "highest_severity" : _highest_severity(severities),
        "total_hits"       : len(unique),
    }


# ─────────────────────────────────────────────────────────────
# SQLiDetector
# ─────────────────────────────────────────────────────────────

class SQLiDetector:
    """
    Dedicated SQL injection detector.

    Parameters
    ----------
    timeout        : per-request HTTP timeout (seconds)
    time_threshold : minimum delay (seconds) that counts as a hit
    user_agent     : User-Agent header value
    session        : optional pre-configured requests.Session
    """

    def __init__(
        self,
        timeout:        int                        = 10,
        time_threshold: float                      = 4.0,
        user_agent:     str                        = "AegisSecurity/1.0 Web Application Assessment",
        session:        Optional[requests.Session] = None,
    ):
        self.timeout        = timeout
        self.time_threshold = time_threshold

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

    # ── Error-based (GET param) ───────────────────────────────

    def _run_error_based(self, url: str, param: str) -> List[Dict]:
        findings = []
        for payload in ERROR_PAYLOADS:
            injected = _inject_param(url, param, payload)
            resp     = self._get(injected)
            if resp is None:
                continue
            hit, sig = _has_error_sig(resp.text)
            if hit:
                findings.append({
                    "technique"   : "error_based",
                    "payload"     : payload,
                    "evidence"    : f'DB error signature: "{sig}"',
                    "severity"    : "high",
                    "injected_url": injected,
                    "status_code" : resp.status_code,
                })
                logger.warning("[SQLi-ERROR] param=%s  sig=%s", param, sig)
        return findings

    # ── Boolean-based (GET param) ─────────────────────────────

    def _run_boolean_based(self, url: str, param: str) -> List[Dict]:
        findings = []
        for true_pl, false_pl in BOOLEAN_PAYLOAD_PAIRS:
            r_true  = self._get(_inject_param(url, param, true_pl))
            r_false = self._get(_inject_param(url, param, false_pl))
            if r_true is None or r_false is None:
                continue
            len_t, len_f = len(r_true.text), len(r_false.text)
            if len_t == 0:
                continue
            diff = abs(len_t - len_f) / len_t
            if diff >= BOOLEAN_LENGTH_THRESHOLD:
                findings.append({
                    "technique"   : "boolean_based",
                    "payload"     : f'TRUE: "{true_pl}"  /  FALSE: "{false_pl}"',
                    "evidence"    : (
                        f"Response size differs by {diff*100:.1f}%: "
                        f"true={len_t}B, false={len_f}B"
                    ),
                    "severity"    : "critical",
                    "injected_url": _inject_param(url, param, true_pl),
                    "status_code" : r_true.status_code,
                })
        return findings

    # ── Time-based (GET param) ────────────────────────────────

    def _run_time_based(self, url: str, param: str) -> List[Dict]:
        findings = []
        for item in TIME_PAYLOADS:
            injected = _inject_param(url, param, item["payload"])
            t0       = time.monotonic()
            resp     = self._get(injected)
            elapsed  = time.monotonic() - t0
            if resp is None:
                continue
            if elapsed >= (item["delay"] * TIME_THRESHOLD_FACTOR):
                findings.append({
                    "technique"   : "time_based",
                    "payload"     : item["payload"],
                    "evidence"    : (
                        f"Response took {elapsed:.2f}s with "
                        f"SLEEP({item['delay']}) payload ({item['db']})"
                    ),
                    "severity"    : "critical",
                    "injected_url": injected,
                    "status_code" : resp.status_code,
                })
        return findings

    # ── Error-based (form field) ──────────────────────────────

    def _run_error_based_form(
        self, url: str, param: str, method: str, base_inputs: Dict[str, str]
    ) -> List[Dict]:
        findings = []
        for payload in ERROR_PAYLOADS:
            data = {**base_inputs, param: payload}
            resp = self._post_form(url, data) if method == "POST" else \
                   self._get(_inject_param(url, param, payload))
            if resp is None:
                continue
            hit, sig = _has_error_sig(resp.text)
            if hit:
                findings.append({
                    "technique"   : "error_based",
                    "payload"     : payload,
                    "evidence"    : f'DB error signature: "{sig}"',
                    "severity"    : "high",
                    "injected_url": url,
                    "status_code" : resp.status_code,
                })
                logger.warning("[SQLi-FORM-ERROR] url=%s param=%s sig=%s",
                               url, param, sig)
        return findings

    # ── Boolean-based (form field) ────────────────────────────

    def _run_boolean_based_form(
        self, url: str, param: str, method: str, base_inputs: Dict[str, str]
    ) -> List[Dict]:
        findings = []
        for true_pl, false_pl in BOOLEAN_PAYLOAD_PAIRS:
            if method == "POST":
                r_true  = self._post_form(url, {**base_inputs, param: true_pl})
                r_false = self._post_form(url, {**base_inputs, param: false_pl})
            else:
                r_true  = self._get(_inject_param(url, param, true_pl))
                r_false = self._get(_inject_param(url, param, false_pl))

            if r_true is None or r_false is None:
                continue
            len_t, len_f = len(r_true.text), len(r_false.text)
            if len_t == 0:
                continue
            diff = abs(len_t - len_f) / len_t
            if diff >= BOOLEAN_LENGTH_THRESHOLD:
                findings.append({
                    "technique"   : "boolean_based",
                    "payload"     : f'TRUE: "{true_pl}"  /  FALSE: "{false_pl}"',
                    "evidence"    : (
                        f"Response size differs by {diff*100:.1f}%: "
                        f"true={len_t}B, false={len_f}B"
                    ),
                    "severity"    : "critical",
                    "injected_url": url,
                    "status_code" : r_true.status_code,
                })
        return findings

    # ── public API — URL param detection ─────────────────────

    def detect(self, url: str, param: str) -> Dict:
        """Run all three SQLi detection techniques on *url* / *param* (GET)."""
        logger.info("[SQLiDetector] URL param test %s  param=%s", url, param)
        all_findings = (
            self._run_error_based(url, param)
            + self._run_boolean_based(url, param)
            + self._run_time_based(url, param)
        )
        return _build_result(url, param, all_findings)

    # ── public API — Form field detection  ← NEW ─────────────

    def detect_form(
        self,
        url:         str,
        param:       str,
        method:      str           = "POST",
        base_inputs: Optional[Dict[str, str]] = None,
    ) -> Dict:
        """
        Test a single form field for SQL injection.

        Parameters
        ----------
        url         : form action URL
        param       : field name to inject payloads into
        method      : "POST" or "GET"
        base_inputs : all other form fields with their default values
                      (needed so POST requests include CSRF tokens etc.)
        """
        logger.info("[SQLiDetector] Form test %s  param=%s  method=%s",
                    url, param, method)
        base = dict(base_inputs or {})
        if param not in base:
            base[param] = "test"

        all_findings = (
            self._run_error_based_form(url, param, method, base)
            + self._run_boolean_based_form(url, param, method, base)
            # Time-based skipped for forms to keep scan time reasonable;
            # add if needed.
        )
        return _build_result(url, param, all_findings)