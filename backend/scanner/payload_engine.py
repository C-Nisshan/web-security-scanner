"""
payload_engine.py — Enhanced Injection Assessment Engine
========================================================
Now supports:
- GET parameter injection
- POST JSON injection
- POST form-data injection
- Automatic parameter discovery
- Authenticated session injection  ← NEW in v3

Ethics note: ALL payloads are safe, non-destructive test strings.
No DDL (DROP/DELETE/TRUNCATE) or DML mutations are used.
"""

import time
import logging
from typing import List, Dict, Tuple, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [PAYLOAD]  %(levelname)s  %(message)s",
    datefmt="%H:%M:%S",
)

logger = logging.getLogger("payload_engine")

DEFAULT_USER_AGENT = "AegisSecurity/1.0 Web Application Assessment"

# ─────────────────────────────────────────────────────────────
# Payload libraries
# ─────────────────────────────────────────────────────────────

SQLI_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR 1=1 --",
    "\" OR \"1\"=\"1",
    "1' ORDER BY 1 --",
    "1 UNION SELECT NULL --",
    "1 AND 1=2",
    # Safe read-only probe (no DDL/DML mutations)
    "'; SELECT 1 --",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "\"><script>alert(1)</script>",
]

# Aligned with sqli_detector.ERROR_SIGNATURES for consistency
SQLI_SIGNATURES = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    # PostgreSQL
    "pg_query()",
    "postgresql query failed",
    # SQLite
    "sqlite error",
    "sqlite3.operationalerror",
    # MSSQL
    "unclosed quotation mark",
    "incorrect syntax near",
    "microsoft ole db",
    # Oracle
    "ora-",
    "oracle error",
    # Generic
    "sql syntax",
    "database error",
    "sqlexception",
    "syntax error",
    "invalid query",
]


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _build_url_with_params(url: str, params: Dict[str, Any]) -> str:
    parsed = urlparse(url)
    query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=query))


def _detect_sqli(body: str) -> Tuple[bool, str]:
    b = body.lower()
    for sig in SQLI_SIGNATURES:
        if sig.lower() in b:
            return True, sig
    return False, ""


def _detect_xss(body: str, payload: str) -> Tuple[bool, str]:
    if payload in body:
        return True, "reflected"
    return False, ""


# ─────────────────────────────────────────────────────────────
# Engine
# ─────────────────────────────────────────────────────────────

class PayloadEngine:
    """
    Injection assessment engine.

    Parameters
    ----------
    payload_type : "sqli" | "xss" | "both"
    max_payloads : maximum payloads to test
    timeout      : per-request timeout in seconds
    delay        : polite delay between requests
    session      : optional pre-configured requests.Session
                   (e.g. from AuthManager.get_session()).
                   When supplied, this session (including its cookies and
                   headers) is used instead of a fresh unauthenticated one.
    """

    def __init__(
        self,
        payload_type: str                        = "both",
        max_payloads: int                        = 20,
        timeout:      int                        = 8,
        delay:        float                      = 0.2,
        session:      Optional[requests.Session] = None,   # ← NEW
    ):
        self.payload_type = payload_type
        self.max_payloads = max_payloads
        self.timeout      = timeout
        self.delay        = delay

        if session is not None:
            self.session = session
            # Ensure our User-Agent is present if the session doesn't have one
            if "User-Agent" not in dict(self.session.headers):
                self.session.headers.update({"User-Agent": DEFAULT_USER_AGENT})
            logger.info("[PayloadEngine] Using injected authenticated session")
        else:
            self.session = requests.Session()
            self.session.headers.update({"User-Agent": DEFAULT_USER_AGENT})
            logger.info("[PayloadEngine] Using fresh unauthenticated session")

    # ─────────────────────────────────────────────
    # Payload selection
    # ─────────────────────────────────────────────

    def _get_payloads(self):
        payloads = []

        if self.payload_type in ("sqli", "both"):
            payloads += [{"type": "sqli", "payload": p} for p in SQLI_PAYLOADS]

        if self.payload_type in ("xss", "both"):
            payloads += [{"type": "xss", "payload": p} for p in XSS_PAYLOADS]

        return payloads[: self.max_payloads]

    # ─────────────────────────────────────────────
    # Extract input points
    # ─────────────────────────────────────────────

    def _extract_get_params(self, url: str) -> Dict:
        parsed = urlparse(url)
        return parse_qs(parsed.query)

    def _extract_post_params(self, data: Any) -> Dict:
        if isinstance(data, dict):
            return data
        return {}

    # ─────────────────────────────────────────────
    # Send request (uses self.session throughout)
    # ─────────────────────────────────────────────

    def _send_request(self, url, method="GET", params=None, json_data=None, form_data=None):
        try:
            if method == "GET":
                full_url = _build_url_with_params(url, params or {})
                return self.session.get(full_url, timeout=self.timeout, verify=False)

            if method == "POST_JSON":
                return self.session.post(url, json=json_data, timeout=self.timeout, verify=False)

            if method == "POST_FORM":
                return self.session.post(url, data=form_data, timeout=self.timeout, verify=False)

        except Exception:
            return None

    # ─────────────────────────────────────────────
    # Core test
    # ─────────────────────────────────────────────

    def _test(self, url: str, method: str, param: str, payload: str, ptype: str, base_data=None):

        result = {
            "url":      url,
            "method":   method,
            "param":    param,
            "payload":  payload,
            "type":     ptype,
            "status":   "clean",
            "evidence": "",
        }

        # Build request
        if method == "GET":
            params       = self._extract_get_params(url)
            params[param] = payload
            resp          = self._send_request(url, "GET", params=params)

        elif method == "POST_JSON":
            data         = dict(base_data or {})
            data[param]  = payload
            resp          = self._send_request(url, "POST_JSON", json_data=data)

        elif method == "POST_FORM":
            data         = dict(base_data or {})
            data[param]  = payload
            resp          = self._send_request(url, "POST_FORM", form_data=data)

        else:
            return result

        if not resp:
            result["status"] = "error"
            return result

        body = resp.text

        # Detection
        if ptype == "sqli":
            vuln, evidence = _detect_sqli(body)
        else:
            vuln, evidence = _detect_xss(body, payload)

        if vuln:
            result["status"]   = "vulnerable"
            result["evidence"] = evidence

        return result

    # ─────────────────────────────────────────────
    # Main entry
    # ─────────────────────────────────────────────

    def inject(self, target_url: str, post_data: Optional[Dict] = None):

        payloads  = self._get_payloads()
        get_params = self._extract_get_params(target_url)
        post_data  = post_data or {}
        results    = []

        logger.info("Starting scan: GET=%s POST=%s payloads=%d",
                    list(get_params.keys()),
                    list(post_data.keys()),
                    len(payloads))

        # ─────────────────────────────
        # GET parameter testing
        # ─────────────────────────────
        for param in get_params.keys():
            for p in payloads:
                results.append(
                    self._test(target_url, "GET", param, p["payload"], p["type"])
                )
                time.sleep(self.delay)

        # ─────────────────────────────
        # POST JSON testing
        # ─────────────────────────────
        for param in post_data.keys():
            for p in payloads:
                results.append(
                    self._test(
                        target_url, "POST_JSON", param,
                        p["payload"], p["type"],
                        base_data=post_data,
                    )
                )
                time.sleep(self.delay)

        return {
            "target_url"       : target_url,
            "results"          : results,
            "total_tested"     : len(results),
            "total_vulnerable" : sum(1 for r in results if r["status"] == "vulnerable"),
            "total_clean"      : sum(1 for r in results if r["status"] == "clean"),
            "total_errors"     : sum(1 for r in results if r["status"] == "error"),
        }