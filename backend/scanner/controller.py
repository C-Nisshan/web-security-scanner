"""
controller.py — Scanner Controller
====================================
Orchestrates the full four-stage scan pipeline:

    Stage 1 — Discovery   : Crawler maps all reachable pages + forms
    Stage 2 — Extraction  : URL params and form inputs are identified
    Stage 3 — Injection   : SQLiDetector + XSSDetector probe each target
    Stage 4 — Analysis    : ResponseAnalyzer aggregates findings
    Stage 5 — Reporting   : ReportGenerator produces HTML + PDF

Changes from v2
---------------
- Crawler now returns a "forms" list alongside visited URLs.
- The controller drives two injection loops:
    (a) URL-parameter loop  — unchanged from v2, tests GET params
    (b) Form-field loop     — NEW, tests discovered form inputs via
        SQLiDetector.detect_form() and XSSDetector.detect_form()
- max_targets applies to the combined pool of URL + form targets.
- Authenticated session is still injected into both detectors.

Layer : Orchestration Layer
"""

import time
import uuid
import logging
from datetime import datetime
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse, parse_qs

from .crawler           import Crawler
from .sqli_detector     import SQLiDetector
from .xss_detector      import XSSDetector
from .response_analyzer import ResponseAnalyzer
from .report_generator  import ReportGenerator
from .auth_manager      import AuthManager, build_auth_manager

logger = logging.getLogger("controller")


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _extract_params(url: str) -> List[str]:
    """Return the list of GET parameter names in *url*."""
    qs = parse_qs(urlparse(url).query, keep_blank_values=True)
    return list(qs.keys())


def _prioritise_urls(visited_urls: List[str], max_targets: int) -> List[str]:
    """
    Select a representative subset of URLs that have query parameters
    (most interesting for injection testing), then fill with parameterless
    URLs up to *max_targets*.
    """
    with_params    = [u for u in visited_urls if "?" in u]
    without_params = [u for u in visited_urls if "?" not in u]
    return (with_params + without_params)[:max_targets]


# ─────────────────────────────────────────────────────────────
# ScannerController
# ─────────────────────────────────────────────────────────────

class ScannerController:
    """
    End-to-end scan orchestrator.

    Parameters
    ----------
    report_dir     : directory for generated reports
    max_crawl_depth: BFS depth for the crawler
    max_crawl_urls : URL cap for the crawler
    max_targets    : cap on how many targets (URLs + forms) get tested
    max_payloads   : payload limit per URL / param
    payload_type   : "sqli" | "xss" | "both"
    progress_cb    : optional callable(pct: int, msg: str) for live progress
    """

    def __init__(
        self,
        report_dir:      str                = "reports",
        max_crawl_depth: int                = 2,
        max_crawl_urls:  int                = 40,
        max_targets:     int                = 10,
        max_payloads:    int                = 20,
        payload_type:    str                = "both",
        progress_cb:     Optional[Callable] = None,
    ):
        self.report_dir      = report_dir
        self.max_crawl_depth = max_crawl_depth
        self.max_crawl_urls  = max_crawl_urls
        self.max_targets     = max_targets
        self.max_payloads    = max_payloads
        self.payload_type    = payload_type
        self.progress_cb     = progress_cb

    # ── progress helper ───────────────────────────────────────

    def _progress(self, pct: int, msg: str):
        logger.info("[%3d%%] %s", pct, msg)
        if self.progress_cb:
            self.progress_cb(pct, msg)

    # ── public API ────────────────────────────────────────────

    def run_scan(self, target_url: str, options: Optional[Dict] = None) -> Dict:
        """
        Execute the full pipeline and return a structured result dict.

        Parameters
        ----------
        target_url : seed URL for the scan
        options    : optional overrides including an "auth" sub-dict.
                     See AuthManager / build_auth_manager for auth shapes.

        Returns
        -------
        dict with keys:
            scan_id, target_url, scan_date, duration_seconds,
            auth_type, crawl_result, sqli_results, xss_results,
            analysis, report_html_path, report_pdf_path,
            error (only if a fatal exception occurred)
        """
        opts = options or {}
        max_depth    = int(opts.get("max_depth",    self.max_crawl_depth))
        max_urls     = int(opts.get("max_urls",     self.max_crawl_urls))
        max_targets  = int(opts.get("max_targets",  self.max_targets))
        max_payloads = int(opts.get("max_payloads", self.max_payloads))
        payload_type = opts.get("payload_type", self.payload_type)
        auth_config  = opts.get("auth")

        scan_id   = str(uuid.uuid4())[:8]
        scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        t_start   = time.monotonic()

        logger.info("=== Scan started  id=%s  target=%s ===", scan_id, target_url)
        self._progress(0, f"Starting scan of {target_url}")

        # ── Authentication setup ──────────────────────────────
        auth_manager:   Optional[AuthManager]        = None
        auth_session                                  = None
        auth_type_label                               = "none"

        if auth_config:
            self._progress(3, "Configuring authentication…")
            auth_manager = build_auth_manager(auth_config)
            if auth_manager and auth_manager.is_authenticated:
                auth_session    = auth_manager.get_session()
                auth_type_label = auth_manager.auth_type or "unknown"
                logger.info("[Controller] Auth configured: type=%s", auth_type_label)
            else:
                logger.warning("[Controller] Auth config provided but login failed "
                               "— continuing unauthenticated")

        # ── Stage 1: Discovery ────────────────────────────────
        self._progress(5, "Crawling target application…")
        try:
            crawler = Crawler(
                max_depth = max_depth,
                max_urls  = max_urls,
                session   = auth_session,
            )
            crawl_result = crawler.crawl(target_url)
        except Exception as exc:
            logger.exception("Crawler failed")
            return {"scan_id": scan_id, "error": f"Crawler failed: {exc}"}

        visited = crawl_result.get("visited_urls", [])
        forms   = crawl_result.get("forms",        [])

        self._progress(25, (
            f"Discovered {len(visited)} pages, "
            f"{len(forms)} form(s)"
        ))

        # ── Stage 2: Target Selection ─────────────────────────
        url_targets  = _prioritise_urls(visited, max_targets)
        form_targets = forms[:max_targets]

        logger.info("URL targets: %d / %d  |  Form targets: %d / %d",
                    len(url_targets), len(visited),
                    len(form_targets), len(forms))
        self._progress(30, (
            f"Selected {len(url_targets)} URL target(s) "
            f"and {len(form_targets)} form target(s)"
        ))

        # ── Stage 3: Injection Testing ────────────────────────
        sqli_results: List[Dict] = []
        xss_results:  List[Dict] = []

        sqli_det = SQLiDetector(session=auth_session)
        xss_det  = XSSDetector(session=auth_session)

        total_url_targets  = max(len(url_targets), 1)
        total_form_targets = max(len(form_targets), 1)

        # ── 3a: URL parameter injection ───────────────────────
        for idx, url in enumerate(url_targets):
            pct = 30 + int(((idx + 1) / total_url_targets) * 25)
            self._progress(pct, f"URL param test — {url}")

            params = _extract_params(url)
            if not params:
                test_url = url + ("&" if "?" in url else "?") + "input=test"
                params   = ["input"]
            else:
                test_url = url

            for param in params[:3]:
                if payload_type in ("sqli", "both"):
                    result = sqli_det.detect(test_url, param)
                    if result.get("confirmed"):
                        sqli_results.append(result)

                if payload_type in ("xss", "both"):
                    result = xss_det.detect(test_url, param)
                    if result.get("confirmed"):
                        xss_results.append(result)

        # ── 3b: Form field injection  ← NEW ──────────────────
        self._progress(55, f"Testing {len(form_targets)} form(s)…")

        for idx, form in enumerate(form_targets):
            pct = 55 + int(((idx + 1) / total_form_targets) * 25)
            form_url = form["url"]
            method   = form["method"]   # "GET" or "POST"
            inputs   = form["inputs"]   # {field_name: default_value}

            self._progress(pct, f"Form test ({method}) — {form_url}")

            # Test each injectable field (skip pure hidden/csrf-only forms)
            injectable = [
                k for k, v in inputs.items()
                if not k.lower() in ("user_token", "_token", "csrf", "csrfmiddlewaretoken")
            ]
            if not injectable:
                # Fall back to testing all fields if we can't identify inputs
                injectable = list(inputs.keys())

            for param in injectable[:3]:
                if payload_type in ("sqli", "both"):
                    result = sqli_det.detect_form(form_url, param, method, inputs)
                    if result.get("confirmed"):
                        sqli_results.append(result)

                if payload_type in ("xss", "both"):
                    result = xss_det.detect_form(form_url, param, method, inputs)
                    if result.get("confirmed"):
                        xss_results.append(result)

        self._progress(80, "Injection testing complete")

        # ── Stage 4: Analysis ─────────────────────────────────
        self._progress(85, "Analysing findings…")
        analyzer = ResponseAnalyzer()
        analysis = analyzer.analyze(sqli_results, xss_results)

        # ── Stage 5: Report Generation ────────────────────────
        self._progress(90, "Generating reports…")
        duration = f"{time.monotonic() - t_start:.1f}s"

        scan_meta = {
            "target_url"   : target_url,
            "scan_date"    : scan_date,
            "duration"     : duration,
            "pages_crawled": crawl_result.get("total_visited", 0),
            "forms_found"  : crawl_result.get("total_forms",   0),
            "scan_id"      : scan_id,
            "auth_type"    : auth_type_label,
        }

        report_html_path = None
        report_pdf_path  = None

        try:
            gen = ReportGenerator(output_dir=self.report_dir)
            report_html_path = gen.generate_html(analysis, scan_meta, scan_id)
            try:
                report_pdf_path = gen.generate_pdf(analysis, scan_meta, scan_id)
            except ImportError:
                logger.warning("ReportLab not installed — skipping PDF.")
            except Exception as pdf_exc:
                logger.exception("PDF generation failed: %s", pdf_exc)
        except Exception as exc:
            logger.exception("Report generation failed: %s", exc)

        duration_seconds = time.monotonic() - t_start
        self._progress(100, "Scan complete")
        logger.info(
            "=== Scan complete  id=%s  findings=%d  duration=%.1fs ===",
            scan_id, analysis.get("total_findings", 0), duration_seconds
        )

        return {
            "scan_id"          : scan_id,
            "target_url"       : target_url,
            "scan_date"        : scan_date,
            "duration_seconds" : round(duration_seconds, 2),
            "duration"         : duration,
            "auth_type"        : auth_type_label,
            "crawl_result"     : crawl_result,
            "sqli_results"     : sqli_results,
            "xss_results"      : xss_results,
            "analysis"         : analysis,
            "report_html_path" : report_html_path,
            "report_pdf_path"  : report_pdf_path,
        }