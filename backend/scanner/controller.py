"""
controller.py — Scanner Controller
====================================
Orchestrates the full four-stage scan pipeline:

    Stage 1 — Discovery   : Crawler maps all reachable pages
    Stage 2 — Extraction  : GET parameters are identified per URL
    Stage 3 — Injection   : SQLiDetector + XSSDetector probe each param
    Stage 4 — Analysis    : ResponseAnalyzer aggregates findings
    Stage 5 — Reporting   : ReportGenerator produces HTML + PDF

The controller also tracks progress (0–100 %) so the Flask layer
can stream status updates to the frontend if needed.

Layer : Orchestration Layer
"""

import time
import uuid
import logging
from datetime import datetime
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse, parse_qs

from .crawler          import Crawler
from .sqli_detector    import SQLiDetector
from .xss_detector     import XSSDetector
from .response_analyzer import ResponseAnalyzer
from .report_generator  import ReportGenerator

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
    targets        = (with_params + without_params)[:max_targets]
    return targets


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
    max_targets    : cap on how many discovered URLs get injection-tested
    max_payloads   : payload limit per URL / param
    payload_type   : "sqli" | "xss" | "both"
    progress_cb    : optional callable(pct: int, msg: str) for live progress
    """

    def __init__(
        self,
        report_dir:      str            = "reports",
        max_crawl_depth: int            = 2,
        max_crawl_urls:  int            = 40,
        max_targets:     int            = 10,
        max_payloads:    int            = 20,
        payload_type:    str            = "both",
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
        options    : optional overrides for crawl/payload settings

        Returns
        -------
        dict with keys:
            scan_id, target_url, scan_date, duration_seconds,
            crawl_result, sqli_results, xss_results,
            analysis, report_html_path, report_pdf_path,
            error (only if a fatal exception occurred)
        """
        opts = options or {}
        max_depth    = int(opts.get("max_depth",    self.max_crawl_depth))
        max_urls     = int(opts.get("max_urls",     self.max_crawl_urls))
        max_targets  = int(opts.get("max_targets",  self.max_targets))
        max_payloads = int(opts.get("max_payloads", self.max_payloads))
        payload_type = opts.get("payload_type", self.payload_type)

        scan_id   = str(uuid.uuid4())[:8]
        scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        t_start   = time.monotonic()

        logger.info("=== Scan started  id=%s  target=%s ===", scan_id, target_url)
        self._progress(0, f"Starting scan of {target_url}")

        # ── Stage 1: Discovery ────────────────────────────────
        self._progress(5, "Crawling target application…")
        try:
            crawler      = Crawler(max_depth=max_depth, max_urls=max_urls)
            crawl_result = crawler.crawl(target_url)
        except Exception as exc:
            logger.exception("Crawler failed")
            return {"scan_id": scan_id, "error": f"Crawler failed: {exc}"}

        visited  = crawl_result.get("visited_urls", [])
        self._progress(25, f"Discovered {len(visited)} pages")

        # ── Stage 2: Target Selection ─────────────────────────
        targets = _prioritise_urls(visited, max_targets)
        logger.info("Injection targets selected: %d / %d", len(targets), len(visited))
        self._progress(30, f"Selected {len(targets)} targets for injection testing")

        # ── Stage 3: Injection Testing ────────────────────────
        sqli_results: List[Dict] = []
        xss_results:  List[Dict] = []

        sqli_det = SQLiDetector()
        xss_det  = XSSDetector()

        total_targets = max(len(targets), 1)
        for idx, url in enumerate(targets):
            pct  = 30 + int(((idx + 1) / total_targets) * 50)
            self._progress(pct, f"Testing {url}")

            params = _extract_params(url)

            # If no params, inject a synthetic 'input' param
            if not params:
                test_url = url + ("&" if "?" in url else "?") + "input=test"
                params   = ["input"]
            else:
                test_url = url

            for param in params[:3]:  # limit to first 3 params per URL
                if payload_type in ("sqli", "both"):
                    result = sqli_det.detect(test_url, param)
                    if result.get("confirmed"):
                        sqli_results.append(result)

                if payload_type in ("xss", "both"):
                    result = xss_det.detect(test_url, param)
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
            "scan_id"      : scan_id,
        }

        report_html_path = None
        report_pdf_path  = None

        try:
            gen = ReportGenerator(output_dir=self.report_dir)
            report_html_path = gen.generate_html(analysis, scan_meta, scan_id)
            try:
                report_pdf_path = gen.generate_pdf(analysis, scan_meta, scan_id)
            except ImportError:
                logger.warning("ReportLab not installed — skipping PDF generation.")
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
            "crawl_result"     : crawl_result,
            "sqli_results"     : sqli_results,
            "xss_results"      : xss_results,
            "analysis"         : analysis,
            "report_html_path" : report_html_path,
            "report_pdf_path"  : report_pdf_path,
        }