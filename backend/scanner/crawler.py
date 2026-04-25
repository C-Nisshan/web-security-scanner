"""
crawler.py — Hybrid Surface Discovery Module
=============================================
Performs BFS crawling with:
- Fast static HTML parsing (requests + BeautifulSoup)
- JS-render fallback using Playwright for SPA apps
- Auth-aware session injection (cookie / bearer / form login)
- Fixed external-link scope filtering
- Form extraction: discovers <form> elements and their inputs
  so the controller can inject payloads into POST/GET form fields

Layer  : Processing Layer

Changes from v2
---------------
- Added _extract_forms() to parse HTML forms (action, method, inputs)
- Crawler collects all forms discovered across visited pages and
  returns them in the crawl result under the "forms" key.
- Forms with duplicate (action_url, method, frozenset(param_names)) are
  de-duplicated so the controller is not flooded with identical targets.
- Hidden inputs (CSRF tokens etc.) are included in base_inputs so that
  POST requests constructed by the detectors carry the right fields.
"""

import time
import logging
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse, urldefrag
from collections import deque

import requests
from bs4 import BeautifulSoup

from playwright.sync_api import sync_playwright


# ─────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [CRAWLER]  %(levelname)s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("crawler")


# ─────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────

DEFAULT_MAX_DEPTH  = 3
DEFAULT_MAX_URLS   = 100
DEFAULT_TIMEOUT    = 8
DEFAULT_DELAY      = 0.3
DEFAULT_USER_AGENT = "AegisSecurity/1.0 Web Application Assessment"

_SPA_MIN_BODY_SIZE = 200


# ─────────────────────────────────────────────────────────────
# URL helpers
# ─────────────────────────────────────────────────────────────

def _normalise_url(url: str) -> str:
    url, _ = urldefrag(url)
    return url.rstrip("/")


def _host_only(netloc: str) -> str:
    return netloc.split(":")[0].lower()


def _is_internal(url: str, base_domain: str) -> bool:
    parsed = urlparse(url)
    if not parsed.netloc:
        return True
    base_host = _host_only(base_domain)
    link_host = _host_only(parsed.netloc)
    return link_host == base_host


def _is_crawlable_link(href: str) -> bool:
    skip = ("mailto:", "tel:", "javascript:", "data:", "#", "void")
    return not any(href.lower().strip().startswith(p) for p in skip)


# ─────────────────────────────────────────────────────────────
# Link extraction (static HTML)
# ─────────────────────────────────────────────────────────────

def _extract_links(html: str, base_url: str) -> List[str]:
    soup = BeautifulSoup(html, "html.parser")
    links = []
    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        if not _is_crawlable_link(href):
            continue
        absolute = urljoin(base_url, href)
        absolute = _normalise_url(absolute)
        if urlparse(absolute).scheme in ("http", "https"):
            links.append(absolute)

    seen, unique = set(), []
    for link in links:
        if link not in seen:
            seen.add(link)
            unique.append(link)
    return unique


# ─────────────────────────────────────────────────────────────
# Form extraction  ← NEW
# ─────────────────────────────────────────────────────────────

# Field types that are never injection targets
_NON_INJECTABLE_TYPES = frozenset(
    {"submit", "button", "reset", "image", "file", "checkbox", "radio"}
)


def _extract_forms(html: str, base_url: str) -> List[Dict]:
    """
    Parse all <form> elements and return a structured list.

    Each entry has:
        url         : absolute form action URL
        method      : "GET" or "POST"
        inputs      : {field_name: default_value, ...}
                      includes hidden inputs (CSRF tokens etc.)
        source_url  : page where the form was found
    """
    soup = BeautifulSoup(html, "html.parser")
    forms = []

    for form in soup.find_all("form"):
        action = (form.get("action") or "").strip()
        method = (form.get("method") or "GET").strip().upper()
        if method not in ("GET", "POST"):
            method = "POST"

        abs_action = _normalise_url(
            urljoin(base_url, action) if action else base_url
        )

        inputs: Dict[str, str] = {}

        for field in form.find_all(["input", "textarea", "select"]):
            name  = (field.get("name") or "").strip()
            ftype = (field.get("type") or "text").lower()

            if not name:
                continue

            if ftype in _NON_INJECTABLE_TYPES:
                continue

            # Keep value for hidden fields (CSRF tokens); use "test" for others
            val = field.get("value") or ""
            inputs[name] = val if (ftype == "hidden" and val) else (val or "test")

        if inputs:
            forms.append({
                "url"       : abs_action,
                "method"    : method,
                "inputs"    : inputs,
                "source_url": base_url,
            })

    return forms


def _dedup_forms(forms: List[Dict]) -> List[Dict]:
    """
    De-duplicate forms that share the same action URL, method, and
    parameter set — common when the same login/search form appears
    on every page.
    """
    seen: Set[tuple] = set()
    unique: List[Dict] = []
    for f in forms:
        key = (f["url"], f["method"], frozenset(f["inputs"].keys()))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# ─────────────────────────────────────────────────────────────
# Playwright renderer (JS support)
# ─────────────────────────────────────────────────────────────

def _render_js(url: str, timeout: int = 8000) -> str:
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page    = browser.new_page()
            page.goto(url, timeout=timeout)
            page.wait_for_load_state("networkidle")
            html = page.content()
            browser.close()
            return html
    except Exception as e:
        logger.warning("Playwright render failed %s: %s", url, e)
        return ""


def _is_spa(html: str) -> bool:
    if not html or len(html) < _SPA_MIN_BODY_SIZE:
        return False
    indicators = ["<app-root", "ng-version", "react-root"]
    if any(i in html for i in indicators):
        return True
    soup = BeautifulSoup(html, "html.parser")
    return len(soup.find_all("a", href=True)) == 0


# ─────────────────────────────────────────────────────────────
# Crawler
# ─────────────────────────────────────────────────────────────

class Crawler:
    """
    BFS web crawler with optional authenticated session support
    and HTML form extraction.

    Parameters
    ----------
    max_depth  : maximum BFS depth from the seed URL
    max_urls   : hard cap on total URLs visited
    timeout    : per-request timeout in seconds
    delay      : polite delay between requests (seconds)
    user_agent : User-Agent header value
    session    : optional pre-configured requests.Session
                 (e.g. from AuthManager.get_session())
    """

    def __init__(
        self,
        max_depth:  int            = DEFAULT_MAX_DEPTH,
        max_urls:   int            = DEFAULT_MAX_URLS,
        timeout:    int            = DEFAULT_TIMEOUT,
        delay:      float          = DEFAULT_DELAY,
        user_agent: str            = DEFAULT_USER_AGENT,
        session:    Optional[requests.Session] = None,
    ):
        self.max_depth  = max_depth
        self.max_urls   = max_urls
        self.timeout    = timeout
        self.delay      = delay
        self.user_agent = user_agent

        if session is not None:
            self._session = session
            if "User-Agent" not in dict(self._session.headers):
                self._session.headers.update({"User-Agent": user_agent})
            logger.info("[Crawler] Using injected authenticated session")
        else:
            self._session = requests.Session()
            self._session.headers.update({"User-Agent": self.user_agent})
            logger.info("[Crawler] Using fresh unauthenticated session")

    # ─────────────────────────────────────────────────────────
    # Fetch (static)
    # ─────────────────────────────────────────────────────────

    def _fetch(self, url: str) -> Optional[requests.Response]:
        try:
            response = self._session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False,
            )
            response.raise_for_status()
            return response
        except Exception as e:
            logger.warning("Fetch failed %s: %s", url, e)
            return None

    # ─────────────────────────────────────────────────────────
    # Crawl
    # ─────────────────────────────────────────────────────────

    def crawl(self, seed_url: str) -> Dict:
        seed_url    = _normalise_url(seed_url)
        base_domain = urlparse(seed_url).netloc

        logger.info("Crawl start seed=%s depth=%d max=%d",
                    seed_url, self.max_depth, self.max_urls)

        visited:      Set[str]              = set()
        queued:       Set[str]              = {seed_url}
        failed:       List[str]             = []
        url_to_links: Dict[str, List[str]]  = {}
        all_forms:    List[Dict]            = []   # ← NEW: accumulate forms

        queue = deque([(seed_url, 0)])

        while queue:
            if len(visited) >= self.max_urls:
                logger.info("Max URLs reached (%d)", self.max_urls)
                break

            url, depth = queue.popleft()
            logger.info("[depth=%d] %s", depth, url)

            response = self._fetch(url)
            if not response:
                failed.append(url)
                continue

            visited.add(url)
            html  = response.text

            # ── Extract links ─────────────────────────────────
            links = _extract_links(html, url)

            # ── SPA fallback (Playwright) ─────────────────────
            if not links and _is_spa(html):
                logger.info("SPA detected → rendering JS: %s", url)
                rendered = _render_js(url)
                if rendered:
                    links = _extract_links(rendered, url)
                    html  = rendered   # use rendered HTML for form extraction

            url_to_links[url] = links

            # ── Extract forms  ← NEW ─────────────────────────
            page_forms = _extract_forms(html, url)
            if page_forms:
                logger.info("[Crawler] Found %d form(s) on %s", len(page_forms), url)
            all_forms.extend(page_forms)

            # ── Enqueue internal links ────────────────────────
            if depth < self.max_depth:
                for link in links:
                    if (
                        link not in visited
                        and link not in queued
                        and _is_internal(link, base_domain)
                        and len(visited) + len(queue) < self.max_urls
                    ):
                        queue.append((link, depth + 1))
                        queued.add(link)

            time.sleep(self.delay)

        deduped_forms = _dedup_forms(all_forms)

        result = {
            "seed_url"     : seed_url,
            "base_domain"  : base_domain,
            "visited_urls" : sorted(visited),
            "failed_urls"  : failed,
            "url_to_links" : url_to_links,
            "forms"        : deduped_forms,          # ← NEW
            "total_visited": len(visited),
            "total_failed" : len(failed),
            "total_forms"  : len(deduped_forms),     # ← NEW
            "crawl_depth"  : self.max_depth,
        }

        logger.info("Crawl complete visited=%d failed=%d forms=%d",
                    result["total_visited"], result["total_failed"],
                    result["total_forms"])

        return result