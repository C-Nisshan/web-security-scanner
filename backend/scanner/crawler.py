"""
crawler.py — Hybrid Surface Discovery Module
=============================================
Performs BFS crawling with:
- Fast static HTML parsing (requests + BeautifulSoup)
- JS-render fallback using Playwright for SPA apps

Layer  : Processing Layer
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


# ─────────────────────────────────────────────────────────────
# URL helpers
# ─────────────────────────────────────────────────────────────

def _normalise_url(url: str) -> str:
    url, _ = urldefrag(url)
    return url.rstrip("/")


def _is_internal(url: str, base_domain: str) -> bool:
    parsed = urlparse(url)
    return parsed.netloc == base_domain or parsed.netloc == ""


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

    # deduplicate
    seen = set()
    unique = []
    for link in links:
        if link not in seen:
            seen.add(link)
            unique.append(link)

    return unique


# ─────────────────────────────────────────────────────────────
# Playwright renderer (JS support)
# ─────────────────────────────────────────────────────────────

def _render_js(url: str, timeout: int = 8000) -> str:
    """
    Render page using headless Chromium.
    Used when static crawl finds no links (SPA detection).
    """
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()

            page.goto(url, timeout=timeout)
            page.wait_for_load_state("networkidle")

            html = page.content()

            browser.close()
            return html

    except Exception as e:
        logger.warning("Playwright render failed %s: %s", url, e)
        return ""


def _is_spa(html: str) -> bool:
    """
    Heuristic SPA detection.
    """
    if not html:
        return True

    indicators = [
        "<app-root",
        "ng-version",
        "react-root",
    ]

    if any(i in html for i in indicators):
        return True

    # no links = likely JS-rendered app
    soup = BeautifulSoup(html, "html.parser")
    return len(soup.find_all("a", href=True)) == 0


# ─────────────────────────────────────────────────────────────
# Crawler
# ─────────────────────────────────────────────────────────────

class Crawler:

    def __init__(
        self,
        max_depth: int = DEFAULT_MAX_DEPTH,
        max_urls: int = DEFAULT_MAX_URLS,
        timeout: int = DEFAULT_TIMEOUT,
        delay: float = DEFAULT_DELAY,
        user_agent: str = DEFAULT_USER_AGENT,
    ):
        self.max_depth  = max_depth
        self.max_urls   = max_urls
        self.timeout    = timeout
        self.delay      = delay
        self.user_agent = user_agent

        self._session = requests.Session()
        self._session.headers.update({"User-Agent": self.user_agent})

    # ─────────────────────────────────────────────────────────
    # Fetch (static)
    # ─────────────────────────────────────────────────────────

    def _fetch(self, url: str) -> Optional[requests.Response]:
        try:
            response = self._session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=True,
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

        seed_url = _normalise_url(seed_url)
        base_domain = urlparse(seed_url).netloc

        logger.info("Crawl start seed=%s depth=%d max=%d",
                    seed_url, self.max_depth, self.max_urls)

        visited: Set[str] = set()
        queued: Set[str] = {seed_url}
        failed: List[str] = []
        url_to_links: Dict[str, List[str]] = {}

        queue = deque([(seed_url, 0)])

        while queue:

            if len(visited) >= self.max_urls:
                logger.info("Max URLs reached")
                break

            url, depth = queue.popleft()
            logger.info("[depth=%d] %s", depth, url)

            response = self._fetch(url)

            if not response:
                failed.append(url)
                continue

            visited.add(url)

            html = response.text
            links = _extract_links(html, url)

            # ────────────────────────────────────────────────
            # SPA fallback (Playwright)
            # ────────────────────────────────────────────────
            if not links and _is_spa(html):
                logger.info("SPA detected → rendering JS: %s", url)
                rendered = _render_js(url)

                if rendered:
                    links = _extract_links(rendered, url)

            url_to_links[url] = links

            # enqueue discovered links
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

        result = {
            "seed_url": seed_url,
            "base_domain": base_domain,
            "visited_urls": sorted(visited),
            "failed_urls": failed,
            "url_to_links": url_to_links,
            "total_visited": len(visited),
            "total_failed": len(failed),
            "crawl_depth": self.max_depth,
        }

        logger.info("Crawl complete visited=%d failed=%d",
                    result["total_visited"], result["total_failed"])

        return result