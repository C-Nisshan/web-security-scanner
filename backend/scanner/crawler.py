"""
crawler.py — Surface Discovery Module
=======================================
Performs breadth-first crawling of a target web application,
discovering all reachable internal URLs up to a configurable depth.

Layer  : Processing Layer
"""

import time
import logging
from typing import Dict, List, Optional, Set, Deque
from urllib.parse import urljoin, urlparse, urldefrag
from collections import deque

import requests
from bs4 import BeautifulSoup

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [CRAWLER]  %(levelname)s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("crawler")

DEFAULT_MAX_DEPTH  = 3
DEFAULT_MAX_URLS   = 100
DEFAULT_TIMEOUT    = 8
DEFAULT_DELAY      = 0.3
DEFAULT_USER_AGENT = "AegisSecurity/1.0 Web Application Assessment"


# ─────────────────────────────────────────────────────────────
# Helpers
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


def _extract_links(html: str, base_url: str) -> List[str]:
    soup  = BeautifulSoup(html, "html.parser")
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
# Crawler
# ─────────────────────────────────────────────────────────────

class Crawler:
    """
    Breadth-first web crawler.

    Parameters
    ----------
    max_depth  : int   — maximum BFS depth from the seed URL
    max_urls   : int   — maximum number of URLs to visit
    timeout    : int   — per-request HTTP timeout (seconds)
    delay      : float — polite pause between requests (seconds)
    user_agent : str   — User-Agent header value
    """

    def __init__(
        self,
        max_depth:  int   = DEFAULT_MAX_DEPTH,
        max_urls:   int   = DEFAULT_MAX_URLS,
        timeout:    int   = DEFAULT_TIMEOUT,
        delay:      float = DEFAULT_DELAY,
        user_agent: str   = DEFAULT_USER_AGENT,
    ):
        self.max_depth  = max_depth
        self.max_urls   = max_urls
        self.timeout    = timeout
        self.delay      = delay
        self.user_agent = user_agent

        self._session = requests.Session()
        self._session.headers.update({"User-Agent": self.user_agent})

    def _fetch(self, url: str) -> Optional[requests.Response]:
        try:
            response = self._session.get(
                url, timeout=self.timeout, allow_redirects=True, verify=True
            )
            response.raise_for_status()
            return response
        except requests.exceptions.SSLError:
            logger.warning("SSL error — %s", url)
        except requests.exceptions.ConnectionError:
            logger.warning("Connection error — %s", url)
        except requests.exceptions.Timeout:
            logger.warning("Timeout — %s", url)
        except requests.exceptions.HTTPError as exc:
            logger.warning("HTTP %s — %s", exc.response.status_code, url)
        except requests.exceptions.RequestException as exc:
            logger.warning("Request error %s: %s", url, exc)
        return None

    def crawl(self, seed_url: str) -> Dict:
        """
        Crawl from *seed_url* using breadth-first search.

        Returns
        -------
        dict : seed_url, base_domain, visited_urls, failed_urls,
               url_to_links, total_visited, total_failed, crawl_depth
        """
        seed_url    = _normalise_url(seed_url)
        base_domain = urlparse(seed_url).netloc

        logger.info("Crawl start  seed=%s  depth=%d  max=%d",
                    seed_url, self.max_depth, self.max_urls)

        visited:      Set[str]          = set()
        failed:       List[str]         = []
        url_to_links: Dict[str, List]   = {}

        queue:  deque = deque([(seed_url, 0)])
        queued: Set[str] = {seed_url}

        while queue:
            if len(visited) >= self.max_urls:
                logger.info("max_urls=%d reached — stopping", self.max_urls)
                break

            url, depth = queue.popleft()
            logger.info("[depth=%d] %s", depth, url)

            response = self._fetch(url)
            if response is None:
                failed.append(url)
                continue

            visited.add(url)

            if depth < self.max_depth:
                content_type = response.headers.get("Content-Type", "")
                if "text/html" not in content_type:
                    url_to_links[url] = []
                    continue

                found = _extract_links(response.text, url)
                url_to_links[url] = found

                for link in found:
                    if (
                        link not in visited
                        and link not in queued
                        and _is_internal(link, base_domain)
                        and len(visited) + len(queue) < self.max_urls
                    ):
                        queue.append((link, depth + 1))
                        queued.add(link)
            else:
                url_to_links[url] = []

            time.sleep(self.delay)

        result = {
            "seed_url"     : seed_url,
            "base_domain"  : base_domain,
            "visited_urls" : sorted(visited),
            "failed_urls"  : failed,
            "url_to_links" : url_to_links,
            "total_visited": len(visited),
            "total_failed" : len(failed),
            "crawl_depth"  : self.max_depth,
        }

        logger.info("Crawl complete  visited=%d  failed=%d",
                    result["total_visited"], result["total_failed"])
        return result