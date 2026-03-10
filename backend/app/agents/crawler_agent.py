from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup


POLICY_KEYWORDS = [
    "privacy", "privacy policy", "cookie", "data protection", "terms", "سياسة الخصوصية", "الخصوصية", "الشروط",
]


@dataclass
class CrawledPage:
    url: str
    html: str
    text: str
    is_policy_related: bool


class CrawlerAgent:
    def __init__(self, max_pages: int = 10, timeout: float = 12.0):
        self.max_pages = max_pages
        self.timeout = timeout

    async def crawl(self, root_url: str) -> list[CrawledPage]:
        domain = urlparse(root_url).netloc
        queue = deque([root_url])
        visited = set()
        pages: list[CrawledPage] = []

        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            while queue and len(pages) < self.max_pages:
                current = queue.popleft()
                if current in visited:
                    continue
                visited.add(current)

                try:
                    resp = await client.get(current)
                    if "text/html" not in resp.headers.get("content-type", ""):
                        continue
                    html = resp.text
                except Exception:
                    continue

                soup = BeautifulSoup(html, "lxml")
                text = soup.get_text(" ", strip=True)
                is_policy_related = self._is_policy_page(current, text)
                pages.append(CrawledPage(current, html, text, is_policy_related))

                for link in self._extract_links(soup, current, domain):
                    if link not in visited and len(queue) < self.max_pages * 3:
                        queue.append(link)

        return pages

    def _extract_links(self, soup: BeautifulSoup, current_url: str, domain: str) -> Iterable[str]:
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            full = urljoin(current_url, href)
            parsed = urlparse(full)
            if parsed.scheme in {"http", "https"} and parsed.netloc == domain:
                yield full

    def _is_policy_page(self, url: str, text: str) -> bool:
        corpus = f"{url} {text[:2000]}".lower()
        return any(keyword in corpus for keyword in POLICY_KEYWORDS)
