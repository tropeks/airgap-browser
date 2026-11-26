"""Cache curto de páginas sanitizadas, endereçadas por id opaco."""

from __future__ import annotations

import secrets
import time
from collections import OrderedDict
from dataclasses import dataclass


@dataclass
class CachedPage:
    html: str
    url: str
    title: str
    expires_at: float


class PageCache:
    def __init__(self, ttl_seconds: int, max_entries: int) -> None:
        self.ttl = ttl_seconds
        self.max_entries = max_entries
        self._pages: OrderedDict[str, CachedPage] = OrderedDict()

    def put(self, html: str, url: str, title: str) -> str:
        self._evict()
        page_id = secrets.token_urlsafe(16)
        self._pages[page_id] = CachedPage(html, url, title, time.monotonic() + self.ttl)
        while len(self._pages) > self.max_entries:
            self._pages.popitem(last=False)
        return page_id

    def get(self, page_id: str) -> CachedPage | None:
        page = self._pages.get(page_id)
        if page is None:
            return None
        if page.expires_at < time.monotonic():
            del self._pages[page_id]
            return None
        return page

    def _evict(self) -> None:
        now = time.monotonic()
        expired = [k for k, v in self._pages.items() if v.expires_at < now]
        for k in expired:
            del self._pages[k]
