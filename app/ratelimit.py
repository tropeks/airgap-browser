"""Rate limit por cliente (janela deslizante simples, em memória)."""

from __future__ import annotations

import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self, limit_per_minute: int) -> None:
        self.limit = limit_per_minute
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._last_sweep = time.monotonic()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        window = self._hits[key]
        while window and window[0] <= now - 60:
            window.popleft()
        if len(window) >= self.limit:
            return False
        window.append(now)
        if now - self._last_sweep > 300:
            self._sweep(now)
        return True

    def _sweep(self, now: float) -> None:
        self._last_sweep = now
        for key in [k for k, w in self._hits.items() if not w or w[-1] <= now - 60]:
            del self._hits[key]
