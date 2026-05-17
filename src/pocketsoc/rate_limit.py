from __future__ import annotations

import time
from collections import defaultdict, deque


class SlidingRateLimiter:
    def __init__(self, limit: int = 60, window_seconds: int = 60) -> None:
        self.limit = limit
        self.window = window_seconds
        self._buckets: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.time()
        q = self._buckets[key]
        cutoff = now - self.window
        while q and q[0] < cutoff:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        return True
