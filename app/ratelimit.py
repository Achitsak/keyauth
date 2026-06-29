from collections import defaultdict, deque


class RateLimiter:
    def __init__(self):
        self._hits: dict[str, deque] = defaultdict(deque)

    def allow(self, bucket: str, limit: int, window: int, now: int) -> bool:
        q = self._hits[bucket]
        cutoff = now - window
        while q and q[0] <= cutoff:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        return True

    def reset(self):
        self._hits.clear()

    def sweep(self, now: int, max_window: int) -> None:
        cutoff = now - max_window
        for bucket in list(self._hits.keys()):
            q = self._hits[bucket]
            while q and q[0] <= cutoff:
                q.popleft()
            if not q:
                del self._hits[bucket]


limiter = RateLimiter()
