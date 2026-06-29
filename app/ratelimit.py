import threading
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self):
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, bucket: str, limit: int, window: int, now: int) -> bool:
        with self._lock:
            q = self._hits[bucket]
            cutoff = now - window
            while q and q[0] <= cutoff:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True

    def sweep(self, now: int, max_window: int) -> None:
        cutoff = now - max_window
        with self._lock:
            for bucket in list(self._hits.keys()):
                q = self._hits[bucket]
                while q and q[0] <= cutoff:
                    q.popleft()
                if not q:
                    self._hits.pop(bucket, None)

    def reset(self):
        with self._lock:
            self._hits.clear()


limiter = RateLimiter()
