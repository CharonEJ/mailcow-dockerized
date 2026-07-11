"""In-memory sliding-window rate limiter.

Runs inside a single gunicorn worker (see Dockerfile: -w 1 --threads),
so one shared instance covers all requests.
"""

import threading
import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self):
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key, limit, window_seconds):
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and q[0] <= now - window_seconds:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            # opportunistic cleanup of stale keys
            if len(self._hits) > 10000:
                for k in [k for k, v in self._hits.items() if not v]:
                    del self._hits[k]
            return True
