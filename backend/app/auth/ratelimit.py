"""A small in-memory limit on login attempts per IP address.

This complements the per-account lockout: lockout protects one account from many
guesses; this slows one source trying many accounts (password spraying). It is per
process, which is enough for a single API instance; a shared limiter (database or
reverse proxy) is a hosting decision for M14.
"""

import threading
import time
from collections import defaultdict, deque


class SlidingWindowLimiter:
    def __init__(self, max_events: int, window_seconds: float) -> None:
        self.max_events = max_events
        self.window = window_seconds
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, now: float | None = None) -> bool:
        """Record an attempt for `key`; False if it exceeds the limit."""
        now = time.monotonic() if now is None else now
        with self._lock:
            events = self._events[key]
            while events and events[0] <= now - self.window:
                events.popleft()
            if len(events) >= self.max_events:
                return False
            events.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._events.clear()


# 20 login attempts per 5 minutes per IP address.
login_limiter = SlidingWindowLimiter(max_events=20, window_seconds=300)
