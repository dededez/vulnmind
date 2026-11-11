"""Per-target token-bucket rate limiting (design section 15, network constraints).

The limiter is process-local and in-memory: it protects a single worker, not a
cluster, and it is not a substitute for network-level isolation. Callers provide
the clock so tests can advance time deterministically.
"""
from __future__ import annotations

import time
from collections.abc import Callable


class RateLimitExceeded(Exception):
    """The bucket for this key is empty; the call must not proceed."""


class RateLimiter:
    def __init__(self, *, capacity: int, refill_per_second: float,
                 clock: Callable[[], float] | None = None):
        if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity < 1:
            raise ValueError("capacity must be a positive integer")
        if not isinstance(refill_per_second, (int, float)) or isinstance(refill_per_second, bool) \
                or refill_per_second <= 0:
            raise ValueError("refill rate must be positive")
        self._capacity = float(capacity)
        self._refill = float(refill_per_second)
        self._clock = clock or time.monotonic
        self._buckets: dict[str, tuple[float, float]] = {}

    def acquire(self, key: str, tokens: int = 1) -> None:
        if not isinstance(tokens, int) or isinstance(tokens, bool) or tokens < 1:
            raise ValueError("tokens must be a positive integer")
        if not key or not key.strip():
            raise ValueError("rate limit key cannot be blank")
        now = self._clock()
        level, updated = self._buckets.get(key, (self._capacity, now))
        level = min(self._capacity, level + (now - updated) * self._refill)
        if level < tokens:
            self._buckets[key] = (level, now)
            raise RateLimitExceeded(key)
        self._buckets[key] = (level - tokens, now)

    def available(self, key: str) -> float:
        level, updated = self._buckets.get(key, (self._capacity, self._clock()))
        return min(self._capacity, level + (self._clock() - updated) * self._refill)

    def reset(self, key: str) -> None:
        self._buckets.pop(key, None)
