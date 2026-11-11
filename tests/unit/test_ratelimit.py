"""Rate limiter tests with a deterministic clock."""
import pytest

from vulnmind.security.ratelimit import RateLimitExceeded, RateLimiter


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def limiter(capacity=3, refill=1.0, clock=None):
    return RateLimiter(capacity=capacity, refill_per_second=refill, clock=clock)


def test_bucket_drains_then_refuses():
    clock = Clock()
    bucket = limiter(capacity=2, refill=1.0, clock=clock)
    bucket.acquire("target-a")
    bucket.acquire("target-a")
    with pytest.raises(RateLimitExceeded):
        bucket.acquire("target-a")
    clock.now = 1.0
    bucket.acquire("target-a")
    assert bucket.available("target-a") == pytest.approx(0.0)


def test_refill_is_capped_at_capacity():
    clock = Clock()
    bucket = limiter(capacity=2, refill=5.0, clock=clock)
    bucket.acquire("a")
    clock.now = 100.0
    assert bucket.available("a") == 2.0


def test_keys_are_isolated_and_tokens_are_counted():
    clock = Clock()
    bucket = limiter(capacity=5, refill=0.5, clock=clock)
    bucket.acquire("a", tokens=5)
    with pytest.raises(RateLimitExceeded):
        bucket.acquire("a")
    bucket.acquire("b")
    assert bucket.available("b") == pytest.approx(4.0)


def test_reset_restores_a_full_bucket():
    clock = Clock()
    bucket = limiter(capacity=1, refill=0.001, clock=clock)
    bucket.acquire("a")
    with pytest.raises(RateLimitExceeded):
        bucket.acquire("a")
    bucket.reset("a")
    bucket.acquire("a")


def test_configuration_is_validated():
    for kwargs in ({"capacity": 0, "refill_per_second": 1.0},
                   {"capacity": True, "refill_per_second": 1.0},
                   {"capacity": 1, "refill_per_second": 0},
                   {"capacity": 1, "refill_per_second": -2}):
        with pytest.raises(ValueError):
            RateLimiter(**kwargs)
    bucket = limiter()
    for key, tokens in ((" ", 1), ("a", 0), ("a", True)):
        with pytest.raises(ValueError):
            bucket.acquire(key, tokens=tokens)
