"""Fixed-window rate limiter backends (Phase 3f hardening).

Both backends share one contract, so the parametrised cases run
against each:

* ``hit(key, limit, window)`` increments and reports whether the new
  count is within ``limit``, plus seconds until the window resets.
* ``peek(key, limit, window)`` reports the same without incrementing.
  It's used for the failure lockout, which is checked on every request
  but only incremented on failures.
* Windows reset after ``window`` seconds, and keys are independent.

The Redis backend is exercised against a small in-test fake that
implements the handful of commands it uses, with a controllable clock.
Backend failures surface as :class:`RateLimitBackendError` so the
caller can fail closed.
"""

from __future__ import annotations

from typing import Any

import pytest
import redis

from wg_manager.ratelimit import (
    MemoryLimiter,
    RateLimitBackendError,
    RedisLimiter,
    make_limiter,
)


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class _FakeRedis:
    """Just enough Redis for RedisLimiter: INCR, EXPIRE NX, TTL, GET, pipelines."""

    def __init__(self, clock: _Clock) -> None:
        self.clock = clock
        self.data: dict[str, tuple[int, float | None]] = {}
        self.fail = False

    def _live(self, key: str) -> tuple[int, float | None] | None:
        item = self.data.get(key)
        if item and item[1] is not None and item[1] <= self.clock():
            del self.data[key]
            return None
        return item

    def incr(self, key: str) -> int:
        item = self._live(key)
        count = (item[0] if item else 0) + 1
        self.data[key] = (count, item[1] if item else None)
        return count

    def expire(self, key: str, seconds: int, nx: bool = False) -> bool:
        item = self._live(key)
        if item is None or (nx and item[1] is not None):
            return False
        self.data[key] = (item[0], self.clock() + seconds)
        return True

    def ttl(self, key: str) -> int:
        item = self._live(key)
        if item is None:
            return -2
        if item[1] is None:
            return -1
        return max(1, int(round(item[1] - self.clock())))

    def get(self, key: str) -> bytes | None:
        item = self._live(key)
        return str(item[0]).encode() if item else None

    def pipeline(self, transaction: bool = True) -> "_FakePipe":
        return _FakePipe(self)


class _FakePipe:
    def __init__(self, r: _FakeRedis) -> None:
        self.r = r
        self.ops: list[tuple[str, tuple, dict]] = []

    def __getattr__(self, name: str):
        def _queue(*args: Any, **kwargs: Any) -> "_FakePipe":
            self.ops.append((name, args, kwargs))
            return self
        return _queue

    def execute(self) -> list[Any]:
        if self.r.fail:
            raise redis.ConnectionError("valkey down")
        return [getattr(self.r, n)(*a, **k) for n, a, k in self.ops]


@pytest.fixture(params=["memory", "redis"])
def limiter_and_clock(request: pytest.FixtureRequest):
    clock = _Clock()
    if request.param == "memory":
        return MemoryLimiter(clock=clock), clock
    return RedisLimiter(_FakeRedis(clock)), clock


class TestContract:
    def test_allows_up_to_limit_then_blocks(self, limiter_and_clock) -> None:
        lim, _ = limiter_and_clock
        decisions = [lim.hit("k", limit=3, window=60) for _ in range(4)]
        assert [d.allowed for d in decisions] == [True, True, True, False]
        assert decisions[-1].count == 4
        assert 0 < decisions[-1].retry_after <= 60

    def test_window_resets(self, limiter_and_clock) -> None:
        lim, clock = limiter_and_clock
        for _ in range(3):
            lim.hit("k", limit=2, window=60)
        clock.now += 61
        assert lim.hit("k", limit=2, window=60).allowed

    def test_window_is_fixed_not_extended_by_hits(self, limiter_and_clock) -> None:
        """Hammering mustn't push the reset time out forever."""
        lim, clock = limiter_and_clock
        lim.hit("k", limit=1, window=60)
        clock.now += 50
        assert lim.hit("k", limit=1, window=60).retry_after <= 10

    def test_keys_are_independent(self, limiter_and_clock) -> None:
        lim, _ = limiter_and_clock
        lim.hit("a", limit=1, window=60)
        assert not lim.hit("a", limit=1, window=60).allowed
        assert lim.hit("b", limit=1, window=60).allowed

    def test_peek_does_not_increment(self, limiter_and_clock) -> None:
        lim, _ = limiter_and_clock
        assert lim.peek("k", limit=2, window=60).count == 0
        lim.hit("k", limit=2, window=60)
        for _ in range(5):
            d = lim.peek("k", limit=2, window=60)
        assert d.count == 1 and d.allowed

    def test_peek_blocks_once_limit_reached(self, limiter_and_clock) -> None:
        lim, _ = limiter_and_clock
        lim.hit("k", limit=2, window=60)
        lim.hit("k", limit=2, window=60)
        d = lim.peek("k", limit=2, window=60)
        assert not d.allowed
        assert 0 < d.retry_after <= 60


class TestRedisSpecifics:
    def test_keys_are_namespaced(self) -> None:
        fake = _FakeRedis(_Clock())
        RedisLimiter(fake).hit("ip:1.2.3.4", limit=5, window=60)
        assert list(fake.data) == ["wgm:rl:ip:1.2.3.4"]

    def test_backend_error_is_wrapped(self) -> None:
        fake = _FakeRedis(_Clock())
        fake.fail = True
        lim = RedisLimiter(fake)
        with pytest.raises(RateLimitBackendError):
            lim.hit("k", limit=1, window=60)
        with pytest.raises(RateLimitBackendError):
            lim.peek("k", limit=1, window=60)


class TestFactory:
    def test_memory(self) -> None:
        from wg_manager.config import Settings

        assert isinstance(
            make_limiter(Settings(enroll_rate_limit_backend="memory")), MemoryLimiter
        )

    def test_redis_defaults_to_broker_url(self) -> None:
        from wg_manager.config import Settings

        lim = make_limiter(Settings(
            enroll_rate_limit_backend="redis",
            celery_broker_url="redis://:pw@valkey:6379/0",
        ))
        assert isinstance(lim, RedisLimiter)
        kw = lim.client.connection_pool.connection_kwargs
        assert (kw["host"], kw["port"]) == ("valkey", 6379)

    def test_redis_url_override(self) -> None:
        from wg_manager.config import Settings

        lim = make_limiter(Settings(
            enroll_rate_limit_backend="redis",
            enroll_rate_limit_redis_url="redis://other:6380/2",
        ))
        kw = lim.client.connection_pool.connection_kwargs
        assert (kw["host"], kw["port"], kw["db"]) == ("other", 6380, 2)

    def test_unknown_backend_rejected(self) -> None:
        from wg_manager.config import Settings

        with pytest.raises(ValueError):
            make_limiter(Settings(enroll_rate_limit_backend="nope"))
