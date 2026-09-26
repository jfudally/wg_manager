"""Fixed-window rate limiting (Phase 3f hardening).

Protects the unauthenticated enrollment endpoint (see
:mod:`wg_manager.enroll_app`). Two interchangeable backends:

* :class:`RedisLimiter`: production. The counters live in Valkey (the
  Celery broker by default), so every enrollment replica shares them.
  Each key is one ``INCR`` plus ``EXPIRE … NX`` in a pipeline, so the
  window starts on the first hit and further hits don't extend it.
* :class:`MemoryLimiter`: tests and single-process dev. Counters live in
  one process only.

Fixed windows are deliberately simple. The worst case is about ``2 ×
limit`` requests across a window boundary, which is fine for coarse
abuse protection. The strict protection is the failure lockout, and a
boundary burst doesn't help an attacker there, because tokens are
unguessable.

Backend failures raise :class:`RateLimitBackendError` so the caller can
fail closed.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

import redis

from wg_manager.config import Settings

_KEY_PREFIX = "wgm:rl:"


class RateLimitBackendError(RuntimeError):
    """The limiter's store couldn't be reached or answered garbage."""


@dataclass(frozen=True, slots=True)
class Decision:
    """Outcome of a :meth:`Limiter.hit` or :meth:`Limiter.peek`.

    :ivar allowed: For ``hit``: the new count is within the limit. For
        ``peek``: another attempt would still be within the limit.
    :ivar count: Current count in the window.
    :ivar retry_after: Whole seconds until the window resets (at least 1
        while a window is open, 0 if there's no window yet).
    """

    allowed: bool
    count: int
    retry_after: int


class Limiter(Protocol):
    """Interface both backends implement."""

    def hit(self, key: str, *, limit: int, window: int) -> Decision:
        """Count one event against ``key`` and decide."""
        ...

    def peek(self, key: str, *, limit: int, window: int) -> Decision:
        """Decide without counting."""
        ...


class MemoryLimiter:
    """In-process fixed windows. Thread-safe; not shared across processes."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        """:param clock: Monotonic seconds source; injectable for tests."""
        self._clock = clock
        self._lock = threading.Lock()
        self._windows: dict[str, tuple[int, float]] = {}

    def _current(self, key: str) -> tuple[int, float] | None:
        entry = self._windows.get(key)
        if entry is not None and entry[1] <= self._clock():
            del self._windows[key]
            return None
        return entry

    def _retry_after(self, reset_at: float) -> int:
        return max(1, int(round(reset_at - self._clock())))

    def hit(self, key: str, *, limit: int, window: int) -> Decision:
        """See :meth:`Limiter.hit`."""
        with self._lock:
            entry = self._current(key)
            if entry is None:
                entry = (0, self._clock() + window)
            count, reset_at = entry[0] + 1, entry[1]
            self._windows[key] = (count, reset_at)
            return Decision(count <= limit, count, self._retry_after(reset_at))

    def peek(self, key: str, *, limit: int, window: int) -> Decision:
        """See :meth:`Limiter.peek`."""
        with self._lock:
            entry = self._current(key)
            if entry is None:
                return Decision(True, 0, 0)
            return Decision(entry[0] < limit, entry[0], self._retry_after(entry[1]))


class RedisLimiter:
    """Fixed windows in Redis / Valkey, shared by every replica."""

    def __init__(self, client: Any) -> None:
        """:param client: A ``redis.Redis``-compatible client."""
        self.client = client

    def hit(self, key: str, *, limit: int, window: int) -> Decision:
        """See :meth:`Limiter.hit`."""
        k = _KEY_PREFIX + key
        try:
            pipe = self.client.pipeline(transaction=True)
            pipe.incr(k)
            # NX: only the first hit in a window sets the expiry.
            pipe.expire(k, window, nx=True)
            pipe.ttl(k)
            count, _, ttl = pipe.execute()
        except redis.RedisError as exc:
            raise RateLimitBackendError(str(exc)) from exc
        count = int(count)
        return Decision(count <= limit, count, max(1, int(ttl)) if ttl > 0 else window)

    def peek(self, key: str, *, limit: int, window: int) -> Decision:
        """See :meth:`Limiter.peek`."""
        k = _KEY_PREFIX + key
        try:
            pipe = self.client.pipeline(transaction=True)
            pipe.get(k)
            pipe.ttl(k)
            raw, ttl = pipe.execute()
        except redis.RedisError as exc:
            raise RateLimitBackendError(str(exc)) from exc
        count = int(raw) if raw is not None else 0
        if count == 0:
            return Decision(True, 0, 0)
        return Decision(count < limit, count, max(1, int(ttl)) if ttl > 0 else window)


def make_limiter(settings: Settings) -> MemoryLimiter | RedisLimiter:
    """Build the limiter selected by ``ENROLL_RATE_LIMIT_BACKEND``.

    :param settings: Resolved settings.
    :return: A :class:`RedisLimiter` pointed at
        ``ENROLL_RATE_LIMIT_REDIS_URL`` (default: the Celery broker URL),
        or a :class:`MemoryLimiter`.
    :raises ValueError: For an unknown backend name.
    """
    backend = settings.enroll_rate_limit_backend
    if backend == "memory":
        return MemoryLimiter()
    if backend == "redis":
        url = settings.enroll_rate_limit_redis_url or settings.celery_broker_url
        # Short timeouts: a stalled Valkey must turn into a quick 503,
        # not a hung enrollment request.
        client = redis.Redis.from_url(
            url, socket_timeout=2, socket_connect_timeout=2
        )
        return RedisLimiter(client)
    raise ValueError(
        f"ENROLL_RATE_LIMIT_BACKEND must be 'redis' or 'memory', got {backend!r}"
    )
