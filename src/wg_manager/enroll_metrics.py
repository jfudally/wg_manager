"""Outcome counters for ``POST /v1/enroll`` (Phase 3f hardening).

The enrollment listener is its own process on a public, cert-optional
port, so it can't serve ``/metrics`` without exposing it to anyone.
Instead every enroll replica adds its outcomes to **one Valkey hash**,
the same store the rate limiter uses, and the operator API's mTLS
``/metrics`` reads the hash at scrape time
(:class:`wg_manager.metrics.EnrollMetricsCollector`). One scrape then
covers every replica, and there's no new port.

Three counter families, stored as hash fields:

* ``response:<status>``: every enroll response, by HTTP status.
* ``reject:<reason>``: token rejections, by the reason also written to
  the ``enroll.reject`` audit line (``missing_token``, ``unknown_token``,
  ``expired``, ``exhausted``, ...). Callers never see the reason.
* ``rate_limited:<bucket>``: 429s, by bucket (``requests`` /
  ``failures``). Unlike the audit line, every blocked request counts.

Every label value comes from wg-manager's own code, not from the
request, so cardinality is bounded.

Recording is best effort: :meth:`RedisEnrollMetrics.record_response`
and friends never raise, because a metrics outage must not change what
a caller gets. Failures are logged at most once a minute so an attack
during an outage can't flood the log. Reading
(:meth:`~RedisEnrollMetrics.snapshot`) does raise, so the scrape can
report the store as down.

The counters are cumulative from the hash's creation. If Valkey loses
them (restart without persistence, flush), Prometheus sees a counter
reset, which ``rate()`` / ``increase()`` already handle.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Protocol

import redis

from wg_manager.config import Settings

logger = logging.getLogger(__name__)

HASH_KEY = "wgm:enroll:metrics"
_KINDS = ("response", "reject", "rate_limited")
_LOG_EVERY_SECONDS = 60.0


class EnrollMetricsBackendError(RuntimeError):
    """The metrics store couldn't be read."""


@dataclass(frozen=True, slots=True)
class EnrollMetricsSnapshot:
    """Current counter values, keyed by label value.

    :ivar responses: HTTP status (as a string) -> count.
    :ivar rejects: rejection reason -> count.
    :ivar rate_limited: limiter bucket -> count.
    """

    responses: dict[str, int] = field(default_factory=dict)
    rejects: dict[str, int] = field(default_factory=dict)
    rate_limited: dict[str, int] = field(default_factory=dict)


def _snapshot_from_fields(fields: dict[str, int]) -> EnrollMetricsSnapshot:
    """Split ``kind:label`` fields into a snapshot, dropping anything unknown."""
    by_kind: dict[str, dict[str, int]] = {k: {} for k in _KINDS}
    for name, value in fields.items():
        kind, sep, label = name.partition(":")
        if sep and label and kind in by_kind:
            by_kind[kind][label] = value
    return EnrollMetricsSnapshot(
        responses=by_kind["response"],
        rejects=by_kind["reject"],
        rate_limited=by_kind["rate_limited"],
    )


class EnrollMetrics(Protocol):
    """Interface both backends implement."""

    def record_response(self, status: int) -> None:
        """Count one enroll response with HTTP ``status``. Never raises."""
        ...

    def record_reject(self, reason: str) -> None:
        """Count one token rejection for ``reason``. Never raises."""
        ...

    def record_rate_limited(self, bucket: str) -> None:
        """Count one 429 from ``bucket``. Never raises."""
        ...

    def snapshot(self) -> EnrollMetricsSnapshot:
        """Read every counter.

        :raises EnrollMetricsBackendError: If the store can't be read.
        """
        ...


class _Recorder:
    """Shared ``record_*`` front end; subclasses implement :meth:`_incr`."""

    def record_response(self, status: int) -> None:
        """See :meth:`EnrollMetrics.record_response`."""
        self._incr(f"response:{int(status)}")

    def record_reject(self, reason: str) -> None:
        """See :meth:`EnrollMetrics.record_reject`."""
        self._incr(f"reject:{reason}")

    def record_rate_limited(self, bucket: str) -> None:
        """See :meth:`EnrollMetrics.record_rate_limited`."""
        self._incr(f"rate_limited:{bucket}")

    def _incr(self, name: str) -> None:
        raise NotImplementedError


class MemoryEnrollMetrics(_Recorder):
    """In-process counters, for tests and single-process dev.

    Not visible to the operator API's ``/metrics`` unless both run in
    the same process.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counts: Counter[str] = Counter()

    def _incr(self, name: str) -> None:
        with self._lock:
            self._counts[name] += 1

    def snapshot(self) -> EnrollMetricsSnapshot:
        """See :meth:`EnrollMetrics.snapshot`."""
        with self._lock:
            return _snapshot_from_fields(dict(self._counts))


class RedisEnrollMetrics(_Recorder):
    """Counters in one Valkey hash, shared by every enroll replica."""

    def __init__(self, client: Any) -> None:
        """:param client: A ``redis.Redis``-compatible client."""
        self.client = client
        self._last_warning = float("-inf")

    def _incr(self, name: str) -> None:
        try:
            self.client.hincrby(HASH_KEY, name, 1)
        except redis.RedisError as exc:
            # Best effort, and throttled: see the module docstring.
            now = time.monotonic()
            if now - self._last_warning >= _LOG_EVERY_SECONDS:
                self._last_warning = now
                logger.warning("could not record enroll metrics (%s): %s", name, exc)

    def snapshot(self) -> EnrollMetricsSnapshot:
        """See :meth:`EnrollMetrics.snapshot`."""
        try:
            raw = self.client.hgetall(HASH_KEY)
        except redis.RedisError as exc:
            raise EnrollMetricsBackendError(str(exc)) from exc
        fields: dict[str, int] = {}
        for key, value in raw.items():
            name = key.decode() if isinstance(key, bytes) else str(key)
            try:
                fields[name] = int(value)
            except (TypeError, ValueError):
                continue
        return _snapshot_from_fields(fields)


def make_enroll_metrics(settings: Settings) -> MemoryEnrollMetrics | RedisEnrollMetrics:
    """Build the metrics store matching ``ENROLL_RATE_LIMIT_BACKEND``.

    It uses the same store as the rate limiter: ``ENROLL_RATE_LIMIT_REDIS_URL``,
    defaulting to the Celery broker URL. The operator API calls this too,
    so both sides agree on where the counters live.

    :param settings: Resolved settings.
    :raises ValueError: For an unknown backend name.
    """
    backend = settings.enroll_rate_limit_backend
    if backend == "memory":
        return MemoryEnrollMetrics()
    if backend == "redis":
        url = settings.enroll_rate_limit_redis_url or settings.celery_broker_url
        # Short timeouts: a stalled Valkey mustn't hold up an enroll
        # response or a scrape.
        client = redis.Redis.from_url(url, socket_timeout=2, socket_connect_timeout=2)
        return RedisEnrollMetrics(client)
    raise ValueError(
        f"ENROLL_RATE_LIMIT_BACKEND must be 'redis' or 'memory', got {backend!r}"
    )
