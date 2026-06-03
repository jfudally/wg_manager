"""Celery application for asynchronous provisioning work.

The broker and result backend are read from
:class:`wg_manager.config.Settings` so they honour the same ``.env`` /
environment variables the API uses. Valkey is wire-compatible with Redis,
so the default ``redis://`` scheme works against either.
"""

from __future__ import annotations

from celery import Celery

from wg_manager.config import settings


celery_app = Celery(
    "wg_manager",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["wg_manager.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_track_started=True,
    task_acks_late=True,
    result_expires=3600,
    timezone="UTC",
    enable_utc=True,
)

# Phase 3a cycle 1: importing the metrics module registers its
# ``task_prerun`` + ``task_postrun`` signal handlers as a side effect.
# Importing here (rather than only from ``main``) means the metrics
# fire under the celery worker process too, not just the API.
import wg_manager.metrics  # noqa: F401, E402 — side-effect import
