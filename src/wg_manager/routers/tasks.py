"""/tasks router — poll the state of a Celery provisioning task."""

from __future__ import annotations

from celery.result import AsyncResult
from fastapi import APIRouter

from wg_manager.celery_app import celery_app
from wg_manager.schemas import TaskStatusResponse

router = APIRouter(prefix="/tasks", tags=["tasks"])


@router.get("/{task_id}", response_model=TaskStatusResponse)
def get_task_status(task_id: str) -> TaskStatusResponse:
    """Return the current state of a Celery task by ID.

    Unknown task IDs will report ``state="PENDING"`` — Celery cannot
    distinguish "queued but not yet picked up" from "never existed".
    """
    result = AsyncResult(task_id, app=celery_app)
    state: str = result.state
    payload: dict[str, object] | None = None
    error: str | None = None
    if state == "SUCCESS":
        raw = result.result
        if isinstance(raw, dict):
            payload = raw
        else:
            payload = {"value": raw}
    elif state == "FAILURE":
        error = str(result.result)
    return TaskStatusResponse(
        task_id=task_id,
        state=state,
        result=payload,
        error=error,
    )
