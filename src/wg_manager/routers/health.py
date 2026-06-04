"""/healthz + /readyz — Phase 3d cycle 1 HA control-plane probes.

Two probes, two contracts:

* ``/healthz`` (liveness) — "is this process alive?" Returns 200
  unconditionally as long as the FastAPI handler chain is running.
  The load balancer uses this to decide whether to restart the pod;
  an out-of-pool replica whose handlers still answer is healthy.
  Liveness must **not** touch the database or any other external
  dep — a transient MySQL outage would otherwise have the LB
  restart every replica simultaneously, which makes the outage
  permanent.
* ``/readyz`` (readiness) — "can this process serve traffic *right
  now*?" Returns 200 only when every external dependency is
  reachable; otherwise 503 with a structured per-dep status body
  the LB can log + the operator can read. The cycle 1 dep set is
  just the database (the only hard requirement to serve any
  request); cycle 2 will layer Vault + Celery broker checks on top
  once the API needs them per request.

Both endpoints **bypass mTLS auth**. Load balancers don't carry
operator certs (and shouldn't — they're infra, not API callers).
:class:`wg_manager.auth.MTLSAuthMiddleware` consults
:meth:`is_health_path` (this module's constants are the source of
truth) to decide.

Mounted at both ``/`` and ``/v1`` — the dual mount keeps it cheap
(same handler, two routes) and matches Phase 3c's contract.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlmodel import Session, select


# Path constants exported so :class:`MTLSAuthMiddleware.is_health_path`
# can match without importing the router (which would pull FastAPI
# into the auth path).
HEALTHZ_PATH = "/healthz"
READYZ_PATH = "/readyz"
V1_HEALTHZ_PATH = "/v1/healthz"
V1_READYZ_PATH = "/v1/readyz"

HEALTH_PATHS: frozenset[str] = frozenset(
    {HEALTHZ_PATH, READYZ_PATH, V1_HEALTHZ_PATH, V1_READYZ_PATH}
)


# Router uses no prefix — the two probes live at the root and the
# /v1 mount is added by ``main.create_app`` for parity with every
# other router (Phase 3c contract).
router = APIRouter(tags=["health"], include_in_schema=False)


@router.get("/healthz")
def healthz() -> dict[str, str]:
    """Liveness probe — 200 iff the process is up.

    Deliberately does **no** dep checks. Touching the DB here would
    let a transient MySQL outage cascade to "every replica fails
    its liveness probe, every replica restarts, MySQL stays down,
    pods keep restarting". Liveness must be ortgonal to dep health.
    """
    return {"status": "ok"}


@router.get("/readyz")
def readyz() -> JSONResponse:
    """Readiness probe — 200 iff every external dep is reachable.

    Cycle 1 ships the database check only; Vault + Celery broker
    layers in subsequent cycles. The response body always carries
    the per-dep status so an operator running ``curl
    https://api/readyz`` sees what was checked + what passed.

    Status codes:

    * **200** with ``{"status": "ok", "checks": {...}}`` when every
      dep is reachable.
    * **503** with ``{"status": "degraded", "checks": {...}}`` when
      any dep is unreachable. The LB takes the replica out of
      rotation; new requests land on a healthy replica until the
      dep comes back.
    """
    checks: dict[str, Any] = {}
    overall_ok = True

    # --- DB probe ----------------------------------------------------
    try:
        # Import locally so a test that monkeypatches
        # ``db_module.engine`` mid-test sees the patched value (the
        # module-level engine is rebound, not mutated).
        from wg_manager import db as db_module

        with Session(db_module.engine) as session:
            session.exec(select(1)).all()
        checks["db"] = "ok"
    except Exception as exc:
        overall_ok = False
        # Stringify the exception so the LB-side log shows the
        # exact driver error rather than a typed object. Truncate so
        # a long pymysql traceback doesn't blow the body up.
        msg = str(exc)
        if len(msg) > 200:
            msg = msg[:200] + "…"
        checks["db"] = f"error: {msg}"

    body = {
        "status": "ok" if overall_ok else "degraded",
        "checks": checks,
    }
    return JSONResponse(
        status_code=200 if overall_ok else 503,
        content=body,
    )
