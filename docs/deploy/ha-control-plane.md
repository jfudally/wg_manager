# HA control plane (Phase 3d)

Phase 3d makes the wg-manager API safe to run as **two or more
replicas behind a load balancer**. This doc captures the design
contracts and operator workflow; the cycle-by-cycle work itself
lives in the ROADMAP and CHANGELOG.

## Topology

```
                  ┌────────────────┐
                  │   operator     │  mTLS client cert
                  │   browser/CLI  │
                  └────────┬───────┘
                           │ mTLS
                  ┌────────▼───────┐
                  │ load balancer  │  health-checks /healthz + /readyz
                  │ (nginx/Caddy/  │  passes mTLS through (no
                  │  Traefik)      │  termination at the LB layer)
                  └─┬───────────┬──┘
                    │           │
              ┌─────▼───┐   ┌───▼─────┐
              │ wg-mgr  │   │ wg-mgr  │
              │ API #1  │   │ API #2  │
              └──┬──────┘   └────┬────┘
                 │               │
                 └───────┬───────┘
                         │
              ┌──────────▼────────────┐
              │ MySQL (primary)       │  every replica → one writable DB
              │ Vault (Transit + PKI) │  every replica → same Vault
              │ Valkey (Celery)       │  every replica → same broker
              └───────────────────────┘
```

Key invariants:

1. **No session stickiness.** Any request can hit any replica.
2. **mTLS termination at each replica**, not at the LB. The LB
   passes the TLS connection through (TCP-mode for nginx, `tls
   passthrough` for Traefik). Terminating at the LB would force
   wg-manager to trust whatever subject the LB inserted, which
   undermines Phase 2d's "operator cert == operator identity"
   contract.
3. **External state lives in the lower tier.** MySQL, Vault, and
   Valkey are shared; no replica writes to local disk during a
   request.

## Probe contract

Two probes ship under `/healthz` and `/readyz` (Phase 3d cycle 1).
Both are dual-mounted at `/v1/healthz` + `/v1/readyz` per Phase 3c.
Both **bypass mTLS** so a load balancer without a client cert can
poll them.

| Probe | Returns 200 when | Returns 503 when |
|---|---|---|
| `/healthz` | The Python process is alive and FastAPI is handling requests | Never. Liveness is intentionally orthogonal to dependency health. |
| `/readyz` | Every external dep is reachable (cycle 1: MySQL; later cycles: Vault, Valkey) | Any dep round-trip fails. Body carries per-dep status so the LB-side log shows which dep is down. |

### Why two probes?

A single combined probe would conflate "kill this pod" with "stop
routing to this pod". When MySQL has a transient outage, you do
**not** want every replica to fail its liveness probe and restart
simultaneously — the outage would cascade indefinitely. Splitting
liveness from readiness lets the LB take a replica out of rotation
without the orchestrator restarting it.

### Configuring the LB

`nginx` example:

```
upstream wg_manager_api {
    server api1.internal:8000;
    server api2.internal:8000;
}

server {
    listen 443 ssl;
    # TLS passthrough — do NOT terminate here; mTLS belongs at the
    # replica so the operator cert reaches MTLSAuthMiddleware intact.
    proxy_pass https://wg_manager_api;
    # Health checks use plain HTTPS without a client cert.
    health_check uri=/readyz interval=10s passes=2 fails=3
                 match=ready_match;
}

match ready_match {
    status 200;
    header content-type ~ "application/json";
}
```

## Statelessness checklist

Before adding a new endpoint or middleware, verify:

- [ ] No module-level mutable `dict` / `set` / `list` on the
      request path. Caches that depend on data only one replica
      wrote are cross-replica unsafe.
- [ ] No file-system writes outside operator-controlled CLI paths.
      A row that points at a file only one replica has is a
      stickiness requirement.
- [ ] No in-process locks / counters / rate-limit state.
      Externalize to Valkey or the DB.
- [ ] No "if not bootstrapped, bootstrap" startup hooks that
      mutate external state — the second replica racing the first
      is a hazard.
- [ ] All secret material flows through Vault Transit / SSH CA /
      PKI. The `LocalDev*` backends are dev-only and are blocked
      at startup (`_enforce_ha_startup_guards`) when production
      posture is enabled (`TLS_REQUIRED=true`) without explicit
      cross-replica PEM pinning.
- [ ] New endpoints that mutate state grep cleanly for
      `_CACHE`, `lru_cache`, `write_text`, `Lock`. None of these
      are forbidden — they're stop signs that demand a "is this
      cross-replica safe?" answer in the PR description.

## Startup guards

`wg_manager.main._enforce_ha_startup_guards` runs once at
`create_app()` time. It fires `RuntimeError` when:

- `TLS_REQUIRED=true` AND `PKI_BACKEND=local` AND no
  `PKI_LOCAL_DEV_*` PEMs are pinned.
- `TLS_REQUIRED=true` AND `SSH_CA_BACKEND=local` AND no
  `SSH_CA_LOCAL_DEV_PEM` is pinned.

Both shapes would silently produce per-replica divergent CAs in
production. The error message names the env vars to set, so an
operator can fix the misconfiguration without reading source.

The dev posture (`TLS_REQUIRED=false`, used by the test suite and
local development) is permitted to run the local backends
unpinned.

## Celery worker scaling (Phase 3d cycle 2)

The Celery side is safe to run as 2+ workers behind the same broker.
Cycle 2 added the at-least-once delivery contract and a per-task
idempotency review.

### Delivery contract

Two Celery config flags together produce at-least-once delivery:

| Flag | Value | Effect |
|---|---|---|
| `task_acks_late` | `True` (shipped Phase 1) | Tasks acknowledged on success, not receipt. A worker that picks up a task and dies before completing it leaves the task in the broker. |
| `task_reject_on_worker_lost` | `True` (cycle 2) | Hard worker death (SIGKILL, OOM, container terminated) is treated as a failure — the broker re-queues. Without this, a SIGKILL'd worker mid-task drops the task silently. |

Together: **every task in `wg_manager.tasks` may be delivered more
than once**, and every task is written to be safe under re-delivery.

### Per-task idempotency table

| Task | Verdict | Reason |
|---|---|---|
| `provision_server_task` | **GUARDED_BY_ROW_LOCK** | Cycle 3 added `task_row_lock("server", server_id)` around the body. Concurrent workers serialize at the lock; on contention the second worker skips. Remote SSH commands remain re-run safe as the belt to the lock's suspenders. |
| `rotate_host_cert_task` | **GUARDED_BY_ROW_LOCK** | `task_row_lock("server", server_id)`. No racing Vault signatures. |
| `reconfigure_server_task` | **GUARDED_BY_ROW_LOCK** | `task_row_lock("server", server_id)`. No racing `wg-quick` flaps. |
| `provision_client_task` | **GUARDED_BY_ROW_LOCK** | `task_row_lock("client", client_id)`. Follow-up `reconfigure_server_task` takes its own lock. |
| `discover_peers_task` | **NATURALLY_IDEMPOTENT** | Read-only SSH + upsert keyed on `(server_id, public_key)`. No lock needed — concurrent reads converge on the same row set. |
| `discover_all_peers_task` | **NATURALLY_IDEMPOTENT** | Inherits from `discover_peers_task`. |

Each verdict is also pinned in the task's `__doc__` so a refactor
that rewrites a task body without re-examining the audit trips the
docstring-presence test in `tests/test_celery_ha_config.py`.

### Advisory lock contract (cycle 3)

The four mutating tasks acquire a MySQL advisory lock keyed on the
row they mutate:

```python
with task_row_lock(session, "server", server_id) as acquired:
    if not acquired:
        return {"status": "skipped", "reason": "concurrent_run", ...}
    # ... do the work ...
```

Lock-name shape: `wgm:<scope>:<row_id>` (e.g. `wgm:server:7`,
`wgm:client:42`). The `wgm:` prefix keeps the namespace clean if
the operator's MySQL is shared with other apps using `GET_LOCK`.

Acquire shape: `GET_LOCK(name, 5)` — five-second wait, then fail.
The "fail fast" timeout is suitable for at-least-once delivery:
letting the broker re-deliver in a few seconds is cheaper than
queuing waiters indefinitely.

Release shape: `RELEASE_LOCK(name)` runs on context exit. The lock
is also auto-released when the underlying connection closes, so a
worker crash mid-task leaves no stranded lock.

On SQLite (the test suite), `task_row_lock` is a no-op acquire —
SQLite's `StaticPool` has no multi-connection contention shape
worth modelling. Task-level integration tests monkey-patch the
lock function to simulate the contended branch.

### Adding a new task

The Statelessness checklist above applies, plus:

- [ ] Classify the task as `NATURALLY_IDEMPOTENT`, `BENIGN_OVERWRITE`,
      or `NEEDS_GUARD`. If the third, you must add the guard before
      shipping.
- [ ] Add the verdict to the task's `__doc__` in a `Phase 3d cycle 2`
      stanza — the test in `tests/test_celery_ha_config.py` will
      enforce the marker is present.
- [ ] Add the task to `_EXPECTED_TASK_NAMES` in that same test so a
      future refactor that drops the `@celery_app.task` decorator
      trips a clear assertion.
- [ ] Update the per-task table above.

## What's next

Phase 3d ships in cycles:

- **Cycle 1 (shipped)** — statelessness audit + `/healthz` + `/readyz`
  + startup guards.
- **Cycle 2 (shipped)** — Celery worker scaling contract +
  `task_reject_on_worker_lost` + per-task idempotency audit.
- **Cycle 3 (shipped)** — per-row advisory locks on the 4 mutating
  tasks. Verdicts upgraded from BENIGN_OVERWRITE to
  GUARDED_BY_ROW_LOCK. Read-replica routing deferred to cycle 4.
- **Cycle 4** — docker-compose `ha` profile with the LB +
  multi-replica example, plus the deferred read-replica routing.
