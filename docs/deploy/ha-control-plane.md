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

## What's next

Phase 3d ships in cycles. Cycle 1 (this doc) lands the
statelessness audit + `/healthz` + `/readyz` + startup guards.
Subsequent cycles will layer:

- **Cycle 2** — Celery worker scaling guarantees (beat scheduler
  safety, task idempotency review).
- **Cycle 3** — MySQL primary + read replica routing.
- **Cycle 4** — docker-compose `ha` profile with the LB +
  multi-replica example.
