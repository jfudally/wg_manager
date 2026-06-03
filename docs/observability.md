# Observability

Phase 3a ships in three cycles. **Cycle 1** (this doc) covers
Prometheus metrics + a starter Grafana dashboard; **cycle 2** adds
OTLP traces on the provisioning path; **cycle 3** layers a
cert-lifecycle dashboard + Prometheus alerting recipes.

For the phase-by-phase plan see [`ROADMAP.md`](../ROADMAP.md) §
Phase 3a.

## Metrics

The `/metrics` endpoint exposes the standard Prometheus text format
on the same mTLS listener every other route lives on — scrapers
configure a client cert the same way operators do.

### Metric families

| Metric | Type | Labels |
|---|---|---|
| `wg_manager_http_requests_total` | Counter | `method`, `path`, `status` |
| `wg_manager_http_request_duration_seconds` | Histogram | `method`, `path` |
| `wg_manager_celery_tasks_total` | Counter | `task_name`, `state` |
| `wg_manager_celery_task_duration_seconds` | Histogram | `task_name` |
| `wg_manager_vault_requests_total` | Counter | `engine`, `operation`, `result` |
| `wg_manager_vault_request_duration_seconds` | Histogram | `engine`, `operation` |
| `wg_manager_certs_issued_total` | Counter | `cert_type` |
| `wg_manager_certs_renewed_total` | Counter | `cert_type` |
| `wg_manager_certs_revoked_total` | Counter | `cert_type` |

The HTTP `path` label uses the FastAPI **route template** (e.g.
`/clients/{client_id}`), not the raw URL — cardinality stays
bounded by the route table rather than by request volume.

The middleware skips two paths intentionally: **OPTIONS preflight**
(high-volume + low-signal noise from the dashboard CORS
negotiation) and **`/metrics` itself** (Prometheus scrapes every
15s by default, so self-counts mask real traffic patterns).

### Prometheus scrape config

`/metrics` requires a valid mTLS client cert (mint a `cli`-type
cert via `wg-manager certs issue --type cli --cn prometheus`).
Then wire it into your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: wg-manager
    metrics_path: /metrics
    scheme: https
    scrape_interval: 15s
    static_configs:
      - targets: ['wg-manager.internal:8000']
    tls_config:
      ca_file: /etc/prometheus/wg-manager/ca.crt
      cert_file: /etc/prometheus/wg-manager/client.crt
      key_file: /etc/prometheus/wg-manager/client.key
      server_name: wg-manager.internal
```

The cert is recorded in the `certificate` audit registry just like
operator certs, so it's covered by `wg-manager certs renew --due`
and the cycle 4 evidence pack.

### Grafana dashboard

`docs/observability/grafana-dashboard.json` is the starter
dashboard. Import via Grafana UI: **Dashboards → Import → Upload
JSON file**. The dashboard expects a Prometheus datasource — the
import flow asks which one to bind.

Seven panels covering the four metric families:

1. **HTTP request rate by status** — 2xx / 3xx / 4xx / 5xx
   split, in requests-per-second.
2. **HTTP request p95 latency by route** — surfaces slow
   endpoints. The route-template path label keeps this readable.
3. **Celery task throughput by name + state** — provisioning task
   completion rate, split by SUCCESS / FAILURE / REVOKED.
4. **Celery task p95 duration** — flags slow provisioning runs
   before they cascade into timeout failures.
5. **Vault round-trip p95 latency by engine + operation** —
   transit/encrypt, ssh/sign-user, pki/issue, etc. Vault is the
   blast-radius bottleneck so latency here matters.
6. **Vault round-trip rate by engine + result** — ok vs error
   counts. An error spike is the cleanest "Vault is degraded"
   signal.
7. **Cert lifecycle events by type** — issued / renewed / revoked
   per cert type per hour. Useful for confirming the cycle 4
   renewal walker is doing its job.

## Instrumenting your own call sites

Three patterns:

### HTTP

The `MetricsMiddleware` records every HTTP request automatically.
No per-route changes needed.

### Celery

The `task_prerun` / `task_postrun` signal handlers in
`wg_manager.metrics` fire on every task. No per-task changes
needed — even tasks that don't return cleanly land in
`celery_tasks_total{state="FAILURE"}`.

### Vault

The `vault_call` context manager:

```python
from wg_manager.metrics import vault_call

with vault_call(engine="transit", operation="encrypt"):
    client.secrets.transit.encrypt_data(...)
```

Records latency and outcome (`result="ok"` on clean exit,
`result="error"` on any exception, then re-raises). New
Vault-backed call sites should wrap their round-trips in this
context manager so the engine/operation labels stay accurate.

## What's coming next

- **Cycle 2** — OTLP trace exporter on the four provisioning tasks
  + sub-spans for SSH connections and Vault round-trips.
  Configurable exporter (default off; in-memory for tests).
- **Cycle 3** — Operator dashboard for the cert-lifecycle view
  (renewal due dates, expiring-soon, revoked-this-week), plus
  example Prometheus alerting rules (5xx surge, Vault round-trip
  p95 > 2s, cert TTL < 7 days).
