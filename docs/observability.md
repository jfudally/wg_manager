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

## Tracing (Phase 3a cycle 2)

OpenTelemetry trace exporter on the provisioning path. Three
exporter modes selected via `OTEL_EXPORTER`:

- **`none`** (default) — zero overhead. The tracer provider is the
  NoOp default; calls into the wrapping helpers compile to nothing.
  v0.1.0 operators who don't run a collector pay nothing.
- **`console`** — every finished span prints to stderr. Local dev.
- **`otlp-http`** — POSTs to `OTEL_EXPORTER_OTLP_ENDPOINT` (default
  `http://localhost:4318`). Production wires this at a collector
  that fans out to Jaeger / Tempo / Honeycomb / etc.

### Span topology

A single provisioning run produces a trace shaped like:

```
celery.wg_manager.tasks.provision_server           (root)
├── vault.ssh.sign-user
├── ssh.run         (cmd="apt install wireguard")
├── ssh.run         (cmd="wg-quick up wg0")
├── vault.ssh.sign-host
└── ssh.run         (cmd="install host cert")
```

Three families:

| Family | Span name | Attributes | Wrapped by |
|---|---|---|---|
| Celery tasks | `celery.<task_name>` | task args | `CeleryInstrumentor` (auto) |
| Vault round-trips | `vault.<engine>.<operation>` | `vault.engine`, `vault.operation` | `vault_call` ctx mgr |
| SSH commands | `ssh.<operation>` | `ssh.host`, `ssh.cmd` | `ssh_span` ctx mgr |

The Vault span is emitted by the same `vault_call` context manager
that records the cycle 1 metrics — one wrap site, two streams. A
metric-only deployment and a metric+trace deployment never drift.

### Configuring an OTLP collector

A minimal stack: run an OpenTelemetry Collector locally, point
`OTEL_EXPORTER_OTLP_ENDPOINT` at it, and configure the collector's
exporters to your preferred backend (Jaeger, Tempo, Honeycomb,
SigNoz, ...).

```yaml
# otel-collector-config.yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318

exporters:
  otlphttp:
    endpoint: https://api.honeycomb.io
    headers:
      x-honeycomb-team: ${env:HONEYCOMB_API_KEY}

service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [otlphttp]
```

Then on the wg-manager side:

```bash
export OTEL_EXPORTER=otlp-http
export OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector.internal:4318
export OTEL_SERVICE_NAME=wg-manager
make run     # API
make worker  # Celery worker (gets its own setup_tracing call)
```

The worker process picks up the same env via
`wg_manager.celery_app`'s top-level `setup_tracing` call — every
provisioning task gets a trace under the worker, not just the API.

## Cert lifecycle (Phase 3a cycle 3)

A second Grafana dashboard +
[`docs/observability/grafana-cert-lifecycle.json`](observability/grafana-cert-lifecycle.json),
plus a per-cert TTL gauge so the operator dashboard can render
"expiring soon" tables and the Prometheus alerting rule can fire
at the right threshold.

### Cert-expiry gauge

The new metric:

| Metric | Type | Labels |
|---|---|---|
| `wg_manager_cert_not_after_seconds` | Gauge | `serial`, `cn`, `cert_type` |

A custom collector walks the `certificate` table on every scrape
and emits one sample per **non-revoked** row (revoked rows are
deliberately excluded — emitting their expiry would either fire
noisy "expiring soon" alerts on a cert nobody cares about, or mask
the absence of a real replacement).

Cardinality is bounded by the active cert count (operators +
service certs, typically tens) so per-cert labels are safe.

Useful PromQL:

```promql
# Certs expiring in the next 7 days
(wg_manager_cert_not_after_seconds - time()) < 7 * 86400

# Top 20 by nearest expiry
bottomk(20, wg_manager_cert_not_after_seconds)

# Active cert count by type
count by (cert_type) (wg_manager_cert_not_after_seconds)
```

### Cert-lifecycle dashboard

[`docs/observability/grafana-cert-lifecycle.json`](observability/grafana-cert-lifecycle.json)
ships 5 panels:

1. **Certs by nearest expiry (top 20)** — table view. Row-by-row
   plan for the next rotation sweep.
2. **Expiring within 7 days, by type** — single-stat per cert type.
3. **Expiring within 30 days, by type** — same, longer horizon.
4. **Cert lifecycle event rate by type** — issue / renew / revoke
   timeseries. A renewal spike here should match the cert-renew
   systemd-timer firings; a steady issue rate without matching
   renewals points at the renewal walker being stuck.
5. **Active cert count by type** — total non-revoked, by type.
   Sudden drops or rises are worth investigating.

Import via **Dashboards → Import → Upload JSON file** just like
the cycle 1 service-health dashboard.

## Alerting recipes (Phase 3a cycle 3)

[`docs/observability/prometheus-alerts.yaml`](observability/prometheus-alerts.yaml)
ships three alert rules covering the most operationally-meaningful
failure modes:

| Alert | Trigger | Runbook |
|---|---|---|
| `Wg5xxSurge` | 5xx fraction > 5% over 5m | [`observability.md#alerting-recipes`](#alerting-recipes) |
| `WgVaultLatencyHigh` | Vault round-trip p95 > 2s for 5m | [`docs/runbooks/vault-down.md`](runbooks/vault-down.md) |
| `WgCertExpiringSoon` | Non-revoked cert TTL < 7 days | [`docs/deploy/systemd-timer.md`](deploy/systemd-timer.md) |

Drop the YAML into your Prometheus config:

```yaml
# prometheus.yml
rule_files:
  - /etc/prometheus/wg-manager-alerts.yaml
```

Tune the `for:` durations to your deployment's pain tolerance.
The defaults are conservative: short enough to catch real
incidents, long enough that a transient blip doesn't page
on-call.

### Annotated runbooks

Each rule includes a `runbook` annotation pointing at the
corresponding wg-manager runbook so an Alertmanager template
can render it as a clickable link in the page payload:

```yaml
# alertmanager template (example)
{{ define "runbook" -}}
{{- if .Annotations.runbook }}https://github.com/jfudally/wg_manager/blob/main/{{ .Annotations.runbook }}{{ end -}}
{{- end }}
```
