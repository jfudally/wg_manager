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

### SSH host-cert expiry gauge

| Metric | Type | Labels |
|---|---|---|
| `wg_manager_host_cert_valid_before_seconds` | Gauge | `kind` (`server`/`client`), `id`, `name`, `hostname` |

One sample per `ready` server and SSH-provisioned client with a
recorded host cert: the rows the beat sweep rotates. Manual clients,
rows that are `pending` or in `error`, and rows with no cert yet are
left out, since nothing is meant to renew them.

Beat renews each cert 12h before expiry, so in a healthy fleet every
value sits 12–24h ahead of `time()`. The Celery task counters can't
show rotation failures to Prometheus: they live in the worker
process, and only the API serves `/metrics`.

```promql
# Hours left on each host cert, nearest first
sort((wg_manager_host_cert_valid_before_seconds - time()) / 3600)
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
ships alert rules covering the most operationally-meaningful
failure modes:

| Alert | Trigger | Runbook |
|---|---|---|
| `Wg5xxSurge` | 5xx fraction > 5% over 5m | [`observability.md#alerting-recipes`](#alerting-recipes) |
| `WgVaultLatencyHigh` | Vault round-trip p95 > 2s for 5m | [`docs/runbooks/vault-down.md`](runbooks/vault-down.md) |
| `WgCertExpiringSoon` | Non-revoked cert TTL < 7 days | [`docs/deploy/systemd-timer.md`](deploy/systemd-timer.md) |
| `WgHostCertRotationFailing` | SSH host cert < 8h from expiry for 15m (warning) | [`single-host-prod.md#automatic-host-cert-renewal`](deploy/single-host-prod.md#automatic-host-cert-renewal) |
| `WgHostCertExpired` | SSH host cert past expiry for 5m (critical) | [`single-host-prod.md` Path B](deploy/single-host-prod.md#path-b--cli-for-scripted--ci-use) |

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

## Warm standby (Phase 3d cycle 5e)

The standby host runs no API, so there is no `/metrics` to scrape
there. Instead `make standby-metrics`, run every minute by
`wg-manager-standby-metrics.timer`, writes a **node_exporter
textfile-collector** file. Prometheus scrapes it through the
standby's node_exporter. The units are in
[`systemd-timer.md`](deploy/systemd-timer.md#warm-standby-metrics-and-drill-phase-3d-cycle-5e).

### Setup

1. Run node_exporter on the standby with the textfile collector:
   `--collector.textfile.directory=/var/lib/node_exporter/textfile_collector`.
   The directory must be writable by the timer's user.
2. If you use a different directory, set `STANDBY_METRICS_FILE` in the
   standby's `.env.host`.
3. Scrape the standby's node_exporter as usual (`job="node"`). Keep
   an `up{job="node"} == 0` alert for it. If node_exporter itself
   dies, every standby series goes stale and none of the rules below
   can fire.
4. Load the `wg-manager.standby` rule group from
   [`observability/prometheus-alerts.yaml`](observability/prometheus-alerts.yaml)
   along with the others.

### Metrics

All gauges. Times are Unix timestamps, not ages, so `time() - x`
keeps growing even if the metrics timer stops.

| Metric | Meaning |
|---|---|
| `wg_manager_standby_replication_configured` | 1 if this host is a configured MySQL replica |
| `wg_manager_standby_replication_io_running` / `_sql_running` | 1 if the replica's IO / SQL thread runs |
| `wg_manager_standby_replication_lag_seconds` | `Seconds_Behind_Source`; omitted when MySQL reports NULL |
| `wg_manager_standby_bundle_present` | 1 once a bundle from the primary has been installed |
| `wg_manager_standby_bundle_created_timestamp_seconds` | When the installed bundle (Vault snapshot + files) was created on the primary |
| `wg_manager_standby_bundle_commit_drift` | 1 if the primary's commit differs from the standby's checkout |
| `wg_manager_standby_drill_last_success_timestamp_seconds` / `_failure_` | Last passed / failed `make standby-drill` |
| `wg_manager_standby_metrics_generated_timestamp_seconds` | When the file was written |

### Alerts

| Alert | Fires when | Severity |
|---|---|---|
| `WgStandbyReplicationBroken` | IO or SQL thread down for 5m | critical |
| `WgStandbyReplicationLagging` | lag > 300s for 10m | warning |
| `WgStandbyBundleStale` | no bundle, or the last one is > 1h old, for 15m | warning |
| `WgStandbyCodeDrift` | the primary runs a different commit, for 1h | warning |
| `WgStandbyMetricsStale` | the metrics file is > 10m old, for 5m | warning |
| `WgStandbyDrillFailed` | the latest drill failed | warning |
| `WgStandbyDrillOverdue` | no successful drill in 8 days, or never drilled (after 1h) | warning |

None of these use `absent()`, so a single-host install (no standby
series) stays quiet. `make alerts-check` validates the rules and
runs their promtool unit tests
([`observability/prometheus-alerts.test.yaml`](observability/prometheus-alerts.test.yaml)).
CI runs it too.
