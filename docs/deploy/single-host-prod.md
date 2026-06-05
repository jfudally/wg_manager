# Single-host production stack

`docker-compose.prod.yml` is the operator's path from "dev stack
running on my laptop" to "single-host non-HA stack running on a real
box". It overlays the existing `docker-compose.yml` so the dev file
stays untouched, and adds the three production services the dev
stack omits (`api`, `worker`, `web`) plus hardened overrides on the
existing `mysql` / `valkey` / `vault` services.

This guide documents the **one-time bootstrap sequence** to get the
stack running on a fresh box, plus the day-2 operational reference
(restart behaviour, where the state lives, what to back up).

## When to use this vs. the HA profile

| Posture | When |
|---|---|
| `make ha-up` (Phase 3d cycle 4a) | You want to verify the HA topology — 2 API replicas + nginx passthrough LB — on a single host. **Dev posture** (TLS off, dev cert reuse). |
| `make prod-up` (this guide) | You want a hardened single-host stack to actually serve traffic — TLS on, MySQL TLS on, all backends pinned to Vault, secrets sourced from `.env.prod`. **Non-HA, one of everything.** |

## What you need before the first boot

1. **A linux host with docker + docker compose v2.** Tested on Ubuntu
   22.04 and 24.04. RHEL 9 likely works but is untested.
2. **The repo checked out** in a directory writeable by your operator
   account. The `./tls` directory is bind-mounted into the containers
   for cert delivery — write access matters.
3. **DNS or a static IP** that resolves to the box's public interface,
   for the API and the dashboard listeners.

## Bootstrap (one command)

```bash
cp .env.prod.example .env.prod
$EDITOR .env.prod      # fill in the four CHANGEME values + BOOTSTRAP_OPERATOR_CN
make prod-up           # done
```

That's the whole flow. `make prod-up` boots Vault, runs the two
self-bootstrap containers (Vault PKI / SSH CA / audit + MySQL cert
mint, then migrate + register operator + mint API & CLI certs),
then brings up MySQL + Valkey + api + worker + web in the right
order. `--wait` blocks the command until every service is healthy
or the bootstrap containers have exited 0, so when the make target
returns the stack is fully usable.

Re-running `make prod-up` on existing state is a no-op (cert files
present → skip mint; operator registered → skip; alembic at head →
no-op). Safe to run any time.

### What you fill in

Required values in `.env.prod`:

| Var | What | How to generate |
|---|---|---|
| `VAULT_ROOT_TOKEN` | Vault dev-mode root token | `openssl rand -hex 32` |
| `MYSQL_ROOT_PASSWORD` | MySQL root password (used only at first boot) | `openssl rand -base64 24` |
| `MYSQL_APP_PASSWORD` | App-tier MySQL password (api + worker use this) | `openssl rand -base64 24` |
| `VALKEY_PASSWORD` | Valkey AUTH password | `openssl rand -base64 32` |
| `BOOTSTRAP_OPERATOR_CN` | CN baked into the operator's CLI client cert | DNS-style: `ops@yourbox.example` |

Optional values worth setting for a real DNS-fronted deployment:

| Var | What |
|---|---|
| `API_SERVER_CN` | API server cert CN. Default `localhost`. Set to your public DNS name. |
| `API_SERVER_SANS` | Comma-separated SANs on the API cert. Default `localhost,127.0.0.1,api`. Add your DNS. |
| `WG_MANAGER_API_BIND_ADDR` | Public ingress interface for the API. Default `0.0.0.0`. |
| `WG_MANAGER_WEB_BIND_ADDR` | Public ingress interface for the dashboard. Default `0.0.0.0`. |

**Treat `.env.prod` like the master password file it is** — every
secret in it can decrypt every secret the substrate protects. Back
it up encrypted; restrict to the operator group; never commit.

### Smoke after `make prod-up` returns

```bash
curl --cacert tls/ca-bundle.crt \
     --cert tls/client.crt --key tls/client.key \
     https://yourbox.example/v1/healthz
# {"status":"ok"}

curl --cacert tls/ca-bundle.crt \
     --cert tls/client.crt --key tls/client.key \
     https://yourbox.example/v1/readyz
# {"status":"ok","checks":{"db":"ok"}}
```

Note on the curl flags: `/healthz` + `/readyz` bypass mTLS at the
**app layer**, but uvicorn is configured with `ssl.CERT_REQUIRED` —
the TLS handshake still demands a client cert, so the probe carries
`--cert/--key`. (Open issue: the doc-vs-implementation gap.)

The dashboard is reachable at `http://${WG_MANAGER_WEB_BIND_ADDR}:3000`
— the BFF proxy inside the container handles the mTLS handshake to
`api:8000` using the same operator cert, so the browser sees plain
HTTP.

## What the self-bootstrap actually does

Two run-to-completion containers do the work. They use the same
wg-manager image as api + worker; the bootstrap scripts are
[`scripts/prod_bootstrap_substrate.sh`](../../scripts/prod_bootstrap_substrate.sh)
and [`scripts/prod_bootstrap_app.sh`](../../scripts/prod_bootstrap_app.sh).

| Container | Waits for | Does | Then |
|---|---|---|---|
| `bootstrap-substrate` | Vault healthy | Vault PKI / SSH CA / audit bootstrap, MySQL server + client cert mint into `tls/mysql/`. | Exits 0 → MySQL + Valkey start. |
| `bootstrap-app` | MySQL + Valkey healthy | Alembic `upgrade head`, `operators add` for `BOOTSTRAP_OPERATOR_CN`, API server cert + operator CLI cert mint into `tls/`. | Exits 0 → api + worker + web start. |

The dependency graph is the standard Compose primitive
(`depends_on: { service_completed_successfully }`), so `make prod-down`
followed by `make prod-up` re-walks the same sequence — but each
step short-circuits if its output already exists, which makes the
re-run nearly instant.

## Advanced: manual bootstrap (for debugging)

If self-bootstrap fails partway and you want to drive it by hand
(e.g. to inspect Vault state between mints), the eight-step manual
flow below is exactly what the two bootstrap scripts do — just in
your shell instead of a container. Use it when you need to step
through the cert mints with the wg-manager CLI's TUI prompts
visible.

1. `docker compose ... up -d vault`
2. `export VAULT_ADDR=... VAULT_TOKEN=... PKI_BACKEND=vault CRYPTO_BACKEND=vault SSH_CA_BACKEND=vault`
3. `make pki-bootstrap ssh-ca-bootstrap vault-audit-bootstrap`
4. `make mysql-tls-issue` + `wg-manager certs issue --type mysql-client ...`
5. `docker compose ... up -d mysql valkey`
6. Export `DATABASE_*` env + `make migrate`
7. `wg-manager operators add` + `wg-manager certs issue --type api` + `--type cli`
8. `docker compose ... up -d api worker web`

## Day-2 reference

### Where state lives

| Volume | Service | What it carries |
|---|---|---|
| `wg_manager_mysql_data` | mysql | Schema + all rows. **Back this up.** |
| `wg_manager_valkey_data` | valkey | Celery broker queue (transient — ok to rebuild). |
| `wg_manager_vault_audit_logs` | vault, vector | Vault file audit device output. |
| `wg_manager_vault_data` | vault | Reserved for the Phase 2e file-storage flip — unused today. |

The host's `./tls/` directory holds every cert the stack consumes:
the API server cert, MySQL server + client certs, operator client
cert. Back this up alongside `.env.prod`; without it the stack
won't restart.

### Restart behaviour

Every long-running service in the overlay pins `restart: always`.
The box rebooting brings the stack back up unattended provided:

1. Docker is enabled to start at boot (`sudo systemctl enable docker`).
2. `tls/` and `.env.prod` exist on disk (they survive reboots
   automatically, but a host re-image needs them re-provisioned).
3. **Vault is dev mode.** A Vault restart wipes its in-memory state —
   you re-run `make pki-bootstrap` + the SSH CA + audit bootstrap
   targets. The Phase 2e Vault production cycle is what swaps in
   file storage so this becomes a non-event.

### Known limitations (vs. fully production-ready)

| Limit | When it matters | Mitigation |
|---|---|---|
| **Vault in dev mode** | Vault data lost on container restart; the root token sits in env on api + worker. | Re-bootstrap after restart; rotate token to AppRole (cookbook §5); track Phase 2e Vault production cycle. |
| **No reverse proxy** | API and dashboard each have their own listener on the public interface. | Operator runs an external LB / TLS-terminating ingress for the dashboard if needed. mTLS at the API listener must stay end-to-end. |
| **No Prometheus/Grafana in-stack** | Metrics exposed at `/metrics` but no scraper in the compose file. | Operator scrapes from their existing observability stack. Phase 3a shipped the metric families + Grafana JSON. |
| **Single MySQL** | No primary/replica, no failover. | Track Phase 3d cycle 4b for in-app read-replica routing. |
| **Single Celery worker** | Throughput ceiling at one worker's CPU. | Scale the worker service horizontally — Phase 3d cycle 3's per-row advisory locks make it safe. |
| **`/healthz` + `/readyz` require a client cert despite the Phase 3d cycle 1 doc claim of mTLS bypass** | LB probes must carry a client cert; the in-container Compose healthcheck does so via the operator client cert. | Code-side cycle (planned) flips uvicorn from `ssl.CERT_REQUIRED` to `ssl.CERT_OPTIONAL` so the app-layer `MTLSAuthMiddleware` exemption actually fires. Until then: every probe carries `--cert/--key`. |

### Backups

The Phase 2e backup tooling covers the two pieces of state that
matter:

```bash
make db-backup o=backups/wg-$(date +%F).json    # Phase 2e CP3 — encrypted DB dump
make backup-vault                                # Phase 2e CP5 — Vault raft snapshot (no-op in dev mode)
```

Encrypted DB dumps go in `backups/`; the Vault snapshot target is a
no-op against dev mode (there's no raft store to snapshot) and
becomes useful when the Phase 2e Vault production cycle lands.

## Upgrade path to HA

When ready to scale beyond one host:

1. The Phase 3d HA topology in `docs/deploy/ha-control-plane.md`
   describes the multi-replica + LB shape end-to-end.
2. `make ha-up` (Phase 3d cycle 4a) verifies it works on one host
   first; the compose file teaches you the dependency shape.
3. The HA migration is mostly **moving the data tier off the
   control-plane host** — once MySQL, Vault, Valkey are external,
   the API container scales horizontally with the same image and
   env that this overlay uses.
