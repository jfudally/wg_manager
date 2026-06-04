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

## Bootstrap sequence (one-time)

The order matters: the API needs certs minted from the Vault PKI,
which means Vault has to be up and bootstrapped first.

### 1. Populate `.env.prod`

```bash
cp .env.prod.example .env.prod
$EDITOR .env.prod
```

Every `${VAR:?...}`-shaped reference in the overlay must be filled
in or `compose up` fails loud at startup. The template's inline
comments document how to generate strong values for each one.

**Treat `.env.prod` like the master password file it is** — every
secret in it can decrypt every secret the substrate protects. Back
it up encrypted; restrict to the operator group; never commit.

### 2. Mint the MySQL server cert bundle

The prod stack pins `DATABASE_TLS_REQUIRED=true`. The CA bundle +
server cert + key must live in `tls/mysql/` before MySQL can boot.

```bash
make mysql-tls-issue
```

This invokes Phase 2d CP4.2's cert minter against your local Vault
PKI. **The local Vault has to be up first** — for the initial boot
this means starting just Vault from the dev compose, bootstrapping
PKI, minting the cert, then tearing the dev Vault down. The Make
target documents the sequence if Vault isn't reachable.

### 3. Bring up the data tier only

```bash
make prod-up
```

Compose brings up everything in the merged file — that's fine. The
data tier (mysql, vault, valkey) comes up healthy first; api +
worker + web cycle their healthchecks waiting for Vault to be
bootstrapped (next step).

### 4. Bootstrap the Vault substrate

The three substrate engines need their roles created on the running
Vault before the API can issue or sign anything:

```bash
# These targets read VAULT_ADDR and VAULT_TOKEN from environment;
# export them to point at the prod Vault container.
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN="$(grep ^VAULT_ROOT_TOKEN .env.prod | cut -d= -f2)"

make pki-bootstrap            # Phase 2d — PKI mount + roles
make ssh-ca-bootstrap         # Phase 2c — SSH CA mount + roles
make vault-audit-bootstrap    # Phase 2e — file audit device
```

Each is idempotent — re-runs against a bootstrapped Vault are a
no-op so you can safely re-execute after a `compose down && up` of
the Vault container.

### 5. Mint the API + operator + dashboard certs

```bash
wg-manager operators add --cn ops@yourbox.example --role admin
wg-manager certs issue --type api --cn yourbox.example \
    --out-cert tls/server.crt \
    --out-key tls/server.key \
    --out-chain tls/ca-bundle.crt
wg-manager certs issue --type cli --cn ops@yourbox.example \
    --out-cert tls/client.crt \
    --out-key tls/client.key \
    --out-chain tls/client.chain.crt
```

The `--cn` on the API cert should match the public DNS name
operators will use, or the static IP if there is no DNS yet — TLS
hostname verification trips otherwise.

If the operator CN you minted with `operators add` matches
`BOOTSTRAP_OPERATOR_CN` in `.env.prod`, you can skip the explicit
`operators add` — `MTLSAuthMiddleware` self-registers the first
matching cert it sees.

### 6. Apply Alembic migrations

```bash
# Point the local migration CLI at the prod MySQL (TLS required —
# the helper picks up DATABASE_TLS_* from .env.prod).
set -a; source .env.prod; set +a
export DATABASE_URL=mysql+pymysql://${MYSQL_APP_USER:-wg}:${MYSQL_APP_PASSWORD}@127.0.0.1:3306/${MYSQL_DATABASE:-wg_manager}
export DATABASE_TLS_REQUIRED=true
export DATABASE_TLS_CA_PEM=$(pwd)/tls/mysql/ca.crt
export DATABASE_TLS_CERT_PEM=$(pwd)/tls/mysql/client.crt
export DATABASE_TLS_KEY_PEM=$(pwd)/tls/mysql/client.key
make migrate
```

### 7. Restart api + worker + web

```bash
docker compose --env-file .env.prod \
    -f docker-compose.yml -f docker-compose.prod.yml \
    restart api worker web
```

The healthchecks should flip to `healthy` within ~30s. Smoke from
the operator host:

```bash
curl --cacert tls/ca-bundle.crt \
     --cert tls/client.crt --key tls/client.key \
     https://yourbox.example/v1/healthz
# {"status":"ok"}
```

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
