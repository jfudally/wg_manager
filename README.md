# wg-manager

FastAPI control-plane that registers and manages a WireGuard hub-and-spoke network.

## Quickstart

```bash
make db-up           # MySQL + Valkey via docker compose
make install         # editable install + dev deps
cp .env.example .env
make migrate         # apply Alembic migrations

# In one terminal — the API:
make run             # uvicorn on 127.0.0.1:8000

# In another terminal — the Celery worker that runs provisioning:
make worker
```

OpenAPI docs: http://127.0.0.1:8000/docs

## Dashboard

A Next.js + Tailwind dashboard lives in [`web/`](web/). It talks to the
same FastAPI control plane over HTTP and is the recommended way to
manage SSH keys, register servers/clients, and trigger discovery
interactively. See [`web/README.md`](web/README.md) for setup; quick
start:

```bash
make ui-install      # one-time
make ui-dev          # http://127.0.0.1:3000
```

CORS for the dashboard origin is configured via `CORS_ORIGINS` in
`.env` (defaults to `http://localhost:3000`).

## Async provisioning

`POST /servers` and `POST /clients` return **HTTP 202** with the persisted
row (in `pending` state) plus a Celery `task_id`:

```json
{ "task_id": "8f3...", "server": { "id": 1, "status": "pending", ... } }
```

Poll the task at `GET /tasks/{task_id}` — it returns one of `PENDING`,
`STARTED`, `SUCCESS`, or `FAILURE`. The row's own `status` column also
flips to `ready` or `error` once the task finishes, so `GET /servers/{id}`
or `GET /clients/{id}` is an equally valid way to check progress.

The broker and result backend default to Valkey on `redis://localhost:6379/0`
(Valkey is wire-compatible with Redis). Override via `CELERY_BROKER_URL` /
`CELERY_RESULT_BACKEND` in `.env`.

## Peer discovery

`POST /servers/{id}/discover` SSHes into the hub, runs `wg show <interface>
dump`, parses every peer line, and upserts a row into the `discoveredpeer`
table. The endpoint is idempotent — re-running it refreshes existing rows
keyed on `(server_id, public_key)` and never duplicates. Peers whose public
key matches a managed `Client` on the same server are tagged
`is_managed=true` so you can spot wg-manager-controlled peers at a glance.

Discovery is **fail-soft**: if the server is unreachable (SSH timeout,
auth failure, refused connection) the error is logged at `ERROR` level and
the task returns `status="ssh_failed"` for that server instead of raising.
This lets the batch endpoint walk every host without one bad node aborting
the run.

```bash
wg-manager servers discover 1 --wait        # scan one host, block on the task
wg-manager servers discover-all --wait      # walk every server; skip failures
wg-manager servers discovered-peers 1       # list what was found for host 1
```

`GET /servers/{id}/discovered-peers` returns the per-server peer list;
`GET /servers/discovered-peers/all` returns every discovered peer across
all servers. `POST /servers/discover-all` kicks off the batch task — the
per-host outcome (ok / ssh_failed) is on the task's result payload
visible via `GET /tasks/{task_id}`.

## Manual clients (devices wg-manager can't SSH into)

Some peers can't be provisioned by wg-manager dialling them over SSH —
phones, tablets, IoT boxes, vendor appliances. For those, register a
**manual client**. The control plane:

1. Generates a WireGuard X25519 keypair server-side.
2. Allocates the next free address in the parent server's subnet
   (sharing the pool with SSH-provisioned clients).
3. Stores a `Client` row in `ready` state with `is_manual=true`.
4. Reconfigures the hub so the new peer is admitted.

The operator then fetches the rendered `wg0.conf` and installs it on
the device by hand (drop it at `/etc/wireguard/wg0.conf` on Linux, or
import it into the WireGuard app on a phone — most apps accept the
text body directly or render it as a QR code from a file).

```bash
# Register a phone and write the rendered config straight to disk.
wg-manager clients add-manual \
    --name phone \
    --server-id 1 \
    --config-output ./phone.conf

# Re-export the config later (handy if you lost it).
wg-manager clients config 2 -o ./phone.conf
```

The HTTP equivalents are `POST /clients/manual` (returns the row plus
the hub-reconfigure `task_id`) and `GET /clients/{id}/config` (returns
`text/plain` with the full config body, including the private key).

Manual clients are deliberately excluded from `GET /clients/export/ssh-config`
— wg-manager has no SSH credentials for them — and from
`POST /clients/{id}/reprovision`, which would try to SSH in. Use the
config-export endpoint to roll keys (delete the row, add a fresh
manual client) instead.

## SSH config export

Once clients are provisioned, `GET /clients/export/ssh-config` (or
`wg-manager clients ssh-config`) renders a ready-to-append `~/.ssh/config`
block. Every managed client becomes one entry:

```
Host <name>.vpn
    HostName <wg-assigned-ip>
    User <ssh_username>
    IdentityFile ~/.ssh/<ssh-key-name>
```

`HostName` is the bare WireGuard IP (the stored `/32` is stripped), and
`IdentityFile` assumes the private key has been placed under your local
`$HOME/.ssh/` using the same name the key is registered with in
wg-manager. Type `ssh <name>.vpn` after connecting to the VPN to reach
the box.

```bash
wg-manager clients ssh-config                # print to stdout
wg-manager clients ssh-config -o ~/.ssh/wg-manager.conf
```

A common pattern is to write the block to its own file and `Include` it
from `~/.ssh/config` so the export can be regenerated without touching
the rest of your SSH config.

## Encryption at rest

Every persisted secret (SSH private keys, SSH passphrases, manual-client
WireGuard private keys) is wrapped via
[`wg_manager.crypto`](src/wg_manager/crypto.py). Two backends share the
same contract:

- **`vault`** (production) — HashiCorp Vault Transit. Plaintext goes
  over the connection; ciphertext comes back. The master key never
  leaves Vault.
- **`local`** (dev / tests) — Fernet keyed from `CRYPTO_LOCAL_DEV_KEY`.
  Convenient but the key lives in the app's environment, so a host
  compromise reads every secret. **Never set this in production.**

Pick a backend in `.env`:

```bash
CRYPTO_BACKEND=vault
VAULT_ADDR=http://127.0.0.1:8200
VAULT_TOKEN=dev-only-root            # Phase 2e replaces with AppRole
CRYPTO_VAULT_TRANSIT_KEY=wg-manager  # must be created with derived=true
```

Then provision the Transit key (one-time):

```bash
vault secrets enable transit
vault write -f transit/keys/wg-manager derived=true
```

Operator surfaces:

- `GET /crypto/status` and the **Crypto** page on the dashboard show
  the active backend, the current Transit key version, and per-table
  counts of rows holding ciphertext vs. legacy rows that bypassed the
  encryption seam.
- After a Transit rotation (`vault write -f
  transit/keys/wg-manager/rotate`), run `wg-manager crypto rewrap` so
  every row lands on the same key version. Idempotent — safe to run
  on a schedule.
- Each row's encrypted state is also visible per-row on the **SSH
  Keys** table: an `encrypted` badge means `private_key_ct` is
  populated, `legacy` means the row was inserted bypassing the
  encryption seam.

Alembic revisions:

- `0004_encryption_at_rest` — adds `_ct` ciphertext columns
  (dual-write).
- `0005_drop_plaintext` — drops the legacy plaintext columns. Apply
  only after `GET /crypto/status` reports `sshkey_legacy == 0` and
  `client_legacy == 0`; the cookbook documents the full sequence.

## Migrations

Schema is managed by Alembic. Common commands:

```bash
make migrate                              # alembic upgrade head
make migrate-down                         # alembic downgrade -1
make migration m="add foo column"         # autogenerate a new revision
```

The DB URL is read from `DATABASE_URL` (via `wg_manager.config.settings`)
inside `alembic/env.py`, so it always matches what the app uses.

## Tests

```bash
pytest -q
```

Tests use an in-memory SQLite DB and a fake SSH runner; no network or real
MySQL is required.

## Roadmap, security, and threat model

- [`ROADMAP.md`](ROADMAP.md) lays out the phases. v1 covers Phase 0 (spike)
  and Phase 1 (MVP). Phase 2 is the hardening track — encryption at rest,
  Vault-signed SSH certs, mTLS everywhere, supply-chain hygiene — and is
  the active work.
- [`SECURITY.md`](SECURITY.md) lists the current security posture, what
  v1 explicitly does not defend against, and how to report a
  vulnerability.
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) is the STRIDE model the
  roadmap phases are tied to. Every threat in the table names the phase
  that closes it.

**Do not run v1 against anything you care about.** See
[`SECURITY.md`](SECURITY.md#current-posture-v1) for the concrete reasons
and the v1-deployment hardening recommendations if you must.
