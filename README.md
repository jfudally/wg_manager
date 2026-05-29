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
manage SSH roles, register servers/clients, and trigger discovery
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
    IdentityFile ~/.ssh/<role-name>
```

`HostName` is the bare WireGuard IP (the stored `/32` is stripped).
`IdentityFile` uses the role name as a filename convention only —
wg-manager itself no longer stores SSH private keys (Phase 2c
retired that), and the worker's own provisioning connections use
short-lived Vault-signed certs. Operators who want to SSH into the
clients themselves keep their personal keys under `~/.ssh/` (named
to match the role for convenience) and reach the box with `ssh
<name>.vpn` after connecting to the VPN.

```bash
wg-manager clients ssh-config                # print to stdout
wg-manager clients ssh-config -o ~/.ssh/wg-manager.conf
```

A common pattern is to write the block to its own file and `Include` it
from `~/.ssh/config` so the export can be regenerated without touching
the rest of your SSH config.

## Encryption at rest

Every persisted secret (today: manual-client WireGuard private keys
only — SSH private keys are no longer stored as of Phase 2c CP4.4)
is wrapped via [`wg_manager.crypto`](src/wg_manager/crypto.py). Two
backends share the same contract:

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

Alembic revisions:

- `0004_encryption_at_rest` — adds `_ct` ciphertext columns
  (dual-write).
- `0005_drop_plaintext` — drops the legacy plaintext columns. Apply
  only after `GET /crypto/status` reports `sshkey_legacy == 0` and
  `client_legacy == 0`; the cookbook documents the full sequence.

## SSH CA (Phase 2c)

wg-manager **does not store SSH private keys**. Every worker
connection mints a fresh Ed25519 keypair in memory, asks an SSH CA
to sign the public half, hands the (private PEM, cert) pair to
paramiko for one session, then drops both on the floor. The `sshkey`
table is a name-and-mode label — a *role* you reference from a
server or client row, not a credential store.

Host-key verification flips from TOFU
(`paramiko.AutoAddPolicy`) to
[`KnownHostsCAPolicy`](src/wg_manager/ssh.py): the worker only
trusts hosts whose presented host cert chains back to the same
Vault CA the user certs come from.
[`wg_manager.ssh_ca`](src/wg_manager/ssh_ca.py) is the module; both
backends (`vault` for prod, `local` for dev/tests) share one
contract.

Backend selection mirrors `wg_manager.crypto`:

```bash
SSH_CA_BACKEND=vault                           # production
SSH_CA_VAULT_MOUNT=ssh
SSH_CA_VAULT_USER_ROLE=wg-manager-provision
SSH_CA_VAULT_HOST_ROLE=wg-manager-hosts
```

Bootstrap the Vault SSH engine + the two roles (idempotent):

```bash
make ssh-ca-bootstrap
```

## How to add a server

The Phase 2c flow is **role-first**: register a role name, then
register a server that references it. No private keys to upload.

1. **Bootstrap the Vault SSH CA** (once per cluster):

   ```bash
   make vault-up                # dev Vault on :8200
   make ssh-ca-bootstrap        # creates SSH engine + the two roles
   ```

2. **Register a role.** Dashboard: **SSH Roles → + Add SSH role**
   and pick a memorable name (`lab-2026`, `prod-edge`, …). CLI
   equivalent: `wg-manager keys add --name lab-2026`. The row
   carries no credential material — it's a label that ties future
   server / client rows back to the Vault CA configuration.

3. **Register the server.** Dashboard: **Servers → + Register hub
   server**; fill in hostname, SSH port (22), SSH username (the
   account on the box that will accept the cert; defaults to
   `root` for self-managed boxes, `ubuntu` for Ubuntu AMIs, etc.),
   and pick the role you just created. CLI equivalent:
   `wg-manager servers register -H <hostname> -u <ssh-user> -e
   <endpoint-host> -k <role-id>` (the role ID is the integer
   surfaced by `wg-manager keys list`). The control plane sets
   the row to `pending` and
   dispatches a Celery task that:
   * mints a short-lived user cert against the role, opens an SSH
     session with `KnownHostsCAPolicy` (TOFU is off);
   * installs WireGuard, writes `/etc/wireguard/wg0.conf`, and
     brings up the interface;
   * mints + installs a Vault-signed host cert into
     `/etc/ssh/sshd_config.d/wg-manager.conf` so future sessions
     can validate the host cert chain;
   * flips the row to `ready`.

4. **First-connect requirements on the target host.** The Vault
   CA's pubkey must be installed as `TrustedUserCAKeys` on the
   target host *before* the first wg-manager registration —
   otherwise sshd will reject the user cert and the provisioning
   task fails. The cookbook
   [`docs/migrations/2c-ssh-ca.md`](docs/migrations/2c-ssh-ca.md)
   walks through this for both fresh hosts and fleets being
   migrated off the Phase 1 / 2b stored-key model.

Phase 2c shipped across five checkpoints (CP1–CP5) — module +
runner + host install + per-row routing + migration + dockerised-
sshd acceptance suite. See `ROADMAP.md` for the full history and
`docs/migrations/2c-ssh-ca.md` for the operator-facing migration
cookbook covering fleets provisioned under the Phase 1 / 2b
stored-key model.

Tests:

```bash
make test                        # fast hermetic suite (uses local CA)
make vault-up && make e2e-up
make test-e2e                    # CP5 acceptance against dockerised sshd
```

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
make test                        # fast hermetic suite — in-memory
                                 # SQLite, FakeSSHRunner, local CA
make test-e2e                    # Phase 2c CP5 dockerised-sshd
                                 # acceptance suite (needs Vault +
                                 # the sshd-e2e container; see the
                                 # SSH CA section above)
```

The fast suite (`make test`) uses an in-memory SQLite DB and a fake
SSH runner; no network or real MySQL/Vault is required. The e2e
suite is opt-in via the `e2e` pytest marker so the default
invocation stays under 60 seconds and doesn't drag docker into the
inner loop.

## Roadmap, security, and threat model

- [`ROADMAP.md`](ROADMAP.md) lays out the phases. Phase 0 (spike),
  Phase 1 (MVP), Phase 2a (Vault spike), 2b (encryption at rest),
  and 2c (Vault SSH CA — no more stored SSH keys) are shipped.
  Phase 2d (TLS / mTLS everywhere via Vault PKI) and 2e (supply
  chain + audit) are the active work.
- [`SECURITY.md`](SECURITY.md) lists the current security posture,
  what wg-manager today explicitly does not defend against, and how
  to report a vulnerability.
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) is the STRIDE
  model the roadmap phases are tied to. Every threat in the table
  names the phase that closes (or has closed) it.

**Not yet a finished system.** Phases 2d and 2e are still ahead —
the API has no auth, the app ↔ MySQL link is plaintext, and there's
no audit log. See
[`SECURITY.md`](SECURITY.md#current-posture) for the concrete state
and the hardening recommendations for production use today.
