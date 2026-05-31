# wg-manager

FastAPI control-plane that registers and manages a WireGuard hub-and-spoke network.

## Quickstart

```bash
make db-up           # MySQL + Valkey via docker compose
make install         # editable install + dev deps
cp .env.example .env
make migrate         # apply Alembic migrations

# Register an operator + mint API server cert + an operator client
# cert (Phase 2d CP3.3). Local-dev defaults to LocalDevPKI; production
# points the PKI backend at Vault — see "Running with TLS" below.
wg-manager operators add --cn dev-operator --role admin
wg-manager certs issue --type api --cn 127.0.0.1 \
  --out-cert tls/server.crt --out-key tls/server.key --out-chain tls/ca-bundle.crt
wg-manager certs issue --type cli --cn dev-operator \
  --out-cert tls/client.crt --out-key tls/client.key --out-chain tls/client.chain.crt
export TLS_REQUIRED=true \
       TLS_CERT_PEM=tls/server.crt \
       TLS_KEY_PEM=tls/server.key \
       TLS_CA_BUNDLE_PEM=tls/ca-bundle.crt

# In one terminal — the API (uvicorn over mTLS on 127.0.0.1:8000):
make run

# In another terminal — the Celery worker that runs provisioning:
make worker
```

OpenAPI docs: https://127.0.0.1:8000/docs — see "Running with TLS"
below for the client cert curl/browser needs.

## Dashboard

A Next.js + Tailwind dashboard lives in [`web/`](web/). It talks to
the FastAPI control plane through a **Backend-For-Frontend (BFF)
proxy** that runs inside Next.js: the browser issues same-origin plain
HTTP to `http://localhost:3100/api/proxy/...`, the Node runtime then
presents the wg-manager client certificate to the (mTLS-required)
FastAPI listener, and surfaces the response verbatim. The browser
never participates in the mTLS handshake — see [`web/README.md`](web/README.md#how-the-dashboard-talks-to-the-api-bff-proxy)
for the details. Quick start:

```bash
make ui-install                                  # one-time
# Mint the certs via the CP3.3 CLI (see Quickstart at top of README):
wg-manager operators add --cn dev-operator --role admin
wg-manager certs issue --type api --cn 127.0.0.1 \
  --out-cert tls/server.crt --out-key tls/server.key --out-chain tls/ca-bundle.crt
wg-manager certs issue --type cli --cn dev-operator \
  --out-cert tls/client.crt --out-key tls/client.key --out-chain tls/client.chain.crt
cp web/.env.example web/.env.local               # wire BFF env vars
make ui-dev                                      # http://127.0.0.1:3100
```

The BFF makes the legacy `CORS_ORIGINS` setting moot for browser
traffic (every request is same-origin), but the env still exists for
non-browser clients that may call the API directly.

The dashboard ships a **Certificates** page (Phase 2d CP3.4) that
mirrors `wg-manager certs` over HTTP: a "Who am I?" splash that
surfaces the cert subject the API actually saw on the live TLS
handshake (a 200 there is the visible proof a freshly-imported
PKCS#12 was accepted), a per-row inventory of every cert wg-manager
has issued (with live / revoked badges and a one-click Revoke action
for admins), and an Issue form that produces a downloadable cert /
key / chain triple — or a single browser-importable PKCS#12 archive
when the cert type is `dashboard`. Auditors can read the inventory
but cannot mint or revoke; plain operators see neither.

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
3. Stores a `Client` row in `ready` state with `is_manual=true` and
   only the **public** key — the private key is dropped after the
   response, because wg-manager has no operational use for the key
   of a device it can't log into.
4. Returns the rendered `wg0.conf` body (with the private key inline)
   in the registration response as `wg_config`. This is the **only**
   moment the body exists outside the device.
5. Reconfigures the hub so the new peer is admitted.

The operator then installs the rendered `wg0.conf` on the device by
hand (drop it at `/etc/wireguard/wg0.conf` on Linux, or import it
into the WireGuard app on a phone — most apps accept the text body
directly or render it as a QR code from a file).

> **Save the config on first sight.** Because the control plane does
> not persist the private key, there is no way to re-render the
> `wg0.conf` for an existing manual client. If you lose the body
> before installing it, delete the row (`DELETE /clients/{id}`) and
> register again — a fresh keypair is minted and the hub is
> reconfigured to swap the public key.

```bash
# Register a phone and write the rendered config straight to disk.
wg-manager clients add-manual \
    --name phone \
    --server-id 1 \
    --config-output ./phone.conf
```

The HTTP equivalent is `POST /clients/manual` — the response body is
`{task_id, client, wg_config}` where `wg_config` is the full
`wg0.conf` text (including the private key). There is no
`GET /clients/{id}/config` to re-fetch from later (the route was
retired in the manual-client redesign).

Manual clients are deliberately excluded from `GET /clients/export/ssh-config`
— wg-manager has no SSH credentials for them — and from
`POST /clients/{id}/reprovision`, which would try to SSH in. To roll a
manual client's keypair, delete the row and register a fresh manual
client.

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

## Running with TLS (Phase 2d CP2)

The API listener requires mTLS in production. `make run` delegates to
[`python -m wg_manager`](src/wg_manager/__main__.py), which refuses to
start unless `TLS_CERT_PEM`, `TLS_KEY_PEM`, and `TLS_CA_BUNDLE_PEM`
are all set; combined with `TLS_REQUIRED=true`, the
[CP2 auth middleware](src/wg_manager/auth.py) 401s every non-OPTIONS
request that arrives without a client certificate.

**Dev path — LocalDevPKI + Phase 2d CP3.3 CLI:**

```bash
# Register the bootstrap operator (CP3.2 / CP3.3).
wg-manager operators add --cn dev-operator --role admin

# Mint the API server cert + the operator's CLI client cert.
wg-manager certs issue --type api --cn 127.0.0.1 \
  --out-cert tls/server.crt --out-key tls/server.key --out-chain tls/ca-bundle.crt
wg-manager certs issue --type cli --cn dev-operator \
  --out-cert tls/client.crt --out-key tls/client.key --out-chain tls/client.chain.crt

export TLS_REQUIRED=true \
       TLS_CERT_PEM=tls/server.crt \
       TLS_KEY_PEM=tls/server.key \
       TLS_CA_BUNDLE_PEM=tls/ca-bundle.crt
make run

# In another terminal:
curl --cacert tls/ca-bundle.crt \
     --cert tls/client.crt \
     --key  tls/client.key \
     https://127.0.0.1:8000/crypto/status
```

The certs land on disk verbatim and the metadata is recorded in the
`certificate` audit table (`wg-manager certs list` prints it as JSON,
the dashboard's `/certificates` page surfaces the same shape). Phase
2d CP4.3 ships the renewal flow — see "Cert renewal" below.

**Production path — Vault PKI:**

```bash
make pki-bootstrap                           # one-time
# Same wg-manager certs issue invocations as the dev path, but
# PKI_BACKEND=vault routes them through the Vault PKI mount.
export TLS_REQUIRED=true \
       TLS_CERT_PEM=/etc/wg-manager/server.crt \
       TLS_KEY_PEM=/etc/wg-manager/server.key \
       TLS_CA_BUNDLE_PEM=/etc/wg-manager/ca-bundle.crt
make run
```

Implementation notes:
- uvicorn 0.44 doesn't ship the ASGI-TLS extension natively
  (encode/uvicorn#1530), so
  [`wg_manager._tls_uvicorn`](src/wg_manager/_tls_uvicorn.py)
  backfills `scope["extensions"]["tls"]["client_cert_chain"]` from
  the transport's SSL object at module import. Delete that module
  once upstream catches up.
- OPTIONS preflight bypasses the middleware enforcement so the
  dashboard's CORS negotiation works on a TLS session that already
  carries the cert.

## MySQL TLS (Phase 2d CP4)

CP4.1 wires pymysql `ssl={ca, cert, key, check_hostname}` connect
args into the engine when `DATABASE_TLS_REQUIRED=true`; CP4.2 ships
the matching docker-compose mounts + a my.cnf drop-in that turns on
`require_secure_transport=ON` server-side. The end-to-end walkthrough
lives in
[`docs/migrations/2d-mysql-tls.md`](docs/migrations/2d-mysql-tls.md) —
here's the short form:

```bash
# 1. Mint the server cert into the bind-mount directory.
make mysql-tls-issue

# 2. Mint the matching service-principal client cert.
wg-manager certs issue --type mysql-client --cn wg-manager-app \
  --out-cert tls/mysql/client.crt --out-key tls/mysql/client.key \
  --out-chain tls/mysql/client-ca.crt

# 3. Bounce the DB so the my.cnf drop-in picks the new certs up.
make db-down && make db-up

# 4. Flip the engine on (add to .env):
#      DATABASE_TLS_REQUIRED=true
#      DATABASE_TLS_CA_PEM=tls/mysql/client-ca.crt
#      DATABASE_TLS_CERT_PEM=tls/mysql/client.crt
#      DATABASE_TLS_KEY_PEM=tls/mysql/client.key
make run
```

Two cert types power this:

- `mysql` — `serverAuth`, presented by the mysqld daemon.
- `mysql-client` — `clientAuth`, presented by the app + worker.
  Service principal, no `Operator` FK.

Both are 30-day leaves by default — pair with the renewal flow below
so rotation isn't manual.

## Cert renewal (Phase 2d CP4.3)

Each cert wg-manager issues lands in the `certificate` audit table
with the on-disk PEM paths recorded (`out_cert_path` / `out_key_path`
/ `out_chain_path`, populated when `wg-manager certs issue
--out-cert/...` is used). `wg-manager certs renew` walks the table
and re-mints in place:

```bash
# Renew one specific cert by row id.
wg-manager certs renew --id 7

# Walk the registry; re-mint every non-revoked cert past 50% of its
# lifetime. Idempotent — safe to run on a cron / systemd timer.
wg-manager certs renew --due --threshold-pct 50

# Preview without minting.
wg-manager certs renew --due --dry-run
```

The dashboard's `/certificates` page grew a per-row Renew button
(admin only); the freshly-issued PEMs land in the same artefact-
download panel as the Issue flow. The API surface is `POST
/certs/{id}/renew` if you want to drive it from a script.

Production deployments wire `wg-manager certs renew --due` into a
systemd timer — see
[`docs/deploy/systemd-timer.md`](docs/deploy/systemd-timer.md) for
the unit files + the "bounce the API + worker on a successful
rotation" pattern. Rows minted via `POST /certs` (no `out_*_path`)
are skipped by the walker; re-issue them via the CLI to opt them
into automated rotation.

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
  Phase 2d (TLS / mTLS everywhere via Vault PKI) is in progress;
  CP1 lands the [`wg_manager.pki`](src/wg_manager/pki.py) module
  with both backends (`LocalDevPKI` for dev/tests, `VaultPKI` for
  production) and the `make pki-bootstrap` idempotent setup —
  see [`docs/vault-cookbook.md`](docs/vault-cookbook.md#4-pki--internal-tls-phase-2d)
  §4 for the full reference. Phase 2e (supply chain + audit) is
  the next sub-phase.
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
