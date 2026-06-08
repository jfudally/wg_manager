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
| `MYSQL_ROOT_PASSWORD` | MySQL root password (used only at first boot) | `openssl rand -hex 32` |
| `MYSQL_APP_PASSWORD` | App-tier MySQL password (api + worker use this) | `openssl rand -hex 32` |
| `VALKEY_PASSWORD` | Valkey AUTH password | `openssl rand -hex 32` |
| `BOOTSTRAP_OPERATOR_CN` | CN baked into the operator's CLI client cert | DNS-style: `ops@yourbox.example` |

No `VAULT_ROOT_TOKEN` — that token is generated on first `make
prod-up` by `vault operator init` and captured in `vault-init.json`
(mode 0600, gitignored). The `bootstrap-substrate` container reads
it from there on every restart and exports it into api / worker /
bootstrap-app via the entrypoint shim baked into the wg-manager
image. **Back up `vault-init.json` alongside `.env.prod`** —
losing both means losing every secret the substrate holds.

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

## Onboarding a target host (SSH CA install)

Before wg-manager can SSH into a freshly-provisioned VPN hub box,
the box needs to trust the Vault SSH CA — that means
`/etc/ssh/wg-manager-user-ca.pub`, a signed host cert, and an
`sshd_config.d` drop-in pointing at them. The full design + cert
profiles live in `docs/operator-guide.md` §3; this section is the
recipe for running the install from inside the prod stack.

The `wg-manager bootstrap-host` CLI does the install in one shot
— opens **one** TOFU-permitted SSH session with your existing key
(the only legitimate TOFU site in the codebase, by design), mints
a host cert against Vault, drops the three files, reloads sshd,
exits. Idempotent — re-running rotates the host cert in place
before TTL expiry.

### Prerequisites on the target host

| Requirement | Default on stock Linux | How to fix if missing |
|---|---|---|
| ed25519 host key at `/etc/ssh/ssh_host_ed25519_key.pub` | Generated at sshd install on every modern distro | `sudo ssh-keygen -A` on the target |
| Sudo for your SSH user (writes to `/etc/ssh/`) | yes for `root`, `ubuntu`, etc. | passwordless sudo (or a NOPASSWD line for the specific commands) |
| Your SSH user is in `SSH_CA_VAULT_ALLOWED_USERS` | `root,ubuntu,ec2-user,azureuser,debian,admin` | extend `SSH_CA_VAULT_ALLOWED_USERS` in `.env.prod`, `make prod-down -v` + `make prod-up` (re-runs `ssh-ca-bootstrap`) |

### The install — pick a path

There are two equivalent ways to run the install. Both end with the
same three files on the target (`/etc/ssh/wg-manager-user-ca.pub`,
the signed host cert, the sshd drop-in) and the same audit-log line
on the API side.

#### Path A — Dashboard (the easy button)

Open the dashboard → **Servers → + Register server**, fill in the
usual fields, then expand the **Bootstrap this host first** section
at the bottom of the form and paste the *contents* of your
operator's bootstrap private key (e.g. `~/.ssh/id_ed25519`) into
the PEM textarea. Submit. The single task does bootstrap first,
then the regular CA-mode provision — one click, one row, one task
to poll.

When the section is left collapsed (or expanded but blank), the
registration assumes the box was already bootstrapped (Path B
below, baked AMI, prior run) and falls through to today's behaviour.
A box that hasn't been bootstrapped fails cleanly with
`host cert signed by an untrusted CA` at provision time — easy to
spot, easy to recover from by reprovisioning with the PEM filled in.

The key body is encrypted server-side via the configured crypto
backend (Vault Transit in prod) before it touches the broker, and
nothing about it is persisted to the DB. Close the browser tab
after registration if you want the bytes out of the page's memory
too. See [`docs/operator-guide.md`](../operator-guide.md) §3 for
the trust model.

#### Path B — CLI (for scripted / CI use)

The CLI is baked into the api/worker image, so the cleanest
invocation is a one-shot container that joins the compose network
where Vault lives and mounts your operator SSH key read-only:

```bash
docker compose --env-file .env.prod \
    -f docker-compose.yml -f docker-compose.prod.yml \
    run --rm \
    -v ~/.ssh:/keys:ro \
    --entrypoint wg-manager \
    api \
    bootstrap-host \
      --hostname <target-fqdn-or-ip> \
      --ssh-user <user> \
      --ssh-key /keys/<your-key-filename>
```

Notes:

- `--rm` so the container disappears after the install.
- `run` inherits the api service's env (`VAULT_ADDR=http://vault:8200`,
  `VAULT_TOKEN=…`, the four backend pins) so the CLI hits Vault on
  the docker network without any extra wiring.
- Optional flags: `--principal <name>` (when the cert's host
  principal differs from the SSH dial-name — typically internal
  DNS vs public IP), `--ssh-key-passphrase <pass>` (or set
  `WG_MANAGER_BOOTSTRAP_SSH_KEY_PASSPHRASE`), `--ssh-port 22`,
  `--ttl-seconds 86400`, `--connect-timeout 15`.

Expected output:

```
[OK] bootstrapped <hostname>: cert serial=<n> valid_until=<ts>
```

`bootstrap-host` deliberately does **not** write to the wg-manager
DB — that's the CLI flow's "verify before register" contract.
Follow up with `servers register` to catalogue the box. Path A
above collapses these into one action; choose Path B when you
want to land the install separately (CI, an unattended cron, etc.).

### Register the server (DB-side)

Dashboard: **Servers → + Register server**, fill in hostname,
SSH port (22), SSH username (the account on the box that will
accept the CA-minted cert — `root` for self-managed boxes,
`ubuntu` for Ubuntu AMIs, etc.), pick the SSH role from step 2 of
`docs/operator-guide.md`. If the host hasn't been bootstrapped via
Path B yet, expand **Bootstrap this host first** and paste the OOB
key (see Path A above).

CLI equivalent:

```bash
docker compose --env-file .env.prod \
    -f docker-compose.yml -f docker-compose.prod.yml \
    run --rm \
    --entrypoint wg-manager \
    api \
    servers register \
      -H <target-fqdn-or-ip> \
      -u <user> \
      -e <target-fqdn-or-ip> \
      -k <role-id>
```

From here every wg-manager SSH session into that host uses a fresh
5-minute CA-minted user cert with `permit-pty` — no stored private
key on the wg-manager side, no `authorized_keys` entry on the
target side.

### Re-running against an already-bootstrapped host

Safe to re-run any time — `bootstrap-host` rotates the host cert
in place before TTL expiry. The 24h default host-cert TTL
(`SSH_HOST_CERT_TTL_SECONDS`) pairs cleanly with a cron / systemd
timer firing the same command nightly. The wg-manager API also
re-installs a fresh host cert during `POST
/servers/{id}/rotate-host-cert` (Phase 2c CP3) once the row is
registered.

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
| `wg_manager_vault_data` | vault | **Vault file storage backend** — PKI hierarchy, SSH CA keypair, Transit master key, every secret the substrate engines hold. **Back this up.** |
| `wg_manager_vault_audit_logs` | vault, vector | Vault file audit device output. |

Three operator-managed files on the host:

| File | What | When you need it |
|---|---|---|
| `.env.prod` | Operator passwords + tunable knobs | Always — `make prod-up` refuses to start without it |
| `vault-init.json` | 5 Vault unseal keys + the root token, generated by `vault operator init` on first prod-up (mode 0600, gitignored) | On every restart — `bootstrap-substrate` reads it to auto-unseal Vault. Losing it means losing every secret Vault holds. **Back this up encrypted, alongside `.env.prod`.** |
| `tls/` directory | API server cert, MySQL server + client certs, operator client cert | On every restart — `bootstrap-substrate` re-mints them if missing, but the audit trail is then a fresh row in the `certificate` table rather than the original. |

### Restart behaviour

Every long-running service in the overlay pins `restart: always`.
The box rebooting brings the stack back up unattended provided:

1. Docker is enabled to start at boot (`sudo systemctl enable docker`).
2. `tls/`, `.env.prod`, AND `vault-init.json` all exist on disk
   (they survive reboots automatically, but a host re-image needs
   them re-provisioned).
3. **Vault auto-unseals on every boot.** `bootstrap-substrate`
   reads `vault-init.json` (which carries the 5 unseal keys + the
   root token from `vault operator init`) and POSTs the keys to
   `/v1/sys/unseal` until threshold is met. No operator action
   required. State (PKI hierarchy, SSH CA keypair, Transit master
   key, audit device) is preserved across restarts because Vault
   uses **file storage**, not in-memory.

### Known limitations (vs. fully production-ready)

| Limit | When it matters | Mitigation |
|---|---|---|
| **Vault unseal keys live on disk in `vault-init.json`** | An attacker with shell access to the host can read the keys and unseal Vault. | The unseal keys file lives at the same trust boundary as `.env.prod` (which also has every password the stack uses). The real next step is cloud-KMS auto-unseal (transit/awskms/gcpckms) — out of scope without cloud creds. Restrict OS-level access to the operator group; back up `vault-init.json` encrypted alongside `.env.prod`. |
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
