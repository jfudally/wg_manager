# Operator guide

The day-2 walkthroughs the [README](../README.md) Quickstart skips —
how to run wg-manager against a real production stack, register a
server end-to-end, set up MySQL TLS, and keep certs rotating
automatically.

For incident response see [`docs/runbooks/`](runbooks/). For the
phase-by-phase implementation history (why decisions were made,
what each checkpoint shipped) see [`ROADMAP.md`](../ROADMAP.md).

## Contents

1. [Running with TLS](#running-with-tls)
2. [MySQL TLS](#mysql-tls)
3. [Cert renewal](#cert-renewal)
4. [Adding a server](#adding-a-server)
5. [Zero-touch enrollment (userdata)](#zero-touch-enrollment-userdata)

---

## Running with TLS

The API listener requires mTLS. `make run` delegates to
[`python -m wg_manager`](../src/wg_manager/__main__.py), which
refuses to start unless `TLS_CERT_PEM`, `TLS_KEY_PEM`, and
`TLS_CA_BUNDLE_PEM` are all set; combined with `TLS_REQUIRED=true`,
the [auth middleware](../src/wg_manager/auth.py) 401s every
non-OPTIONS request without a valid client certificate.

### Dev path — LocalDevPKI

Suitable for local development on a single host. The PKI material
lives on disk in `tls/` and is regenerated whenever you re-run the
mint commands.

```bash
# Register the bootstrap operator.
wg-manager operators add --cn dev-operator --role admin

# Mint the API server cert + the operator's CLI client cert.
wg-manager certs issue --type api --cn 127.0.0.1 \
  --out-cert tls/server.crt --out-key tls/server.key \
  --out-chain tls/ca-bundle.crt
wg-manager certs issue --type cli --cn dev-operator \
  --out-cert tls/client.crt --out-key tls/client.key \
  --out-chain tls/client.chain.crt

export TLS_REQUIRED=true \
       TLS_CERT_PEM=tls/server.crt \
       TLS_KEY_PEM=tls/server.key \
       TLS_CA_BUNDLE_PEM=tls/ca-bundle.crt
make run

# In another terminal, exercise the listener:
curl --cacert tls/ca-bundle.crt \
     --cert tls/client.crt \
     --key  tls/client.key \
     https://127.0.0.1:8000/crypto/status
```

Every issued leaf is recorded in the `certificate` audit table —
`wg-manager certs list` prints it as JSON; the dashboard's
`/certificates` page surfaces the same data with one-click
revocation for admins.

### Production path — Vault PKI

```bash
make pki-bootstrap                           # one-time

# Same `wg-manager certs issue` invocations as the dev path, but
# with PKI_BACKEND=vault set in .env. The leaves are signed by the
# Vault PKI intermediate instead of the in-process LocalDevPKI.
export TLS_REQUIRED=true \
       TLS_CERT_PEM=/etc/wg-manager/server.crt \
       TLS_KEY_PEM=/etc/wg-manager/server.key \
       TLS_CA_BUNDLE_PEM=/etc/wg-manager/ca-bundle.crt
make run
```

OPTIONS preflight bypasses the middleware enforcement so the
dashboard's CORS negotiation works on a TLS session that already
carries the cert. `wg_manager._tls_uvicorn` backfills the
ASGI-TLS extension that uvicorn 0.44 doesn't ship natively (see
[encode/uvicorn#1530](https://github.com/encode/uvicorn/issues/1530));
remove it when upstream catches up.

---

## MySQL TLS

App ↔ MySQL traffic is encrypted by default in production. The
short form:

```bash
# 1. Mint the server cert into the docker-compose bind-mount.
make mysql-tls-issue

# 2. Mint the matching service-principal client cert for the app + worker.
wg-manager certs issue --type mysql-client --cn wg-manager-app \
  --out-cert tls/mysql/client.crt --out-key tls/mysql/client.key \
  --out-chain tls/mysql/client-ca.crt

# 3. Bounce the DB so the my.cnf drop-in picks up the new server cert.
make db-down && make db-up

# 4. Flip the engine on (add to .env):
#      DATABASE_TLS_REQUIRED=true
#      DATABASE_TLS_CA_PEM=tls/mysql/client-ca.crt
#      DATABASE_TLS_CERT_PEM=tls/mysql/client.crt
#      DATABASE_TLS_KEY_PEM=tls/mysql/client.key
make run
```

Two cert types power this:

- `mysql` — `serverAuth`, presented by the mysqld daemon (via the
  bind-mount the `make db-up` compose stack reads from).
- `mysql-client` — `clientAuth`, presented by the app + worker.
  Service principal, no operator FK.

Both default to 30-day TTLs — pair with [cert
renewal](#cert-renewal) so rotation isn't manual. Full
walkthrough at
[`docs/migrations/2d-mysql-tls.md`](migrations/2d-mysql-tls.md).

---

## Cert renewal

Every cert wg-manager issues lands in the `certificate` audit
table with its on-disk PEM paths recorded (populated when
`wg-manager certs issue --out-cert/...` is used). The walker
re-mints in place:

```bash
# Renew one specific cert by row id.
wg-manager certs renew --id 7

# Walk the registry; re-mint every non-revoked cert past 50% of
# its lifetime. Idempotent — safe to run on a cron / systemd timer.
wg-manager certs renew --due --threshold-pct 50

# Preview without minting.
wg-manager certs renew --due --dry-run
```

The dashboard's `/certificates` page has a per-row Renew button
(admin only); freshly-issued PEMs land in the same artefact-
download panel as the Issue flow. The HTTP equivalent is
`POST /certs/{id}/renew`.

Production deployments wire the walker into a systemd timer — see
[`docs/deploy/systemd-timer.md`](deploy/systemd-timer.md) for the
unit files + the "bounce the API + worker on a successful
rotation" pattern. Rows minted via `POST /certs` (no `out_*_path`)
are skipped by the walker; re-issue them via the CLI to opt them
into automated rotation.

---

## Adding a server

The flow is **role-first**: register a role (an SSH CA configuration
label), then register a server that references it. No long-lived
SSH keys to upload — the worker mints short-lived Vault-signed
user certs per session.

### 1. Bootstrap the Vault SSH CA (once per cluster)

```bash
make vault-up                # dev Vault on :8200
make ssh-ca-bootstrap        # creates the SSH engine + the two roles
```

In production, point `VAULT_ADDR` + `VAULT_TOKEN` at your real
Vault before running `make ssh-ca-bootstrap`. The script is
idempotent; running it twice against an already-configured Vault
is a no-op.

### 2. Register a role

Dashboard: **SSH Roles → + Add SSH role** and pick a memorable
name (`lab-2026`, `prod-edge`, …). CLI equivalent:
`wg-manager keys add --name lab-2026`. The row carries no
credential material — it's just a label that ties future server /
client rows back to the Vault CA configuration.

### 3. Bootstrap the target host's SSH CA trust

Before wg-manager can ever SSH into a fresh box, the box must
trust the Vault CA. Use the `bootstrap-host` CLI, passing whatever
long-lived SSH key you already use to dial it:

```bash
wg-manager bootstrap-host \
    --hostname vpn-hub-1.example.com \
    --ssh-user ubuntu \
    --ssh-key ~/.ssh/id_ed25519
```

Optional flags: `--principal <name>` (adds an alias principal to
the host cert alongside `--hostname` — typically internal DNS when
you dial a public IP; wg-manager always requires the cert to name the
host it dials, so register the row with the same `--hostname`),
`--ssh-key-passphrase <pass>` (or set
`WG_MANAGER_BOOTSTRAP_SSH_KEY_PASSPHRASE`), `--ssh-port 22`,
`--ttl-seconds 86400`, `--connect-timeout 15`.

The command opens **one** SSH session with TOFU host-key
acceptance — the only legitimate TOFU site in the codebase, where
you are consciously trusting the box for the first time so
wg-manager can refuse TOFU thereafter. It then mints a host cert
against the Vault SSH CA, drops three files
(`/etc/ssh/wg-manager-user-ca.pub`, the signed host cert, and an
`sshd_config.d/wg-manager.conf` drop-in), reloads sshd, and
exits with:

```
[OK] bootstrapped vpn-hub-1.example.com: cert serial=<n> valid_until=<ts>
```

Idempotent — re-running rotates the host cert in place before TTL
expiry.

The command does **not** write to the wg-manager database. Two
operator actions on purpose so you can verify the install before
committing a row.

Fleets migrating off the pre-Phase-2c stored-key model should
follow the cookbook in
[`docs/migrations/2c-ssh-ca.md`](migrations/2c-ssh-ca.md);
`bootstrap-host` replaces the manual file-copy step that cookbook
used to call out.

### 4. Register the server

Dashboard: **Servers → + Register hub server**; fill in
hostname, SSH port (22), SSH username (the account on the box
that will accept the cert — defaults to `root` for self-managed
boxes, `ubuntu` for Ubuntu AMIs, etc.), and pick the role you
created in step 2. CLI equivalent:

```bash
wg-manager servers register \
  -H vpn-hub-1.example.com \
  -u ubuntu \
  -e vpn-hub-1.example.com \
  -k <role-id>
```

The role ID is the integer surfaced by `wg-manager keys list`.

The control plane sets the row to `pending` and dispatches a
Celery task that:

1. Mints a short-lived user cert against the role and opens an
   SSH session with `KnownHostsCAPolicy` (TOFU is off — the box
   already trusts the CA from step 3).
2. Installs WireGuard, writes `/etc/wireguard/wg0.conf`, brings
   up the interface.
3. Mints + installs a Vault-signed host cert into the sshd
   drop-in (so future sessions can validate the host cert chain).
4. Flips the row to `ready`.

Poll progress with `GET /tasks/{task_id}` (returned in the 202
response) or `GET /servers/{id}` (its `status` column flips too).

### 5. Register clients

Same shape as servers — `wg-manager clients register` /
**Dashboard → Clients → + Register client**. The client must trust
the SSH CA first, exactly like a hub (step 3): either run
`wg-manager bootstrap-host` against it, or expand **Bootstrap this
host first** in the Register-client form and paste the OOB key the
client already trusts (`bootstrap_ssh_key_pem` on `POST /clients`),
which bootstraps and provisions in one task.

Devices wg-manager can't SSH into (phones, IoT boxes) are the
exception. For those:

```bash
wg-manager clients add-manual \
    --name phone \
    --server-id 1 \
    --config-output ./phone.conf
```

The control plane generates the X25519 keypair server-side,
allocates the next free address in the parent server's subnet,
stores only the **public** key (the private key is dropped after
the response — wg-manager has no operational use for the key of a
device it can't log into), and writes the rendered `wg0.conf`
body to the output path. The hub is reconfigured to admit the
new peer.

> **Save the config on first sight.** Because the control plane
> does not persist the private key, there is no way to re-render
> the `wg0.conf` for an existing manual client. If you lose the
> body before installing it, delete the row
> (`DELETE /clients/{id}`) and register again — a fresh keypair
> is minted and the hub is reconfigured to swap the public key.

Manual clients are excluded from `GET /clients/export/ssh-config`
(no SSH credentials) and from `POST /clients/{id}/reprovision`.
To roll their keypair, delete the row and re-register.

---

## Zero-touch enrollment (userdata)

Phase 3f. A freshly launched host can join the fleet by itself, from
outside the VPN, with no operator SSH session. You mint a single-use
**enrollment token** and put it in the instance's userdata. On first
boot, `scripts/enroll_node.sh` redeems it on the **enrollment
listener**, a separate port that accepts TLS without a client cert
and serves nothing except `POST /v1/enroll` and health probes. The
host ends up as an ordinary managed client: reprovision, host-cert
rotation and discovery all work on it.

### 1. Turn on the enrollment listener (once)

It's off by default. In `.env.prod`:

```bash
COMPOSE_PROFILES=enroll
WG_MANAGER_ENROLL_BIND_PORT=8443   # the port hosts will reach
```

Then `make prod-up`. Open that port to wherever new hosts boot (a
cloud security group, for example). The operator API port can stay
as locked down as before. For local dev, `make run-enroll` starts it
on `127.0.0.1:8001` using the same `TLS_CERT_PEM` / `TLS_KEY_PEM` as
`make run`.

> **The worker must be able to reach the VPN.** An enrolled host is
> dialled at its VPN address: that's the only name its host cert
> vouches for, and the host may have no reachable public IP. Run the
> worker on a hub or another VPN peer. Otherwise the daily host-cert
> rotation, and every later reprovision, will fail for enrolled
> hosts.

### 2. Mint a token

Admin only (admin on the hub's tenant, or a super-admin):

```bash
curl --cert ops.crt --key ops.key --cacert ca-bundle.crt \
  -X POST https://wg.example.com/v1/enrollment-tokens \
  -H 'Content-Type: application/json' \
  -d '{"server_id": 1, "ssh_key_id": 1, "ssh_username": "wgmgr",
       "name_prefix": "web", "ttl_seconds": 3600, "max_uses": 1}'
```

| Field | Meaning |
| --- | --- |
| `server_id` | Hub the host joins. Must be `ready`. |
| `ssh_key_id` / `ssh_username` | How the worker will SSH in later. The key must be in the hub's tenant; the script creates the user with passwordless sudo if it's missing. |
| `name_prefix` | Clients are named `<prefix>-<hostname>`. |
| `ttl_seconds` | 60 s to 7 days (default 1 h). |
| `max_uses` | 1 to 100 (default 1). Use more than 1 only for autoscaling groups. Simultaneous enrollments are safe: hub reconfigures coalesce, so a burst costs about one hub restart. |

The response carries `token` **once**. Only its SHA-256 is stored.

### 3. Put it in userdata

```bash
#!/bin/bash
export WGM_ENROLL_URL=https://wg.example.com:8443
export WGM_ENROLL_TOKEN=wgmenr_...
export WGM_CA_BUNDLE_PEM='-----BEGIN CERTIFICATE-----
...contents of tls/ca-bundle.crt...
-----END CERTIFICATE-----'
/opt/wg-manager/enroll_node.sh   # baked into the image, or fetched from a pinned release tag
```

The script generates the WireGuard key on the host (it never leaves),
sends only the public keys, retries while the control plane answers
5xx, installs the returned `wg0.conf`, SSH user CA, host cert and
sshd drop-in, and brings `wg0` up. See the header of
`scripts/enroll_node.sh` for every setting.

### What the control plane does on redemption

In one transaction, serialised per hub:

- it consumes one use of the token,
- allocates the next VPN address,
- signs the host's ed25519 key with **only that address** as the
  principal (the hostname the host reports never becomes a
  principal),
- creates the client row, writes a `client.enroll` audit event, then
  queues a hub reconfigure.

If anything fails after the token is consumed, the whole transaction
rolls back and the use is returned.

A bad, expired or used-up token always gets the same `401`. The token
is checked before the body, so a caller without a live token never sees
a `422`. The real
reason goes to the audit log as `enroll.reject`, which is worth
alerting on.

### Rate limits

`POST /v1/enroll` is limited per source IP, with counters in Valkey
shared by every enroll replica:

| Setting | Default | Meaning |
| --- | --- | --- |
| `ENROLL_RATE_LIMIT_REQUESTS` / `_WINDOW_SECONDS` | 120 / 60 | All enroll requests from one IP. |
| `ENROLL_FAILURE_LIMIT` / `ENROLL_FAILURE_WINDOW_SECONDS` | 10 / 600 | Failed attempts (bad token = 401, bad body with a live token = 422) before that IP is locked out for the rest of the window, **even with a valid token**. |

Set a limit to `0` to disable it. Blocked calls get `429` with
`Retry-After`, and `enroll_node.sh` backs off and retries. If Valkey
is unreachable, enrollment fails closed with `503`, which the script
also retries. Each trip writes one `enroll.rate_limited` line to the
audit log.

Things to know:

- **Fleets behind NAT share an IP.** An autoscaling group in a private
  subnet usually reaches the internet through one NAT address. Raise
  `ENROLL_RATE_LIMIT_REQUESTS` if large groups enroll at once. It only
  slows them down; they retry.
- **One broken host can lock out its neighbours.** A host behind the
  same NAT that keeps sending a bad token counts toward the shared
  failure bucket. Check `enroll.reject` in the audit log for the
  reason.
- **Proxies hide client IPs.** The limit keys on the TCP peer. Behind
  the HA nginx L4 proxy, or Docker's userland proxy, every caller looks
  like the proxy and shares one bucket. Publish the enroll port
  directly, with iptables DNAT (Docker's default for IPv4), until
  PROXY protocol support lands.

### Treat userdata as readable

Anyone who can read the instance's metadata can read the token.
That's why tokens are single-use by default, short-lived, and tied to
one hub and one tenant. Keep `ttl_seconds` close to how long a boot
takes, and keep `max_uses` at 1 unless you really need more.

### List and revoke tokens

Both are admin only, like minting. A tenant admin sees and revokes only
their own tenant's tokens.

```bash
# Newest first. Filters: ?server_id=1, ?active=true (redeemable now).
curl --cert ops.crt --key ops.key --cacert ca-bundle.crt \
  https://wg.example.com/v1/enrollment-tokens

# Revoke token 7. Safe to repeat.
curl --cert ops.crt --key ops.key --cacert ca-bundle.crt \
  -X POST https://wg.example.com/v1/enrollment-tokens/7/revoke
```

Each row has a `status`: `active`, `revoked`, `expired` or `exhausted`
(all uses taken). The token itself and its hash are never returned.

Revoke a token as soon as you suspect its userdata leaked, or when an
autoscaling group with a multi-use token is retired. Revocation is
immediate, including for a redemption already in progress. Redeeming
a revoked token gets the same `401` as any other bad token, with
`reason: revoked` in the `enroll.reject` audit line. Hosts that already
enrolled with the token stay enrolled; delete their clients to remove
them. Revocations are audited as `enrollment_token.revoke`.
