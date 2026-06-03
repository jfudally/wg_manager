# Vault cookbook

A short, copy-pastable reference for the four Vault secrets engines
wg-manager will depend on across Phase 2. Each section shows the
minimum Python (`hvac`) needed to round-trip; the production code in
later phases lifts directly from these snippets.

The canonical runnable version of everything below is
[`scripts/vault_smoke.py`](../scripts/vault_smoke.py) — run it via
`make vault-smoke` against `make vault-up`.

> **Scope.** This document is the *spike* output: it captures what
> works and what we discovered during Phase 2a. The same patterns get
> hardened (error handling, retry, AppRole auth, contexts, audit
> logging) inside `wg_manager.crypto` and `wg_manager.ssh_ca` in
> Phase 2b/2c.

## 0. Connecting

The dev container exposes Vault on `127.0.0.1:8200` with root token
`dev-only-root`. Both are hard-coded in `docker-compose.yml` and are
**dev-only** — production reads them from injected env / AppRole.

```python
import hvac

client = hvac.Client(url="http://127.0.0.1:8200", token="dev-only-root")
assert client.is_authenticated()
```

## 1. Transit — encryption at rest (Phase 2b)

The single most important engine for wg-manager. Plaintext goes in,
ciphertext comes out; the master key never leaves Vault.

```python
import base64

# Idempotent: enabling an already-mounted engine raises InvalidRequest
# with "path is already in use".
client.sys.enable_secrets_engine(backend_type="transit", path="transit")
client.secrets.transit.create_key(name="wg-manager")

ct = client.secrets.transit.encrypt_data(
    name="wg-manager",
    plaintext=base64.b64encode(b"secret bytes").decode(),
    # Context binds the ciphertext to its row. Without this, a DB-read
    # attacker who swaps row A's blob into row B can still decrypt it.
    context=base64.b64encode(b"sshkey:42").decode(),
)["data"]["ciphertext"]
# ct looks like: "vault:v1:abcd…"

pt = client.secrets.transit.decrypt_data(
    name="wg-manager",
    ciphertext=ct,
    context=base64.b64encode(b"sshkey:42").decode(),
)["data"]["plaintext"]
assert base64.b64decode(pt) == b"secret bytes"
```

### Phase 2b notes
- The `vault:vN:` prefix is the key *version*. Rotation
  (`POST /transit/keys/wg-manager/rotate`) bumps `N` for new writes;
  existing ciphertext still decrypts. `transit/rewrap` upgrades an
  existing blob to the latest version without touching the plaintext.
- `cryptography.fernet.Fernet` is the test-only fallback for
  `WG_MANAGER_CRYPTO_BACKEND=local`.

### Phase 2b checkpoint 3 — drop-plaintext rollout

The migration sequence from a fresh Phase-1 schema to fully encrypted
storage is:

1. `alembic upgrade 0004_encryption_at_rest` — adds the `_ct`
   ciphertext columns alongside the plaintext (dual-write).
2. `wg-manager crypto migrate` — backfill ciphertext for any legacy
   rows that pre-date Phase 2b. **Run this on the previous wg-manager
   release**; the command was removed in checkpoint 3 alongside the
   column drop. (`mysqldump | grep -c 'BEGIN OPENSSH'` should return
   `0` after this step.)
3. `GET /crypto/status` — confirm `sshkey_legacy == 0` and
   `client_legacy == 0`. The dashboard's Crypto Status panel renders
   these counts at `/crypto`.
4. `alembic upgrade 0005_drop_plaintext` — drops the plaintext
   columns. **Forward-only**: the downgrade re-adds the columns but
   does not restore the data that lived in them.

After step 4 the row carries ciphertext only.

#### Post-rotation: `wg-manager crypto rewrap`

After `vault write -f transit/keys/wg-manager/rotate` the Transit key
version bumps. Existing blobs (`vault:v1:…`) still decrypt because
Transit retains old versions; new writes use the new version
(`vault:v2:…`). `wg-manager crypto rewrap` walks every row and
re-encrypts under the current version so the data store lands on one
homogeneous version.

```bash
# Rotation drill.
vault write -f transit/keys/wg-manager/rotate
wg-manager crypto rewrap --dry-run   # preview
wg-manager crypto rewrap             # commit
curl http://127.0.0.1:8000/crypto/status | jq .key_version
```

`rewrap` is idempotent. Running it again after a full pass produces
fresh nonces but identical plaintext, so it's safe as a scheduled
sanity check.

#### Recovering from a 0005 downgrade

The downgrade re-adds the plaintext columns but with `NULL` values.
The ciphertext columns are still populated, so the recovery flow is:

```bash
alembic downgrade -1   # 0005 → 0004 (data NOT restored automatically)
# ...migrate to a wg-manager build that still has the dual-read
# resolver, then for each row:
#   1. resolve_sshkey_private(backend, row) → plaintext
#   2. write the plaintext back into the row.private_key column
# A small standalone script is the right tool here; we do not ship
# one because the path is intended to be never trodden.
```

## 2. KV v2 — generic secret storage

Used in Phase 2e for the small handful of operator-supplied secrets
(SMTP creds, webhook tokens, etc.) that don't fit the Transit model.
Most of wg-manager's secret data goes through Transit, not KV.

```python
client.sys.enable_secrets_engine(
    backend_type="kv",
    path="secret",
    options={"version": "2"},
)

client.secrets.kv.v2.create_or_update_secret(
    path="wg-manager/smtp",
    secret={"user": "ops", "password": "hunter2"},
    mount_point="secret",
)

read = client.secrets.kv.v2.read_secret_version(
    path="wg-manager/smtp",
    mount_point="secret",
    raise_on_deleted_version=True,
)
assert read["data"]["data"]["user"] == "ops"
```

## 3. SSH secrets engine (CA mode) — Phase 2c

The killer feature. wg-manager generates an ephemeral Ed25519 keypair
in memory, Vault signs the public half, the cert is used for one
provisioning run, then both are discarded. **No SSH private key ever
lives in MySQL.**

### Phase 2c checkpoint 1 — `wg_manager.ssh_ca` shipped (2026-05-27)

The raw hvac calls below have been wrapped into
[`wg_manager.ssh_ca`](../src/wg_manager/ssh_ca.py). Application code
calls one of two backends instead of poking hvac directly:

* `LocalDevSSHCA` — in-process throwaway Ed25519 CA, selected by
  `SSH_CA_BACKEND=local`. Used by the test suite (the
  `local`/`vault` parameterised fixture in `tests/test_ssh_ca.py`)
  and by developers who don't want a Vault container in the loop.
* `VaultSSHCA` — wraps the real Vault SSH engine, selected by
  `SSH_CA_BACKEND=vault`. The CA private key never leaves Vault.

Both implement the same `SSHCABackend` protocol:

```python
backend.ca_public_key                                    # for TrustedUserCAKeys
backend.mint_user_cert(principals=["root"], ttl_seconds=300)
backend.mint_host_cert(public_key_openssh=..., principals=[...], ttl_seconds=86400)
```

`VaultSSHCA.bootstrap(...)` and the `make ssh-ca-bootstrap` target run
the idempotent setup against a configured Vault. Example output:

```
$ make ssh-ca-bootstrap
[OK] SSH CA configured at 'ssh'
     user role: wg-manager-provision
     host role: wg-manager-hosts
     allowed user principals: root,ubuntu,ec2-user,azureuser,debian,admin
     allowed host domains: (any — dev default)
     CA public key (drop into /etc/ssh/wg-manager-user-ca.pub):
       ssh-rsa AAAAB3NzaC1yc2E…
```

The user-principal list comes from `SSH_CA_VAULT_ALLOWED_USERS`
(default covers the common cloud-image accounts so a freshly-cut
Ubuntu/Amazon-Linux/Azure VM can be reached on first run). The host
domain set comes from `SSH_CA_VAULT_ALLOWED_HOST_DOMAINS`; empty is
treated as "any principal" (`allowed_domains='*'`,
`allow_bare_domains=true`, `allow_subdomains=true`) — appropriate
for IP-only fleets and dev. Tighten both for production by exporting
the env vars before `make ssh-ca-bootstrap`.

> The dev-mode Vault generates an **RSA** CA key by default. OpenSSH
> happily accepts a cert with an `ssh-ed25519-cert-v01@openssh.com`
> subject signed by an RSA CA, so this is correct but visually noisy.
> Production bootstraps should pass `key_type="ed25519"` to
> `submit_ca_information(...)` for symmetry; the `LocalDevSSHCA`
> already uses Ed25519 for the dev CA so test output is uniform.

Test snapshot (`make vault-up && pytest -q tests/test_ssh_ca.py`):

```
26 passed in ~23s   # 13 local + 13 vault — full matrix
```

### Raw hvac flow (reference)

Kept here so a reader can recognise what the wrapper is doing. New
code should call `wg_manager.ssh_ca` instead.

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

client.sys.enable_secrets_engine(backend_type="ssh", path="ssh")
client.secrets.ssh.submit_ca_information(
    generate_signing_key=True, mount_point="ssh"
)
client.secrets.ssh.create_role(
    name="wg-manager-provision",
    key_type="ca",
    allow_user_certificates=True,
    default_user="root",
    allowed_users="root",
    default_extensions={"permit-pty": ""},
    allowed_extensions="permit-pty",
    ttl="5m",
    max_ttl="5m",
    mount_point="ssh",
)

# Generate ephemeral keypair in memory — no persistence.
priv = Ed25519PrivateKey.generate()
pub_openssh = priv.public_key().public_bytes(
    encoding=serialization.Encoding.OpenSSH,
    format=serialization.PublicFormat.OpenSSH,
).decode()

signed = client.secrets.ssh.sign_ssh_key(
    name="wg-manager-provision",
    public_key=pub_openssh,
    valid_principals="root",
    cert_type="user",
    ttl="5m",
    mount_point="ssh",
)["data"]["signed_key"]
# signed is an `ssh-ed25519-cert-v01@openssh.com …` line.
```

### Phase 2c checkpoint 2 — runner + task wiring shipped (2026-05-27)

The runner-side half of CP2 lives in
[`wg_manager.ssh`](../src/wg_manager/ssh.py); the task-side half lives
in [`wg_manager.tasks`](../src/wg_manager/tasks.py). The whole CA
flow becomes a single setting flip:

```bash
# .env (or your AppRole-wrapped equivalent)
SSH_AUTH_MODE=ca               # default "legacy" until CP4 promotes it
SSH_CA_BACKEND=vault           # uses VaultSSHCA from CP1
SSH_USER_CERT_TTL_SECONDS=300  # cap aligns with the Vault role's max_ttl
```

What that turns on:

1. Every Celery task (`provision_server_task`,
   `reconfigure_server_task`, `provision_client_task`,
   `discover_peers_task`) calls `_open_runner(...)` which mints a
   fresh Ed25519 keypair + user cert for the principal matching the
   row's `ssh_username`. The keypair never touches disk; the cert
   carries only the principal sshd needs.
2. The runner is constructed with `cert_pem` + `ca_public_key`. It:
   - calls `paramiko.Ed25519Key.load_certificate(cert_pem)` so the
     client offers `ssh-ed25519-cert-v01@openssh.com` to the server;
   - installs `KnownHostsCAPolicy(ca_public_key)` in place of
     `AutoAddPolicy`. TOFU is gone — the connection refuses any host
     that doesn't present a host cert signed by the same CA.
3. The new `UntrustedHostKeyError` is in the task layer's
   `_SSH_EXPECTED_ERRORS` tuple, so a missing host cert surfaces as a
   tidy task failure (clean message, no 30-frame paramiko traceback)
   rather than an unhandled exception. Same for `SSHCAError` when
   Vault refuses to sign — the row's `status` flips to `error` and
   the API caller sees a normal failure.

Legacy mode is unchanged. Flipping `SSH_AUTH_MODE` back to `legacy`
(or simply leaving it unset) skips the mint entirely and resolves
credentials from the `sshkey` ciphertext columns as in Phase 2b.

> The runner is ready to dial CA-mode sessions today, but the
> *target* host still needs `TrustedUserCAKeys` and a signed host
> cert installed in `/etc/ssh/sshd_config.d/` before a real
> connection will succeed. That host-side install is CP3.

Test snapshot (`pytest -q tests/test_ssh_cert_mode.py
tests/test_tasks_ssh_ca.py`):

```
14 passed in ~0.2s
```

### Phase 2c checkpoint 3 — host-side install + rotation endpoint shipped (2026-05-27)

CP3 closes the loop the CP2 docstring promised: every CA-mode
provision now also installs the CA pubkey + a freshly-minted host
cert on the target host, so [`KnownHostsCAPolicy`](../src/wg_manager/ssh.py)
has something real to verify against. The new module is
[`wg_manager.host_ssh`](../src/wg_manager/host_ssh.py); the operator-
facing rotation hook is `POST /servers/{id}/rotate-host-cert`.

What CP3 turns on (on top of the CP2 setting flip):

1. **Host-side install** during `provision_server_task` when
   `SSH_AUTH_MODE=ca`. The task SSHes in with a freshly-minted user
   cert, runs the usual WireGuard install, then calls
   `host_ssh.install_host_cert(...)` which:
   - reads `/etc/ssh/ssh_host_ed25519_key.pub` over SSH;
   - asks the CA to sign it as a host cert for `server.hostname`
     (TTL controlled by `SSH_HOST_CERT_TTL_SECONDS`, default 24 h);
   - writes the CA pubkey to `/etc/ssh/wg-manager-user-ca.pub`,
     the cert to `/etc/ssh/ssh_host_ed25519_key-cert.pub`, and a
     drop-in at `/etc/ssh/sshd_config.d/wg-manager.conf` with
     `TrustedUserCAKeys` + `HostCertificate` directives;
   - runs `systemctl reload sshd` (falls back to `restart sshd`
     and the `ssh` unit name on debian-likes that use that).
2. **Persisted snapshot** on the `server` row via the new Alembic
   0006 columns (`host_cert_serial`, `host_cert_principals`,
   `host_cert_valid_after`, `host_cert_valid_before`,
   `host_cert_pem`, `host_cert_ca_public_key`). The dashboard
   reads these to render the cert summary + expiry badge.
3. **Operator-driven rotation** at
   `POST /servers/{id}/rotate-host-cert`. Dispatches the new
   `rotate_host_cert_task` which re-runs the install (idempotent —
   every file is overwritten in place) and updates the row's
   columns. Refuses with **409** when `SSH_AUTH_MODE != "ca"`.
4. **Dashboard parity** — every server row exposes a "Rotate cert"
   button; populated rows render a `cert #<serial> · expires in
   <N>d` line under the hostname, which goes amber inside 30 days
   and red once expired.

```bash
# .env additions on top of CP2
SSH_HOST_CERT_TTL_SECONDS=86400  # 24 h; cap aligns with the Vault host role's max_ttl
```

The sshd drop-in body wg-manager writes:

```
# Managed by wg-manager (Phase 2c CP3). Do not hand-edit.
TrustedUserCAKeys /etc/ssh/wg-manager-user-ca.pub
HostCertificate   /etc/ssh/ssh_host_ed25519_key-cert.pub
```

Test snapshot (`pytest -q tests/test_host_cert_columns.py
tests/test_host_ssh.py tests/test_tasks_host_cert.py
tests/test_rotate_host_cert.py`):

```
16 passed in ~0.2s
```

(Plus 2 vitest specs in `web/__tests__/servers-host-cert.test.tsx`
covering the dashboard rotation button + cert summary line.)

### Phase 2c checkpoint 4.1 — per-key auth mode shipped (2026-05-27)

CP4 reframes the `sshkey` table from "credential store" to "role
label" by moving the auth-mode decision off the global
`SSH_AUTH_MODE` env var and onto the row itself. 4.1 ships just the
column + routing flip; 4.2 will ship the
`wg-manager ssh migrate-to-ca <id>` CLI that walks a legacy row
through to `ca`.

What CP4.1 turns on:

1. **`SSHKey.mode` column** (Alembic 0007). VARCHAR(16), NOT NULL,
   server-default `'legacy'`. Existing rows are backfilled to
   `'legacy'` so a populated Phase 2b/2c DB stays consistent
   without operator action. The enum is a `str` subclass
   ([`wg_manager.models.SSHKeyMode`](../src/wg_manager/models.py))
   so JSON / SQL serialise to the literal value, not the Python
   repr — important for the dashboard and for the CP4.2 migration
   CLI's `WHERE mode = 'legacy'` lookups.
2. **Per-row routing.** [`wg_manager.tasks._open_runner`](../src/wg_manager/tasks.py)
   and `_maybe_install_host_cert` now branch on `ssh_key.mode`,
   not `settings.ssh_auth_mode`. The
   `POST /servers/{id}/rotate-host-cert` endpoint's 409 precondition
   reads the row's key mode too, and its detail string names the
   exact `wg-manager ssh migrate-to-ca <key_id>` invocation an
   operator needs to run. `SSH_AUTH_MODE` survives in
   [`Settings`](../src/wg_manager/config.py) for backwards compat
   but is no longer consulted on any code path — CP4.4 removes the
   setting once every row is `ca`.
3. **API surface.** `SSHKeyRead` (`GET /ssh-keys`, `POST /ssh-keys`,
   `GET /ssh-keys/{id}`) carries `mode`. `web/lib/types.ts` mirrors
   the `SSHKeyMode` literal so the CP4.3 dashboard reframe can
   render the badge without a backend round-trip.

```bash
# .env additions on top of CP3 — none. The CP2 SSH_AUTH_MODE setting
# stays in place but is now a no-op; the column drives routing.
```

Test snapshot (`pytest -q tests/test_ssh_key_mode.py`):

```
13 passed in ~0.4s
```

Plus 8 CP2 / CP3 tests refactored to use the new
`promote_all_keys_to_ca(session)` conftest helper instead of relying
on `SSH_AUTH_MODE=ca` to flip routing. Full suite 216/216 green in
`local` mode; dashboard vitest 26/26.

### Phase 2c checkpoint 4.2 — migrate-to-ca endpoint + CLI (2026-05-28)

CP4.2 closes the chicken-and-egg gap CP4.1 left behind. A `mode=ca`
row can't reach a host that hasn't been bootstrapped with a
CA-signed cert (the client-side `KnownHostsCAPolicy` refuses to
TOFU), but the cert install requires an SSH session in the first
place. The migration takes a one-shot legacy SSH private key —
typically the same key the operator used historically for the host
— and uses it as the bridge.

What CP4.2 ships:

1. **`POST /ssh-keys/{id}/migrate-to-ca`** (router:
   [`wg_manager.routers.ssh_keys`](../src/wg_manager/routers/ssh_keys.py)).
   Body: `{private_key_b64, passphrase?}`. The private key is used
   in-memory by the helper and never persisted. Always returns 200
   on a well-formed call — partial failure is encoded in the
   per-server result list, not the HTTP status, so the dashboard
   and CLI render the per-host outcome table uniformly. 404 on
   unknown key id; 422 on malformed `private_key_b64`.
2. **`wg_manager.ssh_migrate.migrate_key_to_ca`** — HTTP-agnostic
   helper that walks every `Server` row referencing the key,
   constructs a *legacy* `SSHRunner` (no `cert_pem` / `ca_public_key`
   — the whole point is to reach a not-yet-trusting host), drives
   `host_ssh.install_host_cert` to push the CA trust anchor + signed
   host cert, and persists the `host_cert_*` columns on each server.
   After every server succeeds: flips the SSH key row to `mode=ca`
   and NULLs `private_key_ct` + `passphrase_ct`. If *any* server
   fails the row is left untouched so the operator has a clean
   retry path.
3. **`wg-manager ssh migrate-to-ca <id> --key-file PATH
   [--passphrase ...]`** (CLI:
   [`wg_manager.cli`](../src/wg_manager/cli.py)). Thin HTTP wrapper:
   reads the PEM body from disk, base64-encodes it, posts, and
   pretty-prints the per-server envelope. Exits non-zero if any
   server failed — CI-friendly fail-fast behaviour while still
   showing every host's outcome.

```bash
# Steady-state operator flow for migrating a legacy row to CA:
wg-manager ssh migrate-to-ca 3 --key-file ~/.ssh/id_rsa
# {
#   "key_id": 3,
#   "name": "azure_rsa.pem",
#   "mode": "ca",
#   "servers_total": 1,
#   "servers_ok": 1,
#   "servers_failed": 0,
#   "results": [
#     {"server_id": 4, "hostname": "65.52.211.113", "status": "ok",
#      "cert_serial": 12345, "valid_before": "2026-05-29T21:07:02"}
#   ]
# }
```

```bash
# Partial-failure path — one host unreachable, row stays mode=legacy:
wg-manager ssh migrate-to-ca 3 --key-file ~/.ssh/id_rsa
# {
#   "key_id": 3, "mode": "legacy", "servers_failed": 1,
#   "results": [
#     {"server_id": 4, "status": "ok", ...},
#     {"server_id": 7, "status": "ssh_failed",
#      "error": "SSH connection to 10.0.0.99:22 failed: timed out"}
#   ]
# }
# CLI exits 1; row mode stays "legacy" so the operator can re-run
# after fixing 10.0.0.99 without losing the ok server's persisted
# host cert (the bootstrap is idempotent on already-installed hosts).
```

The migration also covers the "labelled `ca` but never
bootstrapped" shape that the 2026-05-27 smart-backfill fix labelled
as `ca` based on NULL `private_key_ct`: pass the same one-shot key
and the migration walks each host through the install, leaving the
row's already-correct `ca` mode intact.

Test snapshot (`pytest -q tests/test_ssh_migrate.py tests/test_cli_ssh_migrate.py`):

```
14 passed in ~0.4s
```

Full suite 254 passed in `local` mode (1 unrelated pre-existing
crypto failure).

### Target-host setup (Phase 2c provisioning step)

The managed host needs to trust the CA. Provisioning writes:

```
# /etc/ssh/sshd_config.d/wg-manager.conf
TrustedUserCAKeys /etc/ssh/wg-manager-ca.pub
```

The CA pubkey itself comes from
`GET /v1/ssh/config/ca` (response: `{"data": {"public_key": "ssh-rsa …"}}`).

Host *certs* (the inverse direction — wg-manager trusts the host) use a
second role with `allow_host_certificates=true` and `key_type="ca"`; the
client passes the CA pubkey to paramiko's host-key policy. Replaces TOFU.

## 4. PKI — internal TLS (Phase 2d)

The X.509 layer wg-manager will use for the API listener (mTLS),
operator/CLI client certs, and the MySQL boundary. CP1 lands the
module + bootstrap; CP2+ wires it through.

### Phase 2d checkpoint 1 — `wg_manager.pki` shipped (2026-05-29)

The raw `hvac` calls below have been wrapped into
[`wg_manager.pki`](../src/wg_manager/pki.py). Application code calls
one of two backends instead of poking hvac directly:

* `LocalDevPKI` — in-process root + intermediate built on
  `cryptography`, selected by `PKI_BACKEND=local`. Used by the test
  suite and by developers who don't want a Vault container in the
  loop. The hierarchy regenerates on every restart unless the
  operator pins all four PEMs via the `PKI_LOCAL_DEV_*` env vars
  (the same shape Phase 2c's `SSH_CA_LOCAL_DEV_PEM` allows). Pinning
  is required for multi-process dev because the API and Celery
  worker each call `make_pki_backend()` at import time.
* `VaultPKI` — wraps the real Vault PKI engine with a two-tier
  root (10y) → intermediate (5y) hierarchy, selected by
  `PKI_BACKEND=vault`. CA private keys never leave Vault.

Both implement the same `PKIBackend` protocol:

```python
backend.ca_bundle_pem                                              # trust anchors
backend.issue_server_cert(common_name="api.wg.local",
                          sans=["api.wg.local", "127.0.0.1"],
                          ttl_seconds=300)                         # → Cert
backend.issue_client_cert(common_name="ops@wg.local",
                          sans=["ops@wg.local"], ttl_seconds=300)  # → Cert
backend.revoke_cert(serial=<int>)
backend.crl_pem()                                                  # PEM-encoded CRL
```

`Cert` is a frozen dataclass with `cert_pem`, `private_pem`,
`chain_pem`, `serial`, `common_name`, `sans`, `not_before`,
`not_after` — enough to feed straight into uvicorn's
`--ssl-keyfile`/`--ssl-certfile`/`--ssl-ca-certs` (CP2) or a MySQL
client connection-arg block (CP4).

`VaultPKI.bootstrap(...)` and the `make pki-bootstrap` target run
the idempotent setup against a configured Vault. Example output:

```
$ make pki-bootstrap
[OK] PKI configured
     root mount:         pki
     intermediate mount: pki_int
     server role:        wg-manager-server
     client role:        wg-manager-client
     allowed domains:    (any — dev default)
     ca_bundle:
       - CN=wg-manager PKI intermediate, NotAfter=2031-05-28T17:18:29+00:00
       - CN=wg-manager PKI root, NotAfter=2036-05-26T17:18:29+00:00
```

The bootstrap also `tune_mount_configuration`s both mounts so the 10y
root TTL isn't silently clipped by Vault's default 32-day system
`max_lease_ttl` — without the tune, leaves issued under any role
inherit the cap and the CA is effectively neutered.

The `allowed_domains` list comes from `PKI_VAULT_ALLOWED_DOMAINS`;
empty (the default) is treated as "any name" via `allow_any_name`
on both roles — appropriate for dev / IP-only fleets. The server
role enforces the list when set; the client role stays permissive
so operator CNs like `ops@wg.local` work without per-operator role
proliferation.

Test snapshot (`make vault-up && pytest -q tests/test_pki.py`):

```
37 passed in ~3s   # full local + vault matrix
```

### Raw hvac flow (reference)

Kept here so a reader can recognise what the wrapper is doing. New
code should call `wg_manager.pki` instead.

```python
client.sys.enable_secrets_engine(
    backend_type="pki",
    path="pki",
    config={"max_lease_ttl": "87600h"},  # 10y — otherwise capped to 768h
)
client.sys.tune_mount_configuration(path="pki", max_lease_ttl="87600h")
client.secrets.pki.generate_root(
    type="internal",
    common_name="wg-manager PKI root",
    extra_params={"ttl": "87600h"},
    mount_point="pki",
)

client.sys.enable_secrets_engine(
    backend_type="pki",
    path="pki_int",
    config={"max_lease_ttl": "43800h"},  # 5y
)
client.sys.tune_mount_configuration(path="pki_int", max_lease_ttl="43800h")
csr = client.secrets.pki.generate_intermediate(
    type="internal",
    common_name="wg-manager PKI intermediate",
    extra_params={"key_type": "ec", "key_bits": 256},
    mount_point="pki_int",
)["data"]["csr"]
signed = client.secrets.pki.sign_intermediate(
    csr=csr, common_name="wg-manager PKI intermediate",
    extra_params={"ttl": "43800h"}, mount_point="pki",
)["data"]["certificate"]
# Concatenate the root onto the signed intermediate so /ca_chain
# returns the full path — without this, TLS clients trusting the
# bundle can't build a chain from a leaf back to the trust anchor.
root_pem = client.adapter.get("/v1/pki/ca/pem").text
client.secrets.pki.set_signed_intermediate(
    certificate=signed.rstrip() + "\n" + root_pem,
    mount_point="pki_int",
)

client.secrets.pki.create_or_update_role(
    name="wg-manager-server",
    extra_params={
        "allowed_domains": ["wg.local"],
        "allow_subdomains": True,
        "allow_bare_domains": True,   # so SAN=wg.local works
        "allow_ip_sans": True,
        "server_flag": True,
        "client_flag": False,
        "max_ttl": "8760h",
    },
    mount_point="pki_int",
)

cert = client.secrets.pki.generate_certificate(
    name="wg-manager-server",
    common_name="api.wg.local",
    extra_params={"ttl": "5m"},
    mount_point="pki_int",
)["data"]
# cert keys: certificate, private_key, ca_chain, serial_number, expiration
```

CP2 wires the issued cert into uvicorn's ASGI server; CP3 adds an
operator-facing `wg-manager certs issue --type ...` CLI on top of
this surface; CP4 reuses the same intermediate for the MySQL boundary
so renewal is one job, not three. CRL endpoints (`/v1/pki_int/crl`)
back the CP5 revocation-rejection test.

## 5. Auth: AppRole (Phase 2b onward)

The smoke script uses the dev root token because it's a spike. As soon
as `wg_manager.crypto` lands in Phase 2b, the app authenticates via
AppRole:

```python
client = hvac.Client(url="http://vault:8200")
client.auth.approle.login(role_id=ROLE_ID, secret_id=SECRET_ID)
# client.token is now a short-lived child token; renew it before TTL.
```

**Deployment shape.**

- `ROLE_ID` is baked into the deploy manifest (systemd unit / k8s
  manifest); it's not a secret.
- `SECRET_ID` is generated at deploy time using a Vault-side
  *response-wrapped* token so it can be unwrapped exactly once by the
  app, and never seen by the operator running the deploy. See
  `vault write -wrap-ttl=10m -force auth/approle/role/wg-manager/secret-id`.
- The app's token has a short TTL (e.g. 1 h) and is renewed by a
  background task; expired tokens trigger a re-login from
  `(ROLE_ID, SECRET_ID)`.

Document the AppRole policy alongside the production Vault config; for
the Phase 2a spike, policy is `root`, which is fine because the
container is throwaway.

## 6. Audit logs (Phase 2e)

Vault audit devices are the canonical record of every API call the
server processes — admin actions, key writes, cert issuance, the lot.
Phase 2e audit-log work ships off-host audit in three cycles:

- **Cycle 1 (this section)** — enable a Vault file audit device
  writing to a persistent volume.
- **Cycle 2** — add a `vector` sidecar to docker-compose that tails
  the audit file and emits to its own stdout for dev visibility.
- **Cycle 3** — document production paths (journald, syslog, SIEM
  connectors) for off-host shipping.

### Cycle 1 — file audit device

`docker-compose.yml` mounts the `wg_manager_vault_audit_logs` named
volume at `/vault/logs/` on the Vault container so the audit file
survives container restarts. The dev compose stack does **not** enable
the device automatically — that lands as an operator-driven step so
the audit-trail wire-up is visible in the cookbook, not a magic
container-startup hook the operator never sees.

Enable it:

```bash
make vault-up                    # if Vault isn't already running
make vault-audit-bootstrap       # enable the file audit device
```

The Makefile target wraps [`scripts/vault_audit_bootstrap.py`](../scripts/vault_audit_bootstrap.py)
which in turn calls [`wg_manager.vault_audit.bootstrap_file_audit_device`](../src/wg_manager/vault_audit.py).
The helper is **idempotent**: re-running against an already-bootstrapped
Vault prints `already present` and exits 0. If a non-`file` audit
device (syslog / socket) is already mounted at the target path, the
helper refuses to overwrite — operator must migrate manually.

Verify a record was written:

```bash
# 1. Trigger an audit-worthy operation (anything that writes to Vault):
docker compose exec vault vault kv put secret/audit-test foo=bar

# 2. Tail the audit file:
docker compose exec vault tail /vault/logs/audit.log
```

Each line is a JSON record with the request method, path, client
token hash, and any response data — Vault's audit log is the
hash-chained forensic record of who-did-what.

### Reset semantics

Because dev Vault is in-memory, a `docker compose down && up` resets
Vault's state and the audit device must be re-enabled with another
`make vault-audit-bootstrap`. The audit file itself **persists** in
the named volume across restarts; if you want a clean log, also
`docker volume rm wg_manager_vault_audit_logs`.

### Production wire-up

In production the file audit device is one of several options. The
matching production-path docs land in cycle 3 of this work-stream.
Short version: a `vector` / `fluent-bit` / `promtail` sidecar tails
the file and ships to a tamper-evident store (Loki, CloudWatch,
S3 + Object Lock). The Vault audit log's hash-chain means downstream
corruption is detectable by replaying the chain.

## 7. Open operator concerns (deferred to Phase 2e)

The dev container hides these — they need real answers before any
production rollout.

- **Auto-unseal.** Dev mode is auto-unsealed at startup; production
  needs a real seal (cloud KMS, transit-seal against a second Vault,
  or Shamir with operator-held shares). Pick **cloud KMS** when we know
  the cloud, else **transit-seal**.
- **Storage backend.** `vault server -dev` is in-memory. Production
  uses integrated Raft storage with periodic `vault operator raft
  snapshot save` to S3/GCS.
- **HA.** Three-node Raft cluster for prod; this is the bulk of the
  "Vault in production" operational cost.
- **Audit log retention.** Cycle 1 (above) enables the dev wire-up;
  cycles 2-3 ship the off-host story. Production retention is then a
  question of the downstream sink — how long Loki / CloudWatch holds
  the chain, with retention tuned to your incident-response window.
- **Token TTL policy.** AppRole token TTL, secret-id TTL, and
  response-wrap TTL all need real values. Drafts in
  `docs/vault-policies.md` (Phase 2b).
- **Backup story.** A leaked Vault snapshot is the new crown jewel.
  Encrypt at rest, restrict to a separate IAM role, and keep snapshots
  on a separate blast radius from app backups.

## 8. Why Vault (and what we considered instead)

- **App-layer envelope encryption with a master key in env.** Cheapest;
  defeats T-1 alone. Rejected because the SSH CA flow (Phase 2c)
  *eliminates* T-1's column outright rather than encrypting it — a
  strictly better outcome.
- **Cloud KMS only (e.g. AWS KMS / GCP KMS).** Solves Transit but not
  SSH CA or PKI. Would force us to bolt on a separate SSH CA later.
- **External secret store (HCP Vault, Doppler, 1Password Secrets).**
  Same envelope shape as KMS; doesn't solve SSH CA either.

Vault is the only single tool we found that covers Transit + SSH CA +
PKI + audit log under one auth/policy model. The cost is operational
(unseal, HA, audit retention) and it's a real cost — see §7.
