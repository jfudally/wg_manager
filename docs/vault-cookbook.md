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
     CA public key (drop into /etc/ssh/wg-manager-user-ca.pub):
       ssh-rsa AAAAB3NzaC1yc2E…
```

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

```python
client.sys.enable_secrets_engine(backend_type="pki", path="pki")
client.secrets.pki.generate_root(
    type="internal",
    common_name="wg-manager root",
    extra_params={"ttl": "8760h"},  # 1 year — Phase 2d uses an intermediate.
    mount_point="pki",
)
client.secrets.pki.create_or_update_role(
    name="api-server",
    extra_params={
        "allowed_domains": ["wg.local"],
        "allow_subdomains": True,
        "max_ttl": "30d",
    },
    mount_point="pki",
)

cert = client.secrets.pki.generate_certificate(
    name="api-server",
    common_name="api.wg.local",
    extra_params={"ttl": "7d"},
    mount_point="pki",
)["data"]
# cert keys: certificate, private_key, ca_chain, serial_number, expiration
```

Phase 2d stands up a proper two-tier hierarchy (root → intermediate)
and uses CRL endpoints (`/v1/pki/crl`) for revocation.

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

## 6. Open operator concerns (deferred to Phase 2e)

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
- **Audit log retention.** Vault audit logs are hash-chained — they're
  the forensic record of who-did-what. Phase 2e ships them to a
  separate sink (file + `vector`, or directly to Loki/CloudWatch).
- **Token TTL policy.** AppRole token TTL, secret-id TTL, and
  response-wrap TTL all need real values. Drafts in
  `docs/vault-policies.md` (Phase 2b).
- **Backup story.** A leaked Vault snapshot is the new crown jewel.
  Encrypt at rest, restrict to a separate IAM role, and keep snapshots
  on a separate blast radius from app backups.

## 7. Why Vault (and what we considered instead)

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
(unseal, HA, audit retention) and it's a real cost — see §6.
