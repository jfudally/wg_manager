# Phase 2c — Migrating from stored SSH keys to the SSH CA

This cookbook documents the operator path from the Phase 2b
stored-key world (every `sshkey` row carries an encrypted private
key body) to the Phase 2c CA world (every row is a name-and-mode
label and every connection mints a short-lived user certificate
from the SSH CA). It also documents the **CP4.4 cutover** — the
release that drops the `sshkey.private_key_ct` and
`sshkey.passphrase_ct` columns — and the recovery path for operators
whose `alembic upgrade head` refuses with the legacy-row guard.

## TL;DR — when the guard fires

```
$ alembic upgrade head
…
RuntimeError: Alembic 0008 refuses to run — 3 sshkey row(s) still in
mode='legacy'. Dropping the ciphertext columns now would destroy the
bootstrap material those rows still need. Migrate them to CA mode
first; see docs/migrations/2c-ssh-ca.md for the two supported recovery
paths (prior-release CLI or manual SQL fixup). Inspect the offending
rows with: SELECT id, name FROM sshkey WHERE mode = 'legacy';
```

There are exactly two supported paths from this state. **Both leave
the schema in a re-upgradeable state — Alembic 0008 just refuses to
run; no half-applied state.**

1. **Roll back to the previous release** (recommended). The CP4.3
   release shipped `wg-manager ssh migrate-to-ca <key_id>` and the
   matching dashboard form. Drive one of those, then re-run
   `alembic upgrade head` against the current release.
2. **Manual SQL fixup** (for fleets without a working bastion or
   anyone who already removed the prior release). See §4 below.

## 1. What changed in the schema

Phase 2c ships its schema changes across four Alembic revisions:

| Revision                          | Adds                                                                                                                                                                                                  | Drops                                                       |
|-----------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------|
| 0006 `host_cert_columns`          | `server.host_cert_*` (six columns) — host cert metadata.                                                                                                                                              | —                                                           |
| 0007 `sshkey_mode`                | `sshkey.mode` (NOT NULL, server default `'legacy'`). Backfilled per-row from the row's existing `private_key_ct` shape — populated → `'legacy'`, NULL → `'ca'`.                                       | —                                                           |
| 0008 `drop_sshkey_ciphertext`     | —                                                                                                                                                                                                     | `sshkey.private_key_ct`, `sshkey.passphrase_ct`. Refuses to run while any row is still `mode='legacy'`. |

Phase 2c CP4.4 is **0008**. The two ciphertext columns disappear
once every row is CA-mode; from that point on the `sshkey` row is a
name-and-mode label with no secret material at rest.

## 2. Migrating a row from `legacy` to `ca` (CP4.3 release)

On the CP4.3 release (or any prior release that still has the
`migrate-to-ca` endpoint):

```sh
# From a workstation that can talk to the API:
wg-manager ssh migrate-to-ca <key_id> --key-file ~/keys/<row-pem>.pem

# Or via the dashboard:
# /ssh-keys → click "Migrate to CA" on the legacy row → paste the PEM.
```

The migration helper:

1. SELECTs every `server` row that references the SSH key.
2. Opens a *legacy* SSH session to each host using the one-shot key
   you supplied.
3. Drives `wg_manager.host_ssh.install_host_cert` — pushes the CA
   trust anchor, signs a host cert against the host's existing
   `/etc/ssh/ssh_host_ed25519_key.pub`, writes the sshd drop-in, and
   reloads sshd.
4. Persists the host cert metadata onto each `server.host_cert_*`
   column.
5. **Iff every host succeeded**, flips the SSH key row to
   `mode='ca'` and nulls `private_key_ct` / `passphrase_ct`. Partial
   failure leaves the mode unchanged so you have a clean retry path.

Run `wg-manager ssh migrate-to-ca` against every legacy key, then:

```sh
# On the CP4.4 release:
alembic upgrade head
```

The guard sees zero legacy rows and drops the columns.

## 3. Cutting over to CP4.4

After every row is `mode='ca'`:

1. Snapshot the database (the column drop is non-reversible — see
   §6).
2. Deploy the CP4.4 release. The release deletes:
   - the `wg-manager ssh migrate-to-ca <id>` CLI subcommand;
   - the `POST /ssh-keys/{id}/migrate-to-ca` endpoint;
   - the dashboard "Migrate to CA" form;
   - the `wg_manager.crypto` SSH-key helpers
     (`resolve_sshkey_*`, `set_sshkey_*`, `encrypt_sshkey_secrets`);
   - the `private_key_b64` / `passphrase` fields on `POST /ssh-keys`
     and `PATCH /ssh-keys/{id}` (the schema now rejects them with
     422 instead of silently dropping them).
3. `alembic upgrade head` — Alembic 0008 runs, drops the two
   columns, leaves the rest of the table intact.
4. Verify the dashboard. `/ssh-keys` should render every row with a
   `ca` mode badge; the `Add SSH role` form should only ask for a
   name.

## 4. Manual SQL fixup (last-resort recovery)

If the prior-release CLI is unavailable (you already deleted the
old binary, the operator workstation is offline, etc.) and you
*know* the legacy SSH key body is recoverable elsewhere — e.g. you
have the original PEM in a password manager — you can drive the
host-side install by hand and then flip the row directly.

For each `sshkey` row where `mode = 'legacy'`:

1. SSH into every `server` row that references it using the
   stored-key PEM:

   ```sh
   ssh -i ~/keys/<pem> <user>@<host>
   ```

2. Install the CA trust anchor + host cert manually:

   ```sh
   sudo cp /tmp/wg-manager-user-ca.pub /etc/ssh/wg-manager-user-ca.pub
   sudo cp /tmp/ssh_host_ed25519_key-cert.pub /etc/ssh/ssh_host_ed25519_key-cert.pub
   sudo tee /etc/ssh/sshd_config.d/wg-manager.conf <<'EOF'
   TrustedUserCAKeys /etc/ssh/wg-manager-user-ca.pub
   HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
   EOF
   sudo systemctl reload sshd
   ```

   The `wg-manager-user-ca.pub` body is in Vault at
   `ssh/config/ca` (or in the local-dev CA via
   `wg-manager-dev-ssh-ca.pem`). The host cert is minted with
   `vault write ssh/sign/wg-manager-hosts cert_type=host
   public_key=@/etc/ssh/ssh_host_ed25519_key.pub
   valid_principals=<hostname> ttl=24h`.

3. Once every server is bootstrapped, flip the row:

   ```sql
   UPDATE sshkey
      SET mode = 'ca',
          private_key_ct = NULL,
          passphrase_ct = NULL
    WHERE id = <id>;
   ```

4. `alembic upgrade head`. The guard now reports zero legacy rows
   and the column drop proceeds.

## 5. Rolling back

Alembic 0008's downgrade re-adds the two columns as `NULLABLE TEXT`,
but **does not restore the data**. If you've already dropped the
columns and decide to revert to the CP4.3 release, you must:

1. `alembic downgrade -1` — re-adds the empty columns.
2. Re-register every SSH role via the prior release's
   `POST /ssh-keys` body (with `private_key_b64`) so the rows
   regain their key material.

There is no automatic recovery for the ciphertext that lived in the
columns at the time of the upgrade — that is the price of a
forward-only schema cleanup.

## 6. Risks captured

- **Vault outage at migration time.** The CP4.2 migration helper
  hits Vault to mint host certs. Document a maintenance window
  during which Vault is healthy.
- **Cross-version compatibility.** Operators upgrading directly
  from a pre-CP4 release skip CP4.1–CP4.3 entirely. They land on
  CP4.4 with every row defaulted to `mode='legacy'` (via 0007's
  backfill) and 0008's guard refuses to drop the columns until they
  follow §2 or §4.
- **Backup hygiene.** Backups taken on the CP4.3 schema retain the
  ciphertext columns; backups taken on CP4.4 do not. Document this
  in the recovery runbook so an operator restoring an older backup
  is prompted to migrate again.
