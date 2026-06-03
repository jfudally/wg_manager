# Runbook — Backup and restore

You are reading this either because you are setting up the backup
cadence on a fresh deployment, or because you need to restore from a
backup — most often after one of the other two runbooks
([`key-compromise.md`](key-compromise.md),
[`vault-down.md`](vault-down.md)) sent you here.

Two state stores need backing up:

- **MySQL** — every wg-manager row (SSH role labels, server +
  client registry, certificate audit registry, audit events).
- **Vault** — the Transit master key, SSH CA, PKI hierarchy, and
  audit device. Vault stores all of this in raft storage on a
  production deployment; the in-memory dev container has no
  persistent state to back up.

Companion docs:

- [`docs/vault-cookbook.md`](../vault-cookbook.md) — §7 covers the
  production-Vault storage / unseal / HA story this runbook depends
  on.
- [`docs/deploy/systemd-timer.md`](../deploy/systemd-timer.md) — the
  ``wg-manager-backup.service`` + ``.timer`` pattern this runbook's
  cadence section references.
- [`docs/runbooks/key-compromise.md`](key-compromise.md) — if you
  are restoring after a leaked-backup scenario, read the
  Verification section there before turning the new deployment on.

---

## Scope

What this runbook covers — and what it does **not**.

| Asset                                  | Backup mechanism                                           | Restore mechanism |
| -------------------------------------- | ---------------------------------------------------------- | ----------------- |
| MySQL rows                             | `wg-manager db backup --encrypt`                           | `wg-manager db restore --decrypt` |
| Vault raft storage (Transit, SSH CA, PKI, operators) | `vault operator raft snapshot save`           | `vault operator raft snapshot restore` |
| Vault audit log file                   | Vector sidecar ships off-host (see cookbook §6 cycle 3)    | Off-host log store (your S3 / Loki / etc.) is the source of truth |
| Operator PKCS#12 client certs          | **Not backed up** — issue replacements via `wg-manager certs issue` | Re-issue per [`key-compromise.md`](key-compromise.md) §"Operator or service cert revoked or leaked" |
| TLS server certs on disk               | Backed up via the MySQL `certificate` row (out_cert_path, out_key_path, out_chain_path columns) | Re-mint via `wg-manager certs renew --due --threshold-pct 100` |

**Not in scope**: WireGuard peer public keys (not secret), application
logs (your log shipper handles those — see Phase 2e cycle 3 in the
cookbook for the Vault audit log shipping pattern).

---

## Cadence

The default recommendation for a production deployment:

| What                  | Schedule              | Retention             |
| --------------------- | --------------------- | --------------------- |
| MySQL encrypted dump  | Every 6 hours         | 7 days local, 30 days off-host |
| Vault raft snapshot   | Every 1 hour          | 24 hours local, 7 days off-host |
| Audit log shipping    | Continuous (vector)   | Per your sink's retention policy |

These are starting points — tune to your incident-response window.

The systemd-timer pattern documented in
[`docs/deploy/systemd-timer.md`](../deploy/systemd-timer.md) ships
unit files (``wg-manager-backup.service`` + ``wg-manager-backup.timer``)
that run ``wg-manager db backup --encrypt`` on the recommended
cadence. The Vault snapshot is a separate timer because its cadence
is shorter and its target is the Vault binary rather than
``wg-manager``.

---

## Take a backup

Both halves should run together so the MySQL row pointing at a
cert can be matched against the Vault-side material that signed it.

### MySQL (encrypted dump)

```bash
# Production — picks up CRYPTO_BACKEND=vault + Vault Transit settings
# from the environment, so the DEK wrap goes through Vault:
wg-manager db backup \
    --output /var/backups/wg-manager/db-$(date -u +%Y%m%dT%H%M%SZ).enc.json \
    --encrypt

# Dev / local — uses LocalDevBackend (Fernet) for the wrap:
WG_MANAGER_API_URL="..." wg-manager db backup \
    --output /tmp/db.enc.json \
    --encrypt
```

The on-disk file is a JSON envelope containing the ciphertext, the
12-byte nonce, the wrapped data-encryption key (DEK), and a public
context string binding the wrap to this specific backup. The DEK
itself never lands on disk in plaintext.

Tamper-evidence is the AES-GCM tag. A flipped bit anywhere in the
envelope-protected payload (ciphertext, nonce, or wrapped DEK) makes
the restore fail loudly with a clear "decrypt failed" message —
verified by the
[`tests/test_db_backup_encrypt.py`](../../tests/test_db_backup_encrypt.py)
suite.

### Vault (raft snapshot)

```bash
# Production:
VAULT_ADDR=https://vault.internal:8200 \
    vault operator raft snapshot save \
        /var/backups/vault/snap-$(date -u +%Y%m%dT%H%M%SZ).snap

# Dev convenience wrapper (works against any raft-backed Vault):
make backup-vault
```

The dev container runs with in-memory storage (``storage "inmem"``)
which does not support snapshots — ``make backup-vault`` against the
dev stack fails with a clear Vault-side error. The wrapper exists
for the "I'm validating my production config against a local raft
container" workflow; see cookbook §7.

---

## Restore

You are most likely here because the Vault container was lost
(``vault-down.md`` Recovery A) or a leaked backup forced a full
re-issue cycle (``key-compromise.md`` PKI row). The order matters:
**Vault first, then MySQL**.

### Vault (raft snapshot restore)

```bash
# Stop the wg-manager API + worker so they don't write through the
# restore window:
systemctl stop wg-manager-api wg-manager-worker

# Restore the most recent snapshot. -force is required if the
# current cluster has any data the snapshot does not:
VAULT_ADDR=https://vault.internal:8200 \
    vault operator raft snapshot restore -force \
        /var/backups/vault/snap-<TS>.snap

# Verify the cluster is healthy:
vault operator raft list-peers
vault status
```

The chain of Vault operations between the snapshot and now is now
lost — any cert issued, key rotation, or audit-log line in that
window is gone. If your last snapshot is older than the data loss
window you can tolerate, the cadence above is wrong for your
environment.

### MySQL (decrypt + restore)

```bash
# The same CryptoBackend that wrapped the DEK has to be available
# to unwrap it. After the Vault restore above, this is usually the
# case — unless you are restoring into a fresh Vault, in which case
# the dump is unrecoverable (the DEK wrap can't be unwrapped) and
# you are looking at a different runbook entirely.
wg-manager db restore \
    --input /var/backups/wg-manager/db-<TS>.enc.json \
    --decrypt \
    --drop-existing

# Bring wg-manager back online:
systemctl start wg-manager-api wg-manager-worker
```

The ``--drop-existing`` flag truncates the existing tables before
inserting. Restoring without it refuses to proceed if any target
table already has rows — exactly the behaviour you want during a
disaster-recovery drill, where partial state on the new host is a
red flag worth investigating before clobbering.

---

## Verification

Run these end-to-end after any restore. A backup you have not
restored from is a backup you do not know works.

- ``vault status`` reports ``Sealed: false`` and a sane storage
  backend. ``vault operator raft list-peers`` shows the expected
  cluster shape.
- ``wg-manager certs list`` returns the cert inventory you expect.
  Any cert that was active before the disaster must be present.
- ``GET /crypto/status`` returns 200 with a non-zero active Transit
  key version. ``client_legacy == 0`` (the post-Phase-2b invariant)
  still holds.
- A test cert issuance succeeds:
  ``wg-manager certs issue --type api --cn healthcheck.test
  --ttl-days 1`` returns a parseable cert. Revoke it via
  ``wg-manager certs revoke --serial <S>`` once verified.
- The ``wg_manager.audit`` JSON stream is once again emitting one
  line per admit/reject decision when the API serves a request.
- Run a **restore drill** at least quarterly against the
  most-recent backup. The drill is a full ``vault operator raft
  snapshot restore`` + ``wg-manager db restore --decrypt`` cycle
  against an *isolated* environment (not your production deployment).
  Document the runtime + any gaps in your incident file.

---

## Restore drill — first time

If you have never run the restore path before, do not wait for an
incident to discover whether the backup works. The first restore
drill:

1. Spin up a throwaway compose stack: ``make db-up && make
   vault-up``.
2. Bootstrap the bare-minimum trust roots:
   ``make ssh-ca-bootstrap && make pki-bootstrap`` + the Transit
   bootstrap one-liner from
   [`vault-down.md`](vault-down.md) Recovery A.
3. Restore your most-recent production backup onto this throwaway
   stack.
4. Walk the [Verification](#verification) section against it.
5. ``make db-down && make vault-down`` to tear down.

A drill that surfaces a gap is doing its job. Patch the gap, file
the change, then drill again to confirm.
