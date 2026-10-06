# Runbook — Migrate the prod Vault from file to raft storage

You are reading this because a prod host's Vault was set up before
Phase 3d cycle 5 and still uses `storage "file"`. Since cycle 5,
`docker/vault/vault.hcl` uses **raft** storage on a new volume
(`wg_manager_vault_raft`). Raft is what the warm standby needs: it
stays current by restoring `vault operator raft snapshot`s, and file
storage can't produce them
([`docs/deploy/ha-control-plane.md`](../deploy/ha-control-plane.md)).

This is a **one-time, offline** conversion of the existing data. The
SSH CA, PKI, Transit key and audit config come across intact, and
`vault-init.json` (unseal keys + root token) keeps working, because
`vault operator migrate` copies the encrypted entries verbatim.

Fresh hosts skip this: `make prod-up` on a new box initializes Vault
straight onto raft.

Companion docs:

- [`host-migration.md`](host-migration.md) — `make host-export` is the
  full cold backup taken in step 2.
- [`vault-down.md`](vault-down.md) — if Vault won't unseal afterwards.

---

## How to tell whether a host needs this

After pulling a cycle-5 commit, a host that still needs the migration
fails `make prod-up` in `bootstrap-substrate` with:

```
ERROR: Vault reports uninitialized, but /app/vault-init.json already
       holds keys for an existing Vault. Refusing to re-init.
```

That's the guard in `scripts/vault_init_unseal.sh` doing its job.
Before it existed, this situation silently re-initialized Vault: it
overwrote `vault-init.json` and minted a new SSH CA that no managed
host trusts. Nothing has been lost. Continue with the procedure
below. The migration script cleans up the empty raft store that the
failed boot left behind.

## Time budget

Same clock as a host migration. Managed hosts' SSH host certs may have
as little as **~12h** left when the control plane stops renewing them
([`host-migration.md` → Time budget](host-migration.md#time-budget)).
The migration itself takes seconds. Budget 15–30 minutes of control
plane downtime, including the backup.

The VPN keeps running throughout. WireGuard on the hubs doesn't depend
on wg-manager.

---

## Procedure

### 1. Quiesce (stack still running on the OLD commit)

```bash
make prod-logs          # Ctrl-C once the worker is idle
make prod-db-backup     # encrypted DB dump, backups/*.enc.json
```

### 2. Stop and take a full cold backup

```bash
make prod-down          # never `down -v`
make host-export o=/var/tmp/wg-pre-raft
```

`host-export` copies every volume plus `.env.prod`, `vault-init.json`
and `tls/`. It's your fallback if everything else goes wrong. Keep it
`0700` and delete it once step 5 passes.

### 3. Pull the cycle-5 commit

```bash
git pull            # or check out the release tag
```

Don't run `make prod-up` yet. If you already did, that's fine: the
guard stopped it, and step 4 handles the leftovers.

### 4. Migrate

```bash
make vault-migrate-raft
```

The script (`scripts/vault_migrate_raft.sh`) checks the following,
in this order, before writing anything:

| Check | On failure |
|---|---|
| `vault` service stopped | refuses — `make prod-down` first |
| raft volume empty | probes it: **initialized** Vault → refuses ("already on raft"); **uninitialized** leftover from a premature `prod-up` → clears it and continues; can't tell → refuses |
| file-storage data present (`/vault/file/core`) | refuses — nothing to migrate |

It then runs `vault operator migrate` with
`docker/vault/migrate-raft.hcl` and ends with
`Success! All of the keys have been migrated.`

### 5. Start and verify

```bash
make prod-up
```

Then confirm that Vault is on raft and that it's the **same** Vault:

```bash
TOKEN=$(sudo jq -r .root_token vault-init.json)

# Storage Type raft, Sealed false
docker compose exec -T vault sh -c 'VAULT_ADDR=http://127.0.0.1:8200 vault status'

# Exactly one voter, wg-manager-vault, leader
docker compose exec -T -e VAULT_TOKEN="$TOKEN" vault \
  sh -c 'VAULT_ADDR=http://127.0.0.1:8200 vault operator raft list-peers'

# The SSH CA public key is unchanged. Compare with what a managed host trusts:
docker compose exec -T -e VAULT_TOKEN="$TOKEN" vault \
  sh -c 'VAULT_ADDR=http://127.0.0.1:8200 vault read -field=public_key ssh/config/ca'
ssh <a-managed-host> cat /etc/ssh/wg-manager-user-ca.pub
```

Finally, run one real operation through the control plane: re-run
`bootstrap-host` against a managed host, or wait for the next `beat`
host-cert renewal and watch for it in `make prod-logs`. A mint that
succeeds proves the SSH CA, Transit and the root token all came
across.

The SSH CA mount defaults to `ssh`. If you set `SSH_CA_VAULT_MOUNT` in `.env.prod`,
use that path instead.

---

## Rollback

The migration never writes to the old file-storage volume
(`wg_manager_vault_data`). To go back:

```bash
make prod-down
git checkout <the pre-cycle-5 commit>   # vault.hcl back to storage "file"
make prod-up
```

Vault boots from the untouched file storage with the same
`vault-init.json`. **Anything Vault wrote after the migration is
lost.** That means certs issued since step 5 are missing from Vault,
though their rows in MySQL survive. Roll back early or not at all. If
the file volume itself is damaged, restore the step 2 bundle with
`make host-import`, onto a clean host or after removing the volumes.

## Troubleshooting

- **`could not tell whether the raft volume holds an initialized
  Vault`.** The probe server didn't answer within 30s. Look at it by
  hand:
  `docker compose run --rm --no-deps --entrypoint sh vault -c 'ls -lA /vault/raft'`.
  Don't delete anything you can't account for. Restore from the
  step 2 bundle if in doubt.
- **Vault comes up uninitialized after step 5.** The server isn't
  reading the raft volume. Check that `docker compose config` shows
  `wg_manager_vault_raft:/vault/raft` on the `vault` service, and
  that `vault.hcl`'s `node_id` matches `migrate-raft.hcl`'s.
  `tests/test_vault_migrate_raft.py` enforces both.
- **Unseal fails.** See [`vault-down.md`](vault-down.md). The keys
  didn't change, so a failure here usually means `vault-init.json`
  was edited or replaced.
