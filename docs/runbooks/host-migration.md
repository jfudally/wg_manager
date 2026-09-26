# Runbook — Migrate the prod stack to a new host

You are reading this because the single-host prod stack
([`docs/deploy/single-host-prod.md`](../deploy/single-host-prod.md))
has to move to a different machine: hardware refresh, a new VM, a
different provider. The goal is **zero data loss**: every MySQL row,
the whole Vault (PKI, SSH CA, Transit key), and the audit trail
arrive intact, and the fleet keeps trusting the control plane.

Companion docs:

- [`backup-restore.md`](backup-restore.md) — routine backups. Take
  one before you start (step 2).
- [`vault-down.md`](vault-down.md) — if Vault won't unseal on the
  new host.
- [`docs/deploy/systemd-timer.md`](../deploy/systemd-timer.md) — the
  timer units you move in step 8.

---

## Why a cold volume copy

Two facts about the prod stack rule out the logical backup tools as
the migration path:

- **Vault uses `storage "file"`** (`docker/vault/vault.hcl`), not
  raft, so `vault operator raft snapshot` doesn't work. The only way
  to move Vault is to copy its storage volume.
- **The encrypted DB dump can only be decrypted by *this* Vault.**
  `wg-manager db backup --encrypt` wraps its data key with Vault
  Transit. Without the same Vault, the dump is unreadable.

So the migration is a byte-for-byte copy of the **stopped** stack.
`scripts/migrate_host.sh` (via `make host-export` /
`make host-import`) does the copy and refuses the unsafe cases. It
won't copy a running stack, won't overwrite state on the target, and
won't restore onto a different commit or compose project name.

## What moves

| Item | Carried by | Notes |
|---|---|---|
| `wg_manager_mysql_data` volume | `host-export` | Every row. |
| `wg_manager_vault_data` volume | `host-export` | PKI, SSH CA, Transit key. Losing it breaks trust with every managed host. |
| `wg_manager_vault_audit_logs` volume | `host-export` | Audit trail. |
| `.env.prod`, `vault-init.json`, `tls/`, `backups/` | `host-export` (`files.tar`) | `vault-init.json` holds the unseal keys for *that* Vault data. The two only work together. |
| `wg_manager_valkey_data` volume | **not moved** | Celery queue only. Drain it in step 2 and it rebuilds empty. |
| systemd timer units | **you, by hand** (step 8) | They live in `/etc/systemd/system`, outside the repo. |

The export bundle holds the Vault unseal keys, the root token and every
password. Keep it `0700`, move it only over SSH, and delete it once the
migration is verified.

## Time budget

SSH host certs on managed hubs and clients last
`SSH_HOST_CERT_TTL_SECONDS` (24h). `beat` renews them once they're
within `SSH_HOST_CERT_RENEW_BEFORE_SECONDS` (12h) of expiry, so when
you stop the old stack some hosts may have as little as **~12h** left.
A host whose cert expires while the control plane is down can't be
rotated. It has to be re-bootstrapped with `bootstrap-host` and its
out-of-band SSH key. **Plan to finish steps 3–7 in well under 12h**;
most migrations take under an hour.

---

## Procedure

### 1. Prepare the new host (old stack still serving)

- Install Docker and Compose v2 and enable Docker at boot
  (`sudo systemctl enable docker`).
- Clone the repo at **the same commit** as the old host
  (`git rev-parse HEAD` there), into a directory with **the same
  name**. Compose derives volume names from the directory name
  (`wg_manager` → `wg_manager_wg_manager_mysql_data`). `host-import`
  refuses a mismatch, because `prod-up` would otherwise start on empty
  volumes and initialise a brand-new Vault.
- Do **not** create `.env.prod` or run `make prod-up` yet. The import
  brings `.env.prod` over and refuses to overwrite one.
- Make sure the new host can reach every managed hub and client over
  SSH. If any of them only accept SSH from the old host's IP (firewall
  rules, security groups, `sshd` `Match Address`), add the new IP
  **now**.

### 2. Quiesce and record a baseline (old host)

```bash
# Nothing mid-provision: wait until the worker logs are idle and no
# server/client row is in a pending/provisioning state.
make prod-logs      # Ctrl-C once quiet

make db-counts > before-counts.txt                      # exact per-table row counts
make db-backup o=backups/pre-migrate-$(date +%F).json   # extra safety copy
```

### 3. Stop the old stack (old host)

```bash
make prod-down      # never `down -v`: that deletes the volumes
sudo systemctl disable --now wg-manager-certs-rotate.timer   # and any backup timer
```

From here until step 7 the control plane is down. The VPN itself
keeps running, because WireGuard on the hubs doesn't depend on
wg-manager.

### 4. Export (old host)

```bash
make host-export o=/var/tmp/wg-migrate
cat /var/tmp/wg-migrate/MANIFEST
```

The bundle holds `volumes/*.tar`, `files.tar`, `MANIFEST` (commit,
compose project, image digests) and `SHA256SUMS`.

### 5. Transfer

```bash
rsync -a --progress /var/tmp/wg-migrate/ newhost:/var/tmp/wg-migrate/
```

### 6. Import (new host)

```bash
cd ~/wg_manager      # the same-named checkout from step 1
make host-import i=/var/tmp/wg-migrate
```

Import first checks every checksum, the git commit, the compose
project name, and that no target volume or operator file already
exists. If all of that passes, it recreates the volumes (with Compose
labels) and unpacks the files with ownership preserved. To import
onto a different commit on purpose, set
`MIGRATE_ALLOW_COMMIT_MISMATCH=1`. Only do that if the newer commit
adds no Alembic migrations you haven't reviewed, because `prod-up`
applies them on first boot.

**Pin the data-tier images.** The base compose uses floating tags
(`mysql:8`, …). The `image` lines in `MANIFEST` record the exact
digests the old host ran. Pull those digests and re-tag them so the
new host doesn't open the MySQL datadir with a different release:

```bash
grep '^image ' /var/tmp/wg-migrate/MANIFEST
# e.g.  image mysql:8 mysql@sha256:0744ee…
docker pull mysql@sha256:0744ee…
docker tag  mysql@sha256:0744ee… mysql:8
```

**If the hostname or IP changes**, edit `.env.prod`: set
`API_SERVER_CN` and add the new name to `API_SERVER_SANS`. The API
cert gets re-minted in step 7.

### 7. Start and verify (new host)

```bash
make prod-up        # auto-unseals from vault-init.json; bootstrap steps skip
make certs-rotate   # only if the hostname/IP changed: re-mints the API cert with the new SANs
make db-counts > after-counts.txt
diff before-counts.txt after-counts.txt && echo "no rows lost"
```

Then work through the checks in
[`backup-restore.md` → Verification](backup-restore.md#verification)
(`/v1/readyz`, `wg-manager certs list`, `/crypto/status`), plus the
one that proves the fleet still trusts the new host:

```bash
# Rotate one hub's host cert end-to-end: a fresh SSH session signed by
# the migrated SSH CA, and a cert from the migrated Vault.
curl --cacert tls/ca-bundle.crt --cert tls/client.crt --key tls/client.key \
     -X POST https://<new-host>/v1/servers/<id>/rotate-host-cert
```

Watch `make prod-logs` for the task to finish. Over the next hour,
confirm that `beat`'s sweep logs no `host-cert rotation failed` lines.

### 8. Cut over the surroundings

- Point DNS at the new host (or move the IP).
- Update anything that calls the API by address: the `--api-url` in
  `scripts/wg_bootstrap.sh` invocations, dashboards, monitoring
  scrapes of `/metrics`, and the Vector audit-log sink if it filters
  by source host.
- Install the systemd units from
  [`systemd-timer.md`](../deploy/systemd-timer.md) on the new host with
  `WorkingDirectory` set to the new checkout, then
  `sudo systemctl enable --now` them.

### 9. Retire the old host (after a soak period)

Leave the old host **stopped but intact** for a few days as your
rollback. **Never run both stacks at once**: two `beat` schedulers and
two workers would provision and rotate the same fleet at the same time.
Once you're satisfied:

```bash
shred -u /var/tmp/wg-migrate/files.tar && rm -rf /var/tmp/wg-migrate   # both hosts
# old host only, when you are sure:
docker compose --env-file .env.prod -f docker-compose.yml -f docker-compose.prod.yml down -v
```

---

## Variant: rehearsal copy while the source keeps running

Use this to stand up a verified copy on the new host before the real
cutover, for example to validate the new box. The source is stopped
only for the export (about a minute for a few hundred MB) and then
comes back **on exactly the same containers**.

1. **Pause the source's timers** so `certs-rotate-if-due` can't fire
   mid-export: `sudo systemctl stop wg-manager-certs-rotate.timer`.
2. **Stop, don't remove:** `$(PROD_COMPOSE) stop`, i.e.
   `docker compose --env-file .env.prod -f docker-compose.yml
   -f docker-compose.prod.yml stop`. Avoid `make prod-down` plus
   `make prod-up` here: `prod-up` runs with `--build`, so the source
   would come back rebuilt on whatever commit is checked out, which is
   a silent upgrade.
3. `make host-export o=DIR`.
4. **Restart the same containers in dependency order** with
   `docker start`: `vault`, then `bootstrap_substrate` (wait for exit 0;
   it unseals Vault), then `mysql valkey vector`, then
   `api worker beat web`. Resume the timer.
5. On the target, import as usual. Then start **everything except
   `worker` and `beat`**:
   ```bash
   docker compose --env-file .env.prod -f docker-compose.yml \
       -f docker-compose.prod.yml up -d --wait vector api web
   ```
   Neither `api` nor `web` depends on `worker`/`beat`, so they stay
   uncreated. Two stacks must never both provision or rotate certs on
   the same fleet.
6. Consider binding the copy's listeners to a private or VPN address
   (`WG_MANAGER_API_BIND_ADDR` / `WG_MANAGER_WEB_BIND_ADDR` in its
   `.env.prod`), because the dashboard is plain HTTP.

The copy is a snapshot. Anything the source changes afterwards isn't in
it, so the real cutover needs a fresh export into clean volumes.

## Rollback

Before step 8, rolling back just means **not** switching over. Run
`make prod-down` on the new host, re-enable the timers on the old host,
and `make prod-up` there. The old volumes were never modified. Any
writes made on the new host in the meantime are lost, so roll back
before operators start using the new host.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `host-export`: *stack is still running* | Run `make prod-down` first. The export won't copy live MySQL/Vault files. |
| `host-export`: *compose volume 'X' is not classified* | Someone added a volume to compose. Add it to `MIGRATE_VOLUMES` or `SKIP_VOLUMES` in `scripts/migrate_host.sh` with a reason, and add a test. |
| `host-import`: *checksum verification failed* | The transfer was truncated. Re-run the `rsync` from step 5. |
| `host-import`: *compose project is 'X' but the bundle came from 'Y'* | Re-clone into a directory named `Y`. |
| `host-import`: *couldn't find env file .env.prod* | You're running a version before the fresh-clone fix. `host-import` now reads `.env.prod` from the bundle. Update `scripts/migrate_host.sh`. |
| `host-import`: *… already exists — refusing to overwrite* | The target isn't clean (a previous attempt, or a `prod-up` run too early). Inspect it before removing anything. If it came from an early `prod-up`, it's an empty, freshly initialised Vault that you don't need. |
| Vault stays sealed after `prod-up` | `vault-init.json` doesn't belong to the restored Vault data. Both must come from the same bundle. See [`vault-down.md`](vault-down.md). |
| `host cert expired` on some hosts | They ran past the time budget. Re-run `bootstrap-host` for each (see `single-host-prod.md`). |
