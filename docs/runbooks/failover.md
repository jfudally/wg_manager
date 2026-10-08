# Runbook — Fail over to the warm standby (and back)

Phase 3d cycle 5d. You are reading this because the primary (first
deployment: `rv`) is down or about to be taken down, and the standby
(`general`) should take over the control plane. The VPN itself keeps
running either way: WireGuard on the hubs doesn't depend on wg-manager.
What stops without a control plane is provisioning, enrollment, the
dashboard/API, and SSH host-cert renewal, which gives you a ~12h clock
([`host-migration.md` → Time budget](host-migration.md#time-budget)).

Setup this depends on: [`standby-replication.md`](standby-replication.md)
(cycles 5b + 5c). Design: [`docs/deploy/ha-control-plane.md`](../deploy/ha-control-plane.md).

| You want to | Run |
|---|---|
| Move the control plane on purpose (maintenance, upgrade, failback) | [Planned switchover](#planned-switchover) — no data loss |
| Keep running while the primary is dead | [Unplanned failover](#unplanned-failover) |
| Bring the old primary back as the new standby | [Rejoin](#rejoin-the-old-primary) |

---

## Before you ever need this

Check these now, not during an outage:

- [ ] `make standby-status` on the standby ends with two `OK`s
  (replication + bundle), and alerting watches it.
- [ ] Clients reach the control plane through **one DNS name** you can
  move (e.g. `wg.vpn`) with a low TTL. That covers operators' CLI and
  dashboard, and `enroll_node.sh` userdata. Not `rv.vpn`.
- [ ] That name is in **`API_SERVER_SANS`** in the shared `.env.prod`,
  and the API cert was minted with it. The standby serves the primary's
  `tls/` (shipped by 5c), so the cert is valid there only if the shared
  name is on it.

  ```bash
  openssl x509 -in tls/server.crt -noout -ext subjectAltName   # includes wg.vpn
  ```

  Not there yet? Add it to `API_SERVER_SANS` and run `make certs-rotate`
  on the primary.
- [ ] Managed hubs and clients accept SSH from **both** hosts' IPs
  (firewalls, security groups, `sshd` `Match Address`).
- [ ] Both hosts run the two host units from
  [`systemd-timer.md`](../deploy/systemd-timer.md#warm-standby-host-setup-mysql-firewall-and-boot-order-phase-3d-cycle-5).
  - `wg-manager-mysql-firewall@<the other host's WireGuard IP>`, so only
    the peer reaches 3306. It covers both roles, so a failover needs no
    firewall change.
  - The `docker.service.d/after-wg.conf` drop-in, so MySQL's bind to
    the WireGuard address survives a reboot.
- [ ] Both hosts are on the **same commit** (`standby-status` reports
  `DRIFT` otherwise).
- [ ] The weekly drill passes and the `wg-manager.standby` alerts are
  loaded ([The weekly drill](#the-weekly-drill)).

---

## Planned switchover

The primary hands over cleanly: no transaction is lost and Vault is
current to the second.

1. **On the primary (`rv`):**

   ```bash
   make demote
   ```

   This removes the app containers (api, worker, beat, web, enroll) and
   makes MySQL read-only. MySQL and Vault keep running, so the standby
   can catch up and take a final bundle. Clients get errors from here
   until step 3.

2. **On the standby (`general`):**

   ```bash
   make failover
   ```

   It sees the primary as **read-only** (demoted) and then:
   1. Pulls a final bundle, so Vault is current.
   2. Waits until every transaction of the primary is applied here.
   3. Promotes MySQL.
   4. Restores Vault from the snapshot, restarts Vault so it loads the
      snapshot's seal config, then unseals it with the shipped keys and
      checks the SSH/PKI/Transit engines are there.
   5. Flips `.env.host` to `primary`, runs `make prod-up`, and creates
      the replication user.

3. **Move the DNS name** to the standby's address.

4. **Back on the old primary:** [rejoin](#rejoin-the-old-primary) it as
   the new standby.

5. **Timers.** On the new primary, disable the three standby timers
   (`wg-manager-standby-pull`, `-standby-metrics`, `-standby-drill`)
   and enable `wg-manager-certs-rotate.timer`. On the new standby, do
   the reverse ([`systemd-timer.md`](../deploy/systemd-timer.md)).

Failback (when `rv` should be primary again) is this same procedure in
reverse.

`make failover` **refuses while the primary is still writable**. Two
writable primaries is the one outcome this whole design exists to
prevent. There is no force flag: demote it first.

---

## Unplanned failover

The primary is dead, or unreachable from the standby.

1. **Fence the primary.** Make sure it is down **and stays down**. From
   the standby, a dead primary and a network split look exactly the
   same. If `rv` is actually alive and still serving clients, promoting
   `general` gives you two primaries (split-brain, below). Ways to fence
   it:
   - power it off (provider console);
   - or, if you can still reach it, `make prod-down` there;
   - or cut it off from clients and managed hosts.

2. **On the standby:**

   ```bash
   make failover confirm=primary-is-down
   ```

   Without `confirm=primary-is-down` it refuses and tells you why. It
   promotes MySQL with every transaction it had *received*, so writes
   from the primary's last seconds may be lost. Vault comes from the
   last pulled snapshot (at most ~15 min old), and the run prints its
   age. Certs issued after that snapshot exist in MySQL but not in
   Vault's PKI store.

3. **Move the DNS name** to the standby, then fix the
   [timers](#planned-switchover) as in step 5 above.

4. **When the old primary comes back:** see split-brain below, then
   [rejoin](#rejoin-the-old-primary).

### split-brain: keep the old primary from coming back as a primary

The prod stack's containers are `restart: always`. If `rv` boots after
an unplanned failover, its whole stack comes back **as a primary**:
API, `beat` and a writable MySQL that knows nothing of the writes
`general` took since. Then:

- `beat` on both hosts renews SSH host certs. Both sign with the same
  CA, so the managed hosts keep working, but `rv`'s records diverge.
- Anything still pointed at `rv` (stale DNS, a hard-coded address)
  writes to the wrong database.

So, in order of preference:

1. Keep it from booting into the network until you're ready. For
   example, detach it in the provider console, or boot it with Docker
   disabled (`sudo systemctl disable docker` before it goes down, if
   you can).
2. As soon as it's up, run `make rejoin primary=<new primary>` there.
   That's the first thing it does: it removes the app containers and
   makes MySQL read-only.

Writes `rv` took after the failover show up as **errant transactions**
when it rejoins. See [Re-seeding the old primary](#re-seeding-the-old-primary).

---

## Rejoin the old primary

On the old primary, once `make failover` has finished on the new one:

```bash
make rejoin primary=general.vpn      # the NEW primary's MySQL name
```

It does nothing unless `general.vpn` answers as a **writable primary**.
This guards against running it on the wrong host or with a typo. Then
it:

1. Flips `.env.host` to `standby`.
2. Removes the app containers and Vault.
3. Restarts MySQL with the standby flags and makes it read-only.
4. Checks that this host has no transactions the new primary lacks.
5. Replicates from the new primary, with no re-seed.

Then point the pulls at the new primary. In `.env.host`, set
`STANDBY_PRIMARY_SSH=ops@general.vpn`, and on `general` authorize this
host's pull key with the forced command
([`standby-replication.md`](standby-replication.md) setup step 3).
Finish with:

```bash
make standby-pull && make standby-status
```

After a **planned** switchover, the rejoin always works: the demoted
primary's transactions are a subset of the new primary's. After an
**unplanned** one, it works if the dead primary had no unreplicated
writes. Otherwise it refuses, lists the errant GTIDs, and leaves the
host read-only and not replicating.

### Re-seeding the old primary

Re-seed when `rejoin` reports errant transactions. Those are writes
the old primary took that never reached the new primary.

1. **Back them up first.** They may matter, for example a server
   registered seconds before the crash.

   ```bash
   mkdir -p backups && umask 077
   docker exec wg_manager_mysql sh -c \
     'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysqldump -uroot --single-transaction --databases wg_manager' \
     > "backups/pre-reseed-$(date -u +%Y%m%dT%H%M%SZ).sql"
   ```

2. Decide whether anything in them must be re-entered on the new
   primary, through the API or CLI. Don't load the dump there.

3. **Re-seed** (this deletes this host's MySQL data):

   ```bash
   # CHECK `hostname` FIRST.
   make standby-down
   docker volume rm wg_manager_wg_manager_mysql_data
   make standby-up
   make standby-seed primary=general.vpn
   ```

---

## The weekly drill

`make standby-drill` runs weekly on the standby, from
`wg-manager-standby-drill.timer`. It proves the standby could take
over, without touching anything real:

1. **Vault.** It restores the latest shipped snapshot into a
   **throwaway** Vault, using the same path `make failover` uses
   (restore, restart, unseal with the shipped keys, check the
   SSH/PKI/Transit engines). That throwaway Vault gets its own
   internal Docker network and an anonymous volume, and is removed
   afterwards. The standby's own compose project is only read, to
   find the image names.
2. **MySQL.** Replication must be running and within
   `REPL_MAX_LAG_SECONDS`.

Each run records its result in `standby/drill.last_success` or
`standby/drill.last_failure`. `make standby-metrics` exports both,
and the `WgStandbyDrillFailed` and `WgStandbyDrillOverdue` alerts
watch them. A standby that reports metrics but has never drilled
alerts after an hour, so run it once by hand at setup.

**When it fails**, a real failover would most likely fail the same
way. Read the output (`journalctl -u wg-manager-standby-drill`):

| Output | Cause | Fix |
|---|---|---|
| *no Vault snapshot in standby/* | pulls aren't running | `make standby-pull`, check its timer |
| *image wg-manager:prod is not built* | `standby-up` never ran on this commit | `make standby-up` (it builds the image) |
| *the Vault restore failed* / *did not verify* | a damaged snapshot, or `vault-init.json` and the snapshot don't belong together | Run `make standby-pull` and re-run the drill. If it keeps failing, compare the primary's Vault with its own `vault-init.json`. |
| *replication is not healthy* | see `make standby-status` | [`standby-replication.md`](standby-replication.md#troubleshooting) |

## If a step fails

Every step can be re-run:

- **`make failover` failed before Vault was restored:** fix the cause
  and run it again. It detects an already-promoted MySQL and resumes.
- **`make failover` failed at `prod-up`:** the host is already the
  primary. Finish with `make prod-up && make repl-primary-setup`, as
  the error says.
- **The Vault restore fails with "lacks ssh/":** the snapshot is
  damaged. Point the restore at the previous one and re-run `make
  failover`:

  ```bash
  cp standby/vault.snap.prev standby/vault.snap
  ```
- **`make rejoin` refused:** nothing was torn down if the refusal came
  from the primary probe. If it came from the errant-transaction
  check, the host is now a read-only standby; re-seed it.

## Afterwards

- `make standby-status` on the new standby shows two `OK`s.
- The API answers on the DNS name:

  ```bash
  curl --cacert tls/ca-bundle.crt --cert tls/client.crt --key tls/client.key https://wg.vpn/v1/readyz
  ```
- Watch `make prod-logs` on the new primary for the next `beat`
  host-cert renewal, which proves the SSH CA works there.
