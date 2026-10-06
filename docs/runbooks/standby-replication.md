# Runbook — Set up and run the warm-standby MySQL replica

Phase 3d cycle 5b. The **primary** (first deployment: `rv`) runs the
full prod stack. The **standby** (`general`) runs MySQL only, as a
read-only GTID replica of the primary, so cycle 5d's `make failover`
can promote it with at most seconds of lost writes. Design and
rationale: [`docs/deploy/ha-control-plane.md`](../deploy/ha-control-plane.md)
→ *Warm standby across hosts*.

Not covered yet: Vault on the standby (cycle 5c ships raft snapshots
plus `vault-init.json`/`tls/`), and promotion itself (cycle 5d).

Prerequisite: the primary is on raft Vault (cycle 5a,
[`vault-raft-migration.md`](vault-raft-migration.md)).

---

## How it fits together

| | Primary (`rv`) | Standby (`general`) |
|---|---|---|
| `.env.prod` | shared, same file on both | copied from the primary |
| `.env.host` (gitignored, per host) | `WG_MANAGER_ROLE=primary`, `MYSQL_BIND_ADDR=<rv private/VPN IP>` | `WG_MANAGER_ROLE=standby`, `MYSQL_BIND_ADDR=<general private/VPN IP>` |
| Runs | `make prod-up`: full stack, mysqld `--server-id=1` | `make standby-up`: mysql only, `--server-id=2`, read-only |
| Refuses | `make standby-up` (would restart its mysqld read-only) | `make prod-up` (a second `beat` would race host-cert renewals) |

Replication runs over **mutual TLS**:

- The standby verifies the primary's MySQL server cert *by name*
  (`VERIFY_IDENTITY`), so that name must be a SAN on the cert
  (`MYSQL_SERVER_EXTRA_SANS`).
- The primary only admits `wg_repl` with a client cert from the
  stack's own CA (`REQUIRE X509`) *and* the password.

Both hosts use the same `tls/` files, so one server cert carries both
hosts' names and stays valid after failover.

---

## One-time setup

### On the primary (`rv`)

1. **Add the shared settings to `.env.prod`:**

   ```bash
   MYSQL_REPL_PASSWORD=<openssl rand -hex 32>   # no quotes/backslashes
   MYSQL_SERVER_EXTRA_SANS=rv.vpn,general.vpn   # the name EACH host is reached at
   ```

2. **Create `.env.host`** from `.env.host.example`:

   ```bash
   WG_MANAGER_ROLE=primary
   MYSQL_BIND_ADDR=<rv's private/VPN IP>
   ```

   Never use a public address. Docker-published ports bypass `ufw`.
   Restrict 3306 on that interface to the standby's IP with your
   firewall or VPN ACLs.

3. **Recreate MySQL with GTIDs on:**

   ```bash
   make prod-up
   ```

   This recreates the `mysql` container with `--gtid-mode=ON
   --server-id=1` and the new bind address. The app sees a few seconds
   of DB unavailability while mysqld restarts. Existing data is
   untouched; the drill verified that a pre-GTID database upgrades in
   place.

4. **Re-mint the MySQL server cert with the extra SANs:**

   ```bash
   make certs-rotate
   openssl x509 -in tls/mysql/server.crt -noout -ext subjectAltName
   # ... DNS:rv.vpn, DNS:general.vpn
   ```

5. **Create the replication user:**

   ```bash
   make repl-primary-setup
   ```

   It refuses if GTIDs are off, i.e. if step 3 didn't happen. It's
   idempotent, so re-run it after changing `MYSQL_REPL_PASSWORD`.

### On the standby (`general`)

1. **Clone the repo at the primary's commit**, into a directory with
   the same name (`wg_manager`). Compose derives volume names from it.

2. **Copy the shared files from the primary** over SSH, keeping them
   private:

   ```bash
   # on general
   scp rv:wg_manager/.env.prod .
   rsync -a rv:wg_manager/tls/ tls/
   chmod 600 .env.prod
   ```

   The standby's mysqld uses the primary's `tls/mysql/` files: the
   same server cert (both names are on it) and the client cert it
   replicates with.

3. **Create `.env.host`:**

   ```bash
   WG_MANAGER_ROLE=standby
   MYSQL_BIND_ADDR=<general's private/VPN IP>
   ```

   The bind address matters after failover, when `rv` becomes the
   replica of `general`.

4. **Start the replica and seed it:**

   ```bash
   make standby-up
   make standby-seed primary=rv.vpn
   make standby-status
   ```

   `standby-seed` waits until MySQL is ready, then:

   1. Dumps the primary's database over mutual TLS.
   2. Loads the dump along with the primary's GTID set.
   3. Starts replication with auto-positioning.
   4. Persists `super_read_only=ON`, so after this even root can't
      write and the setting survives restarts.

   It refuses to run against a mysqld started with the primary's
   flags, when replication is already configured, when the local
   database already has tables, or while app services run on this
   host.

`make standby-status` should end with `OK`:

```
Source_Host:           rv.vpn
Replica_IO_Running:    Yes
Replica_SQL_Running:   Yes
Seconds_Behind_Source: 0
OK
```

---

## Day 2

- **Watch it.** `make standby-status` exits **0** when healthy,
  **1** when broken or not configured, and **2** when lagging more
  than `REPL_MAX_LAG_SECONDS` (default 300). Run it from a systemd
  timer or your monitoring and alert on non-zero. Prometheus alerts
  arrive in cycle 5e.
- **⚠️ Re-copy `tls/` after every cert rotation on the primary.**
  MySQL certs last 30 days, and the primary rotates its own via
  `certs-rotate`. The standby's copy doesn't update until cycle 5c
  ships `tls/` automatically. After a rotation on `rv`:

  ```bash
  # on general
  rsync -a rv:wg_manager/tls/ tls/ && make standby-down && make standby-up
  ```

  If you forget, `standby-status` shows an `SSL` / certificate error
  in `Last_IO_Error` once the copy expires.
- **Primary reboots or outages.** The replica retries every 10s for
  up to ~10 days and resumes on its own once the primary is back,
  usually within 10s; the drill confirmed this. Binlogs are kept 7
  days. After a longer outage, re-seed.
- **Restarting the standby:** `make standby-down && make
  standby-up` (`up --no-deps`). In the drill, a plain `docker compose
  start mysql` did not bring the replica back.

## Re-seeding

Re-seed after a standby outage of more than 7 days, after a
`Last_SQL_Error` (the replica diverged), or after a botched seed.

```bash
# on general — CHECK `hostname` FIRST. This deletes the replica's data.
make standby-down
docker volume rm wg_manager_wg_manager_mysql_data
make standby-up
make standby-seed primary=rv.vpn
```

Never run this on the primary.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `standby-seed`: *the dump from rv.vpn failed*, `SSL ... certificate verify failed` | `rv.vpn` isn't a SAN on the primary's MySQL cert | Primary: add it to `MYSQL_SERVER_EXTRA_SANS`, then `make certs-rotate`. Standby: re-copy `tls/`. |
| `standby-seed`: *Can't connect ... (111)* or a timeout | Primary's `MYSQL_BIND_ADDR`, firewall, or VPN route | `nc -vz rv.vpn 3306` from the standby. |
| `standby-seed`: *Access denied for user 'wg_repl'* | `repl-primary-setup` not run, a password mismatch, or no client cert | Primary: `make repl-primary-setup`. Check that both hosts have the same `.env.prod`. |
| `standby-seed`: *runs with the PRIMARY flags (server-id 1)* | mysql was started by `prod-up` or plain compose | `make standby-down && make standby-up`. |
| `make prod-up` on the standby: *this host is the warm standby* | Working as intended | Promotion is cycle 5d's `make failover`. |
| `Last_IO_Error` mentions certificate/SSL after weeks of working | Standby's `tls/` copy expired | Re-copy `tls/` (see Day 2). |
| `Last_SQL_Error` set, `Replica_SQL_Running: No` | Replica diverged | Re-seed. |
