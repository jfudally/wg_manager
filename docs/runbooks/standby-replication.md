# Runbook — Set up and run the warm standby

The **primary** (first deployment: `rv`) runs the full prod stack.
The **standby** (`general`) keeps two things current, so cycle 5d's
`make failover` can promote it:

- **The database (cycle 5b):** a read-only GTID replica of the
  primary's MySQL. A promotion loses at most seconds of writes.
- **Vault and the shared files (cycle 5c):** a timer pulls a bundle
  from the primary every 15 minutes. It contains a Vault raft
  snapshot plus `vault-init.json`, `.env.prod` and `tls/`.

Design and rationale:
[`docs/deploy/ha-control-plane.md`](../deploy/ha-control-plane.md) →
*Warm standby across hosts*. Promoting the standby, and bringing the
old primary back, is in [`failover.md`](failover.md) (cycle 5d).

> **The standby holds the primary's keys.** The pulled
> `vault-init.json` plus `standby/vault.snap` are the whole Vault:
> unseal keys, root token, SSH CA, Transit key. Secure `general`
> exactly like `rv`.

Prerequisite: the primary is on raft Vault (cycle 5a,
[`vault-raft-migration.md`](vault-raft-migration.md)).

---

## How it fits together

| | Primary (`rv`) | Standby (`general`) |
|---|---|---|
| `.env.prod`, `vault-init.json`, `tls/` | the source | pulled from the primary by `make standby-pull` (timer) |
| Vault | running, the live one | the latest raft snapshot in `standby/vault.snap` (restored at failover) |
| `.env.host` (gitignored, per host) | `WG_MANAGER_ROLE=primary`, `MYSQL_BIND_ADDR=<rv private/VPN IP>`, `MYSQL_PEER_HOST=general.vpn` | `WG_MANAGER_ROLE=standby`, `MYSQL_BIND_ADDR=<general private/VPN IP>`, `MYSQL_PEER_HOST=rv.vpn` |
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
   MYSQL_PEER_HOST=general.vpn          # the standby's name on the MySQL cert
   MYSQL_PEER_ADDR=<general's private/VPN IP>
   ```

   The peer entries put the standby's name into the mysql
   container's `/etc/hosts`. Replication connects by that name (it
   must match the cert), and containers can't see names that only
   the host's `/etc/hosts` or a private DNS knows. The primary needs
   it once roles swap after a failover.

   Never use a public address. Docker-published ports bypass `ufw`,
   so every VPN peer can reach 3306 on that address. Install the two
   host units from
   [`systemd-timer.md`](../deploy/systemd-timer.md#warm-standby-host-setup-mysql-firewall-and-boot-order-phase-3d-cycle-5),
   allowing only the standby's WireGuard IP:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now wg-manager-mysql-firewall@10.8.0.1.service   # general's IP
   ```

   The other unit is the `docker.service.d/after-wg.conf` drop-in. It
   starts Docker after `wg0`, so the bind to the WireGuard address
   survives a reboot.

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

2. **Create `.env.host`:**

   ```bash
   WG_MANAGER_ROLE=standby
   MYSQL_BIND_ADDR=<general's private/VPN IP>
   MYSQL_PEER_HOST=rv.vpn               # what standby-seed primary=... names
   MYSQL_PEER_ADDR=<rv's private/VPN IP>
   STANDBY_PRIMARY_SSH=ops@rv.vpn       # user@host the pull logs in as
   STANDBY_PRIMARY_DIR=wg_manager       # the checkout on rv (relative to that home, or absolute)
   STANDBY_SSH_KEY=/home/ops/.ssh/wg-standby
   ```

   The bind address matters after failover, when `rv` becomes the
   replica of `general`. For the same reason, install the same two
   host units here, allowing only the primary's WireGuard IP: the
   `docker.service.d/after-wg.conf` drop-in, and

   ```bash
   sudo systemctl enable --now wg-manager-mysql-firewall@10.8.0.2.service   # rv's IP
   ```

   ([`systemd-timer.md`](../deploy/systemd-timer.md#warm-standby-host-setup-mysql-firewall-and-boot-order-phase-3d-cycle-5)).
   Each host allows its peer whatever the role, so a failover needs no
   firewall change.

3. **Give the standby a pull-only SSH key on the primary.** On
   general:

   ```bash
   ssh-keygen -t ed25519 -N '' -C wg-standby@general -f ~/.ssh/wg-standby
   ```

   On rv, add the public key to the pull user's
   `~/.ssh/authorized_keys` with a **forced command**, so the key can
   do nothing except produce the bundle. That user must be able to run
   docker, as the operator who runs `make prod-up` does.

   ```
   restrict,command="cd /home/ops/wg_manager && make -s standby-bundle o=-" ssh-ed25519 AAAA... wg-standby@general
   ```

   Use the absolute path of the checkout on rv. `restrict` turns off
   port, agent and X11 forwarding and the pty. The pull still sends
   `cd ... && make ...` as its remote command; with a forced command
   in place, sshd ignores it and runs the forced one.

4. **First pull.** This installs `.env.prod`, `vault-init.json` and
   `tls/` from rv, plus the first Vault snapshot:

   ```bash
   ssh -i ~/.ssh/wg-standby ops@rv.vpn true   # accept rv's host key once
   make standby-pull
   ```

   The standby's mysqld uses the primary's `tls/mysql/` files: the
   same server cert (both names are on it) and the client cert it
   replicates with.

5. **Start the replica and seed it:**

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

6. **Enable the pull timer.** Use `wg-manager-standby-pull.timer`,
   every 15 minutes; the units are in
   [`systemd-timer.md`](../deploy/systemd-timer.md#warm-standby-pull-phase-3d-cycle-5c).

7. **Monitoring and the weekly drill** (cycle 5e).
   - Point node_exporter's textfile collector at
     `STANDBY_METRICS_FILE`.
   - Enable `wg-manager-standby-metrics.timer` and
     `wg-manager-standby-drill.timer`, and load the `wg-manager.standby`
     alert rules
     ([`observability.md`](../observability.md#warm-standby-phase-3d-cycle-5e)).
   - Run the drill once:

     ```bash
     make standby-drill
     ```

`make standby-status` should end with two `OK`s, one for replication
and one for the bundle:

```
Source_Host:           rv.vpn
Replica_IO_Running:    Yes
Replica_SQL_Running:   Yes
Seconds_Behind_Source: 0
OK

Bundle_Created:        2026-10-06T17:57:20Z (412 s ago)
Bundle_Source_Host:    rv
Bundle_Commit:         5af5b50...
OK
```

---

## Day 2

- **Watch it.** The `wg-manager.standby` Prometheus alerts cover all
  of this (cycle 5e). By hand, `make standby-status` exits:
  - **0** when healthy;
  - **1** when broken: replication down, or nothing pulled yet;
  - **2** when degraded: replication lag over `REPL_MAX_LAG_SECONDS`
    (default 300), a bundle older than
    `STANDBY_MAX_BUNDLE_AGE_SECONDS` (default 3600), or **code
    drift**, meaning the primary runs a different commit.

  The weekly `make standby-drill` additionally proves a Vault restore
  works ([`failover.md` → The weekly drill](failover.md#the-weekly-drill)).
- **Cert rotations on the primary are handled.** Each pull installs
  rv's current `tls/`. When `tls/mysql` changed, the pull restarts the
  replica so it loads the new certs.
- **Upgrades:** check out the same commit on both hosts. Until you
  do, `standby-status` reports `DRIFT`, and `standby-pull` warns but
  still installs the data.
- **What a pull refuses** (it leaves the installed state untouched):
  - an SSH or bundle failure;
  - a checksum mismatch;
  - a bundle no newer than the installed one. A replayed or stale
    bundle must not roll the standby back, so check rv's clock if
    you see this.

  The previous snapshot is kept as `standby/vault.snap.prev`.
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
| `standby-seed`: *Unknown MySQL server host 'rv.vpn'* | The mysql container can't resolve the primary's name | Set `MYSQL_PEER_HOST` / `MYSQL_PEER_ADDR` in the standby's `.env.host`, then `make standby-down && make standby-up`. |
| `standby-seed`: *Can't connect ... (111)* or a timeout | Primary's `MYSQL_BIND_ADDR`, firewall, or VPN route | `nc -vz rv.vpn 3306` from the standby. On the primary, `sudo iptables -S DOCKER-USER` must allow the standby's IP: check the `wg-manager-mysql-firewall@` instance. |
| `standby-seed`: *Access denied for user 'wg_repl'* | `repl-primary-setup` not run, a password mismatch, or no client cert | Primary: `make repl-primary-setup`. Check that both hosts have the same `.env.prod`. |
| `standby-seed`: *runs with the PRIMARY flags (server-id 1)* | mysql was started by `prod-up` or plain compose | `make standby-down && make standby-up`. |
| `make prod-up` on the standby: *this host is the warm standby* | Working as intended | Promotion is cycle 5d's `make failover`. |
| `Last_IO_Error` mentions certificate/SSL after weeks of working | Standby's `tls/` expired because pulls stopped | Fix the pulls (`STALE` above), then `make standby-pull`. |
| `Last_SQL_Error` set, `Replica_SQL_Running: No` | Replica diverged | Re-seed. |
| `standby-pull`: *Permission denied (publickey)* | Key not in rv's `authorized_keys`, or the wrong `STANDBY_SSH_KEY` | Re-check setup step 3. |
| `standby-pull`: *the Vault snapshot failed* (from rv) | rv's stack is down or Vault sealed, or rv's checkout predates cycle 5c (no `scripts/vault_snapshot.py`) | On rv: check out the same commit as general, and `make prod-up` if the stack is down. |
| `standby-pull`: *not newer than the installed one* | rv's clock went backwards, or a replayed bundle | Fix rv's clock (NTP). The next pull with a newer timestamp installs. |
| `standby-status`: `STALE` | Timer not running, or pulls failing | `systemctl status wg-manager-standby-pull.timer`; `journalctl -u wg-manager-standby-pull`. |
