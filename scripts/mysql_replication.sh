#!/usr/bin/env bash
# =====================================================================
# MySQL replication for the warm standby (Phase 3d cycle 5b).
# Entry point for `make repl-primary-setup` / `standby-seed` /
# `standby-status`; the procedure is docs/runbooks/standby-replication.md.
#
#   primary-setup   On the PRIMARY. Create/refresh the `wg_repl` user:
#                   password AND a client cert from the stack's CA
#                   (REQUIRE X509). Refuses unless GTIDs are on.
#   seed HOST       On the STANDBY, once. Dump the primary's database
#                   over mutual TLS (VERIFY_IDENTITY against HOST), load
#                   it with its GTID set, then CHANGE REPLICATION SOURCE
#                   + START REPLICA with auto-positioning, and persist
#                   super_read_only=ON into the datadir. Refuses on a
#                   server-id-1 (primary-flagged) mysqld, if replication
#                   is already configured, if the local DB has tables,
#                   or while app services run here.
#   primary-state   On the STANDBY (cycle 5d). Probe the configured
#                   source over the replication channel and print
#                   state=writable|readonly|unreachable (+ host=, gtid=),
#                   or state=not-a-replica (+ local_read_only=,
#                   local_tables=). `make failover` fences on this.
#   probe HOST      Anywhere (cycle 5d). Is HOST a writable primary? Prints
#                   state=writable|readonly|unreachable (+ gtid=). Runs in
#                   a ONE-OFF mysql container, so it works while this
#                   host's own mysqld is down. `rejoin` gates on it.
#   promote         On the STANDBY (cycle 5d). With WAIT_GTID, first wait
#                   until every one of those (the demoted primary's)
#                   transactions is applied here; then stop the IO
#                   thread, apply everything already received, drop the
#                   replication config and persist read-write. Re-running
#                   on an already-promoted host is a no-op; an empty
#                   (never seeded) database is refused.
#   demote          On the PRIMARY (cycle 5d). Persist super_read_only=ON
#                   and print gtid_executed.
#   rejoin HOST     On the OLD PRIMARY after a failover (cycle 5d), running
#                   with the standby flags. Persist read-only first (after
#                   an unplanned failover it was never demoted), then
#                   replicate from HOST without re-seeding, only if this
#                   host has no transactions HOST lacks (GTID_SUBSET);
#                   otherwise refuse, name them, and stay read-only.
#   status          Replication health. Exit 0 healthy, 1 broken or not
#                   configured, 2 lagging over REPL_MAX_LAG_SECONDS
#                   (default 300), so a timer or monitor can call it.
#
# Secrets never touch the host shell or any argv. Each subcommand runs
# a POSIX sh snippet inside the mysql container (`compose exec`), where
# MYSQL_ROOT_PASSWORD / MYSQL_REPL_PASSWORD already live in the env.
# Passwords reach the mysql clients via MYSQL_PWD or SQL on stdin.
#
# Env:
#   COMPOSE               compose command incl. --env-file/-f flags [required]
#   REPL_MAX_LAG_SECONDS  `status` lag threshold (default 300)
# =====================================================================

set -euo pipefail

: "${COMPOSE:?COMPOSE must be set (run via make repl-primary-setup / standby-seed / standby-status)}"

die() { echo "ERROR: $*" >&2; exit 1; }
log() { echo "==> $*"; }

# Word-splitting COMPOSE is intended: it's a command plus flags.
# shellcheck disable=SC2086
compose() { $COMPOSE "$@"; }

# Run a snippet in the mysql container. Extra args are `-e K=V` pairs.
in_mysql() {
    local snippet="$1"; shift
    compose exec -T "$@" mysql sh -c "$snippet"
}

# ---------------------------------------------------------------------
# Shared prelude for the in-container snippets. Single-quoted on
# purpose: every $ expands inside the container, not here.
# shellcheck disable=SC2016
PRELUDE='
set -eu
die() { echo "ERROR: $*" >&2; exit 1; }
# Non-secret one-line queries (root password via MYSQL_PWD, not argv).
# Guards must capture q into a variable first (x="$(q ...)"): a failed
# assignment trips set -e, but a failed $(...) inside [ ] does not, and
# would silently read as an empty answer.
q() { MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot -N -B -e "$1"; }
# SQL on stdin, for anything that embeds a secret.
sql() { MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot; }
check_repl_password() {
    [ -n "${MYSQL_REPL_PASSWORD:-}" ] || die "MYSQL_REPL_PASSWORD is not set — add it to .env.prod (shared by both hosts) and recreate mysql."
    # It is spliced into SQL string literals below.
    case "$MYSQL_REPL_PASSWORD" in
        *"'"'"'"*|*\\*) die "MYSQL_REPL_PASSWORD must not contain quotes or backslashes (use openssl rand -hex 16)." ;;
    esac
    # CHANGE REPLICATION SOURCE TO rejects a SOURCE_PASSWORD over 32
    # characters (ERROR 3056). Catch it here, before seed has loaded a
    # dump or primary-setup has created a user no replica can log in as.
    [ "${#MYSQL_REPL_PASSWORD}" -le 32 ] || die "MYSQL_REPL_PASSWORD is ${#MYSQL_REPL_PASSWORD} characters; MySQL replication allows at most 32 (use openssl rand -hex 16)."
}
TLS_CA=/etc/mysql/certs/ca.crt
TLS_CERT=/etc/mysql/certs/client.crt
TLS_KEY=/etc/mysql/certs/client.key
# GTID sets as mysql -B prints them: strip the literal "\n" it puts
# after each comma, and any whitespace.
gtid_clean() { sed "s/\\\\n//g" | tr -d " \t\n"; }
# Only GTID-set characters may be spliced into SQL.
valid_gtid() { case "$1" in *[!0-9A-Za-z:,_-]*) return 1 ;; esac; }
# Source host configured on this replica ("" when it is not one).
source_host() { q "SELECT HOST FROM performance_schema.replication_connection_configuration WHERE CHANNEL_NAME = \"\""; }
# Run one query on host $1 as wg_repl over mutual TLS.
remote_q() {
    MYSQL_PWD="$MYSQL_REPL_PASSWORD" mysql -h "$1" -u wg_repl --connect-timeout=5 \
        --ssl-mode=VERIFY_IDENTITY --ssl-ca="$TLS_CA" --ssl-cert="$TLS_CERT" --ssl-key="$TLS_KEY" \
        -N -B -e "$2"
}
# Point this server at $1 as its source and start replicating, with
# mutual TLS (VERIFY_IDENTITY) and GTID auto-positioning. Shared by
# `seed` and `rejoin`.
start_replication_from() {
    echo "==> Starting replication from $1 ..."
    # Retry every 10s for ~10 days (binlogs are kept 7). MySQL'"'"'s defaults,
    # 10 tries 60s apart, give up for good after a ~10 minute primary outage.
    sql <<SQL
CHANGE REPLICATION SOURCE TO
  SOURCE_HOST='"'"'$1'"'"', SOURCE_PORT=3306,
  SOURCE_USER='"'"'wg_repl'"'"', SOURCE_PASSWORD='"'"'$MYSQL_REPL_PASSWORD'"'"',
  SOURCE_AUTO_POSITION=1,
  SOURCE_CONNECT_RETRY=10, SOURCE_RETRY_COUNT=86400,
  SOURCE_SSL=1, SOURCE_SSL_VERIFY_SERVER_CERT=1,
  SOURCE_SSL_CA='"'"'$TLS_CA'"'"', SOURCE_SSL_CERT='"'"'$TLS_CERT'"'"', SOURCE_SSL_KEY='"'"'$TLS_KEY'"'"';
START REPLICA;
SQL
}
'

# shellcheck disable=SC2016
PRIMARY_SETUP='
check_repl_password
gtid="$(q "SELECT @@gtid_mode")"
[ "$gtid" = ON ] || die "GTIDs are off on this MySQL. Recreate it with the cycle-5b flags first: make prod-up."
echo "==> Creating/refreshing replication user wg_repl (REQUIRE X509) ..."
sql <<SQL
CREATE USER IF NOT EXISTS '"'"'wg_repl'"'"'@'"'"'%'"'"' IDENTIFIED BY '"'"'$MYSQL_REPL_PASSWORD'"'"' REQUIRE X509;
ALTER USER '"'"'wg_repl'"'"'@'"'"'%'"'"' IDENTIFIED BY '"'"'$MYSQL_REPL_PASSWORD'"'"' REQUIRE X509;
GRANT REPLICATION SLAVE, REPLICATION CLIENT, SELECT, SHOW VIEW, TRIGGER, LOCK TABLES, RELOAD, EVENT ON *.* TO '"'"'wg_repl'"'"'@'"'"'%'"'"';
SQL
echo "==> wg_repl ready."
'

# shellcheck disable=SC2016
SEED='
check_repl_password
sid="$(q "SELECT @@server_id")"
[ "$sid" != 1 ] || die "this mysqld runs with the PRIMARY flags (server-id 1). On the standby, start it with make standby-up first."
rs="$(q "SHOW REPLICA STATUS")"
[ -z "$rs" ] || die "replication is already configured on this host — see make standby-status. To start over, follow the runbook section Re-seeding."
n="$(q "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = '"'"'$MYSQL_DATABASE'"'"'")"
[ "$n" = 0 ] || die "the local $MYSQL_DATABASE database already has $n tables. Seeding needs an empty replica — see the runbook section Re-seeding."

umask 077
dump="${TMPDIR:-/tmp}/wg-standby-seed.sql"
# Whatever happens next, leave the replica read-only and the dump gone.
# PERSIST (not just GLOBAL) writes it into the datadir'"'"'s mysqld-auto.cnf,
# so the replica comes back read-only after every restart. It can'"'"'t be a
# mysqld flag: first-boot init can'"'"'t set the root password under it.
finish() { rm -f "$dump"; q "SET PERSIST super_read_only=ON" || true; }
trap finish EXIT

q "SET GLOBAL super_read_only=OFF"
# Clear this fresh server'"'"'s own GTID history so the dump can set
# GTID_PURGED to the primary'"'"'s. (8.4 syntax first, 8.0 fallback.)
q "RESET BINARY LOGS AND GTIDS" 2>/dev/null || q "RESET MASTER"

echo "==> Dumping $MYSQL_DATABASE from $PRIMARY (mutual TLS, VERIFY_IDENTITY) ..."
if ! MYSQL_PWD="$MYSQL_REPL_PASSWORD" mysqldump -h "$PRIMARY" -u wg_repl \
        --ssl-mode=VERIFY_IDENTITY --ssl-ca="$TLS_CA" --ssl-cert="$TLS_CERT" --ssl-key="$TLS_KEY" \
        --single-transaction --set-gtid-purged=ON --no-tablespaces \
        --routines --triggers --events \
        --databases "$MYSQL_DATABASE" > "$dump"; then
    die "the dump from $PRIMARY failed. Usual causes: $PRIMARY is not a SAN on the primary MySQL cert (add it to MYSQL_SERVER_EXTRA_SANS, then make certs-rotate on the primary); MYSQL_BIND_ADDR / firewall on the primary; make repl-primary-setup not run there."
fi

echo "==> Loading the dump ..."
sql < "$dump"

start_replication_from "$PRIMARY"
echo "==> Seeded. Check with: make standby-status"
'

# shellcheck disable=SC2016
PRIMARY_STATE='
host="$(source_host)"
if [ -z "$host" ]; then
    ro="$(q "SELECT @@super_read_only")"
    n="$(q "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = '"'"'$MYSQL_DATABASE'"'"'")"
    echo "state=not-a-replica"
    echo "local_read_only=$ro"
    echo "local_tables=$n"
    exit 0
fi
check_repl_password
echo "host=$host"
if out="$(remote_q "$host" "SELECT @@super_read_only, @@gtid_executed" 2>/dev/null)"; then
    ro="$(printf "%s" "$out" | cut -f1)"
    gtid="$(printf "%s" "$out" | cut -f2- | gtid_clean)"
    if [ "$ro" = 1 ]; then echo "state=readonly"; else echo "state=writable"; fi
    echo "gtid=$gtid"
else
    echo "state=unreachable"
fi
'

# shellcheck disable=SC2016
PROBE='
check_repl_password
if out="$(remote_q "$PROBE_HOST" "SELECT @@super_read_only, @@gtid_executed" 2>/dev/null)"; then
    ro="$(printf "%s" "$out" | cut -f1)"
    if [ "$ro" = 1 ]; then echo "state=readonly"; else echo "state=writable"; fi
    echo "gtid=$(printf "%s" "$out" | cut -f2- | gtid_clean)"
else
    echo "state=unreachable"
fi
'

# shellcheck disable=SC2016
PROMOTE='
wait_s="${PROMOTE_WAIT_SECONDS:-300}"
rs="$(q "SHOW REPLICA STATUS")"
if [ -z "$rs" ]; then
    # Not a replica: either promoted by an earlier run (resume), or never
    # seeded. A never-seeded standby is writable too, so tell them apart
    # by its (empty) database.
    ro="$(q "SELECT @@super_read_only")"
    n="$(q "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = '"'"'$MYSQL_DATABASE'"'"'")"
    [ "$n" != 0 ] || die "this MySQL is not a replica and its $MYSQL_DATABASE database is empty — the standby was never seeded, so there is nothing to promote."
    if [ "$ro" = 0 ]; then
        echo "==> MySQL is already promoted (no replication source, writable) — nothing to do."
        exit 0
    fi
    die "this MySQL has no replication source but is read-only — neither a replica nor promoted. See docs/runbooks/failover.md."
fi
if [ -n "${WAIT_GTID:-}" ]; then
    valid_gtid "$WAIT_GTID" || die "malformed WAIT_GTID."
    echo "==> Waiting until every transaction of the primary ($WAIT_GTID) is applied here..."
    r="$(q "SELECT WAIT_FOR_EXECUTED_GTID_SET('"'"'$WAIT_GTID'"'"', $wait_s)")"
    [ "$r" = 0 ] || die "the replica did not catch up with the primary within ${wait_s}s — NOT promoting. Check make standby-status."
fi
q "STOP REPLICA IO_THREAD"
raw="$(q "SELECT RECEIVED_TRANSACTION_SET FROM performance_schema.replication_connection_status WHERE CHANNEL_NAME = \"\"")"
received="$(printf "%s" "$raw" | gtid_clean)"
if [ -n "$received" ]; then
    valid_gtid "$received" || die "unexpected received GTID set: $received"
    echo "==> Applying every transaction already received..."
    r="$(q "SELECT WAIT_FOR_EXECUTED_GTID_SET('"'"'$received'"'"', $wait_s)")"
    [ "$r" = 0 ] || die "could not apply everything received within ${wait_s}s — NOT promoting. Replication is stopped; START REPLICA resumes it."
fi
q "STOP REPLICA"
q "RESET REPLICA ALL"
q "SET PERSIST super_read_only=OFF"
q "SET PERSIST read_only=OFF"
g="$(q "SELECT @@gtid_executed")"
echo "==> Promoted: MySQL is writable. gtid_executed=$(printf "%s" "$g" | gtid_clean)"
'

# shellcheck disable=SC2016
DEMOTE='
q "SET PERSIST super_read_only=ON"
g="$(q "SELECT @@gtid_executed")"
echo "==> MySQL is read-only."
echo "gtid=$(printf "%s" "$g" | gtid_clean)"
'

# shellcheck disable=SC2016
REJOIN='
check_repl_password
sid="$(q "SELECT @@server_id")"
[ "$sid" != 1 ] || die "this mysqld runs with the PRIMARY flags (server-id 1). Start it with make standby-up first."
rs="$(q "SHOW REPLICA STATUS")"
if [ -n "$rs" ]; then
    cur="$(source_host)"
    if [ "$cur" = "$NEW_PRIMARY" ]; then
        echo "==> Already replicating from $NEW_PRIMARY — nothing to do."
        exit 0
    fi
    die "this host already replicates from $cur, not $NEW_PRIMARY."
fi
# This host is a standby from here on, whatever the checks below find.
# After an UNPLANNED failover it was never demoted, so it is writable.
ro="$(q "SELECT @@super_read_only")"
[ "$ro" = 1 ] || echo "==> MySQL here is writable (never demoted) — making it read-only."
q "SET PERSIST super_read_only=ON"
raw="$(remote_q "$NEW_PRIMARY" "SELECT @@gtid_executed")" \
    || die "cannot query $NEW_PRIMARY as wg_repl. Did make failover finish there (it runs repl-primary-setup)?"
theirs="$(printf "%s" "$raw" | gtid_clean)"
m="$(q "SELECT @@gtid_executed")"
mine="$(printf "%s" "$m" | gtid_clean)"
valid_gtid "$theirs" || die "unexpected GTID set from $NEW_PRIMARY: $theirs"
valid_gtid "$mine" || die "unexpected local GTID set: $mine"
sub="$(q "SELECT GTID_SUBSET('"'"'$mine'"'"', '"'"'$theirs'"'"')")"
if [ "$sub" != 1 ]; then
    errant="$(q "SELECT GTID_SUBTRACT('"'"'$mine'"'"', '"'"'$theirs'"'"')")"
    die "this host has transactions $NEW_PRIMARY does not ($errant): writes that never reached the standby before the failover. It cannot rejoin as-is (it stays read-only, not replicating) — follow docs/runbooks/failover.md, Re-seeding the old primary (it backs this data up first)."
fi
start_replication_from "$NEW_PRIMARY"
echo "==> Rejoined as a replica of $NEW_PRIMARY."
'

# ---------------------------------------------------------------------

# Block until this stack's mysqld accepts root logins. `compose up
# --wait` can return while the image's first-boot init is still
# swapping its temporary server (no root password yet) for the real
# one, so a seed right after `make standby-up` would hit that window.
wait_ready() {
    local timeout="${REPL_READY_TIMEOUT_SECONDS:-120}"
    local interval="${REPL_READY_INTERVAL_SECONDS:-2}"
    local start=$SECONDS
    until in_mysql "$PRELUDE"'q "SELECT 1" >/dev/null' 2>/dev/null; do
        if (( SECONDS - start >= timeout )); then
            die "mysql in this stack is not accepting root logins after ${timeout}s — check 'docker compose logs mysql' and MYSQL_ROOT_PASSWORD."
        fi
        sleep "$interval"
    done
}

cmd_primary_setup() {
    wait_ready
    in_mysql "$PRELUDE$PRIMARY_SETUP"
}

cmd_seed() {
    local primary="${1:-}"
    # Hostname or IP only — it lands in SQL and on mysqldump's argv.
    [[ "$primary" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]] \
        || die "invalid primary host '${primary}' — expected a hostname or IP, e.g. rv.vpn."

    # The standby runs mysql only. App services here would be writing
    # to (or reading from) a database that's about to be replaced.
    local running
    running="$(compose ps --services --status running)"
    for svc in api worker beat web enroll; do
        if grep -qx "$svc" <<< "$running"; then
            die "'$svc' is running on this host. The standby runs mysql only: make prod-down, then make standby-up."
        fi
    done

    wait_ready
    in_mysql "$PRELUDE$SEED" -e "PRIMARY=$primary"
}

cmd_primary_state() {
    wait_ready
    in_mysql "$PRELUDE$PRIMARY_STATE"
}

cmd_probe() {
    local host="${1:-}"
    [[ "$host" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]] \
        || die "invalid host '${host}' — expected a hostname or IP."
    compose run --rm --no-deps -T -e "PROBE_HOST=$host" --entrypoint sh mysql -c "$PRELUDE$PROBE"
}

cmd_promote() {
    local wait_gtid="${WAIT_GTID:-}"
    [[ "$wait_gtid" =~ ^[0-9A-Za-z:,_-]*$ ]] || die "malformed WAIT_GTID '$wait_gtid'."
    wait_ready
    in_mysql "$PRELUDE$PROMOTE" -e "WAIT_GTID=$wait_gtid" -e "PROMOTE_WAIT_SECONDS=${PROMOTE_WAIT_SECONDS:-300}"
}

cmd_demote() {
    wait_ready
    in_mysql "$PRELUDE$DEMOTE"
}

cmd_rejoin() {
    local new_primary="${1:-}"
    [[ "$new_primary" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]] \
        || die "invalid primary host '${new_primary}' — expected a hostname or IP, e.g. general.vpn."
    wait_ready
    in_mysql "$PRELUDE$REJOIN" -e "NEW_PRIMARY=$new_primary"
}

cmd_status() {
    local max="${REPL_MAX_LAG_SECONDS:-300}" out
    # shellcheck disable=SC2016
    out="$(in_mysql 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot -e "SHOW REPLICA STATUS\G"')"
    field() { sed -n "s/^ *$1: *//p" <<< "$out" | head -n 1; }

    local io sqlr lag
    io="$(field Replica_IO_Running)"
    sqlr="$(field Replica_SQL_Running)"
    lag="$(field Seconds_Behind_Source)"
    if [ -z "$io" ]; then
        echo "Replication is not configured on this host (see make standby-seed)."
        return 1
    fi

    echo "Source_Host:           $(field Source_Host)"
    echo "Replica_IO_Running:    $io"
    echo "Replica_SQL_Running:   $sqlr"
    echo "Seconds_Behind_Source: $lag"
    local ioerr sqlerr
    ioerr="$(field Last_IO_Error)"
    sqlerr="$(field Last_SQL_Error)"
    [ -z "$ioerr" ] || echo "Last_IO_Error:         $ioerr"
    [ -z "$sqlerr" ] || echo "Last_SQL_Error:        $sqlerr"

    if [ "$io" != Yes ] || [ "$sqlr" != Yes ] || ! [[ "$lag" =~ ^[0-9]+$ ]]; then
        echo "UNHEALTHY: replication is not running."
        return 1
    fi
    if [ "$lag" -gt "$max" ]; then
        echo "LAGGING: ${lag}s behind the source (threshold ${max}s)."
        return 2
    fi
    echo "OK"
}

case "${1:-}" in
    primary-setup) cmd_primary_setup ;;
    seed) shift; cmd_seed "${1:-}" ;;
    status) cmd_status ;;
    primary-state) cmd_primary_state ;;
    probe) shift; cmd_probe "${1:-}" ;;
    promote) cmd_promote ;;
    demote) cmd_demote ;;
    rejoin) shift; cmd_rejoin "${1:-}" ;;
    *)
        echo "usage: $(basename "$0") primary-setup | seed HOST | status | primary-state | probe HOST | promote | demote | rejoin HOST" >&2
        echo "See docs/runbooks/standby-replication.md." >&2
        exit 2 ;;
esac
