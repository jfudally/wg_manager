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
        *"'"'"'"*|*\\*) die "MYSQL_REPL_PASSWORD must not contain quotes or backslashes (use openssl rand -hex 32)." ;;
    esac
}
TLS_CA=/etc/mysql/certs/ca.crt
TLS_CERT=/etc/mysql/certs/client.crt
TLS_KEY=/etc/mysql/certs/client.key
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

echo "==> Starting replication from $PRIMARY ..."
# Retry every 10s for ~10 days (binlogs are kept 7). MySQL'"'"'s defaults,
# 10 tries 60s apart, give up for good after a ~10 minute primary outage.
sql <<SQL
CHANGE REPLICATION SOURCE TO
  SOURCE_HOST='"'"'$PRIMARY'"'"', SOURCE_PORT=3306,
  SOURCE_USER='"'"'wg_repl'"'"', SOURCE_PASSWORD='"'"'$MYSQL_REPL_PASSWORD'"'"',
  SOURCE_AUTO_POSITION=1,
  SOURCE_CONNECT_RETRY=10, SOURCE_RETRY_COUNT=86400,
  SOURCE_SSL=1, SOURCE_SSL_VERIFY_SERVER_CERT=1,
  SOURCE_SSL_CA='"'"'$TLS_CA'"'"', SOURCE_SSL_CERT='"'"'$TLS_CERT'"'"', SOURCE_SSL_KEY='"'"'$TLS_KEY'"'"';
START REPLICA;
SQL
echo "==> Seeded. Check with: make standby-status"
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
    *)
        echo "usage: $(basename "$0") primary-setup | seed HOST | status" >&2
        echo "See docs/runbooks/standby-replication.md." >&2
        exit 2 ;;
esac
