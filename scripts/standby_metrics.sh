#!/usr/bin/env bash
# =====================================================================
# Write the warm standby's health as Prometheus metrics (Phase 3d
# cycle 5e). Entry point for `make standby-metrics`, run every minute
# from wg-manager-standby-metrics.timer.
#
# The standby runs no API, so there's no /metrics to scrape. This
# writes a node_exporter textfile-collector file instead (node_exporter
# --collector.textfile.directory=<dir>), atomically (temp file + mv in
# the same directory), so node_exporter never reads a half-written file.
#
# Every value is a gauge:
#   wg_manager_standby_replication_configured            0/1
#   wg_manager_standby_replication_io_running            0/1
#   wg_manager_standby_replication_sql_running           0/1
#   wg_manager_standby_replication_lag_seconds           omitted when NULL
#   wg_manager_standby_bundle_present                    0/1
#   wg_manager_standby_bundle_created_timestamp_seconds  from standby/MANIFEST
#   wg_manager_standby_bundle_commit_drift               0/1 vs this checkout
#   wg_manager_standby_drill_last_success_timestamp_seconds
#   wg_manager_standby_drill_last_failure_timestamp_seconds
#   wg_manager_standby_metrics_generated_timestamp_seconds
#
# Times are timestamps, not ages: Prometheus computes `time() - x`, so
# the age keeps growing even after this timer dies. Unhealthy is data,
# not an error. This exits 0 whenever it wrote the file; the alerts in
# docs/observability/prometheus-alerts.yaml do the judging.
#
# Env (the Makefile sets COMPOSE; STANDBY_METRICS_FILE may also come
# from .env.host):
#   STANDBY_METRICS_FILE  output file
#                         (default /var/lib/node_exporter/textfile_collector/wg_manager_standby.prom)
#   COMPOSE               standby compose command    [required]
#   MYSQL_REPL_SCRIPT     default scripts/mysql_replication.sh
#   REPO_DIR              default $PWD
# =====================================================================

set -euo pipefail

: "${COMPOSE:?COMPOSE must be set (run via make standby-metrics)}"
REPO_DIR="$(cd "${REPO_DIR:-$PWD}" && pwd)"
REPL="${MYSQL_REPL_SCRIPT:-$REPO_DIR/scripts/mysql_replication.sh}"
STATE_DIR="$REPO_DIR/standby"

die() { echo "ERROR: $*" >&2; exit 1; }

# STANDBY_METRICS_FILE from the environment, else .env.host, else default.
out="${STANDBY_METRICS_FILE:-}"
if [ -z "$out" ] && [ -f "$REPO_DIR/.env.host" ]; then
    out="$(sed -n 's/^STANDBY_METRICS_FILE=//p' "$REPO_DIR/.env.host" | tail -n 1)"
fi
out="${out:-/var/lib/node_exporter/textfile_collector/wg_manager_standby.prom}"
[ -d "$(dirname "$out")" ] || die "metrics directory $(dirname "$out") does not exist — point STANDBY_METRICS_FILE at node_exporter's textfile directory."

# --- replication (the status command exits non-zero when unhealthy:
#     that's data here, not a failure)
status="$(COMPOSE="$COMPOSE" "$REPL" status 2>&1)" || true
field() { sed -n "s/^ *$1: *//p" <<< "$status" | head -n 1; }
io="$(field Replica_IO_Running)"
sqlr="$(field Replica_SQL_Running)"
lag="$(field Seconds_Behind_Source)"
configured=1
grep -q "not configured" <<< "$status" && configured=0
yes01() { [ "$1" = Yes ] && echo 1 || echo 0; }

# --- bundle
manifest="$STATE_DIR/MANIFEST"
bundle_present=0 created="" drift=""
if [ -f "$manifest" ]; then
    bundle_present=1
    created="$(sed -n 's/^created_epoch=//p' "$manifest" | tail -n 1)"
    commit="$(sed -n 's/^commit=//p' "$manifest" | tail -n 1)"
    head="$(git -C "$REPO_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
    [ "$commit" = "$head" ] && drift=0 || drift=1
fi

# --- drill
drill_ts() { local f="$STATE_DIR/drill.last_$1"; [ -f "$f" ] && tr -dc '0-9' < "$f" || true; }
drill_ok="$(drill_ts success)"
drill_bad="$(drill_ts failure)"

# --- render
P=wg_manager_standby_
gauge() {  # name help value — skipped when the value isn't a number
    [[ "$3" =~ ^[0-9]+(\.[0-9]+)?$ ]] || return 0
    printf '# HELP %s%s %s\n# TYPE %s%s gauge\n%s%s %s\n' "$P" "$1" "$2" "$P" "$1" "$P" "$1" "$3"
}
tmp="$(mktemp "$(dirname "$out")/.wg_manager_standby.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
{
    gauge replication_configured "1 if this host is configured as a MySQL replica." "$configured"
    gauge replication_io_running "1 if the replica's IO thread is running." "$(yes01 "$io")"
    gauge replication_sql_running "1 if the replica's SQL thread is running." "$(yes01 "$sqlr")"
    gauge replication_lag_seconds "Seconds_Behind_Source (omitted when unknown)." "$lag"
    gauge bundle_present "1 if a bundle from the primary has been installed." "$bundle_present"
    gauge bundle_created_timestamp_seconds "When the installed bundle was created on the primary." "$created"
    gauge bundle_commit_drift "1 if the primary's commit differs from this checkout." "$drift"
    gauge drill_last_success_timestamp_seconds "Last successful make standby-drill." "$drill_ok"
    gauge drill_last_failure_timestamp_seconds "Last failed make standby-drill." "$drill_bad"
    gauge metrics_generated_timestamp_seconds "When this file was written." "$(date -u +%s)"
} > "$tmp"
chmod 644 "$tmp"
mv -f "$tmp" "$out"
trap - EXIT
