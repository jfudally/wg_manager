#!/usr/bin/env bash
# =====================================================================
# Promotion for the warm standby (Phase 3d cycle 5d). Entry point for
# `make demote` / `make failover` / `make rejoin`. The procedure,
# including what only the operator can do (fencing, the DNS move), is
# in docs/runbooks/failover.md.
#
#   demote        On the PRIMARY, for a planned switchover. Remove the app
#                 containers (api worker beat web enroll) and make MySQL
#                 read-only. MySQL and Vault keep running, so the standby
#                 can catch up to the last transaction and take a final
#                 bundle pull. The role stays `primary` until `rejoin`.
#   failover      On the STANDBY. Fences on the primary's state, seen
#                 over the replication channel:
#                   writable     -> refuse: demote it first
#                   readonly     -> planned: final `standby-pull`, wait for
#                                   every primary transaction, promote.
#                                   No data loss.
#                   unreachable  -> unplanned: only with
#                                   CONFIRM=primary-is-down (from here a
#                                   network split looks the same as a dead
#                                   primary); promote with what was
#                                   received. The last seconds may be lost.
#                 Then restore Vault from standby/vault.snap (restore,
#                 restart Vault, verify), flip
#                 .env.host to primary, `make prod-up` and
#                 `make repl-primary-setup`. Re-running after a partial
#                 failure resumes: an already-promoted MySQL is detected.
#   rejoin HOST   On the OLD PRIMARY. Refuse unless HOST answers as a
#                 writable primary. Then flip the role to standby, remove
#                 the app containers and Vault, restart MySQL with the
#                 standby flags, and replicate from HOST. Works without re-seeding
#                 only if this host has no transactions HOST lacks.
#
# Env (set by the Makefile; overridable for tests):
#   COMPOSE            compose command for this host's role   [required]
#   MAKE               make binary                            (default: make)
#   DOCKER, HELPER_IMAGE, REPO_DIR   as in the other standby scripts
#   MYSQL_REPL_SCRIPT  path to mysql_replication.sh
#   CONFIRM            failover: "primary-is-down" for the unplanned path
# =====================================================================

set -euo pipefail

: "${COMPOSE:?COMPOSE must be set (run via make demote / failover / rejoin)}"
MAKE="${MAKE:-make}"
DOCKER="${DOCKER:-docker}"
HELPER_IMAGE="${HELPER_IMAGE:-alpine:3.20}"
REPO_DIR="$(cd "${REPO_DIR:-$PWD}" && pwd)"
REPL="${MYSQL_REPL_SCRIPT:-$REPO_DIR/scripts/mysql_replication.sh}"
APP_SERVICES=(api worker beat web enroll)

die() { echo "ERROR: $*" >&2; exit 1; }
log() { echo "==> $*"; }

# Word-splitting COMPOSE is intended: it's a command plus flags.
# shellcheck disable=SC2086
compose() { $COMPOSE "$@"; }

# Set WG_MANAGER_ROLE in .env.host, keeping every other line.
set_role() {
    local f="$REPO_DIR/.env.host"
    [ -f "$f" ] || die ".env.host is missing."
    if grep -q '^WG_MANAGER_ROLE=' "$f"; then
        sed -i "s/^WG_MANAGER_ROLE=.*/WG_MANAGER_ROLE=$1/" "$f"
    else
        echo "WG_MANAGER_ROLE=$1" >> "$f"
    fi
    log "This host's role is now: $1 (.env.host)"
}

# KEY=VALUE from multi-line `key=value` output.
field() { sed -n "s/^$1=//p" <<< "$2" | head -n 1; }

cmd_demote() {
    log "Removing the app containers (${APP_SERVICES[*]})..."
    # rm, not stop: a stopped `restart: always` container comes back
    # when the Docker daemon restarts (e.g. a reboot).
    compose rm -s -f "${APP_SERVICES[@]}"
    log "Making MySQL read-only..."
    "$REPL" demote
    cat <<'EOF'

Demoted. MySQL and Vault stay up, read-only, so the standby can catch up
and take a final bundle. Next:
  1. On the standby:          make failover
  2. Move the control-plane DNS name to the standby.
  3. Back here, once 1 is done: make rejoin primary=<the standby's MySQL name>
EOF
}

cmd_failover() {
    # --- preflight: everything a promotion needs is on this host
    [ -s "$REPO_DIR/standby/vault.snap" ] && [ -f "$REPO_DIR/standby/MANIFEST" ] \
        || die "no Vault snapshot in standby/ — run make standby-pull (and check its timer) first."
    "$DOCKER" run --rm -v "$REPO_DIR:/src:ro" "$HELPER_IMAGE" test -s /src/vault-init.json \
        || die "vault-init.json is missing or empty — the snapshot can't be unsealed without the primary's keys (make standby-pull)."

    # --- fence
    local probe state
    probe="$("$REPL" primary-state)"
    state="$(field state "$probe")"
    case "$state" in
        writable)
            die "the primary ($(field host "$probe")) is still WRITABLE. Run make demote there first (planned switchover). Promoting now would give you two writable primaries." ;;
        readonly)
            log "The primary is demoted (read-only): planned switchover, no data loss."
            log "Final bundle pull, so Vault here is current to this moment..."
            "$MAKE" standby-pull || die "the final standby-pull failed — not promoting. Fix it and re-run make failover."
            WAIT_GTID="$(field gtid "$probe")" "$REPL" promote ;;
        unreachable)
            if [ "${CONFIRM:-}" != primary-is-down ]; then
                die "the primary ($(field host "$probe")) is unreachable from here. That is a dead primary OR a network split, and only you can tell which. Make sure it is down and stays down (power it off, or stop its stack), then re-run: make failover confirm=primary-is-down. See the split-brain section of docs/runbooks/failover.md."
            fi
            log "Unplanned failover: promoting with every transaction received from the primary."
            log "Writes the primary made in its last seconds may be lost; Vault is as of the last pull ($(sed -n 's/^created=//p' "$REPO_DIR/standby/MANIFEST"))."
            WAIT_GTID="" "$REPL" promote ;;
        not-a-replica)
            if [ "$(field local_read_only "$probe")" = 0 ] && [ "$(field local_tables "$probe")" != 0 ]; then
                log "MySQL here is already promoted — resuming the failover."
            else
                die "this host is not a replica and not promoted — nothing to fail over to (was it ever seeded? make standby-seed)."
            fi ;;
        *)
            die "could not determine the primary's state: $probe" ;;
    esac

    # --- Vault
    log "Starting Vault and restoring the primary's snapshot..."
    compose up -d --no-deps --wait vault
    local shim=/usr/local/bin/entrypoint-wg-manager.sh
    compose run --rm --no-deps -T --entrypoint "$shim" bootstrap-app \
        python /app/scripts/vault_restore.py < "$REPO_DIR/standby/vault.snap" \
        || die "the Vault restore failed (see above). MySQL is already promoted; fix the cause and re-run make failover — it resumes."
    # The running server keeps the OLD seal config in memory after a
    # restore and rejects the snapshot's unseal keys; a restart loads the
    # snapshot's (scripts/vault_restore.py explains).
    log "Restarting Vault so it loads the snapshot's seal config..."
    compose restart vault
    compose up -d --no-deps --wait vault
    compose run --rm --no-deps -T --entrypoint "$shim" bootstrap-app \
        python /app/scripts/vault_restore.py --verify \
        || die "the restored Vault did not verify (see above). MySQL is already promoted; fix the cause and re-run make failover — it resumes."

    # --- become the primary
    set_role primary
    trap 'echo "ERROR: the stack did not come up. This host is already the primary; finish with: make prod-up && make repl-primary-setup" >&2' ERR
    "$MAKE" prod-up
    "$MAKE" repl-primary-setup
    trap - ERR

    cat <<'EOF'

==> This host is now the PRIMARY.

Do now:
  1. Move the control-plane DNS name to this host. The API cert is valid
     for it only if it is in API_SERVER_SANS (docs/runbooks/failover.md).
  2. Timers here: disable wg-manager-standby-pull.timer and enable
     wg-manager-certs-rotate.timer (docs/deploy/systemd-timer.md).
  3. Old primary: keep it from coming back as a primary. When it's
     reachable, run there: make rejoin primary=<this host's MySQL name>
EOF
}

cmd_rejoin() {
    local new_primary="${1:-}"
    [[ "$new_primary" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]] \
        || die "invalid primary host '${new_primary}' — expected a hostname or IP, e.g. general.vpn."
    # Before tearing anything down: HOST must really be the new primary.
    # Catches running this on the wrong host or with a typo'd name.
    local probe
    probe="$("$REPL" probe "$new_primary")"
    [ "$(field state "$probe")" = writable ] \
        || die "$new_primary is not a writable primary ($(field state "$probe")). Run rejoin on the OLD primary, after make failover has finished on $new_primary. Nothing was changed."
    set_role standby
    log "Removing the app containers and Vault (a standby runs MySQL only)..."
    compose rm -s -f "${APP_SERVICES[@]}" vault
    log "Restarting MySQL with the standby flags..."
    "$MAKE" standby-up
    "$REPL" rejoin "$new_primary"

    local ssh_target
    ssh_target="$(sed -n 's/^STANDBY_PRIMARY_SSH=//p' "$REPO_DIR/.env.host" | tail -n 1)"
    # Compare first DNS labels: the SSH and MySQL names may differ in
    # their domain part (general vs general.vpn).
    local ssh_host="${ssh_target#*@}"
    if [ -n "$ssh_target" ] && [ "${ssh_host%%.*}" != "${new_primary%%.*}" ]; then
        echo "WARNING: .env.host still pulls from STANDBY_PRIMARY_SSH=$ssh_target." >&2
        echo "         Point it at the new primary ($new_primary) and authorize this host's" >&2
        echo "         pull key there (docs/runbooks/standby-replication.md), then make standby-pull." >&2
    fi
    cat <<'EOF'

==> This host is now the STANDBY. Enable wg-manager-standby-pull.timer
    and disable wg-manager-certs-rotate.timer here; check make standby-status.
EOF
}

case "${1:-}" in
    demote) cmd_demote ;;
    failover) cmd_failover ;;
    rejoin) shift; cmd_rejoin "${1:-}" ;;
    *)
        echo "usage: $(basename "$0") demote | failover | rejoin HOST" >&2
        exit 2 ;;
esac
