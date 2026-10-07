#!/usr/bin/env bash
# =====================================================================
# Weekly failover drill on the warm standby (Phase 3d cycle 5e). Entry
# point for `make standby-drill`, run by wg-manager-standby-drill.timer.
#
# It proves the standby could take over, without touching anything real:
#
#   1. Vault. Restore the latest shipped snapshot (standby/vault.snap)
#      into a THROWAWAY Vault through the exact path `make failover`
#      uses: vault_restore.py, then a Vault restart, then
#      vault_restore.py --verify. The verify step unseals with the
#      shipped keys and checks the ssh/, pki/ and transit/ engines with
#      the shipped root token. So it also proves vault-init.json and the
#      snapshot belong together.
#   2. MySQL. Replication must be healthy and within
#      REPL_MAX_LAG_SECONDS (`mysql_replication.sh status`).
#
# Isolation: the throwaway Vault gets its own `--internal` Docker
# network, an anonymous volume and a unique name, and is removed
# afterwards whatever happens. The standby's compose project is only
# READ (to find the vault and wg-manager image names). Its containers,
# volumes and network are never touched.
#
# Result: standby/drill.last_success or standby/drill.last_failure gets
# the current epoch. `make standby-metrics` exports both, and the
# WgStandbyDrillFailed / WgStandbyDrillOverdue alerts watch them. A
# failed drill also exits non-zero, so the systemd unit shows `failed`.
#
# Env (set by the Makefile; overridable for tests):
#   COMPOSE              standby compose command               [required]
#   DOCKER               docker binary                         (default: docker)
#   HELPER_IMAGE         image for the vault-init.json check   (default: alpine:3.20)
#   MYSQL_REPL_SCRIPT    default scripts/mysql_replication.sh
#   REPO_DIR             default $PWD
#   DRILL_READY_TIMEOUT_SECONDS  wait for the throwaway Vault  (default: 60)
# =====================================================================

set -euo pipefail

: "${COMPOSE:?COMPOSE must be set (run via make standby-drill)}"
DOCKER="${DOCKER:-docker}"
HELPER_IMAGE="${HELPER_IMAGE:-alpine:3.20}"
REPO_DIR="$(cd "${REPO_DIR:-$PWD}" && pwd)"
REPL="${MYSQL_REPL_SCRIPT:-$REPO_DIR/scripts/mysql_replication.sh}"
STATE_DIR="$REPO_DIR/standby"
READY_TIMEOUT="${DRILL_READY_TIMEOUT_SECONDS:-60}"
NAME="wg-manager-drill-$$"

log() { echo "==> $*"; }

# Record the outcome for the metrics, then exit.
finish() {
    local outcome="$1" msg="${2:-}"
    umask 077
    mkdir -p "$STATE_DIR"
    date -u +%s > "$STATE_DIR/drill.last_$outcome"
    if [ "$outcome" = failure ]; then
        echo "ERROR: drill FAILED: $msg" >&2
        exit 1
    fi
    log "Drill PASSED."
}
# Preflight failures happen before anything is created.
fail() { finish failure "$*"; }

# Word-splitting COMPOSE is intended: it's a command plus flags.
# shellcheck disable=SC2086
compose() { $COMPOSE "$@"; }

# ---------------------------------------------------------------- preflight
[ -s "$STATE_DIR/vault.snap" ] \
    || fail "no Vault snapshot in standby/ — run make standby-pull (and check its timer)."
"$DOCKER" run --rm -v "$REPO_DIR:/src:ro" "$HELPER_IMAGE" test -s /src/vault-init.json \
    || fail "vault-init.json is missing or empty — make standby-pull."

images="$(compose config --format json | python3 -c '
import json, sys
s = json.load(sys.stdin)["services"]
print(s["vault"]["image"], s["bootstrap-app"]["image"])')" \
    || fail "could not read image names from the compose config."
read -r VAULT_IMAGE APP_IMAGE <<< "$images"
"$DOCKER" image inspect "$APP_IMAGE" >/dev/null 2>&1 \
    || fail "image $APP_IMAGE is not built on this host — run make standby-up (it builds it)."

# ---------------------------------------------------------------- throwaway Vault
cleanup() {
    "$DOCKER" rm -f -v "$NAME-vault" >/dev/null 2>&1 || true
    "$DOCKER" network rm "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

log "Starting a throwaway Vault ($NAME-vault) on an isolated network..."
"$DOCKER" network create --internal "$NAME" >/dev/null
"$DOCKER" run -d --name "$NAME-vault" --network "$NAME" --network-alias vault \
    -v "$REPO_DIR/docker/vault/vault.hcl:/vault/config/vault.hcl:ro" \
    --mount type=volume,dst=/vault/raft \
    --entrypoint vault "$VAULT_IMAGE" server -config=/vault/config/vault.hcl >/dev/null

# Wait until the throwaway Vault's API answers. `vault status` exits 0
# (unsealed) or 2 (sealed/uninitialized) once it's up, and 1 while it
# can't connect.
wait_vault() {
    local start=$SECONDS rc
    while :; do
        rc=0
        "$DOCKER" exec "$NAME-vault" sh -c 'VAULT_ADDR=http://127.0.0.1:8200 vault status' \
            >/dev/null 2>&1 || rc=$?
        [ "$rc" != 1 ] && return 0
        (( SECONDS - start < READY_TIMEOUT )) || return 1
        sleep 1
    done
}

# The wg-manager image with the shipped vault-init.json (read-only) and
# this checkout's scripts; the entrypoint shim exports the shipped root
# token.
app() {
    "$DOCKER" run --rm -i --network "$NAME" \
        -e VAULT_ADDR=http://vault:8200 -e VAULT_INIT_FILE=/app/vault-init.json \
        -v "$REPO_DIR/vault-init.json:/app/vault-init.json:ro" \
        -v "$REPO_DIR/scripts:/app/scripts:ro" \
        --entrypoint /usr/local/bin/entrypoint-wg-manager.sh "$APP_IMAGE" \
        python /app/scripts/vault_restore.py "$@"
}

wait_vault || fail "the throwaway Vault did not start within ${READY_TIMEOUT}s."
log "Restoring standby/vault.snap ($(stat -c %s "$STATE_DIR/vault.snap") bytes)..."
app < "$STATE_DIR/vault.snap" || fail "the Vault restore failed (see above)."
log "Restarting the throwaway Vault (as make failover does)..."
"$DOCKER" restart "$NAME-vault" >/dev/null
wait_vault || fail "the throwaway Vault did not come back after the restart."
verify="$(app --verify < /dev/null)" || fail "the restored Vault did not verify (see above)."
echo "$verify"

# ---------------------------------------------------------------- MySQL
log "Checking replication..."
COMPOSE="$COMPOSE" "$REPL" status || fail "replication is not healthy (see above) — a failover now would lose data."

finish success
