#!/usr/bin/env bash
# =====================================================================
# Pull the primary's state onto the warm standby (Phase 3d cycle 5c).
# Entry point for `make standby-pull` (run from a systemd timer, see
# docs/deploy/systemd-timer.md) and the bundle half of
# `make standby-status`. Setup: docs/runbooks/standby-replication.md.
#
#   pull     ssh to the primary, run `make -s standby-bundle o=-` there,
#            and install what comes back:
#              standby/vault.snap      latest raft snapshot (the one
#                                      before it kept as vault.snap.prev)
#              standby/MANIFEST        what was installed and when
#              .env.prod vault-init.json tls/   overwritten in place
#            Refuses — leaving the installed state untouched — on an SSH
#            or bundle failure, a checksum mismatch, an unknown format,
#            or a bundle no newer than the installed one (a replayed or
#            stale bundle must not roll the standby back). Restarts the
#            MySQL replica only when tls/mysql changed (a cert rotation
#            on the primary) and only if it is running.
#   status   Bundle age and code drift. Exit 0 OK, 1 nothing pulled yet,
#            2 older than STANDBY_MAX_BUNDLE_AGE_SECONDS (default 3600)
#            or pulled from a different commit than this checkout.
#
# Settings come from the environment, else from .env.host (parsed as
# plain KEY=VALUE, never sourced):
#   STANDBY_PRIMARY_SSH   user@host of the primary               [required]
#   STANDBY_PRIMARY_DIR   checkout dir on the primary, relative to that
#                         user's home or absolute       (default: wg_manager)
#   STANDBY_SSH_KEY       private key for the pull      (default: ssh's own)
#
# Other env (Makefile / tests):
#   COMPOSE        standby compose command incl. flags        [required for pull]
#   SSH            ssh binary                                 (default: ssh)
#   DOCKER         docker binary                              (default: docker)
#   HELPER_IMAGE   image whose tar writes the checkout        (default: alpine:3.20)
#   REPO_DIR       this checkout                              (default: $PWD)
# =====================================================================

set -euo pipefail

SSH="${SSH:-ssh}"
DOCKER="${DOCKER:-docker}"
HELPER_IMAGE="${HELPER_IMAGE:-alpine:3.20}"
REPO_DIR="$(cd "${REPO_DIR:-$PWD}" && pwd)"
STATE_DIR="$REPO_DIR/standby"

die() { echo "ERROR: $*" >&2; exit 1; }
log() { echo "==> $*"; }

# Value of KEY from the environment, else from .env.host, else $2.
setting() {
    local key="$1" default="${2:-}" val="${!1:-}"
    if [ -z "$val" ] && [ -f "$REPO_DIR/.env.host" ]; then
        val="$(sed -n "s/^${key}=//p" "$REPO_DIR/.env.host" | tail -n 1 | tr -d '"'"'"' ')"
    fi
    echo "${val:-$default}"
}

# KEY=VALUE lookup in a MANIFEST file.
manifest_get() { sed -n "s/^$2=//p" "$1" | tail -n 1; }

# Word-splitting COMPOSE is intended: it's a command plus flags.
# shellcheck disable=SC2086
compose() { $COMPOSE "$@"; }

# sha256 of every file under tls/mysql, read from a helper container
# (the keys belong to the container UID). Empty when there are none.
mysql_tls_digest() {
    "$DOCKER" run --rm -v "$REPO_DIR:/src:ro" "$HELPER_IMAGE" \
        sh -c 'cd /src && [ -d tls/mysql ] && find tls/mysql -type f | sort | xargs sha256sum || true'
}

cmd_pull() {
    : "${COMPOSE:?COMPOSE must be set (run via make standby-pull)}"
    local primary dir key
    primary="$(setting STANDBY_PRIMARY_SSH)"
    dir="$(setting STANDBY_PRIMARY_DIR wg_manager)"
    key="$(setting STANDBY_SSH_KEY)"
    [ -n "$primary" ] || die "STANDBY_PRIMARY_SSH is not set — add e.g. STANDBY_PRIMARY_SSH=ops@rv.vpn to .env.host."
    [[ "$dir" =~ ^[A-Za-z0-9._/~-]+$ ]] || die "STANDBY_PRIMARY_DIR '$dir' has unexpected characters."

    # Everything under standby/ is Vault material: private files only.
    umask 077
    mkdir -p "$STATE_DIR"
    chmod 700 "$STATE_DIR"
    # Global, not local: the EXIT trap runs after cmd_pull has returned.
    INCOMING="$(mktemp -d "$STATE_DIR/incoming.XXXXXX")"
    trap 'rm -rf "$INCOMING"' EXIT
    local in="$INCOMING"

    local ssh_args=(-o BatchMode=yes -o ConnectTimeout=20)
    [ -z "$key" ] || ssh_args+=(-i "$key")
    log "Fetching the bundle from $primary..."
    # With a forced command in the primary's authorized_keys (runbook),
    # the remote command below is ignored and the forced one runs.
    "$SSH" "${ssh_args[@]}" "$primary" "cd $dir && make -s standby-bundle o=-" > "$in/bundle.tar" \
        || die "fetching the bundle from $primary failed (see the primary's output above)."

    mkdir "$in/b"
    tar -C "$in/b" -xf "$in/bundle.tar" MANIFEST SHA256SUMS vault.snap files.tar \
        || die "the bundle from $primary is not a valid standby bundle."
    (cd "$in/b" && sha256sum --quiet -c SHA256SUMS) \
        || die "the bundle from $primary failed its checksums — not installing it."

    local m="$in/b/MANIFEST" format created commit
    format="$(manifest_get "$m" format)"
    created="$(manifest_get "$m" created_epoch)"
    commit="$(manifest_get "$m" commit)"
    [ "$format" = 1 ] || die "unknown bundle format '$format' — is this checkout older than the primary's?"
    [[ "$created" =~ ^[0-9]+$ ]] || die "the bundle MANIFEST has no valid created_epoch."
    [ -s "$in/b/vault.snap" ] || die "the bundle's Vault snapshot is empty."
    if [ -f "$STATE_DIR/MANIFEST" ]; then
        local installed
        installed="$(manifest_get "$STATE_DIR/MANIFEST" created_epoch)"
        if [[ "$installed" =~ ^[0-9]+$ ]] && [ "$created" -le "$installed" ]; then
            die "the bundle ($created) is not newer than the installed one ($installed) — refusing to roll the standby back. Check the primary's clock."
        fi
    fi

    local tls_before tls_after
    tls_before="$(mysql_tls_digest)"

    log "Installing .env.prod, vault-init.json, tls/..."
    "$DOCKER" run --rm -i -v "$REPO_DIR:/dst" "$HELPER_IMAGE" \
        tar -C /dst --numeric-owner -xpf - < "$in/b/files.tar"

    log "Installing the Vault snapshot..."
    [ ! -f "$STATE_DIR/vault.snap" ] || mv -f "$STATE_DIR/vault.snap" "$STATE_DIR/vault.snap.prev"
    mv "$in/b/vault.snap" "$STATE_DIR/vault.snap"
    # MANIFEST last: `status` treats it as "this install is complete".
    mv "$in/b/MANIFEST" "$STATE_DIR/MANIFEST"

    tls_after="$(mysql_tls_digest)"
    if [ "$tls_before" != "$tls_after" ]; then
        if grep -qx mysql <<< "$(compose ps --services --status running)"; then
            log "tls/mysql changed (cert rotation on the primary) — restarting the replica..."
            compose stop mysql
            compose up -d --no-deps --wait mysql
        else
            log "tls/mysql changed; the replica isn't running, so nothing to restart."
        fi
    fi

    local head
    head="$(git -C "$REPO_DIR" rev-parse HEAD)"
    if [ "$commit" != "$head" ]; then
        echo "WARNING: the primary runs commit $commit but this checkout is at $head." >&2
        echo "         A failover would run different code — check out the primary's commit here." >&2
    fi
    log "Pulled bundle created $(manifest_get "$STATE_DIR/MANIFEST" created) on $(manifest_get "$STATE_DIR/MANIFEST" source_host)."
}

cmd_status() {
    local max="${STANDBY_MAX_BUNDLE_AGE_SECONDS:-3600}" m="$STATE_DIR/MANIFEST"
    if [ ! -f "$m" ]; then
        echo "No bundle pulled from the primary yet (make standby-pull)."
        return 1
    fi
    local created age commit head rc=0
    created="$(manifest_get "$m" created_epoch)"
    commit="$(manifest_get "$m" commit)"
    head="$(git -C "$REPO_DIR" rev-parse HEAD)"
    age=$(( $(date -u +%s) - created ))
    echo "Bundle_Created:        $(manifest_get "$m" created) ($age s ago)"
    echo "Bundle_Source_Host:    $(manifest_get "$m" source_host)"
    echo "Bundle_Commit:         $commit"
    if [ "$age" -gt "$max" ]; then
        echo "STALE: the last bundle is older than ${max}s — check the standby-pull timer."
        rc=2
    fi
    if [ "$commit" != "$head" ]; then
        echo "DRIFT: the primary runs commit $commit, this checkout is at $head."
        rc=2
    fi
    [ "$rc" != 0 ] || echo "OK"
    return "$rc"
}

case "${1:-}" in
    pull) cmd_pull ;;
    status) cmd_status ;;
    *)
        echo "usage: $(basename "$0") pull | status" >&2
        exit 2 ;;
esac
