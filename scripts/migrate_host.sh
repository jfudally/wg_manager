#!/usr/bin/env bash
# =====================================================================
# Move the single-host prod stack to a new host without losing data.
# Entry point for ``make host-export`` / ``make host-import`` /
# ``make db-counts``; the procedure is docs/runbooks/host-migration.md.
#
# Why a cold volume copy: Vault runs ``storage "file"`` (no raft
# snapshots), and the encrypted DB dump can only be unwrapped by *this*
# Vault's Transit key. So the only lossless move is a byte-for-byte copy
# of the stopped volumes plus the operator files that unlock them.
#
#   export DIR   Source host, stack stopped. Writes into DIR:
#                  volumes/<key>.tar   one per stateful volume
#                  files.tar           .env.prod vault-init.json tls/ [backups/]
#                  MANIFEST            git commit, compose project, image digests
#                  SHA256SUMS
#   import DIR   Target host, same commit, nothing running. Verifies the
#                bundle, refuses to overwrite existing state, then recreates
#                the volumes (with Compose labels) and unpacks the files.
#   counts       Exact per-table row counts, for a before/after diff.
#
# Env (set by the Makefile; overridable for tests):
#   COMPOSE_BASE   compose command + -f flags, WITHOUT --env-file  [required]
#   ENV_FILE       env file for compose  (default: $REPO_DIR/.env.prod; import
#                  uses the bundle's copy, since the target has none yet)
#   DOCKER         docker binary                     (default: docker)
#   REPO_DIR       the checkout holding .env.prod    (default: $PWD)
#   HELPER_IMAGE   image whose tar does the copying  (default: alpine:3.20)
#   MIGRATE_ALLOW_COMMIT_MISMATCH=1   import onto a different commit
# =====================================================================

set -euo pipefail

: "${COMPOSE_BASE:?COMPOSE_BASE must be set (run via make host-export / host-import)}"
DOCKER="${DOCKER:-docker}"
REPO_DIR="$(cd "${REPO_DIR:-$PWD}" && pwd)"
ENV_FILE="${ENV_FILE:-$REPO_DIR/.env.prod}"
HELPER_IMAGE="${HELPER_IMAGE:-alpine:3.20}"

# Every volume key in the compose config must be in exactly one list, so
# a volume added later fails the export loudly instead of being left
# behind on the old host.
MIGRATE_VOLUMES=(wg_manager_mysql_data wg_manager_vault_data wg_manager_vault_audit_logs)
# Valkey holds only the Celery queue; drained before export, rebuilt empty.
SKIP_VOLUMES=(wg_manager_valkey_data)

# Operator files in the checkout. .env.prod and vault-init.json are
# files; tls is a directory; backups is optional.
REQUIRED_FILES=(.env.prod vault-init.json tls)
OPTIONAL_FILES=(backups)

die() { echo "ERROR: $*" >&2; exit 1; }
log() { echo "==> $*"; }

usage() {
    cat >&2 <<EOF
usage: $(basename "$0") export DIR | import DIR | counts
See docs/runbooks/host-migration.md.
EOF
    exit 2
}

# Word-splitting COMPOSE_BASE is intended: it's a command plus flags.
# shellcheck disable=SC2086
compose() { $COMPOSE_BASE --env-file "$ENV_FILE" "$@"; }

# Print "<field>" of the compose config: `project`, `volumes`
# (key<TAB>name lines) or `images` (registry images: any image a service
# builds locally is excluded, even where another service reuses it).
compose_query() {
    compose config --format json | python3 -c '
import json, sys
cfg = json.load(sys.stdin)
field = sys.argv[1]
if field == "project":
    print(cfg["name"])
elif field == "volumes":
    for key, spec in cfg.get("volumes", {}).items():
        print(key + "\t" + spec.get("name", key))
elif field == "images":
    services = cfg.get("services", {}).values()
    built = {svc.get("image") for svc in services if "build" in svc}
    seen = set()
    for svc in services:
        img = svc.get("image")
        if img and img not in built and img not in seen:
            seen.add(img)
            print(img)
' "$1"
}

# Refuse to run against a live stack: copying MySQL's datadir or Vault's
# file storage while they write can produce a torn copy.
require_stack_stopped() {
    local running
    running="$(compose ps -q)"
    if [ -n "$running" ]; then
        die "the prod stack is still running — run 'make prod-down' first (NOT 'down -v')."
    fi
}

# Map each volume key to its on-host name, and fail on any volume that
# is neither migrated nor explicitly skipped. Sets VOLUME_NAME[key].
declare -A VOLUME_NAME
resolve_volumes() {
    local key name known listing
    # Captured first: a failure inside `< <(...)` would be silently ignored.
    listing="$(compose_query volumes)"
    while IFS=$'\t' read -r key name; do
        [ -n "$key" ] || continue
        known=0
        for k in "${MIGRATE_VOLUMES[@]}" "${SKIP_VOLUMES[@]}"; do
            [ "$k" = "$key" ] && known=1
        done
        [ "$known" = 1 ] || die "compose volume '$key' is not classified in scripts/migrate_host.sh (MIGRATE_VOLUMES or SKIP_VOLUMES)."
        VOLUME_NAME[$key]="$name"
    done <<< "$listing"
    for k in "${MIGRATE_VOLUMES[@]}"; do
        [ -n "${VOLUME_NAME[$k]:-}" ] || die "compose config does not declare volume '$k'."
    done
}

volume_exists() { "$DOCKER" volume inspect "$1" >/dev/null 2>&1; }

# Print the first file under REPO_DIR/$1 that git doesn't track, i.e.
# deployment state; print nothing if there is none. A fresh clone's tls/
# holds only the committed tls/mysql/.gitkeep, which is not state.
first_state_file() {
    local path="$REPO_DIR/$1" f rel
    [ -e "$path" ] || return 0
    while IFS= read -r -d '' f; do
        rel="${f#"$REPO_DIR"/}"
        if ! git -C "$REPO_DIR" ls-files --error-unmatch -- "$rel" >/dev/null 2>&1; then
            echo "$rel"
            return 0
        fi
    done < <(find "$path" -type f -print0)
}

# ---------------------------------------------------------------------
# export
# ---------------------------------------------------------------------
cmd_export() {
    local out="${1:-}"
    [ -n "$out" ] || usage

    require_stack_stopped

    if [ -d "$out" ] && [ -n "$(ls -A "$out")" ]; then
        die "output directory '$out' is not empty."
    fi

    # vault-init.json is owned by the container user (0600), so only
    # existence and size are checked from here — both need no read access.
    [ -f "$REPO_DIR/.env.prod" ] || die ".env.prod not found in $REPO_DIR."
    [ -s "$REPO_DIR/vault-init.json" ] || die "vault-init.json in $REPO_DIR is missing or empty — Vault was never initialised here."
    [ -d "$REPO_DIR/tls" ] || die "tls/ not found in $REPO_DIR."

    resolve_volumes
    local key
    for key in "${MIGRATE_VOLUMES[@]}"; do
        volume_exists "${VOLUME_NAME[$key]}" || die "docker volume '${VOLUME_NAME[$key]}' ($key) does not exist."
    done

    # The bundle holds unseal keys and every password: private from birth.
    umask 077
    mkdir -p "$out/volumes"
    chmod 700 "$out"
    out="$(cd "$out" && pwd)"

    for key in "${MIGRATE_VOLUMES[@]}"; do
        log "Archiving volume ${VOLUME_NAME[$key]}"
        "$DOCKER" run --rm -v "${VOLUME_NAME[$key]}:/v:ro" "$HELPER_IMAGE" \
            tar -C /v --numeric-owner -cpf - . > "$out/volumes/$key.tar"
    done

    # Tar the operator files from inside a container: vault-init.json and
    # tls/ belong to the container UID, so the operator can't read them.
    local files=("${REQUIRED_FILES[@]}") f
    for f in "${OPTIONAL_FILES[@]}"; do
        [ -e "$REPO_DIR/$f" ] && files+=("$f")
    done
    log "Archiving ${files[*]}"
    "$DOCKER" run --rm -v "$REPO_DIR:/src:ro" "$HELPER_IMAGE" \
        tar -C /src --numeric-owner -cpf - "${files[@]}" > "$out/files.tar"

    {
        echo "commit=$(git -C "$REPO_DIR" rev-parse HEAD)"
        echo "dirty=$([ -n "$(git -C "$REPO_DIR" status --porcelain)" ] && echo yes || echo no)"
        echo "project=$(compose_query project)"
        echo "source_host=$(hostname)"
        echo "created=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "volumes=${MIGRATE_VOLUMES[*]}"
        # Pin these on the target: the base compose uses floating tags
        # (mysql:8), and a different MySQL minor must not open this datadir.
        local img digest images
        images="$(compose_query images)"
        while read -r img; do
            [ -n "$img" ] || continue
            # An image that isn't pulled locally has no digest to record.
            digest="$("$DOCKER" image inspect --format '{{index .RepoDigests 0}}' "$img" 2>/dev/null | tr -d '[:space:]')" || digest=""
            echo "image $img ${digest:-unknown}"
        done <<< "$images"
    } > "$out/MANIFEST"

    (cd "$out" && sha256sum MANIFEST files.tar volumes/*.tar > SHA256SUMS)

    log "Bundle written to $out"
    log "It contains the Vault unseal keys — move it only over an encrypted channel (rsync -a over ssh)."
}

# ---------------------------------------------------------------------
# import
# ---------------------------------------------------------------------
cmd_import() {
    local in="${1:-}"
    [ -n "$in" ] || usage
    [ -d "$in" ] || die "bundle directory '$in' not found."
    in="$(cd "$in" && pwd)"

    log "Verifying checksums"
    (cd "$in" && sha256sum --quiet -c SHA256SUMS) \
        || die "checksum verification failed — the bundle is incomplete or corrupted; re-copy it."

    # The target has no .env.prod yet (and must not: see below), so compose
    # is resolved with the bundle's copy, from a private temp file.
    local envdir
    envdir="$(mktemp -d)"
    # shellcheck disable=SC2064  # expand now: envdir is local to this function
    trap "rm -rf '$envdir'" EXIT
    tar -xOf "$in/files.tar" .env.prod > "$envdir/env.prod" \
        || die "bundle files.tar has no .env.prod."
    ENV_FILE="$envdir/env.prod"

    require_stack_stopped

    local manifest_commit head
    manifest_commit="$(sed -n 's/^commit=//p' "$in/MANIFEST")"
    head="$(git -C "$REPO_DIR" rev-parse HEAD)"
    if [ "$manifest_commit" != "$head" ] && [ "${MIGRATE_ALLOW_COMMIT_MISMATCH:-}" != 1 ]; then
        die "bundle was exported at commit $manifest_commit but this checkout is at $head. Check out the same commit (or set MIGRATE_ALLOW_COMMIT_MISMATCH=1)."
    fi

    # Volume names derive from the compose project (the checkout's dir
    # name). A mismatch would restore into volumes prod-up never mounts,
    # and prod-up would then initialise a brand-new, empty Vault.
    local want_project have_project
    want_project="$(sed -n 's/^project=//p' "$in/MANIFEST")"
    have_project="$(compose_query project)"
    [ "$want_project" = "$have_project" ] \
        || die "compose project is '$have_project' but the bundle came from '$want_project' — clone into a directory named '$want_project'."

    local f found
    for f in "${REQUIRED_FILES[@]}" "${OPTIONAL_FILES[@]}"; do
        found="$(first_state_file "$f")"
        [ -z "$found" ] || die "$found already exists in $REPO_DIR — refusing to overwrite. Move it aside first."
    done

    resolve_volumes
    local key
    for key in "${MIGRATE_VOLUMES[@]}"; do
        volume_exists "${VOLUME_NAME[$key]}" \
            && die "docker volume '${VOLUME_NAME[$key]}' ($key) already exists — refusing to overwrite. Remove it only if you are sure it is not live state."
        [ -f "$in/volumes/$key.tar" ] || die "bundle is missing volumes/$key.tar."
    done

    for key in "${MIGRATE_VOLUMES[@]}"; do
        log "Restoring volume ${VOLUME_NAME[$key]}"
        # Compose labels make `prod-up` adopt the volume as its own.
        "$DOCKER" volume create \
            --label "com.docker.compose.project=$have_project" \
            --label "com.docker.compose.volume=$key" \
            "${VOLUME_NAME[$key]}" >/dev/null
        "$DOCKER" run --rm -i -v "${VOLUME_NAME[$key]}:/v" "$HELPER_IMAGE" \
            tar -C /v --numeric-owner -xpf - < "$in/volumes/$key.tar"
    done

    log "Restoring operator files into $REPO_DIR"
    "$DOCKER" run --rm -i -v "$REPO_DIR:/dst" "$HELPER_IMAGE" \
        tar -C /dst --numeric-owner -xpf - < "$in/files.tar"

    log "Import complete. Next: pin images per MANIFEST, then 'make prod-up' (see the runbook)."
}

# ---------------------------------------------------------------------
# counts
# ---------------------------------------------------------------------
cmd_counts() {
    # Runs inside the mysql container over the local socket, which
    # satisfies require_secure_transport. Builds one exact COUNT(*) per
    # base table (information_schema.table_rows is only an estimate).
    # A quoted heredoc keeps $MYSQL_* unexpanded until they reach the
    # container's shell, where the mysql image defines them.
    compose exec -T mysql sh -s <<'EOF'
export MYSQL_PWD="$MYSQL_ROOT_PASSWORD"
db="${MYSQL_DATABASE:-wg_manager}"
tables=$(mysql -uroot -N -B -e "SELECT table_name FROM information_schema.tables WHERE table_schema = '$db' AND table_type = 'BASE TABLE' ORDER BY table_name")
for t in $tables; do
    printf '%s\t%s\n' "$t" "$(mysql -uroot -N -B "$db" -e "SELECT COUNT(*) FROM \`$t\`")"
done
EOF
}

case "${1:-}" in
    export) shift; cmd_export "$@" ;;
    import) shift; cmd_import "$@" ;;
    counts) shift; cmd_counts ;;
    *) usage ;;
esac
