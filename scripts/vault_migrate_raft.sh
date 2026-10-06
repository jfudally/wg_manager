#!/usr/bin/env bash
# =====================================================================
# One-shot, offline conversion of the prod Vault from file storage to
# raft storage. Entry point for ``make vault-migrate-raft``; the
# procedure (and rollback) is docs/runbooks/vault-raft-migration.md.
#
# Why: the warm standby (Phase 3d cycle 5) stays current by restoring
# raft snapshots, and file storage can't produce them.
#
# What it does, in order — any refusal exits non-zero before anything
# is written:
#   1. Refuse if the `vault` service is running (migrating a live
#      storage backend can tear it).
#   2. Refuse if the raft volume already holds data (never clobber an
#      already-migrated or freshly initialised Vault).
#   3. Refuse if there is no file-storage data (nothing to migrate —
#      a fresh host just runs `make prod-up`).
#   4. Run `vault operator migrate` with docker/vault/migrate-raft.hcl
#      in a one-off container of the `vault` service, so both volumes
#      are mounted exactly as the server sees them.
#
# The file volume is only read. The unseal keys and root token in
# vault-init.json are unchanged, because the migration copies the
# encrypted entries verbatim.
#
# Env (set by the Makefile; overridable for tests):
#   COMPOSE_BASE   compose command + -f flags, WITHOUT --env-file  [required]
#   REPO_DIR       the checkout holding .env.prod      (default: $PWD)
#   ENV_FILE       env file for compose  (default: $REPO_DIR/.env.prod)
# =====================================================================

set -euo pipefail

: "${COMPOSE_BASE:?COMPOSE_BASE must be set (run via make vault-migrate-raft)}"
REPO_DIR="$(cd "${REPO_DIR:-$PWD}" && pwd)"
ENV_FILE="${ENV_FILE:-$REPO_DIR/.env.prod}"
MIGRATE_HCL="$REPO_DIR/docker/vault/migrate-raft.hcl"

die() { echo "ERROR: $*" >&2; exit 1; }
log() { echo "==> $*"; }

# Word-splitting COMPOSE_BASE is intended: it's a command plus flags.
# shellcheck disable=SC2086
compose() { $COMPOSE_BASE --env-file "$ENV_FILE" "$@"; }

# Run a shell snippet in a throwaway container of the vault service.
# --no-deps keeps bootstrap-substrate & friends from starting.
vault_sh() { compose run --rm --no-deps -T --entrypoint sh vault -c "$1"; }

[ -f "$ENV_FILE" ] || die "$ENV_FILE is missing — run this from the prod checkout."

log "Checking the vault service is stopped..."
if [ -n "$(compose ps -q vault)" ]; then
    die "the vault service is running — run 'make prod-down' first (NOT 'down -v')."
fi

# Start a throwaway Vault server on the raft volume (no ports published)
# and print `initialized=true|false|unknown`. Needed because ANY boot on
# raft — even one that never gets initialized — writes vault.db/raft.db,
# so "non-empty" alone can't tell a migrated Vault from leftovers.
# The $ expressions must expand inside the container, not here.
# shellcheck disable=SC2016
RAFT_PROBE='
vault server -config=/vault/config/vault.hcl >/tmp/probe.log 2>&1 &
pid=$!
state=unknown
for _ in $(seq 1 30); do
    out="$(VAULT_ADDR=http://127.0.0.1:8200 vault status -format=json 2>/dev/null)"
    case "$out" in
        *"\"initialized\": true"*) state=true; break ;;
        *"\"initialized\": false"*) state=false; break ;;
    esac
    sleep 1
done
kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
echo "initialized=$state"
'

log "Checking the raft volume is empty..."
raft_contents="$(vault_sh 'ls -A /vault/raft')"
if [ -n "$raft_contents" ]; then
    log "The raft volume holds data; probing whether it is an initialized Vault..."
    probe="$(vault_sh "$RAFT_PROBE" | tail -n 1)"
    case "$probe" in
        initialized=true)
            die "the raft volume already holds an initialized Vault — this host is already on raft. Nothing to do." ;;
        initialized=false)
            # Left by a `make prod-up` that ran before this migration:
            # Vault started on the empty volume, the init guard in
            # vault_init_unseal.sh refused to initialize it, and it
            # holds no keys and no data. Safe to clear.
            log "It is an UNINITIALIZED Vault (left by a prod-up before migrating) — clearing it."
            vault_sh 'rm -rf /vault/raft/* /vault/raft/.[!.]*' ;;
        *)
            die "could not tell whether the raft volume holds an initialized Vault ($probe). Not touching it — inspect it by hand (runbook: Troubleshooting)." ;;
    esac
fi

log "Checking there is file-storage data to migrate..."
if ! vault_sh 'test -d /vault/file/core'; then
    die "no file-storage data at /vault/file — nothing to migrate. A fresh host just runs 'make prod-up'."
fi

log "Migrating file storage -> raft storage..."
compose run --rm --no-deps -T \
    -v "$MIGRATE_HCL:/vault/config/migrate-raft.hcl:ro" \
    --entrypoint vault vault \
    operator migrate -config=/vault/config/migrate-raft.hcl

log "Migration complete. The old file storage is untouched (rollback copy)."
cat <<'EOF'

Next steps:
  1. make prod-up        # boots Vault on raft and unseals it from vault-init.json
  2. Verify (runbook step 5): raft list-peers shows one voter, and
     /readyz + an SSH-CA mint succeed.
EOF
