#!/usr/bin/env bash
# =====================================================================
# Build the bundle the warm standby pulls from the primary (Phase 3d
# cycle 5c). Entry point for `make standby-bundle o=FILE|-`; the
# standby runs it over SSH via `make standby-pull`.
# docs/runbooks/standby-replication.md covers the setup.
#
# The bundle is one tar holding:
#   vault.snap   raft snapshot of the RUNNING primary Vault, taken in a
#                throwaway bootstrap-app container (the entrypoint shim
#                exports the root token there; it never reaches the host)
#   files.tar    .env.prod vault-init.json tls/ — tarred from a helper
#                container, since vault-init.json and tls/ belong to the
#                container UID
#   MANIFEST     format, commit, source_host, created_epoch, created
#   SHA256SUMS   over the three files above
#
# It carries the Vault unseal keys and root token: write it only to
# stdout piped into SSH, or to a private (0600) file.
#
# With o=- the tar goes to stdout and EVERYTHING else to stderr. The
# standby reads stdout as the bundle, so a stray line there would
# corrupt it.
#
# Env (set by the Makefile; overridable for tests):
#   COMPOSE        prod compose command incl. --env-file/-f flags [required]
#   DOCKER         docker binary                       (default: docker)
#   HELPER_IMAGE   image whose tar reads the checkout  (default: alpine:3.20)
#   REPO_DIR       the checkout                        (default: $PWD)
# =====================================================================

set -euo pipefail

: "${COMPOSE:?COMPOSE must be set (run via make standby-bundle)}"
DOCKER="${DOCKER:-docker}"
HELPER_IMAGE="${HELPER_IMAGE:-alpine:3.20}"
REPO_DIR="$(cd "${REPO_DIR:-$PWD}" && pwd)"
FILES=(.env.prod vault-init.json tls)

die() { echo "ERROR: $*" >&2; exit 1; }
log() { echo "==> $*" >&2; }

# Word-splitting COMPOSE is intended: it's a command plus flags.
# shellcheck disable=SC2086
compose() { $COMPOSE "$@"; }

dest="${1:-}"
[ -n "$dest" ] || die "usage: $(basename "$0") FILE|-"

[ -s "$REPO_DIR/.env.prod" ] || die ".env.prod is missing — run this on the primary's prod checkout."
[ -d "$REPO_DIR/tls" ] || die "tls/ is missing — run this on the primary's prod checkout."
# vault-init.json may be unreadable to us (container UID, 0600), so
# test size from a helper container rather than from the host.
if ! "$DOCKER" run --rm -v "$REPO_DIR:/src:ro" "$HELPER_IMAGE" test -s /src/vault-init.json; then
    die "vault-init.json is missing or empty — without it the snapshot can't be unsealed."
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
chmod 700 "$work"

log "Taking a Vault raft snapshot..."
compose run --rm --no-deps -T \
    --entrypoint /usr/local/bin/entrypoint-wg-manager.sh bootstrap-app \
    python /app/scripts/vault_snapshot.py > "$work/vault.snap" \
    || die "the Vault snapshot failed — is the stack up and Vault unsealed? (make prod-up)"
[ -s "$work/vault.snap" ] || die "the Vault snapshot is empty."

log "Archiving ${FILES[*]}..."
"$DOCKER" run --rm -v "$REPO_DIR:/src:ro" "$HELPER_IMAGE" \
    tar -C /src --numeric-owner -cpf - "${FILES[@]}" > "$work/files.tar"

{
    echo "format=1"
    echo "commit=$(git -C "$REPO_DIR" rev-parse HEAD)"
    echo "source_host=$(hostname)"
    echo "created_epoch=$(date -u +%s)"
    echo "created=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$work/MANIFEST"
(cd "$work" && sha256sum MANIFEST vault.snap files.tar > SHA256SUMS)

if [ "$dest" = - ]; then
    tar -C "$work" -cf - MANIFEST SHA256SUMS vault.snap files.tar
else
    umask 077
    tar -C "$work" -cf "$dest.partial" MANIFEST SHA256SUMS vault.snap files.tar
    mv "$dest.partial" "$dest"
fi
log "Bundle complete."
