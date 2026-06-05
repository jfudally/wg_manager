#!/usr/bin/env sh
# ===========================================================================
# Entrypoint shim for the wg-manager image.
#
# Sits between Compose's CMD and the actual wg-manager process. Its
# only job: read the root token from ${VAULT_INIT_FILE} (default
# /app/vault-init.json — the prod overlay bind-mounts the file into
# every wg-manager container) and export it as VAULT_TOKEN BEFORE
# exec'ing the real CMD.
#
# Without this shim, every wg-manager container would need
# VAULT_TOKEN baked in at compose-evaluation time. With production-
# mode Vault that token is generated at `vault operator init`
# (NOT operator-provided), so Compose has no value to interpolate
# at `compose up` parse time. The shim resolves the value at
# container-start time instead — AFTER bootstrap-substrate has
# written vault-init.json.
#
# First-boot tolerance: if the file doesn't exist yet (the very
# first prod-up, bootstrap-substrate hasn't run yet), the shim
# does nothing and lets the downstream CMD handle the gap.
# Bootstrap-substrate is the only consumer that runs against an
# uninitialized Vault, and `scripts/vault_init_unseal.sh` does
# its own token sourcing in-script — so the missing-token case
# is harmless there.
# ===========================================================================

set -e

VAULT_INIT_FILE="${VAULT_INIT_FILE:-/app/vault-init.json}"

if [ -f "${VAULT_INIT_FILE}" ] && [ -s "${VAULT_INIT_FILE}" ]; then
    # `root_token` is the canonical field in `vault operator init
    # -format=json` output. We use python (always on PATH in the
    # wg-manager image) rather than jq to avoid an extra runtime
    # dep. `-s` (non-empty) plus a try/except keeps first-boot
    # tolerant: on the very first prod-up the file exists (Makefile
    # touched it so the bind-mount target is a file not a directory)
    # but is empty until bootstrap-substrate populates it. We
    # tolerate the empty case so the shim can still chain to the
    # CMD without crashing.
    _token="$(python -c "
import json, sys
try:
    print(json.load(open('${VAULT_INIT_FILE}'))['root_token'])
except (json.JSONDecodeError, KeyError):
    sys.exit(0)
" 2>/dev/null || true)"
    if [ -n "${_token}" ]; then
        VAULT_TOKEN="${_token}"
        export VAULT_TOKEN
    fi
fi

# Hand off to the real CMD as PID 1 (exec). This is what makes
# `docker stop` SIGTERM reach the wg-manager process directly
# instead of getting absorbed by the shim.
exec "$@"
