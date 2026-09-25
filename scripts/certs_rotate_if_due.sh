#!/usr/bin/env bash
# =====================================================================
# Rotate the prod TLS certs only when one is due. Entry point for
# ``make certs-rotate-if-due``, which a host-side systemd timer runs
# hourly (docs/deploy/systemd-timer.md).
#
# 1. ``scripts/certs_due.py`` checks the leaves ``make certs-rotate``
#    rewrites, inside a throwaway ``bootstrap-app`` container
#    (``--no-deps``: reading PEM files needs no DB / Vault / Valkey).
# 2. Exit 0  → nothing to do.
#    Exit 10 → ``make certs-rotate`` (re-mint + restart the runtime tier).
#    Anything else → the check failed (or compose did); exit non-zero
#    WITHOUT rotating so the timer unit shows failed and someone looks.
#
# Env (set by the Makefile; overridable for tests):
#   PROD_COMPOSE  compose command incl. --env-file / -f flags
#   MAKE          make binary
# =====================================================================

set -uo pipefail

: "${PROD_COMPOSE:?PROD_COMPOSE must be set (run via make certs-rotate-if-due)}"
MAKE="${MAKE:-make}"

# Word-splitting PROD_COMPOSE is intended: it's a command plus flags.
# shellcheck disable=SC2086
$PROD_COMPOSE run --rm --no-deps --entrypoint /app/.venv/bin/python \
    bootstrap-app /app/scripts/certs_due.py
status=$?

case "$status" in
    0)
        echo "==> No certs due for rotation."
        ;;
    10)
        echo "==> Certs due — running make certs-rotate ..."
        exec "$MAKE" certs-rotate
        ;;
    *)
        echo "ERROR: cert check failed (exit ${status}); NOT rotating." >&2
        exit 1
        ;;
esac
