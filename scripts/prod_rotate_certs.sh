#!/usr/bin/env bash
# =====================================================================
# Cert-rotation orchestrator for the single-host prod stack.
#
# Runs inside a `docker compose run --rm bootstrap-app` — same image
# as `prod_bootstrap_app.sh` so the wg-manager entrypoint shim sources
# ``VAULT_TOKEN`` from the bind-mounted ``vault-init.json`` before we
# start. Re-mints the three cert families the prod stack loads from
# ``tls/``:
#
#   1. MySQL server + client leaves (``tls/mysql/*``) — via
#      ``bootstrap_mysql_tls_files.py``. Direct-to-Vault mint that
#      writes PKCS#8-encoded EC keys so MySQL 8.4 loads them cleanly.
#   2. API server cert (``tls/server.{crt,key}`` + ``tls/ca-bundle.crt``)
#      — through ``wg-manager certs issue --type api``. Writes an
#      audit row to the ``certificate`` table.
#   3. Operator CLI client cert (``tls/client.{crt,key}`` +
#      ``tls/client.chain.crt``) — through ``wg-manager certs issue
#      --type cli``. Also audit-logged.
#
# Ordering matters *only* when the current MySQL certs are already
# expired (which breaks the DB connection the `certs issue` CLI
# needs for audit-row writes). If that's the case, run
# ``bootstrap_mysql_tls_files.py`` by hand first and restart mysql
# on the host, then invoke this script; the prod-up recipe already
# knows how to unstick that flow.
#
# The host-side ``make certs-rotate`` wrapper is responsible for
# restarting ``mysql``, ``api``, ``worker``, and ``web`` after this
# script exits — those processes each load cert material at startup
# and won't see the fresh files until they're bounced.
# =====================================================================

set -euo pipefail

# ----- knobs (mirror prod_bootstrap_app.sh so the two scripts agree) -----
TLS_DIR="${TLS_DIR:-/app/tls}"
WG_MANAGER="${WG_MANAGER:-wg-manager}"
API_SERVER_CN="${API_SERVER_CN:-localhost}"
API_SERVER_SANS="${API_SERVER_SANS:-localhost,127.0.0.1,api}"

if [[ -z "${BOOTSTRAP_OPERATOR_CN:-}" ]]; then
    echo "ERROR: BOOTSTRAP_OPERATOR_CN must be set in .env.prod — " \
         "the operator CLI client cert's CN is derived from it." >&2
    exit 1
fi

cd /app

# ----- 1. MySQL server + client (direct-to-Vault, no DB needed) -----
echo "==> Rotating MySQL server + client certs ..."
python /app/scripts/bootstrap_mysql_tls_files.py

# ----- 2. API server cert (wg-manager CLI; writes audit row) -----
echo "==> Rotating API server cert (--type api, CN=${API_SERVER_CN}) ..."
SAN_FLAGS=()
IFS=',' read -ra _sans <<< "${API_SERVER_SANS}"
for s in "${_sans[@]}"; do
    SAN_FLAGS+=(--san "${s}")
done
${WG_MANAGER} certs issue \
    --type api \
    --cn "${API_SERVER_CN}" \
    "${SAN_FLAGS[@]}" \
    --out-cert "${TLS_DIR}/server.crt" \
    --out-key "${TLS_DIR}/server.key" \
    --out-chain "${TLS_DIR}/ca-bundle.crt"

# ----- 3. Operator CLI client cert (wg-manager CLI; audit row) -----
echo "==> Rotating operator CLI client cert (--type cli, CN=${BOOTSTRAP_OPERATOR_CN}) ..."
${WG_MANAGER} certs issue \
    --type cli \
    --cn "${BOOTSTRAP_OPERATOR_CN}" \
    --out-cert "${TLS_DIR}/client.crt" \
    --out-key "${TLS_DIR}/client.key" \
    --out-chain "${TLS_DIR}/client.chain.crt"

# ----- 4. Hand outputs off to the runtime tier -----
# Same rationale as prod_bootstrap_app.sh: this container runs as
# root for portable bind-mount write access, but the api / worker /
# web containers read as `wgmanager` (UID 1001). Keys widen to 0644
# so mysqld's UID 999 can still read them.
echo "==> Chowning ${TLS_DIR} to wgmanager (1001:1001) ..."
chown -R 1001:1001 "${TLS_DIR}"
echo "==> Widening *.key modes to 0644 so non-1001 container UIDs can read ..."
find "${TLS_DIR}" -type f -name "*.key" -exec chmod 0644 {} \;

# shellcheck disable=SC2016  # the backticks are literal text, not a command
echo '==> Rotation complete. `make certs-rotate` will now restart the runtime tier.'
