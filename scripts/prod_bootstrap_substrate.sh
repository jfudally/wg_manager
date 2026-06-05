#!/usr/bin/env bash
# =====================================================================
# Phase 1 of the prod-overlay self-bootstrap.
#
# Runs inside the `bootstrap-substrate` compose service after Vault is
# healthy. Idempotently:
#   1. Bootstraps Vault PKI / SSH CA / audit (each script is idempotent
#      on its own; re-runs against a configured Vault are no-ops).
#   2. Mints the MySQL server cert (CN=localhost, SANs cover the
#      compose-network DNS names) into tls/mysql/server.{crt,key} +
#      tls/mysql/ca.crt.
#   3. Mints the MySQL client cert (--type mysql-client so the EKU is
#      clientAuth — NOT --type mysql which would be serverAuth and
#      get rejected on the client side) into
#      tls/mysql/client.{crt,key} + tls/mysql/client-ca.crt.
#
# After this script exits 0, the `mysql` and `valkey` containers start
# (their `depends_on: bootstrap-substrate: service_completed_successfully`
# enforces the order). Phase 2 (`bootstrap-app`) follows once mysql +
# valkey are healthy.
#
# Audit-row write failures during cert mints are EXPECTED here because
# MySQL isn't up yet — the file outputs are still produced (Phase 2d
# CP4.3 writes files before the audit row). Phase 2 will record the
# audit rows for the certs it mints once MySQL is reachable.
# =====================================================================

set -euo pipefail

# ----- knobs -----
TLS_DIR="${TLS_DIR:-/app/tls}"
MYSQL_CERT_CN="${MYSQL_CERT_CN:-localhost}"
MYSQL_CLIENT_CN="${MYSQL_CLIENT_CN:-wg-manager-app}"
SCRIPT_DIR="${SCRIPT_DIR:-/app/scripts}"
PYTHON="${PYTHON:-python}"
WG_MANAGER="${WG_MANAGER:-wg-manager}"

mkdir -p "${TLS_DIR}/mysql"

# ----- 1. Wait for Vault (compose dep should make this trivial) -----
echo "==> Waiting for Vault at ${VAULT_ADDR}..."
until ${PYTHON} -c "
import urllib.request, sys
try:
    r = urllib.request.urlopen('${VAULT_ADDR}/v1/sys/health', timeout=3)
    sys.exit(0 if r.status in (200, 429, 472, 473) else 1)
except Exception:
    sys.exit(1)
" 2>/dev/null; do
    sleep 1
done
echo "    Vault reachable"

# ----- 2. Bootstrap Vault substrate (idempotent) -----
echo "==> Bootstrapping Vault PKI..."
${PYTHON} "${SCRIPT_DIR}/pki_bootstrap.py"
echo "==> Bootstrapping Vault SSH CA..."
${PYTHON} "${SCRIPT_DIR}/ssh_ca_bootstrap.py"
echo "==> Bootstrapping Vault audit device..."
${PYTHON} "${SCRIPT_DIR}/vault_audit_bootstrap.py"

# ----- 3. Mint MySQL server cert (skip if already present) -----
if [[ -f "${TLS_DIR}/mysql/server.crt" && -f "${TLS_DIR}/mysql/server.key" ]]; then
    echo "==> MySQL server cert already exists at ${TLS_DIR}/mysql/server.crt — skipping mint"
else
    echo "==> Minting MySQL server cert (--type mysql, CN=${MYSQL_CERT_CN})..."
    # `|| true` because the audit-row insert FAILS here (MySQL isn't up
    # yet) but the file writes complete first. Phase 2 backfills the
    # audit row by re-issuing if needed.
    ${WG_MANAGER} certs issue \
        --type mysql \
        --cn "${MYSQL_CERT_CN}" \
        --san localhost --san 127.0.0.1 --san mysql --san wg_manager_mysql \
        --ttl-days 30 \
        --out-cert "${TLS_DIR}/mysql/server.crt" \
        --out-key "${TLS_DIR}/mysql/server.key" \
        --out-chain "${TLS_DIR}/mysql/ca.crt" \
        2>&1 | grep -v "Background on this error\|sqlalche.me\|OperationalError\|Connection refused\|MySQL server" || true
    # File-existence check: if these are missing, the PKI mint truly
    # failed and we should not let the stack continue.
    test -f "${TLS_DIR}/mysql/server.crt" || { echo "ERROR: MySQL server cert was not written"; exit 1; }
    test -f "${TLS_DIR}/mysql/server.key" || { echo "ERROR: MySQL server key was not written"; exit 1; }
    test -f "${TLS_DIR}/mysql/ca.crt"     || { echo "ERROR: MySQL CA chain was not written"; exit 1; }
fi

# ----- 4. Mint MySQL CLIENT cert (--type mysql-client, clientAuth EKU) -----
if [[ -f "${TLS_DIR}/mysql/client.crt" && -f "${TLS_DIR}/mysql/client.key" ]]; then
    echo "==> MySQL client cert already exists — skipping mint"
else
    echo "==> Minting MySQL client cert (--type mysql-client, CN=${MYSQL_CLIENT_CN})..."
    ${WG_MANAGER} certs issue \
        --type mysql-client \
        --cn "${MYSQL_CLIENT_CN}" \
        --out-cert "${TLS_DIR}/mysql/client.crt" \
        --out-key "${TLS_DIR}/mysql/client.key" \
        --out-chain "${TLS_DIR}/mysql/client-ca.crt" \
        2>&1 | grep -v "Background on this error\|sqlalche.me\|OperationalError\|Connection refused\|MySQL server" || true
    test -f "${TLS_DIR}/mysql/client.crt"     || { echo "ERROR: MySQL client cert was not written"; exit 1; }
    test -f "${TLS_DIR}/mysql/client.key"     || { echo "ERROR: MySQL client key was not written"; exit 1; }
    test -f "${TLS_DIR}/mysql/client-ca.crt"  || { echo "ERROR: MySQL client CA chain was not written"; exit 1; }
fi

# ----- 5. Hand outputs off to the runtime tier -----
#
# This is the trickiest part of the cross-host story. The bootstrap
# container runs as root (so the bind-mounted ./tls is writable on
# Linux hosts where the operator's UID != 1001). But the downstream
# consumers run as DIFFERENT non-root UIDs in different containers:
#
#   * wg-manager (api / worker / web) → UID 1001 (`wgmanager` in the
#     Phase 2f Dockerfile)
#   * mysql:8                          → UID 999 (`mysql` in the
#     mysql:8 image)
#
# Both need to read tls/mysql/server.{crt,key} + tls/mysql/ca.crt
# (mysql reads the server side; the apps re-use the chain). And
# both need to read the cert pairs in their own paths. The cleanest
# portable fix that doesn't bake a `mysql:999` magic number into
# this script: chown to 1001:1001 for ergonomic ownership and chmod
# **keys** to 0644 so any container UID can read them.
#
# Security: 0644 on private keys is acceptable here because the
# enclosing ./tls directory itself is what gates host-side access —
# operators on a shared host should `chmod 700 ./tls` to keep
# non-operator users out. The runbook calls this out explicitly.
echo "==> Chowning ${TLS_DIR} to wgmanager (1001:1001) for the runtime tier..."
chown -R 1001:1001 "${TLS_DIR}"
echo "==> Setting key file modes to 0644 so non-1001 container UIDs (mysql=999) can read..."
find "${TLS_DIR}" -type f -name "*.key" -exec chmod 0644 {} \;

echo "==> Phase 1 (substrate bootstrap) complete"
