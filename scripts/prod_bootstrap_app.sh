#!/usr/bin/env bash
# =====================================================================
# Phase 2 of the prod-overlay self-bootstrap.
#
# Runs inside the `bootstrap-app` compose service after MySQL + Valkey
# are healthy. Idempotently:
#   1. Applies Alembic migrations (`alembic upgrade head` — no-op if
#      already at head).
#   2. Registers the bootstrap operator with CN = $BOOTSTRAP_OPERATOR_CN
#      and role = $BOOTSTRAP_OPERATOR_ROLE (default `admin`). Tolerates
#      duplicate-row errors so re-runs are no-ops.
#   3. Mints the API server cert (--type api) into
#      tls/server.{crt,key} + tls/ca-bundle.crt — what uvicorn loads at
#      bind time on the api container.
#   4. Mints the operator CLI client cert (--type cli) into
#      tls/client.{crt,key} + tls/client.chain.crt — what the operator
#      uses to curl the API, and what the dashboard's BFF proxy
#      presents on behalf of the operator.
#
# After this exits 0, the api / worker / web containers start. Their
# `depends_on: bootstrap-app: service_completed_successfully` enforces
# the order.
#
# Single-tenant note: the bootstrap operator is registered as
# `admin`. Tenant rows aren't auto-created — the operator can manage
# tenants via the dashboard or `wg-manager` CLI if they want named
# tenancy boundaries.
# =====================================================================

set -euo pipefail

# ----- knobs -----
TLS_DIR="${TLS_DIR:-/app/tls}"
WG_MANAGER="${WG_MANAGER:-wg-manager}"
ALEMBIC="${ALEMBIC:-alembic}"
API_SERVER_CN="${API_SERVER_CN:-localhost}"
API_SERVER_SANS="${API_SERVER_SANS:-localhost,127.0.0.1,api}"
BOOTSTRAP_OPERATOR_ROLE="${BOOTSTRAP_OPERATOR_ROLE:-admin}"

if [[ -z "${BOOTSTRAP_OPERATOR_CN:-}" ]]; then
    echo "ERROR: BOOTSTRAP_OPERATOR_CN must be set in .env.prod" >&2
    exit 1
fi

# ----- 1. Apply Alembic migrations -----
echo "==> Applying Alembic migrations..."
cd /app
${ALEMBIC} upgrade head
echo "    Migrations at head"

# ----- 2. Register bootstrap operator (idempotent) -----
echo "==> Registering bootstrap operator CN=${BOOTSTRAP_OPERATOR_CN} role=${BOOTSTRAP_OPERATOR_ROLE}..."
# Squelch the duplicate-row error if the operator is already present.
# Re-running prod-up against an existing DB is a supported flow.
${WG_MANAGER} operators add \
    --cn "${BOOTSTRAP_OPERATOR_CN}" \
    --role "${BOOTSTRAP_OPERATOR_ROLE}" \
    2>&1 | tee /tmp/operator-add.log || true
if grep -qiE "already (exists|registered)|duplicate|UNIQUE constraint" /tmp/operator-add.log; then
    echo "    Operator already registered — skipping"
elif grep -q "registered operator" /tmp/operator-add.log; then
    echo "    Operator registered"
else
    echo "ERROR: operators add output didn't match a known shape — see /tmp/operator-add.log"
    cat /tmp/operator-add.log
    exit 1
fi

# ----- 3. Mint API server cert -----
if [[ -f "${TLS_DIR}/server.crt" && -f "${TLS_DIR}/server.key" ]]; then
    echo "==> API server cert already exists — skipping mint"
else
    echo "==> Minting API server cert (--type api, CN=${API_SERVER_CN})..."
    # Build --san flags from the comma-separated env value.
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
    test -f "${TLS_DIR}/server.crt"     || { echo "ERROR: API server cert was not written"; exit 1; }
    test -f "${TLS_DIR}/server.key"     || { echo "ERROR: API server key was not written"; exit 1; }
    test -f "${TLS_DIR}/ca-bundle.crt"  || { echo "ERROR: API CA bundle was not written"; exit 1; }
fi

# ----- 4. Mint operator CLI client cert -----
if [[ -f "${TLS_DIR}/client.crt" && -f "${TLS_DIR}/client.key" ]]; then
    echo "==> Operator client cert already exists — skipping mint"
else
    echo "==> Minting operator CLI client cert (--type cli, CN=${BOOTSTRAP_OPERATOR_CN})..."
    ${WG_MANAGER} certs issue \
        --type cli \
        --cn "${BOOTSTRAP_OPERATOR_CN}" \
        --out-cert "${TLS_DIR}/client.crt" \
        --out-key "${TLS_DIR}/client.key" \
        --out-chain "${TLS_DIR}/client.chain.crt"
    test -f "${TLS_DIR}/client.crt"         || { echo "ERROR: client cert was not written"; exit 1; }
    test -f "${TLS_DIR}/client.key"         || { echo "ERROR: client key was not written"; exit 1; }
    test -f "${TLS_DIR}/client.chain.crt"   || { echo "ERROR: client CA chain was not written"; exit 1; }
fi

# ----- 5. Hand outputs off to the runtime tier -----
# Same reasoning as Phase 1: container runs as root for portable
# write access; runtime tier reads as `wgmanager` (UID 1001).
# Keys → 0644 so non-1001 container UIDs (the mysql image's 999)
# can read them when they walk the bind-mounted tree.
echo "==> Chowning ${TLS_DIR} to wgmanager (1001:1001) for the runtime tier..."
chown -R 1001:1001 "${TLS_DIR}"
echo "==> Setting key file modes to 0644 so non-1001 container UIDs can read..."
find "${TLS_DIR}" -type f -name "*.key" -exec chmod 0644 {} \;

echo "==> Phase 2 (app bootstrap) complete"
