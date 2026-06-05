#!/usr/bin/env bash
# ===========================================================================
# Idempotent Vault init + unseal for the production prod-overlay stack.
#
# Runs from prod_bootstrap_substrate.sh BEFORE any engine bootstrap
# (PKI / SSH CA / Transit / audit) — those all need an authenticated,
# unsealed Vault client. Three states this script handles:
#
#   1. Uninitialized Vault (first-ever prod-up on this host):
#        → `vault operator init -format=json -key-shares=5
#          -key-threshold=3`
#        → write JSON output to ${VAULT_INIT_FILE} (mode 0600)
#        → unseal with the first 3 keys
#   2. Initialized + sealed (every restart of the Vault container
#      after the first prod-up):
#        → read keys from ${VAULT_INIT_FILE}
#        → unseal with the first 3 keys
#   3. Initialized + unsealed (re-run while everything's already
#      up — e.g. a second `make prod-up`):
#        → no-op, print "already unsealed"
#
# Auth: AFTER successful init or unseal, the script exports
# VAULT_TOKEN from ${VAULT_INIT_FILE}'s `root_token` field so the
# engine bootstraps that follow can authenticate.
#
# The init file path is operator-configurable via ${VAULT_INIT_FILE}
# (default /app/vault-init.json — the path the prod overlay's
# bind-mount uses). The number of shares + threshold are configurable
# via ${VAULT_KEY_SHARES} / ${VAULT_KEY_THRESHOLD} (defaults 5 / 3).
#
# Honest about the limitations:
#
#   * The unseal keys live on the operator's host filesystem next to
#     the root token. An attacker with shell access to the host can
#     unseal the entire Vault. This is the "easy to configure"
#     trade-off — every Vault knob the operator would otherwise
#     have to manage by hand (init, key distribution, unseal on
#     boot) is automated here.
#   * The real next step is cloud-KMS auto-unseal (transit /
#     awskms / gcpckms). That requires cloud credentials this work
#     can't assume operators have. Phase 2e production-Vault cycle.
# ===========================================================================

set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:?VAULT_ADDR must be set (e.g. http://vault:8200)}"
VAULT_INIT_FILE="${VAULT_INIT_FILE:-/app/vault-init.json}"
VAULT_KEY_SHARES="${VAULT_KEY_SHARES:-5}"
VAULT_KEY_THRESHOLD="${VAULT_KEY_THRESHOLD:-3}"
PYTHON="${PYTHON:-python}"

export VAULT_ADDR

# ----- Wait for Vault to be reachable (compose dep should make this
#       quick but we belt-and-suspender the network race).
echo "==> Waiting for Vault at ${VAULT_ADDR}..."
until ${PYTHON} -c "
import urllib.request, urllib.error, sys
try:
    # /v1/sys/health returns 501 (uninitialized) or 503 (sealed)
    # BEFORE returning 200 — any of those means Vault is up.
    r = urllib.request.urlopen('${VAULT_ADDR}/v1/sys/health', timeout=3)
    sys.exit(0)
except urllib.error.HTTPError as e:
    sys.exit(0 if e.code in (501, 503, 472, 473, 429) else 1)
except Exception:
    sys.exit(1)
" 2>/dev/null; do
    sleep 1
done
echo "    Vault reachable"

# ----- Probe the current state via sys/init + sys/seal-status.
#       We avoid `vault status` for parsing simplicity — the raw
#       HTTP shape is documented + stable.
state_json="$(${PYTHON} <<'PY'
import json, urllib.request, urllib.error, os, sys

VAULT_ADDR = os.environ["VAULT_ADDR"]

def get(path):
    try:
        r = urllib.request.urlopen(f"{VAULT_ADDR}{path}", timeout=5)
        return json.load(r)
    except urllib.error.HTTPError as e:
        # Vault returns 501 on /sys/init when uninitialized — body
        # is still JSON.
        return json.load(e)

init = get("/v1/sys/init")
seal = get("/v1/sys/seal-status")
print(json.dumps({
    "initialized": bool(init.get("initialized")),
    "sealed":      bool(seal.get("sealed", True)),
    "progress":    int(seal.get("progress", 0)),
    "threshold":   int(seal.get("t", 0)),
}))
PY
)"

initialized="$(echo "${state_json}" | ${PYTHON} -c 'import json,sys; print(json.load(sys.stdin)["initialized"])')"
sealed="$(echo "${state_json}" | ${PYTHON} -c 'import json,sys; print(json.load(sys.stdin)["sealed"])')"
echo "    state: initialized=${initialized} sealed=${sealed}"

# ----- State #1: Uninitialized. Run `vault operator init`. Write
#       the JSON output to ${VAULT_INIT_FILE} (umask 077 → 0600).
if [[ "${initialized}" == "False" ]]; then
    echo "==> Vault is uninitialized — running operator init (key-shares=${VAULT_KEY_SHARES}, key-threshold=${VAULT_KEY_THRESHOLD})..."
    # The HTTP API equivalent of `vault operator init -format=json`:
    # POST /v1/sys/init with the share / threshold knobs.
    umask 077
    # Quoted heredoc (`'PY'`) disables bash expansion inside the
    # body. Without this, backticks in comments would trigger
    # command substitution. We pass env values explicitly via
    # `-e`-style env, NOT via `${VAR}` interpolation.
    SECRET_SHARES="${VAULT_KEY_SHARES}" \
    SECRET_THRESHOLD="${VAULT_KEY_THRESHOLD}" \
    ${PYTHON} <<'PY' >"${VAULT_INIT_FILE}"
import json, urllib.request, os, sys

VAULT_ADDR = os.environ["VAULT_ADDR"]
body = json.dumps({
    "secret_shares":    int(os.environ["SECRET_SHARES"]),
    "secret_threshold": int(os.environ["SECRET_THRESHOLD"]),
}).encode("utf-8")
req = urllib.request.Request(
    f"{VAULT_ADDR}/v1/sys/init",
    data=body,
    method="PUT",
    headers={"Content-Type": "application/json"},
)
sys.stdout.write(urllib.request.urlopen(req, timeout=10).read().decode("utf-8"))
PY
    chmod 0600 "${VAULT_INIT_FILE}"
    # Chown to the wg-manager runtime UID (1001 from the Phase 2f
    # Dockerfile) so the api / worker / bootstrap-app entrypoint
    # shim can read it. The Makefile `touch`es vault-init.json at
    # the host operator's UID (typically 1000) which UID 1001 can't
    # read at mode 0600. This script runs as root in the prod
    # overlay (`user: "0:0"`), so it has the chown right.
    chown 1001:1001 "${VAULT_INIT_FILE}" 2>/dev/null || true
    echo "    wrote ${VAULT_INIT_FILE} (mode 0600, owner 1001:1001)"
    # After init Vault is initialized but still sealed — fall
    # through to the unseal block below.
    sealed="True"
fi

# ----- State #2: Initialized + sealed. Read unseal_keys_b64 from
#       ${VAULT_INIT_FILE} and POST each through /v1/sys/unseal
#       until threshold is met.
if [[ "${sealed}" == "True" ]]; then
    if [[ ! -f "${VAULT_INIT_FILE}" ]]; then
        echo "ERROR: Vault is sealed but ${VAULT_INIT_FILE} is missing." >&2
        echo "       Cannot recover — the unseal keys are gone. Restore" >&2
        echo "       ${VAULT_INIT_FILE} from your operator backup, or" >&2
        echo "       nuke the vault data volume to start over." >&2
        exit 1
    fi
    echo "==> Vault is sealed — unsealing from ${VAULT_INIT_FILE}..."
    # Quoted heredoc disables bash expansion (backticks in
    # comments would trigger command substitution otherwise).
    # VAULT_INIT_FILE flows in via os.environ — already exported above.
    export VAULT_INIT_FILE
    ${PYTHON} <<'PY'
import json, os, urllib.request

VAULT_ADDR = os.environ["VAULT_ADDR"]
INIT_FILE  = os.environ["VAULT_INIT_FILE"]
with open(INIT_FILE) as f:
    init = json.load(f)

# The init JSON output uses either keys_base64 (HTTP API) or
# unseal_keys_b64 (CLI -format=json). Try both.
keys = init.get("unseal_keys_b64") or init.get("keys_base64") or []
if not keys:
    raise SystemExit(
        "ERROR: no unseal keys in " + INIT_FILE
    )

# Submit each key — Vault advances unseal progress until threshold
# is met. Submitting more keys than required is benign (Vault
# returns sealed=False once threshold is reached).
for k in keys:
    body = json.dumps({"key": k}).encode("utf-8")
    req = urllib.request.Request(
        f"{VAULT_ADDR}/v1/sys/unseal",
        data=body,
        method="PUT",
        headers={"Content-Type": "application/json"},
    )
    resp = json.load(urllib.request.urlopen(req, timeout=10))
    print(f"    unseal progress={resp.get('progress', 0)} sealed={resp.get('sealed', True)}")
    if not resp.get("sealed", True):
        break
PY
    echo "    Vault unsealed"
else
    echo "==> Vault already unsealed — no-op"
fi

# ----- Re-export VAULT_TOKEN from the init file so any downstream
#       step in the same bash session inherits the root token.
#       (The entrypoint shim on api/worker/bootstrap-app does the
#       same thing for its own CMD; this is the in-script path
#       for prod_bootstrap_substrate.sh, which runs subsequent
#       engine bootstraps after this.)
if [[ -f "${VAULT_INIT_FILE}" ]]; then
    VAULT_TOKEN="$(${PYTHON} -c "
import json, sys
print(json.load(open('${VAULT_INIT_FILE}'))['root_token'])
")"
    export VAULT_TOKEN
fi

# Ensure the init file is readable by the runtime tier (UID 1001).
# Idempotent — already 1001:1001 from init time stays at 1001:1001.
if [[ -f "${VAULT_INIT_FILE}" ]]; then
    chown 1001:1001 "${VAULT_INIT_FILE}" 2>/dev/null || true
fi

echo "==> Vault init + unseal complete"
