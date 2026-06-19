#!/usr/bin/env bash
#
# wg_bootstrap.sh — VPN-first node bootstrap for the wg_manager fleet.
#
# Replaces the old `wg_node` Cinc cookbook. The cookbook brought a node
# onto the VPN *by converging against the Cinc server first*, which forced
# the Cinc server to be reachable before the node had any VPN connectivity
# — i.e. public-facing. This script flips the order:
#
#   1. `vpn`  — join the node to the WireGuard VPN by calling the wg_manager
#               control plane directly (POST /<ver>/clients/manual, mTLS),
#               pushing the returned wg0.conf to the node and bringing the
#               tunnel up. No Cinc involved.
#   2. `cinc` — bootstrap the node into Cinc with `knife bootstrap`, dialed
#               over the now-up VPN. Because node→Cinc-server traffic rides
#               the tunnel, the Cinc server can stay VPN-only / private.
#   3. `all`  — run `vpn`, capture the assigned VPN IP, then `cinc` against it.
#
# This runs on the operator workstation (the orchestrator) and drives a
# remote node over SSH. It is intentionally pure bash + curl + ssh + knife
# so a fresh box needs no Ruby/Python runtime to join the VPN.
#
# Security: the operator mTLS cert/key live on the workstation and are
# passed to the API call here; they are never shipped to the node. The
# wg0.conf (which carries the node's private key inline) is written 0600 on
# the node and never echoed to the transcript.

set -euo pipefail

PROG="$(basename "$0")"

# --------------------------------------------------------------------------
# Usage
# --------------------------------------------------------------------------

usage() {
  cat <<EOF
${PROG} — VPN-first node bootstrap for wg_manager.

Usage:
  ${PROG} vpn   [options]     Join the node to the WireGuard VPN via the API.
  ${PROG} cinc  [options]     Bootstrap the node into Cinc over the VPN.
  ${PROG} all   [options]     Do both: vpn, then cinc against the assigned VPN IP.
  ${PROG} --help

Common options:
  --target HOST          SSH target to reach the node on (IP or ssh alias). [required]
  --ssh-user USER        SSH login user on the node. (default: current SSH config)
  --interface NAME       WireGuard interface to manage. (default: wg0)

vpn options:
  --api-url URL          wg_manager API base, e.g. https://10.0.0.1:8443. [required]
  --api-version VER      API version prefix. (default: v1)
  --server-id INT        Integer hub/server id to attach to. [required]
  --client-name NAME     wg_manager client name. (default: the node's hostname)
  --client-cert PATH     Operator mTLS client certificate (PEM) on this workstation.
  --client-key PATH      Operator mTLS client private key (PEM) on this workstation.
  --ca-bundle PATH       CA bundle (PEM) to verify the API server certificate.
  --insecure             Skip API server-cert verification (CN=localhost dialed by IP).

cinc options:
  --node-name NAME       Chef node/client name. (default: the node's VPN IP)
  --run-list LIST        knife run-list, e.g. 'role[homelab],role[wireguard]'.
  --secret-file PATH     Encrypted data-bag secret to hand to 'knife bootstrap'.
  --                     Everything after '--' is passed through to 'knife bootstrap'.

Examples:
  ${PROG} all --target 192.168.0.42 --ssh-user ubuntu \\
    --api-url https://10.0.0.1:8443 --server-id 1 --insecure \\
    --client-cert ops.crt --client-key ops.key \\
    --run-list 'role[homelab],role[wireguard]' --secret-file dbsecret
EOF
}

die() {
  echo "${PROG}: error: $*" >&2
  exit 1
}

log() {
  echo "==> $*" >&2
}

require() {
  # require <value> <flag-name>
  [[ -n "${1:-}" ]] || die "missing required option ${2}"
}

# --------------------------------------------------------------------------
# Shared option state (populated by parse_args)
# --------------------------------------------------------------------------

TARGET=""
SSH_USER=""
INTERFACE="wg0"

API_URL=""
API_VERSION="v1"
SERVER_ID=""
CLIENT_NAME=""
CLIENT_CERT=""
CLIENT_KEY=""
CA_BUNDLE=""
INSECURE="false"

NODE_NAME=""
RUN_LIST=""
SECRET_FILE=""
KNIFE_PASSTHROUGH=()

# Set by the vpn phase so `all` can hand the assigned VPN IP to `cinc`.
ASSIGNED_VPN_IP=""

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --target)        TARGET="$2"; shift 2 ;;
      --ssh-user)      SSH_USER="$2"; shift 2 ;;
      --interface)     INTERFACE="$2"; shift 2 ;;
      --api-url)       API_URL="$2"; shift 2 ;;
      --api-version)   API_VERSION="$2"; shift 2 ;;
      --server-id)     SERVER_ID="$2"; shift 2 ;;
      --client-name)   CLIENT_NAME="$2"; shift 2 ;;
      --client-cert)   CLIENT_CERT="$2"; shift 2 ;;
      --client-key)    CLIENT_KEY="$2"; shift 2 ;;
      --ca-bundle)     CA_BUNDLE="$2"; shift 2 ;;
      --insecure)      INSECURE="true"; shift ;;
      --node-name)     NODE_NAME="$2"; shift 2 ;;
      --run-list)      RUN_LIST="$2"; shift 2 ;;
      --secret-file)   SECRET_FILE="$2"; shift 2 ;;
      --)              shift; KNIFE_PASSTHROUGH=("$@"); break ;;
      -h|--help)       usage; exit 0 ;;
      *)               die "unknown option: $1 (try --help)" ;;
    esac
  done
}

# Build an `ssh`/`scp`-style target with the optional user prefix.
ssh_target() {
  if [[ -n "$SSH_USER" ]]; then
    echo "${SSH_USER}@${TARGET}"
  else
    echo "${TARGET}"
  fi
}

# Run a command on the node over SSH. Args are passed as a single remote
# command string so the caller controls quoting.
on_node() {
  ssh -o ConnectTimeout=15 "$(ssh_target)" "$@"
}

# --------------------------------------------------------------------------
# vpn — join the node to the WireGuard VPN
# --------------------------------------------------------------------------

cmd_vpn() {
  require "$TARGET" --target
  require "$API_URL" --api-url
  require "$SERVER_ID" --server-id

  # Default the client name to the node's hostname so a freshly imaged box
  # joins under a predictable, unique identifier.
  if [[ -z "$CLIENT_NAME" ]]; then
    CLIENT_NAME="$(on_node 'hostname' | tr -d '[:space:]')"
    [[ -n "$CLIENT_NAME" ]] || die "could not resolve the node hostname for --client-name"
  fi

  log "Registering manual client '${CLIENT_NAME}' on server ${SERVER_ID} via ${API_URL}"

  # Assemble the curl mTLS flags. The operator cert/key never leave the
  # workstation. --insecure covers the common CN=localhost-dialed-by-IP lab
  # case; otherwise we verify against the supplied CA bundle (or system store).
  local -a curl_tls=()
  [[ -n "$CLIENT_CERT" ]] && curl_tls+=(--cert "$CLIENT_CERT")
  [[ -n "$CLIENT_KEY" ]] && curl_tls+=(--key "$CLIENT_KEY")
  if [[ "$INSECURE" == "true" ]]; then
    curl_tls+=(--insecure)
  elif [[ -n "$CA_BUNDLE" ]]; then
    curl_tls+=(--cacert "$CA_BUNDLE")
  fi

  local url="${API_URL%/}/${API_VERSION#/}/clients/manual"
  local payload
  payload="$(printf '{"name":"%s","server_id":%s}' "$CLIENT_NAME" "$SERVER_ID")"

  # Capture body + HTTP status separately so we can fail loud on non-2xx
  # with the API's own error message.
  local response http_code response_body
  response="$(curl -sS "${curl_tls[@]}" \
    -X POST "$url" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json' \
    -w $'\n%{http_code}' \
    --data "$payload")" || die "API request to ${url} failed (connection/TLS). \
If you saw 'unexpected eof', the API required a client cert (mTLS) and none was sent — pass --client-cert/--client-key."
  http_code="$(printf '%s' "$response" | tail -n1)"
  response_body="$(printf '%s' "$response" | sed '$d')"

  if [[ "$http_code" -lt 200 || "$http_code" -ge 300 ]]; then
    die "API returned HTTP ${http_code} for ${url}: ${response_body}"
  fi

  # Extract the rendered wg0.conf and the assigned VPN address from the JSON.
  # Use python3 on the workstation (always present in this project's env);
  # the node needs nothing.
  local wg_config
  wg_config="$(printf '%s' "$response_body" | python3 -c '
import json, sys
data = json.load(sys.stdin)
cfg = data.get("wg_config")
if not isinstance(cfg, str) or not cfg:
    sys.exit("wg_manager response did not include a wg_config body")
sys.stdout.write(cfg)
')" || die "could not parse wg_config from the API response"

  ASSIGNED_VPN_IP="$(printf '%s' "$response_body" | python3 -c '
import json, sys
data = json.load(sys.stdin)
addr = (data.get("client") or {}).get("address", "")
# Strip any /CIDR suffix so the value is dialable.
sys.stdout.write(addr.split("/")[0])
' 2>/dev/null || true)"

  log "Assigned VPN address: ${ASSIGNED_VPN_IP:-<unknown>}"

  # Push the config and bring the tunnel up on the node. Everything runs as
  # one remote sudo script so we make a single SSH round-trip and keep the
  # private-key-bearing config off argv (it's fed on stdin).
  log "Installing WireGuard config and bringing up ${INTERFACE} on the node"
  printf '%s' "$wg_config" | on_node "sudo bash -s -- '${INTERFACE}'" <<'REMOTE'
set -euo pipefail
iface="$1"
# Ensure WireGuard is present (Debian/Ubuntu). No-op if already installed.
if ! command -v wg-quick >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq wireguard
fi
# Reprovision-safety: tear down any running interface BEFORE writing the new
# config, so a stale tunnel from a prior join can't linger. A bare teardown is
# fine here because we immediately rewrite + bring back up.
wg-quick down "$iface" 2>/dev/null || true
install -d -m 0700 /etc/wireguard
umask 077
cat > "/etc/wireguard/${iface}.conf"
chmod 600 "/etc/wireguard/${iface}.conf"
systemctl enable "wg-quick@${iface}" >/dev/null 2>&1 || true
systemctl restart "wg-quick@${iface}"
REMOTE

  # Validate: a real handshake is the only proof the tunnel works. `wg show`
  # exits 0 even before a handshake, so just surface it for the operator.
  log "Tunnel state on the node:"
  on_node "sudo wg show ${INTERFACE}" >&2 || die "wg show ${INTERFACE} failed — tunnel did not come up"

  log "VPN join complete for '${CLIENT_NAME}'${ASSIGNED_VPN_IP:+ (${ASSIGNED_VPN_IP})}"
}

# --------------------------------------------------------------------------
# cinc — bootstrap the node into Cinc over the VPN
# --------------------------------------------------------------------------

cmd_cinc() {
  require "$TARGET" --target

  command -v knife >/dev/null 2>&1 || die "knife not found on PATH — install the Cinc/Chef workstation tooling"

  # Dial Cinc bootstrap over the VPN when we have an assigned VPN IP (set by
  # the vpn phase in `all`); otherwise fall back to the SSH --target.
  local dial="${ASSIGNED_VPN_IP:-$TARGET}"

  # Default the Chef node/client name to the node's VPN IP — the fleet
  # convention. VPN-first enrollment makes this non-circular: the `vpn` phase
  # already assigned the address (ASSIGNED_VPN_IP, set when run via `all`), so
  # the Chef identity is tied to the stable VPN address rather than a mutable
  # LAN/DHCP one. Standalone `cinc` re-derives it from the node's WireGuard
  # interface; fall back to the dial target only if that can't be read.
  if [[ -z "$NODE_NAME" ]]; then
    if [[ -n "$ASSIGNED_VPN_IP" ]]; then
      NODE_NAME="$ASSIGNED_VPN_IP"
    else
      NODE_NAME="$(on_node "ip -4 -o addr show dev ${INTERFACE} 2>/dev/null | awk '{print \$4}' | cut -d/ -f1 | head -1" | tr -d '[:space:]' || true)"
      [[ -n "$NODE_NAME" ]] || NODE_NAME="$dial"
    fi
  fi

  log "Bootstrapping Cinc on node '${NODE_NAME}' over ${dial}"

  local -a knife_cmd=(knife bootstrap "$dial" -N "$NODE_NAME" --sudo)
  [[ -n "$SSH_USER" ]] && knife_cmd+=(-x "$SSH_USER")
  [[ -n "$RUN_LIST" ]] && knife_cmd+=(-r "$RUN_LIST")
  [[ -n "$SECRET_FILE" ]] && knife_cmd+=(--secret-file "$SECRET_FILE")
  knife_cmd+=("${KNIFE_PASSTHROUGH[@]}")

  "${knife_cmd[@]}"

  log "Cinc bootstrap complete for '${NODE_NAME}'"
}

# --------------------------------------------------------------------------
# all — vpn, then cinc against the assigned VPN IP
# --------------------------------------------------------------------------

cmd_all() {
  cmd_vpn
  cmd_cinc
}

# --------------------------------------------------------------------------
# Dispatch
# --------------------------------------------------------------------------

main() {
  [[ $# -ge 1 ]] || { usage; exit 2; }
  local sub="$1"; shift
  case "$sub" in
    vpn)        parse_args "$@"; cmd_vpn ;;
    cinc)       parse_args "$@"; cmd_cinc ;;
    all)        parse_args "$@"; cmd_all ;;
    -h|--help)  usage; exit 0 ;;
    *)          die "unknown subcommand: ${sub} (expected vpn, cinc, or all; try --help)" ;;
  esac
}

main "$@"
