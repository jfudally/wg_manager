#!/usr/bin/env bash
#
# enroll_node.sh: zero-touch enrollment of a fresh host into wg_manager
# (Phase 3f). Designed to run unattended as cloud-init userdata, on the
# host itself, from outside the VPN.
#
# What it does:
#   1. Generates the host's WireGuard keypair locally (reuses an existing
#      /etc/wireguard/privatekey) and makes sure an ed25519 SSH host key
#      exists.
#   2. Calls POST /v1/enroll on the wg_manager enrollment listener with a
#      single-use token, sending only the two PUBLIC keys and its
#      hostname. It retries while the control plane answers 5xx (hub
#      still coming up, CA briefly unavailable) or 429 (rate limited).
#   3. Installs what comes back: wg0.conf (no private key inside), the
#      SSH user CA, the signed host cert, and the same sshd drop-in the
#      provisioning worker installs.
#   4. Makes sure the management account exists with passwordless sudo,
#      reloads sshd, and brings the tunnel up.
#
# After that, wg_manager's worker can manage the host over the VPN with
# CA-signed SSH certs, with no trust-on-first-use step.
#
# Configuration (environment variables):
#   WGM_ENROLL_URL       Base URL of the enrollment listener. https only.  [required]
#   WGM_ENROLL_TOKEN     Enrollment token (wgmenr_...).                    [required*]
#   WGM_ENROLL_TOKEN_FILE  Or: file holding the token; deleted after use.  [*]
#   WGM_CA_BUNDLE_PEM    PEM of the CA that signed the listener's cert.    [required**]
#   WGM_CA_BUNDLE_FILE   Or: path to that PEM.                             [**]
#   WGM_INTERFACE        WireGuard interface name. (default: wg0)
#   WGM_HOSTNAME         Name to report. (default: short hostname, lowercased)
#   WGM_MAX_ATTEMPTS     Enrollment attempts on 429 / 5xx / network errors. (default: 30)
#   WGM_RETRY_DELAY      Seconds between attempts. (default: 10)
#   WGM_SKIP_PACKAGES    1 = don't install wireguard-tools.
#   WGM_ROOT             Filesystem prefix. Test hook only; leave unset.
#
# Security notes:
#   * The token is handed to curl through a 0600 header file, never argv,
#     so it doesn't show up in `ps`. It's removed from the environment and
#     from disk once used.
#   * There's no "insecure" TLS option on purpose: server verification is
#     what stops the token being sent to an impostor.
#   * The WireGuard private key never leaves this host.
#
# Example userdata:
#   #!/bin/bash
#   export WGM_ENROLL_URL=https://wg.example.com:8443
#   export WGM_ENROLL_TOKEN=wgmenr_...
#   export WGM_CA_BUNDLE_PEM='-----BEGIN CERTIFICATE-----
#   ...
#   -----END CERTIFICATE-----'
#   curl -fsSL https://raw.githubusercontent.com/jfudally/wg_manager/main/scripts/enroll_node.sh | bash
#   (or bake the script into the image, and pin a release tag rather than main)

set -euo pipefail

PROG="enroll_node.sh"
R="${WGM_ROOT:-}"

die() {
  local code=$1; shift
  echo "${PROG}: error: $*" >&2
  exit "$code"
}

log() {
  echo "${PROG}: $*" >&2
}

# --------------------------------------------------------------------------
# Settings
# --------------------------------------------------------------------------

URL="${WGM_ENROLL_URL:-}"
IFACE="${WGM_INTERFACE:-wg0}"
MAX_ATTEMPTS="${WGM_MAX_ATTEMPTS:-30}"
RETRY_DELAY="${WGM_RETRY_DELAY:-10}"

[[ -n "$URL" ]] || die 2 "WGM_ENROLL_URL is required"
[[ "$URL" == https://* ]] || die 2 "WGM_ENROLL_URL must be https:// (the token must not cross the wire in clear)"
if [[ -z "$R" && "$(id -u)" -ne 0 ]]; then
  die 2 "must run as root"
fi
[[ "$IFACE" =~ ^[a-zA-Z0-9_=+.-]{1,15}$ ]] || die 2 "invalid WGM_INTERFACE"

TOKEN="${WGM_ENROLL_TOKEN:-}"
if [[ -z "$TOKEN" && -n "${WGM_ENROLL_TOKEN_FILE:-}" ]]; then
  TOKEN="$(tr -d '[:space:]' < "$WGM_ENROLL_TOKEN_FILE")"
fi
[[ -n "$TOKEN" ]] || die 2 "WGM_ENROLL_TOKEN (or WGM_ENROLL_TOKEN_FILE) is required"
unset WGM_ENROLL_TOKEN

if [[ -z "${WGM_CA_BUNDLE_PEM:-}" && -z "${WGM_CA_BUNDLE_FILE:-}" ]]; then
  die 2 "WGM_CA_BUNDLE_PEM (or WGM_CA_BUNDLE_FILE) is required"
fi

umask 077
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [[ -n "${WGM_CA_BUNDLE_PEM:-}" ]]; then
  printf '%s\n' "$WGM_CA_BUNDLE_PEM" > "$WORK/ca.pem"
else
  cp "$WGM_CA_BUNDLE_FILE" "$WORK/ca.pem"
fi

# The header file is the only place the token lives from here on.
printf 'Authorization: Bearer %s\n' "$TOKEN" > "$WORK/auth.hdr"
unset TOKEN
if [[ -n "${WGM_ENROLL_TOKEN_FILE:-}" ]]; then
  rm -f "$WGM_ENROLL_TOKEN_FILE"
fi

HOST="${WGM_HOSTNAME:-$(hostname)}"
HOST="${HOST%%.*}"
HOST="$(printf '%s' "$HOST" | tr '[:upper:]' '[:lower:]')"

# --------------------------------------------------------------------------
# Local keys
# --------------------------------------------------------------------------

if [[ -z "${WGM_SKIP_PACKAGES:-}" ]] && ! command -v wg >/dev/null 2>&1; then
  log "installing wireguard-tools"
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard-tools
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q wireguard-tools
  elif command -v yum >/dev/null 2>&1; then
    yum install -y -q wireguard-tools
  else
    die 1 "no supported package manager; install wireguard-tools first"
  fi
fi

install -d -m 0700 "$R/etc/wireguard"
if [[ ! -s "$R/etc/wireguard/privatekey" ]]; then
  log "generating WireGuard keypair"
  wg genkey > "$R/etc/wireguard/privatekey"
fi
chmod 600 "$R/etc/wireguard/privatekey"
WG_PUB="$(wg pubkey < "$R/etc/wireguard/privatekey")"

if [[ ! -s "$R/etc/ssh/ssh_host_ed25519_key.pub" ]]; then
  log "generating SSH host keys"
  if [[ -n "$R" ]]; then ssh-keygen -A -f "$R"; else ssh-keygen -A; fi
fi
SSH_PUB="$(head -n1 "$R/etc/ssh/ssh_host_ed25519_key.pub")"

# --------------------------------------------------------------------------
# Enroll
# --------------------------------------------------------------------------

# python3 does the JSON both ways so quoting is never hand-rolled.
HOST="$HOST" WG_PUB="$WG_PUB" SSH_PUB="$SSH_PUB" python3 -c '
import json, os
print(json.dumps({
    "hostname": os.environ["HOST"],
    "wg_public_key": os.environ["WG_PUB"],
    "ssh_host_public_key": os.environ["SSH_PUB"],
}))' > "$WORK/body.json"

ENDPOINT="${URL%/}/v1/enroll"
attempt=0
while :; do
  attempt=$((attempt + 1))
  code="$(curl -sS --proto '=https' --cacert "$WORK/ca.pem" \
    -H @"$WORK/auth.hdr" \
    -H 'Content-Type: application/json' \
    --data-binary @"$WORK/body.json" \
    -o "$WORK/resp.json" -w '%{http_code}' \
    "$ENDPOINT")" || code="000"

  case "$code" in
    201) break ;;
    # 429: per-IP rate limit (a whole fleet behind one NAT address can
    # trip it). 5xx / 000: control plane or network not ready yet.
    000|429|5??)
      if (( attempt >= MAX_ATTEMPTS )); then
        die 1 "enrollment failed after ${attempt} attempts (last HTTP ${code})"
      fi
      log "enrollment attempt ${attempt} got HTTP ${code}; retrying in ${RETRY_DELAY}s"
      sleep "$RETRY_DELAY"
      ;;
    *)
      die 1 "enrollment rejected with HTTP ${code}: $(head -c 500 "$WORK/resp.json" 2>/dev/null || true)"
      ;;
  esac
done
log "enrolled"

# --------------------------------------------------------------------------
# Install what came back
# --------------------------------------------------------------------------

# Split the response into files in $WORK, then install them with the
# right modes. Prints the management username on stdout.
MGMT_USER="$(WORK="$WORK" python3 -c '
import json, os
w = os.environ["WORK"]
r = json.load(open(os.path.join(w, "resp.json")))
for name, key in (("wg.conf", "wg_config"), ("ca.pub", "user_ca_public_key"),
                  ("host-cert.pub", "host_certificate")):
    body = r[key] if key == "wg_config" else r[key] + "\n"
    with open(os.path.join(w, name), "w") as f:
        f.write(body)
print(r["ssh_username"])')"
[[ "$MGMT_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die 1 "control plane returned an invalid ssh_username"

install -D -m 0600 "$WORK/wg.conf" "$R/etc/wireguard/${IFACE}.conf"
install -D -m 0644 "$WORK/ca.pub" "$R/etc/ssh/wg-manager-user-ca.pub"
install -D -m 0644 "$WORK/host-cert.pub" "$R/etc/ssh/ssh_host_ed25519_key-cert.pub"

# Must match wg_manager.host_ssh._SSHD_DROPIN_TEMPLATE byte for byte
# (tests/test_enroll_node_script.py checks this).
cat > "$WORK/sshd.conf" <<'EOF'
# Managed by wg-manager (Phase 2c CP3). Do not hand-edit.
#
# TrustedUserCAKeys tells sshd to accept user certificates signed by
# the listed CA(s) as a substitute for entries in authorized_keys.
# HostCertificate makes sshd present a CA-signed host certificate
# during the SSH handshake so clients using KnownHostsCAPolicy can
# verify the host without TOFU.
TrustedUserCAKeys /etc/ssh/wg-manager-user-ca.pub
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
EOF
install -D -m 0644 "$WORK/sshd.conf" "$R/etc/ssh/sshd_config.d/wg-manager.conf"

# Management account: the worker's user certs are issued for it, and the
# provisioning code runs everything through `sudo -n`.
if ! id -u "$MGMT_USER" >/dev/null 2>&1; then
  log "creating management user ${MGMT_USER}"
  useradd -m -s /bin/bash "$MGMT_USER"
fi
printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$MGMT_USER" > "$WORK/sudoers"
if command -v visudo >/dev/null 2>&1; then
  visudo -cf "$WORK/sudoers" >/dev/null
fi
install -D -m 0440 "$WORK/sudoers" "$R/etc/sudoers.d/wg-manager"

# Validate before reloading, so a bad drop-in can't take sshd down.
sshd -t
systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null \
  || service ssh reload 2>/dev/null || service sshd reload

# Reprovision safety: tear down a running interface before restarting
# on the new config.
wg-quick down "$IFACE" 2>/dev/null || true
systemctl enable "wg-quick@${IFACE}"
systemctl restart "wg-quick@${IFACE}"

log "done: ${IFACE} is up; this host is now managed by wg_manager"
