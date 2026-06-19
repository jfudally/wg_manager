# Default attributes for the wg_node cookbook.
#
# Everything a node needs to self-join a WireGuard VPN lives under the
# node['wg_node'] namespace. Secrets (the mTLS client cert/key) should be
# delivered via an encrypted data bag rather than set in plain attributes
# — see node['wg_node']['tls']['data_bag'] below and README.md.

# Which role this node plays. Phase 1 supports only 'client'. Setting
# 'server' raises a clear error pointing at ROADMAP.md.
default['wg_node']['role'] = 'client'

# --- wg_manager API connection ------------------------------------------

# Base URL of the wg_manager control plane, e.g.
# 'https://wg-api.example.com:8000'. REQUIRED — no safe default.
default['wg_node']['api_url'] = nil

# API version prefix. New callers should stay on 'v1'.
default['wg_node']['api_version'] = 'v1'

# --- client role --------------------------------------------------------

# The hub/server id this client attaches to (integer). REQUIRED for the
# client role.
default['wg_node']['server_id'] = nil

# Unique client name registered with wg_manager. Defaults to the node's
# hostname at recipe time when left nil. The API rejects duplicate names,
# which is part of how re-runs stay idempotent.
default['wg_node']['client_name'] = nil

# WireGuard interface to manage on this node.
default['wg_node']['interface'] = 'wg0'

# Package that provides WireGuard. 'wireguard' is the Debian/Ubuntu
# meta-package (pulls wireguard-tools + the kernel module).
default['wg_node']['package_name'] = 'wireguard'

# Whether this cookbook installs the WireGuard package. Set false if your
# base image already ships it.
default['wg_node']['manage_package'] = true

# Where the rendered tunnel config and the join-state marker live. nil =>
# derived from the interface name at recipe time.
default['wg_node']['config_path'] = nil  # => /etc/wireguard/<iface>.conf
default['wg_node']['state_path']  = nil  # => /var/lib/wg_node/<iface>.json

# --- mutual TLS credentials ---------------------------------------------

# Verify the API server certificate. Only set false for throwaway lab
# endpoints with self-signed certs.
default['wg_node']['tls']['verify'] = true

# PEM bodies for the operator client cert/key and the CA bundle used to
# verify the server. Prefer the data_bag path below for the cert + key so
# secrets never land in node attributes on the Chef server.
default['wg_node']['tls']['client_cert'] = nil
default['wg_node']['tls']['client_key']  = nil
default['wg_node']['tls']['ca_bundle']   = nil

# Alternative to an inline ca_bundle: a path to the wg_manager CA file
# already present on the node (e.g. baked into the image or dropped by
# cloud-init). When set and ca_bundle is empty, the client recipe reads
# this file and uses it to verify the API server certificate. Handy for
# self-signed / private-CA wg_manager deployments.
default['wg_node']['tls']['ca_path'] = nil

# When a CA is available (inline, data bag, or ca_path) install it into
# the node's OS trust store (Debian/Ubuntu: /usr/local/share/ca-certificates
# + update-ca-certificates) so the API call — and any other tooling on the
# box — trusts the wg_manager server with no manual steps. Set false if you
# manage the trust store yourself.
default['wg_node']['tls']['install_ca'] = true

# Optional encrypted data bag holding the mTLS material. When 'name' and
# 'item' are set, the client recipe loads the item and reads the keys in
# 'keys' from it (falling back to the attributes above for anything the
# bag doesn't provide).
default['wg_node']['tls']['data_bag'] = {
  'name' => nil,
  'item' => nil,
  'keys' => {
    'client_cert' => 'client_cert',
    'client_key' => 'client_key',
    'ca_bundle' => 'ca_bundle',
  },
}
