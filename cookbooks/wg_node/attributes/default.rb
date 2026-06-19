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
default['wg_node']['tls']['ca_bundle']   = "-----BEGIN CERTIFICATE-----\nMIICajCCAVKgAwIBAgIUY9u+AMOX8dmyXkCwAr6IUbZXBUMwDQYJKoZIhvcNAQEL\nBQAwHjEcMBoGA1UEAxMTd2ctbWFuYWdlciBQS0kgcm9vdDAeFw0yNjA2MDgxNjI1\nMDFaFw0zMTA2MDcxNjI1MzFaMCYxJDAiBgNVBAMTG3dnLW1hbmFnZXIgUEtJIGlu\ndGVybWVkaWF0ZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKZHJy77GzY5ETkF\nOvylawmnd9o12CYmf25UPTrzsHmdA/TotTgjPH0+BqN7yWbVmoIIHx3tJiZpQqkQ\nCQJJnsmjYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1Ud\nDgQWBBRCy93NKvJSSddKzL1QMTDDAnrIiTAfBgNVHSMEGDAWgBRp3CEGgVXTzuSb\nPlUYRPpAsvTtXDANBgkqhkiG9w0BAQsFAAOCAQEAtyFCzd0CO4zoUZMSQt8TAtbq\nuKKY7JnV1qXBpasE2u0mYva1Vzzy8dcDfnf0YE3CnmShKy3wYqzsc4ToHTtR2hAq\nLGiV0BvF7QOwQ51znga6yVLupiCZtch3aEYqDGJiP4g+Xa99Coezo/Aup8tJYaKy\nvJLqdsszvw4mz9iFEGukVwbHW7VSoLizRCVJKThTOWMRksAOkhFm7L8LL83tzQEV\nFNBofswqRxl3TPNqtDfZjqEOvEEd90bEYN7jfWtHVEutAG6D+k74kImIHqSown/n\nnqzEfNkAa45P6Y/I1W7qPowpRug6SeOoK81vP0AKJdp4LZ0S7wa+6HtKZ2/1hw==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIDLTCCAhWgAwIBAgIUfIqsQWDQvPcHb4wAPqbFhSinizQwDQYJKoZIhvcNAQEL\nBQAwHjEcMBoGA1UEAxMTd2ctbWFuYWdlciBQS0kgcm9vdDAeFw0yNjA2MDgxNjI1\nMDFaFw0zNjA2MDUxNjI1MzFaMB4xHDAaBgNVBAMTE3dnLW1hbmFnZXIgUEtJIHJv\nb3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC/cM22IxYxGRvEmH5E\nTV+PnAGH1s3z2dH6OMb1EKZ2+prt9Jq7twzLujFU4wu5v/9wiqi5a39Mni0mtJW9\nun5xvRqqSKMk9BttxpTs57URZbNY2fd6ZRUWPP3dy1pSyggqkgcwbKKUTftlxzmG\nSsMbXox9DEOURZ9BCG9ObdB5032wTHPE1XQe+Xr7XhPIOrAT1EkeUqTq/gxSWppB\nD+b6WC/7U940iHPOTtf09+eeIAoMZ0cHllVRCxYe558biW/KgN2fTeCoM3yl4c/9\nHwDg4NuUONsur+d3qLEyBxCHRKahjw3yglaUY5BJXecbr2B7c2//BDd3eGJ8ifQe\nfREBAgMBAAGjYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0G\nA1UdDgQWBBRp3CEGgVXTzuSbPlUYRPpAsvTtXDAfBgNVHSMEGDAWgBRp3CEGgVXT\nzuSbPlUYRPpAsvTtXDANBgkqhkiG9w0BAQsFAAOCAQEARZXf/BAdZNaRLGpDg7Cd\nhwm2JYZv9Hb7Om4lpPvlRupKBwpl3kWK4U6q/KAbJYnreKfgIAFBHrEC3QdBJtMa\nxhRdovOde1B2SehPUI7aMwdTwQSuI2r4M+y7UhDnYRfGa7HPCsXMdTPujP0zzyJI\nx/NqExHJbjIz9x9c4UFtjyH2EcweuFyIKU8/OHu5AWIwqRK4WXohnOy042I4BM3w\nwTpaNih0HvJrRus1/PXVbyx4lUvTM9jmYGL0tGpyMpszEw32NB6Hrv6opDPxrZZ+\ntjUHNfCZjwSZSCKsrrwh77VEY1lnhb079w8HlQttsmuMES8MIYUchIRLf1BqlGnY\nDQ==\n-----END CERTIFICATE-----"

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
