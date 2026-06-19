# wg_node cookbook

A Cinc/Chef cookbook that **self-provisions a node onto a WireGuard VPN**
through the [`wg_manager`](../../README.md) API. Spin up a fresh box,
bootstrap Cinc with `wg_node::default` in its run-list, and the node
registers itself and brings its tunnel up — no manual key shuffling, no
operator SSHing in.

> **Phase 1 scope: client nodes only.** A node can self-join as a
> WireGuard *client*. Self-provisioning a *server* (hub) needs a backend
> endpoint that doesn't exist yet — see [ROADMAP.md](ROADMAP.md). Setting
> `role = 'server'` fails fast with a pointer to the roadmap.

## How it works

```
   new node boots
        │
        ▼
  bootstrap Cinc  ──run_list──▶  wg_node::default
                                      │ role = 'client'
                                      ▼
                                 wg_node::client
                                      │
            POST /v1/clients/manual (mTLS, {name, server_id})
                                      │
                          ┌───────────┴───────────┐
                          ▼                        │
              wg_manager generates a              │ response carries the full
              keypair server-side and             │ wg0.conf with the private
              returns the rendered config ────────┘ key inline (one time only)
                          │
                          ▼
            write /etc/wireguard/wg0.conf (0600, sensitive)
            systemctl enable --now wg-quick@wg0
                          │
                          ▼
                  node is on the VPN
```

The control plane never connects back into the node for this path — the
node does all the work locally. This is the `POST /clients/manual`
endpoint, the one wg_manager flow designed for devices that provision
themselves.

### Idempotency

The first converge registers the node and writes a state marker at
`/var/lib/wg_node/<iface>.json`. Subsequent converges see the marker and
**skip registration** (the API rejects duplicate client names anyway), but
still reconcile the `wg-quick@<iface>` service so a rebooted node comes
back onto the VPN. To re-enroll a node, delete the marker and the config,
then converge again.

## Requirements

- **Cinc Client / Chef Infra Client >= 16**, Debian/Ubuntu target (Phase 1).
- A reachable **wg_manager API** and the integer **`server_id`** of the hub
  to join.
- An **mTLS operator client certificate + key** the node can present to the
  API (every endpoint except `/health` requires one). Deliver these via an
  **encrypted data bag** — see below.

## Quick start

### 1. Put the mTLS material in an encrypted data bag

```bash
# one-time: create the data bag and an item holding the cert/key/CA PEMs
knife data bag create wg_node
knife data bag from file wg_node node_enrollment.json --secret-file db.key
```

`node_enrollment.json`:

```json
{
  "id": "enrollment",
  "client_cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "client_key":  "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
  "ca_bundle":   "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"
}
```

### 2. Set node attributes (role, API, server, data bag)

In a role, environment, policyfile, or `knife bootstrap --json-attributes`:

```json
{
  "wg_node": {
    "role": "client",
    "api_url": "https://wg-api.example.com:8000",
    "server_id": 1,
    "tls": {
      "verify": true,
      "data_bag": { "name": "wg_node", "item": "enrollment" }
    }
  },
  "run_list": ["recipe[wg_node::default]"]
}
```

`client_name` defaults to the node's hostname. The data bag's keys map to
`client_cert` / `client_key` / `ca_bundle` by default (override under
`tls.data_bag.keys`).

### 3. Bootstrap the node

```bash
cinc-client -j attrs.json        # or: knife bootstrap, policyfile, etc.
```

On success the node has `/etc/wireguard/wg0.conf` and an active
`wg-quick@wg0` service.

## Attributes

| Attribute | Default | Purpose |
|---|---|---|
| `['wg_node']['role']` | `'client'` | `client` (Phase 1) or `server` (raises). |
| `['wg_node']['api_url']` | `nil` **(required)** | Base URL of the wg_manager API. |
| `['wg_node']['api_version']` | `'v1'` | API version prefix. |
| `['wg_node']['server_id']` | `nil` **(required)** | Hub id the client attaches to. |
| `['wg_node']['client_name']` | `nil` → hostname | Unique client name to register. |
| `['wg_node']['interface']` | `'wg0'` | WireGuard interface to manage. |
| `['wg_node']['package_name']` | `'wireguard'` | Package providing WireGuard. |
| `['wg_node']['manage_package']` | `true` | Install the package, or assume the image has it. |
| `['wg_node']['config_path']` | `nil` → `/etc/wireguard/<iface>.conf` | Rendered tunnel config path. |
| `['wg_node']['state_path']` | `nil` → `/var/lib/wg_node/<iface>.json` | Join-state marker path. |
| `['wg_node']['tls']['verify']` | `true` | Verify the API server certificate. |
| `['wg_node']['tls']['client_cert']` | `nil` | Client cert PEM (prefer the data bag). |
| `['wg_node']['tls']['client_key']` | `nil` | Client key PEM (prefer the data bag). |
| `['wg_node']['tls']['ca_bundle']` | `nil` | CA bundle PEM to verify the server. |
| `['wg_node']['tls']['ca_path']` | `nil` | Path to a CA file already on the node (used when `ca_bundle` is empty). |
| `['wg_node']['tls']['install_ca']` | `true` | Install the resolved CA into the node's OS trust store. |
| `['wg_node']['tls']['data_bag']` | `{name,item,keys}` | Encrypted data bag holding the mTLS PEMs. |

## Resource: `wg_node_client`

The recipe is a thin wrapper over the `wg_node_client` custom resource, which
you can also use directly:

```ruby
wg_node_client 'edge-box-7' do
  api_url     'https://wg-api.example.com:8000'
  server_id   1
  client_cert lazy { node.run_state['wg_cert'] }
  client_key  lazy { node.run_state['wg_key'] }
  ca_bundle   lazy { node.run_state['wg_ca'] }
  action :join
end
```

## Security notes

- The private key is returned by the API **exactly once**; the cookbook
  writes the config (`0600`, `sensitive true`) on first join and never
  fetches it again.
- mTLS material should come from an **encrypted data bag**, not plain node
  attributes (which are stored on the Chef server in the clear).
- Keep `tls.verify = true` in production and supply a `ca_bundle` so the
  node pins the wg_manager CA. `verify = false` is for throwaway labs only.

## Troubleshooting

### `certificate verify failed (self-signed certificate in certificate chain)`

The node reached the API but does not trust its TLS certificate — the
wg_manager server presents a self-signed / private-CA cert and the node
has no matching CA.

**You only need to give the cookbook the CA;** it installs it into the
node's OS trust store automatically (`tls.install_ca`, default `true`) and
passes it to the API client, so no manual `update-ca-certificates` is
required. Supply the CA any one of these ways:

1. **Encrypted data bag `ca_bundle`** (recommended; see Quick start).
2. **Inline attribute:**
   ```ruby
   node['wg_node']['tls']['ca_bundle'] = "-----BEGIN CERTIFICATE-----\n...\n"
   ```
3. **A file already on the node:**
   ```ruby
   node['wg_node']['tls']['ca_path'] = '/etc/wg_node/wg-manager-ca.crt'
   ```

The CA is the bundle the API was started with (`TLS_CA_BUNDLE_PEM` /
`--out-chain`, e.g. `tls/ca-bundle.crt`). Homelab shortcut to capture what
the server presents:
```bash
openssl s_client -connect 192.168.0.239:8443 -showcerts </dev/null 2>/dev/null \
  | openssl x509 > wg-manager-ca.crt   # last cert in the chain is the root
```

**Lab escape hatch** (not for production) — skip verification entirely:
```ruby
node['wg_node']['tls']['verify'] = false
```

### `SSL_read: unexpected eof while reading` (even with `verify = false`)

This is **not** a trust problem — the server accepted the TLS connection
then closed it because the wg_manager API **requires a client certificate
(mTLS)** and the node sent none. Confirm with:
```bash
echo | openssl s_client -connect <api-host>:<port> -state 2>&1 | grep -i "certificate request"
# "read server certificate request" => the API wants a client cert
```
Fix: give the node an **operator** client cert + key. On the API host:
```bash
wg-manager operators add --cn node-enroller --role admin   # if not already registered
wg-manager certs issue --type cli --cn node-enroller \
  --out-cert client.crt --out-key client.key --out-chain client.chain.crt
```
Then deliver them to the node (encrypted data bag recommended, or inline):
```ruby
node['wg_node']['tls']['client_cert'] = "-----BEGIN CERTIFICATE-----\n...\n"
node['wg_node']['tls']['client_key']  = "-----BEGIN PRIVATE KEY-----\n...\n"
```
The cert CN must match a registered, active operator with rights to create
clients.

## Development & testing

This cookbook is developed test-first. The Chef Workstation toolchain
provides everything (`chef exec rspec`, `cookstyle`).

```bash
make test    # full RSpec suite (library unit + ChefSpec)
make lint    # cookstyle
make fmt     # cookstyle -a
make help    # list targets
```

- `spec/unit/` — pure-Ruby unit specs for `WgManager::ApiClient` (HTTP +
  mTLS), Net::HTTP stubbed.
- `spec/recipes/` — ChefSpec for role dispatch, validation, and the
  stepped-into `:join` action.
- `test/integration/` — InSpec profile for Test Kitchen (Phase 3; needs a
  container/VM driver).

See [CHANGELOG.md](CHANGELOG.md) and [ROADMAP.md](ROADMAP.md).
