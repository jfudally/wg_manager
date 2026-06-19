# wg_node cookbook — roadmap

Phased rollout. Each phase is the smallest slice that delivers real value.

## Phase 1 — Client self-join (MVP) ✅

The happy path: a fresh Debian/Ubuntu node bootstraps Cinc and joins the
VPN as a WireGuard **client** by calling `POST /v1/clients/manual`.

- [x] `WgManager::ApiClient` — HTTP client with mTLS, unit-tested.
- [x] `wg_node_client` custom resource — idempotent `:join` action.
- [x] `wg_node::client` + `wg_node::default` (role dispatch).
- [x] mTLS credentials from an encrypted data bag (or attributes).
- [x] ChefSpec + library unit specs, cookstyle clean, Makefile, README.

## Phase 2 — Server self-provisioning

A node should be able to self-provision as a WireGuard **server** (hub)
the same way clients do. **Blocked on a backend gap:** wg_manager has no
endpoint that returns a server config for self-install — `POST /servers`
is SSH-push only (the worker connects *into* the node).

- [ ] **Backend:** add `POST /v1/servers/manual` (symmetric with
      `/clients/manual`) that allocates a subnet, generates a keypair,
      persists the server row in `ready`, and returns the rendered server
      `wg0.conf` inline. TDD in the `wg_manager` Python suite.
- [ ] `wg_node::server` recipe + extend the resource (or a `wg_node_server`
      resource): write config, enable IPv4 forwarding (`net.ipv4.ip_forward`),
      open the listen port, bring up `wg-quick@wg0`.
- [ ] Flip `role = 'server'` from "raises" to a real path.

## Phase 3 — Hardening & breadth

- [ ] **RHEL/Alma/Rocky support** (package names, firewalld) + `supports`.
- [ ] **Test Kitchen integration** with `dokken`/`vagrant` driver and the
      InSpec profile in `test/integration/` running against a live converge
      (mock the API or stand up a wg_manager test instance).
- [ ] **`:leave` action** — `wg-quick down`, remove config + marker, and
      (optionally) call the API to delete/disable the client row.
- [ ] **Token-based node enrollment** — a short-lived bootstrap token issued
      per node instead of a shared operator cert, so a compromised image
      can't mint arbitrary clients. Coordinate with `wg_manager` auth.
- [ ] **Re-key / rotation** action and drift detection (config on disk vs.
      desired).
- [ ] CI workflow (cookstyle + rspec) wired into the repo's GitHub Actions.
