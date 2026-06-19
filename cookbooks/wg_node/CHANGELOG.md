# Changelog

All notable changes to the `wg_node` cookbook are documented here. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this cookbook adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.4] - 2026-06-19

### Fixed
- First-join tunnel bring-up. The pre-join `wg-quick down` left systemd
  thinking the unit was active while the interface was down, so the
  follow-up `:start` was a no-op and the tunnel stayed down until the next
  manual restart. Replaced it with a restart notification on config change
  plus a self-heal that restarts `wg-quick@<iface>` only when the config
  exists but the interface is actually missing (no flap on healthy nodes).

## [0.1.3] - 2026-06-19

### Added
- `tls.ca_path` attribute — trust the wg_manager CA from a file already on
  the node, as an alternative to an inline `ca_bundle`. Eases self-signed /
  private-CA deployments.
- `tls.install_ca` attribute (default `true`) — the client recipe installs
  the resolved CA into the node's OS trust store (Debian/Ubuntu:
  `/usr/local/share/ca-certificates` + `update-ca-certificates`), so a
  self-signed / private-CA wg_manager server is trusted with no manual
  steps. Idempotent; refreshes only when the CA changes.

### Changed
- The API client now raises a specific, actionable error on TLS
  verification failures (points at `ca_bundle` / `ca_path` / `verify`)
  instead of a generic request-failed message.
- TLS errors are now classified: a dropped handshake / "unexpected eof"
  (the server requiring an mTLS client cert) reports a `client_cert` /
  `client_key` hint rather than the misleading "untrusted CA" message.

## [0.1.0] - 2026-06-18

### Added
- Initial release — **Phase 1: client self-join** (see ROADMAP.md).
- `WgManager::ApiClient` library: mTLS HTTP client for the wg_manager API,
  with `register_manual_client` against `POST /v1/clients/manual`.
- `wg_node_client` custom resource with an idempotent `:join` action that
  registers the node, writes `/etc/wireguard/<iface>.conf` (`0600`,
  sensitive), and enables/starts `wg-quick@<iface>`.
- `wg_node::default` (role dispatch) and `wg_node::client` recipes. The
  `server` role raises with a pointer to ROADMAP.md (Phase 2).
- mTLS credential resolution from an encrypted data bag or node attributes.
- RSpec unit specs for the API client and ChefSpec for the recipes and the
  stepped-into resource action; cookstyle-clean; Makefile entrypoint.

[Unreleased]: https://github.com/jfudally/wg_manager/compare/wg_node-v0.1.3...HEAD
[0.1.3]: https://github.com/jfudally/wg_manager/compare/wg_node-v0.1.0...wg_node-v0.1.3
[0.1.0]: https://github.com/jfudally/wg_manager/releases/tag/wg_node-v0.1.0
