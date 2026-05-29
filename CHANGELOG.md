# Changelog

All notable changes to wg-manager are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
for any tagged releases. Pre-tag work lands under `## [Unreleased]`.

## [Unreleased]

### Added

- **Phase 2d checkpoint 1 — `wg_manager.pki` module.** Internal X.509
  substrate behind a `PKIBackend` Protocol with `LocalDevPKI` (in-
  process EC P-256 hierarchy via the `cryptography` library, for
  dev/tests) and `VaultPKI` (wraps the Vault PKI engine; CA private
  keys never leave Vault) implementations. `scripts/pki_bootstrap.py`
  + `make pki-bootstrap` idempotently set up the `pki` (10y root) and
  `pki_int` (5y intermediate) mounts and the `wg-manager-server` /
  `wg-manager-client` roles. See `docs/vault-cookbook.md` §4.
- **Phase 2d checkpoint 2 — mTLS-required FastAPI listener.** New
  `wg_manager.auth.MTLSAuthMiddleware` 401s every non-OPTIONS request
  arriving without a Vault-signed client certificate when
  `TLS_REQUIRED=true`. `python -m wg_manager` is the canonical entry
  point and refuses to start without all three of `TLS_CERT_PEM` /
  `TLS_KEY_PEM` / `TLS_CA_BUNDLE_PEM`. `make tls-issue-dev` mints
  throwaway dev PEMs under `tls/` (gitignored) — production uses
  certs issued from the Vault PKI above. The previous
  `uvicorn --reload` shape is removed; there is no longer a
  sanctioned wg-manager command that serves plain HTTP.
- **Dashboard BFF mTLS proxy.** A Node-runtime catch-all Route
  Handler at `web/app/api/proxy/[...path]/route.ts` forwards every
  dashboard call to the (now mTLS-only) API. The client cert/key
  live exclusively on the Node side; the browser only ever speaks
  same-origin plain HTTP to `localhost:3100`. Required because
  browsers can't easily present a client certificate, so the BFF is
  what makes Phase 2d CP2 holdable without losing dashboard access.
  `web/.env.example` documents the four `WG_MANAGER_API_*` env vars.

### Changed (breaking)

- **API listener is mTLS-only.** `make run` exits 2 without
  `TLS_REQUIRED=true` + the three cert-path env vars. Any callers
  still on plain HTTP must either switch to mTLS or go through the
  dashboard BFF proxy.
- **Manual-client redesign — control plane no longer persists private keys.**
  The `wg0.conf` body for a manual client is now returned **exactly once**
  in the response to `POST /clients/manual` as the new `wg_config` field
  (alongside `task_id` and `client`). The server-generated WireGuard
  private key lives only in that response — the row carries just the
  public key. The control plane has no operational use for the device's
  private key (manual clients are devices wg-manager cannot SSH into),
  so persisting it was pure liability. Operators must capture the body
  on first sight; the only recovery path if the body is lost is to
  `DELETE /clients/{id}` and re-register, which mints a fresh keypair
  and reconfigures the hub.
- **Removed `GET /clients/{id}/config`.** With no server-side private
  key to render from, the endpoint has nothing to return. Clients that
  hit the route now receive a FastAPI 404.
- **Removed `wg-manager clients config <id>` CLI.** Mirror of the API
  change — there is nothing to re-export from. Typer surfaces an
  "unknown command" error.
- **`/crypto/status` response shape shrunk** to `{backend, key_version}`.
  The `client_encrypted` / `client_legacy` per-table counters are gone
  because no wg-manager row carries ciphertext any more (Alembic 0008
  dropped the sshkey ciphertext columns; this release's 0009 drops the
  manual-client one).

### Removed

- `client.private_key_ct` column. Alembic revision
  **`0009_drop_client_private_key_ct`** drops it. Downgrade re-adds
  the column as `NULLABLE TEXT` but the data is irrecoverable
  (ciphertext is gone with the column).
- `wg_manager.crypto.encrypt_client_private_key` and
  `wg_manager.crypto.resolve_client_private_key` row-level helpers
  (no remaining consumers; the row-swap defence pattern itself is
  preserved as a comment in `wg_manager/crypto.py` for any future
  encrypted-at-rest column to reuse).
- Internal CLI rewrap loop over `Client` rows. `wg-manager crypto
  rewrap` is now a no-op against the current schema (no encrypted
  columns to walk) and is retained as a forward-compat surface and
  a backend-reachability smoke test.

### Changed

- `wg-manager clients add-manual` continues to print the rendered
  `wg0.conf` to stdout or `--config-output`, but now reads the body
  from the response's `wg_config` field rather than re-fetching it
  from the retired endpoint.
- Next.js dashboard:
  - The manual-client registration success state surfaces the
    `wg_config` body inline with copy / download affordances, with
    explicit messaging that the control plane does not keep a copy.
  - The "Get config" row action for existing manual rows is replaced
    with a static `Manual` label — there is no re-fetch path.
  - The "Crypto Status" page renders just the backend identity and
    current key version; the per-table panel is gone.

### Security

- Closes threat **T-3** (manual-client WireGuard private keys
  readable from a DB dump). Prior closure was via Vault Transit
  envelope encryption; the redesign closes it more thoroughly by
  removing the attack surface entirely.
- Closes threat **T-8** (browser ↔ API traffic in cleartext) —
  uvicorn terminates TLS with `CERT_REQUIRED`; the only path to
  the API is mTLS.
- Partially closes threat **T-7** (unauthenticated API). The
  middleware now rejects anyone without a Vault-signed client cert;
  Phase 2d CP3 will add the `Operator` registry so that a *valid*
  cert with an unknown CN is no longer waved through.

## Earlier history

Pre-CHANGELOG history is tracked in git (`git log`). Notable prior
milestones:

- **Alembic 0008 (Phase 2c CP4.4)** — dropped `sshkey.private_key_ct`
  / `sshkey.passphrase_ct`; SSH auth mints from the Vault SSH CA at
  task time.
- **Alembic 0004 / 0005 (Phase 2b)** — added then enforced the
  encrypt-at-rest ciphertext columns on `sshkey` and `client`.
