# Security Policy

## Supported versions

wg-manager is pre-1.0; only `main` is supported. Once a versioned release
exists, this section will list which lines receive fixes.

## Reporting a vulnerability

If you find a security issue, **do not open a public GitHub issue.**

Email `justinfudally@gmail.com` with:
- A short description of the issue.
- The minimum steps to reproduce it.
- Your assessment of impact (what an attacker can do).

I aim to acknowledge within 72 hours and to ship a fix or mitigation
within 30 days for high-severity issues. You will be credited in the
release notes unless you ask not to be.

PGP is not currently set up — if encrypted reporting matters to you, say
so in your first email and I will provision a key.

## Threat model

The full STRIDE model lives at
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). The short version:

- **Highest-impact asset historically.** SSH private keys used to
  provision managed hosts. Compromise = root on every node under
  management. wg-manager *no longer stores SSH private keys* as of
  Phase 2c CP4.4 — the `sshkey` table dropped the ciphertext
  columns in Alembic 0008, and every worker connection mints a
  short-lived Vault-signed user cert in memory instead.
- **Realistic attacker today.** With Phase 2d CP4 shipped, the only
  unencrypted/unauthenticated surface left in the control plane is
  the audit log (Phase 2e). A network attacker on the host loopback
  no longer sees plaintext SQL between the app and MySQL — the
  connection now negotiates TLS with a Vault-issued ``mysql-client``
  cert and the daemon refuses cleartext via
  ``require_secure_transport=ON``.
- **Highest residual risk today.** The Vault dev container is
  in-memory and unseals at boot — fine for development, **not**
  production. Run a real Vault before storing anything you care
  about (see [`docs/vault-cookbook.md`](docs/vault-cookbook.md) §6
  for the production-storage / auto-unseal story). Phase 2e adds
  the audit-log story and supply-chain pieces on top.

## Current posture

These are the things you should know before deploying wg-manager
today. They are not bugs — they are the explicit limits of what the
current phase set out to build — but you should not run wg-manager
against anything you care about until the *Closed in* column has
shipped for every row.

| Concern                          | State                                       | Closed in   |
| -------------------------------- | ------------------------------------------- | ----------- |
| SSH private keys at rest         | Not stored — Vault SSH CA mints per session | **Phase 2c (shipped)** |
| SSH host-key verification        | `KnownHostsCAPolicy` — host cert chain      | **Phase 2c (shipped)** |
| Manual-client WireGuard keys at rest | Vault Transit envelope-encrypted        | **Phase 2b (shipped)** |
| API authentication               | mTLS — `MTLSAuthMiddleware` rejects no-cert | **Phase 2d CP2 (shipped)** |
| Browser ↔ API traffic            | TLS terminated at uvicorn (CERT_REQUIRED)   | **Phase 2d CP2 (shipped)** |
| Operator registry + middleware tightening | `MTLSAuthMiddleware` rejects unknown/disabled CNs; bootstrap env knob seeds the first row | **Phase 2d CP3.2 (shipped)** |
| Cert audit registry + issuance CLI | `wg-manager certs issue/revoke/list` records every leaf in the `certificate` table | **Phase 2d CP3.3 (shipped)** |
| Cert HTTP surface + dashboard    | `/certs/{whoami,list,issue,revoke,renew}` + dashboard inventory + Renew button | **Phase 2d CP3.4 / CP4.3 (shipped)** |
| App ↔ MySQL traffic              | TLS — pymysql `ssl={ca,cert,key,check_hostname}` against `require_secure_transport=ON` | **Phase 2d CP4 (shipped)** |
| Cert renewal automation          | `wg-manager certs renew --due` walker + `POST /certs/{id}/renew` + per-row Renew button; systemd-timer pattern in `docs/deploy/systemd-timer.md` | **Phase 2d CP4.3 (shipped)** |
| Per-request audit emission       | `wg_manager.audit` logger emits one-line JSON for every admit / reject decision (cn / serial / role / reason / method / path) | **Phase 2d CP5 (shipped)** |
| Revoked-cert enforcement gate    | `MTLSAuthMiddleware` consults `certificate.revoked` by serial on every request — revoked → 401 + reject audit line | **Phase 2d CP5 (shipped)** |
| End-to-end acceptance suite      | `make test-e2e-tls` — plain-HTTP refused, expired cert handshake refused, revoked cert → 401 + audit line, MySQL rotation (opt-in via `WGM_CP5_MYSQL=1`) | **Phase 2d CP5 (shipped)** |
| Audit storage hardening          | Append-only / external log shipper          | Phase 2e    |
| Supply-chain verification (SBOM, signed builds) | None                           | Phase 2e    |

## Hardening recommendations for current deployments

Phase 2d is now feature-complete: the API listener is mTLS-only
(CP2), the operator registry tightens authz (CP3), the MySQL hop
is TLS + mutually authenticated (CP4), and the CP5 acceptance suite
pins all four behavioural contracts (plain-HTTP refused, expired
cert refused at handshake, revoked cert → 401 + structured audit
line, MySQL rotation under load — opt-in per the suite README). The
``wg_manager.audit`` JSON stream rides Python's ``logging`` so an
operator can route it to an external log shipper today by
configuring the logger name in their deploy. Phase 2e (audit
storage hardening, SBOM, signed builds) is the next chunk. If you
deploy today:

1. **Always set `TLS_REQUIRED=true`** — the default is `false` so the
   test suite stays hermetic, but running without it leaves the API
   unauthenticated. `make run` already refuses to start without the
   `TLS_CERT_PEM` / `TLS_KEY_PEM` / `TLS_CA_BUNDLE_PEM` paths.
2. **Set `DATABASE_TLS_REQUIRED=true`** and point at a Vault-issued
   `mysql-client` cert (see
   [`docs/migrations/2d-mysql-tls.md`](docs/migrations/2d-mysql-tls.md)
   for the bootstrap walkthrough). The docker-compose `mysql` service
   already ships the `require_secure_transport=ON` my.cnf drop-in;
   the engine has to hand pymysql the matching client cert for the
   handshake to complete.
3. **Wire up `wg-manager certs renew --due` on a systemd timer**
   (see [`docs/deploy/systemd-timer.md`](docs/deploy/systemd-timer.md)).
   The 30-day defaults on `api` / `mysql` / `mysql-client` leaves
   little headroom if rotation is manual.
4. Restrict the MySQL user to the smallest grant set that still works
   (no `FILE`, no `SUPER`).
5. Take encrypted MySQL backups (`mysqldump | age -r …`) and audit
   who can read them. A leaked backup no longer leaks SSH keys
   (Phase 2c) or app-↔-MySQL traffic (Phase 2d CP4), but still
   exposes manual-client WireGuard key ciphertext + every
   server/peer endpoint — bad enough.
6. Run a **production** Vault, not the dev container — the dev
   container is in-memory and wipes on restart. See
   [`docs/vault-cookbook.md`](docs/vault-cookbook.md) for the
   production-Vault story (file/raft storage, auto-unseal, audit
   log shipping).
7. Tighten the SSH CA roles' `allowed_users` and `allowed_domains`
   from their dev-friendly defaults to the specific accounts and
   FQDNs in use. The defaults cover cloud-image accounts (`ubuntu`,
   `ec2-user`, `azureuser`, …) for first-boot convenience; that's
   wider than a production deployment should accept.
8. Tighten the PKI role's `allowed_domains` (env:
   `PKI_VAULT_ALLOWED_DOMAINS`) once stable DNS is in place; the
   default permits any name so the first `make pki-bootstrap` run
   doesn't refuse a loopback-only fleet.

## Hall of thanks

Reporters who have responsibly disclosed issues will be listed here
after the first such report.
