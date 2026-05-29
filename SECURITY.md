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
- **Realistic attacker today.** Network attacker on the still-
  plaintext app ↔ MySQL segment (Phase 2d CP2 closed the browser ↔
  API segment with mTLS; CP4 closes the MySQL hop).
- **Highest residual risk today.** App ↔ MySQL is still plaintext,
  so a network attacker on that segment can read every write the
  worker makes (including the manual-client ciphertext bound for
  the encryption-at-rest table). Closes in Phase 2d CP4.

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
| Operator / API cert registry     | Not yet — issuance is `make tls-issue-dev`  | Phase 2d CP3 |
| App ↔ MySQL traffic              | Plaintext                                   | Phase 2d CP4 |
| Audit logging of API mutations   | None beyond app logs                        | Phase 2e    |
| Supply-chain verification (SBOM, signed builds) | None                           | Phase 2e    |

## Hardening recommendations for current deployments

Phase 2d CP2 closes the API-listener slice (mTLS, cert-subject
extraction); CP3 (operator registry + cert-issuance CLI) and CP4
(MySQL TLS) are still ahead, alongside Phase 2e (supply chain +
audit). If you must run today:

1. **Always set `TLS_REQUIRED=true`** — the default is `false` so the
   test suite stays hermetic, but running without it leaves the API
   unauthenticated. `make run` already refuses to start without the
   `TLS_CERT_PEM` / `TLS_KEY_PEM` / `TLS_CA_BUNDLE_PEM` paths.
2. Keep the API bound to `127.0.0.1` (or a tightly-scoped private
   network) until CP3 ships the operator registry — a Vault-signed
   cert chain that satisfies `KnownHostsCAPolicy` but carries an
   unexpected CN is currently accepted as long as it validates
   against the configured CA bundle.
3. Restrict the MySQL user to the smallest grant set that still works
   (no `FILE`, no `SUPER`).
3. Take encrypted MySQL backups (`mysqldump | age -r …`) and audit who
   can read them. A leaked backup no longer leaks SSH keys (Phase 2c)
   but still exposes manual-client WireGuard key ciphertext + every
   server/peer endpoint — bad enough.
4. Run a **production** Vault, not the dev container — the dev
   container is in-memory and wipes on restart. See
   [`docs/vault-cookbook.md`](docs/vault-cookbook.md) for the
   production-Vault story (file/raft storage, auto-unseal, audit
   log shipping).
5. Tighten the SSH CA roles' `allowed_users` and `allowed_domains`
   from their dev-friendly defaults to the specific accounts and
   FQDNs in use. The defaults cover cloud-image accounts (`ubuntu`,
   `ec2-user`, `azureuser`, …) for first-boot convenience; that's
   wider than a production deployment should accept.

## Hall of thanks

Reporters who have responsibly disclosed issues will be listed here
after the first such report.
