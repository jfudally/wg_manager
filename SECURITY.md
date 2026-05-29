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
- **Realistic attacker today.** Network attacker on the unencrypted
  segments still open in Phase 2 (browser ↔ API, app ↔ MySQL).
  Closes in Phase 2d (TLS / mTLS everywhere via Vault PKI).
- **Highest residual risk today.** The API has no authentication;
  the only thing keeping unauthenticated mutations out is the bind
  to `127.0.0.1`. Closes in Phase 2d.

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
| API authentication               | None (bound to `127.0.0.1` only)            | Phase 2d    |
| App ↔ MySQL traffic              | Plaintext                                   | Phase 2d    |
| Audit logging of API mutations   | None beyond app logs                        | Phase 2e    |
| Supply-chain verification (SBOM, signed builds) | None                           | Phase 2e    |

## Hardening recommendations for current deployments

Even with Phase 2b + 2c shipped, Phase 2d (auth + TLS) and 2e
(supply chain + audit) are still ahead. If you must run today:

1. Keep the API bound to `127.0.0.1` and front it with `ssh -L` or a
   tightly scoped reverse proxy with auth.
2. Restrict the MySQL user to the smallest grant set that still works
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
