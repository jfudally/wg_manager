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

- **Highest-impact asset.** SSH private keys used to provision managed
  hosts. Compromise = root on every node under management.
- **Realistic attacker.** Read-only access to the MySQL state store
  (leaked backup, SQLi, rogue insider).
- **Highest residual risk today.** wg-manager v1 stores SSH private keys
  as plaintext PEM in MySQL. Phase 2b of [`ROADMAP.md`](ROADMAP.md)
  replaces this with Vault Transit envelope encryption; Phase 2c
  eliminates the storage of SSH keys altogether by switching to
  Vault-signed short-lived certificates.

## Current posture (v1)

These are the things you should know before deploying wg-manager today.
They are not bugs — they are the explicit limits of what v1 set out to
build — but you should not run v1 against anything you care about.

| Concern                          | v1 state                                   | Closed in   |
| -------------------------------- | ------------------------------------------ | ----------- |
| SSH private keys at rest         | Plaintext PEM in `sshkey.private_key`      | Phase 2b/2c |
| SSH host-key verification        | TOFU (`paramiko.AutoAddPolicy`)            | Phase 2c    |
| API authentication               | None (bound to `127.0.0.1` only)           | Phase 2d    |
| App ↔ MySQL traffic              | Plaintext                                  | Phase 2d    |
| Audit logging of API mutations   | None beyond app logs                       | Phase 2e    |
| Supply-chain verification (SBOM, signed builds) | None                          | Phase 2e    |

## Hardening recommendations for v1 deployments

If you must run v1 before Phase 2 lands:

1. Keep the API bound to `127.0.0.1` and front it with `ssh -L` or a
   tightly scoped reverse proxy with auth.
2. Restrict the MySQL user to the smallest grant set that still works
   (no `FILE`, no `SUPER`).
3. Take encrypted MySQL backups (`mysqldump | age -r …`) and audit who
   can read them. A leaked backup is equivalent to a host compromise.
4. Use a **dedicated** SSH key per managed fleet so blast radius is
   bounded if the DB does leak.
5. Set passphrases on the SSH private keys even though the passphrase is
   stored next to them — it stops `cat sshkey.private_key | ssh -i -`
   trivial use. (Not real protection; Phase 2b fixes this properly.)

## Hall of thanks

Reporters who have responsibly disclosed issues will be listed here
after the first such report.
