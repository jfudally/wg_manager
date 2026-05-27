# Threat Model

A STRIDE-style threat model for wg-manager. Updated in the same change as the
code so the reader can always pin the design against the threats it claims to
defeat. Owned by the maintainer; reviewed at every roadmap phase boundary.

## 1. System overview

wg-manager is a control plane that registers WireGuard hubs ("servers") and
spokes ("clients") and provisions them over SSH. It exposes a FastAPI HTTP
API, persists state in MySQL, runs provisioning jobs in Celery workers
backed by Valkey, and ships a Next.js dashboard.

```
┌──────────────┐  HTTPS    ┌──────────────┐  SQL/TLS   ┌─────────┐
│  Operator    │──────────►│  FastAPI     │───────────►│ MySQL   │
│  (browser /  │           │  API +       │            └─────────┘
│   CLI)       │           │  Celery      │  SSH (key)  ┌─────────┐
└──────────────┘           │  worker      │────────────►│ managed │
                           └──────┬───────┘             │ host    │
                                  │                     └─────────┘
                                  │ AppRole / mTLS
                                  ▼
                           ┌──────────────┐
                           │ HashiCorp    │
                           │ Vault        │
                           └──────────────┘
```

## 2. Assets (ranked by impact if compromised)

| ID  | Asset                                             | Impact of disclosure                          |
| --- | ------------------------------------------------- | --------------------------------------------- |
| A-1 | SSH private keys used to provision managed hosts  | Root on every managed node                    |
| A-2 | WireGuard private keys (server + manual clients)  | Decrypt of traffic; impersonation of peer     |
| A-3 | API itself (any unauthenticated mutation)         | Add rogue peers, harvest configs              |
| A-4 | Vault unseal keys / root token (when introduced)  | Total compromise of all of the above          |
| A-5 | MySQL backups                                     | Same as DB read access (today: == A-1 + A-2)  |
| A-6 | Operator workstation / browser session            | API access at operator's privilege            |

## 3. Trust boundaries

- **B-1.** Browser ↔ FastAPI (today plain HTTP on 127.0.0.1; planned mTLS).
- **B-2.** FastAPI ↔ MySQL (today plain TCP; planned TLS + cert auth).
- **B-3.** FastAPI / worker ↔ Vault (planned mTLS + AppRole).
- **B-4.** Worker ↔ managed host (SSH; today TOFU host keys, planned host
  certificates).
- **B-5.** Operator ↔ managed host (post-provision; out of scope — wg-manager
  ends at writing `wg0.conf`).

## 4. Actors

- **U-1. Authorised operator.** Has API access; assumed trusted but
  fallible (phishing, lost laptop).
- **U-2. Network attacker.** Can sniff or MITM unencrypted segments.
- **U-3. DB-read attacker.** Has read access to MySQL (leaked backup, SQLi,
  rogue DBA). The most realistic "interesting" attacker for v1.
- **U-4. Host-compromise attacker.** Has shell on the wg-manager host.
  Game over by design; we limit blast radius, not prevent compromise.
- **U-5. Supply-chain attacker.** Publishes a malicious dependency.

## 5. Threats (STRIDE)

Each threat is tagged with the STRIDE category, the assets it targets, the
actors who can mount it, and the roadmap phase that closes it. See
[`../ROADMAP.md`](../ROADMAP.md) for phase definitions.

| ID   | STRIDE | Description                                                                         | Assets         | Actor      | Closed by  |
| ---- | ------ | ----------------------------------------------------------------------------------- | -------------- | ---------- | ---------- |
| T-1  | I      | SSH private keys readable from a MySQL dump or read-only DB access                  | A-1            | U-3        | Phase 2b   |
| T-2  | I      | SSH passphrase stored next to the key it protects (defeats the passphrase entirely) | A-1            | U-3        | Phase 2b   |
| T-3  | I      | WireGuard private keys for manual clients readable from DB                          | A-2            | U-3        | Phase 2b   |
| T-4  | I      | SSH key material leaks through error messages or logs                               | A-1            | U-3, U-4   | Phase 2b   |
| T-5  | T      | TOFU host-key acceptance (`AutoAddPolicy`) — MITM at first registration silently owns the channel | A-1, A-2 | U-2 | Phase 2c   |
| T-6  | I      | Long-lived SSH keys remain valid forever even when no longer needed                 | A-1            | U-3        | Phase 2c   |
| T-7  | S, E   | API has no auth — anyone with network access can register peers, rotate keys        | A-3            | U-2        | Phase 2d   |
| T-8  | I      | Browser ↔ API traffic in cleartext (cookies, tokens, config bodies)                 | A-1, A-2, A-3  | U-2        | Phase 2d   |
| T-9  | I      | App ↔ MySQL traffic in cleartext on the host network                                | A-1, A-2       | U-2        | Phase 2d   |
| T-10 | T      | Malicious dependency pulled at build time (paramiko, hvac, …)                       | All            | U-5        | Phase 2e   |
| T-11 | R      | Operator actions are not audit-logged — no forensic trail after an incident         | —              | U-1        | Phase 2e   |
| T-12 | D      | A single dead host on `discover-all` could hang every worker                        | Service uptime | U-4        | Already closed in v1 (fail-soft discovery, `connect_timeout`) |

## 6. Out of scope

- **Host-side compromise of a managed node** after provisioning. wg-manager
  delivers the config and steps away; defending the node itself is the
  operator's problem.
- **DoS via flooding the API.** Rate limiting will be added when the API
  leaves 127.0.0.1, not before.
- **Side-channel attacks on cryptographic primitives.** We rely on
  `cryptography` / `paramiko` / Vault to be correct.
- **Insider attack by an operator with valid credentials.** Audit logging
  (Phase 2e) provides detection, not prevention.

## 7. Assumptions

- Vault, once introduced, is operated correctly (auto-unseal, HA, audit log
  shipped off-host). Misconfigured Vault is its own threat we accept.
- The wg-manager host itself is reasonably hardened (OS patching, SSH
  hardening, no shared accounts). We are not building a TPM/HSM-grade system.
- Operators read the SSH config they install — wg-manager generates SSH
  config blocks but does not write to `~/.ssh/config` on their behalf.

## 8. Review cadence

- Re-read this document at the start of every Phase 2 sub-phase.
- Add a new threat row whenever a new asset or trust boundary is introduced.
- A threat that has been closed stays in the table with its closing phase
  noted, so a reader can see what the system has explicitly defended against.
