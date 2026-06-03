# wg-manager

[![CI](https://github.com/jfudally/wg_manager/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/jfudally/wg_manager/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/jfudally/wg_manager)](https://github.com/jfudally/wg_manager/releases)

**A control plane for hub-and-spoke WireGuard networks.** wg-manager
registers WireGuard hubs and spoke peers through a typed FastAPI
surface, a dashboard, and a CLI; provisions every node end-to-end over
SSH; and keeps the keys, certs, and audit trail in HashiCorp Vault.

## Why this exists

Running WireGuard at any scale beyond a single hub means a stack of
manual chores: keypair management, SSH config sharing, hub
reconfigs on every peer change, cert rotation, audit logging. Most
of that ends up in shell scripts and tribal knowledge.

wg-manager replaces those scripts with one typed surface backed by a
real security substrate:

- **No long-lived SSH keys.** The provisioning worker mints
  short-lived Vault-signed user certs in memory for every session.
- **Encryption at rest.** Manual-client WireGuard keys are
  Transit-encrypted; the master key never leaves Vault.
- **mTLS everywhere.** API, dashboard, MySQL — every trust
  boundary requires a Vault-issued cert.
- **Audited.** Every admit / reject / mutation lands in the
  `auditevent` table and the `wg_manager.audit` structured log
  stream. SOC 2-style evidence packs are one `make evidence` away.

## Status

**v0.1.0 shipped** (2026-06-03) — Phase 2 closed. Every release on
GHCR is cosign-signed via Fulcio keyless OIDC, carries a CycloneDX
SBOM attestation, and is end-to-end verifiable. **Phase 3a
(observability) shipped** — Prometheus metrics + Grafana
dashboards + OTLP traces + Prometheus alerting recipes are on
`main` ahead of the next tagged release. See
[`ROADMAP.md`](ROADMAP.md) for the full phase history (2a Vault
spike → 3a observability) and what's planned for the rest of
Phase 3 (multi-tenant, HA, public API versioning, Helm/Terraform).

## Architecture at a glance

```
       ┌────────────────────┐
       │ Operator           │
       │ (CLI + Dashboard)  │── mTLS ──┐
       └────────────────────┘          │
                                       ▼
                              ┌───────────────────┐
                              │ FastAPI control   │
                              │ plane (uvicorn)   │
                              └─┬───────────────┬─┘
                       mTLS     │               │     mTLS
                      ┌─────────┘               └─────────┐
                      ▼                                   ▼
            ┌──────────────────┐                ┌──────────────────┐
            │ MySQL (state) +  │                │ Vault             │
            │ Valkey (Celery)  │                │ - Transit         │
            └──────────────────┘                │ - SSH CA          │
                                                │ - PKI             │
                                                │ - Audit log       │
                                                └────────┬─────────┘
                                                         │ short-lived
                                                         │ SSH user certs
                                                         ▼
                              ┌────────────────────────────────┐
                              │ Celery worker (provisioning)   │
                              └─────────────┬──────────────────┘
                                            │ SSH (cert auth)
                                            ▼
                              ┌────────────────────────────────┐
                              │ WireGuard hubs + spoke peers   │
                              └────────────────────────────────┘
```

## Quickstart (local dev)

```bash
make db-up                    # MySQL + Valkey via docker compose
make vault-up                 # dev Vault on :8200
make install                  # editable install + dev deps
cp .env.example .env
make migrate                  # apply Alembic migrations
make ssh-ca-bootstrap         # configure Vault SSH CA
make pki-bootstrap            # configure Vault PKI

# Register the bootstrap operator + mint the dev TLS material:
wg-manager operators add --cn dev-operator --role admin
wg-manager certs issue --type api --cn 127.0.0.1 \
  --out-cert tls/server.crt --out-key tls/server.key \
  --out-chain tls/ca-bundle.crt
wg-manager certs issue --type cli --cn dev-operator \
  --out-cert tls/client.crt --out-key tls/client.key \
  --out-chain tls/client.chain.crt

export TLS_REQUIRED=true \
       TLS_CERT_PEM=tls/server.crt \
       TLS_KEY_PEM=tls/server.key \
       TLS_CA_BUNDLE_PEM=tls/ca-bundle.crt

# Terminal 1 — the API (uvicorn over mTLS on 127.0.0.1:8000):
make run

# Terminal 2 — the Celery provisioning worker:
make worker
```

OpenAPI docs live at `https://127.0.0.1:8000/docs` — point your
client cert at it.

For a deeper walkthrough (production TLS, MySQL TLS, registering
your first server end-to-end), see
[`docs/operator-guide.md`](docs/operator-guide.md).

## Try the dashboard

A Next.js + Tailwind dashboard lives in [`web/`](web/) and reaches
the API through a same-origin BFF proxy that handles the mTLS
handshake server-side — the browser never holds the client cert.

```bash
make ui-install                # one-time
cp web/.env.example web/.env.local
make ui-dev                    # http://127.0.0.1:3100
```

The dashboard ships a **Certificates** page that mirrors
`wg-manager certs` over HTTP: a "Who am I?" splash proving the
mTLS handshake worked, a per-row cert inventory with one-click
revoke for admins, an Issue form, and an SBOM/PKCS#12 download
panel. Auditors see the inventory; plain operators see neither.

See [`web/README.md`](web/README.md) for the BFF proxy design.

## Pull pre-built images

Every tagged release publishes two cosign-signed images to GHCR
with CycloneDX SBOM attestations. Verify before pulling:

```bash
cosign verify \
  --certificate-identity-regexp \
      'https://github.com/jfudally/wg_manager/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/jfudally/wg_manager:v0.1.0
```

Then pull:

```bash
docker pull ghcr.io/jfudally/wg_manager:v0.1.0       # API + worker
docker pull ghcr.io/jfudally/wg_manager-web:v0.1.0   # dashboard
```

The release page also attaches `sbom-api.cdx.json` +
`sbom-web.cdx.json` as downloadable assets. See
[`docs/release.md`](docs/release.md) for the full release flow
(SBOM diffing, attestation verify, cutting a new tag).

## Features

| Capability | Surface |
|---|---|
| Hub + spoke provisioning over SSH | `wg-manager servers register` / `clients register` |
| Manual clients for phones / IoT (server-side keygen, render `wg0.conf` once) | `wg-manager clients add-manual` |
| Peer discovery (`wg show … dump` parser) | `POST /servers/{id}/discover` |
| SSH config export of every managed client | `wg-manager clients ssh-config` |
| Async provisioning with Celery | `GET /tasks/{task_id}` |
| Cert lifecycle: issue, revoke, renew, list | `wg-manager certs *` |
| Vault Transit encryption at rest | `wg-manager crypto rewrap` |
| Application audit log (mutations) | `GET /audit` + dashboard `/audit` |
| Encrypted DB backups (Transit envelope) | `wg-manager db backup --encrypt` |
| Vault raft snapshot wrapper | `make backup-vault` |
| SOC 2-style evidence pack | `make evidence` |

## Operator docs

| Need | Doc |
|---|---|
| Add a server end-to-end | [`docs/operator-guide.md`](docs/operator-guide.md) |
| Cut a release | [`docs/release.md`](docs/release.md) |
| Cert renewal via systemd timer | [`docs/deploy/systemd-timer.md`](docs/deploy/systemd-timer.md) |
| Vault setup (raft storage, auto-unseal, audit log shipping) | [`docs/vault-cookbook.md`](docs/vault-cookbook.md) |
| Migrate to MySQL TLS | [`docs/migrations/2d-mysql-tls.md`](docs/migrations/2d-mysql-tls.md) |
| Migrate stored SSH keys → CA mode | [`docs/migrations/2c-ssh-ca.md`](docs/migrations/2c-ssh-ca.md) |
| Incident response — key compromise | [`docs/runbooks/key-compromise.md`](docs/runbooks/key-compromise.md) |
| Incident response — Vault down | [`docs/runbooks/vault-down.md`](docs/runbooks/vault-down.md) |
| Backup + restore drill | [`docs/runbooks/backup-restore.md`](docs/runbooks/backup-restore.md) |
| Observability: metrics + Grafana dashboard | [`docs/observability.md`](docs/observability.md) |

## Development

```bash
make test            # fast hermetic suite (in-memory SQLite, no docker)
make test-e2e        # dockerised sshd suite (needs vault-up + e2e-up)
make test-e2e-tls    # live uvicorn + mTLS acceptance suite
make security        # gitleaks + bandit + pip-audit + npm audit + semgrep
make lockfiles       # uv + npm lockfile parity check
```

The fast suite stays under 60s and uses an in-memory SQLite engine
plus a fake SSH runner — no docker, no Vault, no network. Both e2e
suites are opt-in via dedicated pytest markers (`e2e` and `e2e_tls`).

Schema is managed by Alembic:

```bash
make migrate                              # alembic upgrade head
make migrate-down                         # alembic downgrade -1
make migration m="add foo column"         # autogenerate a new revision
```

## Project docs

- [`ROADMAP.md`](ROADMAP.md) — every phase, every checkpoint, every
  decision. Phase 2 is closed; Phase 3 (multi-tenant, HA,
  observability) is the next named work-stream.
- [`SECURITY.md`](SECURITY.md) — current security posture,
  disclosure policy, hardening recommendations.
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — STRIDE model
  every roadmap phase ties back to.
- [`CHANGELOG.md`](CHANGELOG.md) — per-release notes.
