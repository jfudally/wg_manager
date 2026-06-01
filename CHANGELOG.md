# Changelog

All notable changes to wg-manager are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
for any tagged releases. Pre-tag work lands under `## [Unreleased]`.

## [Unreleased]

### Added

- **Phase 2c CP4.5 — `wg-manager bootstrap-host` CLI.** Closes the
  gap CP4.4 created when it retired `wg_manager.ssh_migrate`: the
  production [`SSHRunner`](src/wg_manager/ssh.py) is locked to CA-only
  auth + `KnownHostsCAPolicy`, so a brand-new VM has nothing for it
  to talk to until `/etc/ssh/wg-manager-user-ca.pub` + a CA-signed
  host cert + the sshd drop-in are in place. Before CP4.5 operators
  had to hand-install those three files via plain `ssh`; the new CLI
  does it in one command. Wire shape:

  ```
  wg-manager bootstrap-host --hostname X --ssh-key ~/.ssh/id_ed25519 \
      [--principal P] [--ssh-user U] [--ssh-port 22] \
      [--ssh-key-passphrase PASS] [--ttl-seconds 86400]
  ```

  Opens an out-of-band SSH session with the operator-supplied
  long-lived key, mints a host cert against the Vault SSH CA,
  drops the three files at the canonical OpenSSH paths, and reloads
  sshd via a portable shell-or chain (systemctl reload sshd / ssh,
  service reload, kill -HUP sshd) so containerised + minimal hosts
  without systemd work too. **Does not touch the database** — the
  operator follows up with `wg-manager servers register` /
  `clients register` to catalogue the box.

  Architecture notes:
  - New module [`wg_manager.bootstrap_ssh`](src/wg_manager/bootstrap_ssh.py)
    holds the operator-driven runner (`BootstrapSSHRunner`) and the
    orchestrator (`bootstrap_host`). The bootstrap runner uses
    `paramiko.AutoAddPolicy` — TOFU once, knowingly — and is
    **never** imported from `tasks.py` so the production no-TOFU
    invariant is safe by construction. A dedicated unit test
    (`test_bootstrap_runner_does_not_install_known_hosts_ca_policy`)
    locks the policy choice down so a future "harden the bootstrap"
    refactor can't accidentally dual-install the CA policy and leak
    TOFU back into the production path.
  - [`host_ssh.py`](src/wg_manager/host_ssh.py) refactored: new
    `HostInstallRunner` Protocol (sudo + write_file) lets the new
    `_install_host_cert_files(*, runner, ca, principal, ttl_seconds)`
    lower-level worker drive either runner without an adapter.
    `install_host_cert` (the production task-layer call site) becomes
    the Server-shaped wrapper around it.
  - Audit emission: every successful bootstrap emits one
    `event=bootstrap.host` line on the existing `wg_manager.audit`
    logger with `hostname`, `principal`, `cert_serial`, `cn` — joins
    the Phase 2d CP5 audit stream so SIEM rules can match the install
    alongside auth admit/reject decisions.
  - Tests: 4 unit cases in
    [`tests/test_bootstrap_ssh.py`](tests/test_bootstrap_ssh.py)
    (AutoAddPolicy wiring, no-CA-policy lock, three-file orchestration,
    audit emission) + 5 CLI cases in
    [`tests/test_cli_bootstrap_host.py`](tests/test_cli_bootstrap_host.py)
    (required args, principal default, principal override, success
    summary, Vault-unreachable exit code) + 1 end-to-end case in
    [`tests/e2e/test_bootstrap_host.py`](tests/e2e/test_bootstrap_host.py)
    that drives the full pre-fail → bootstrap → post-succeed → audit-
    line arc against the existing CP5 dockerised sshd. Backend
    pytest 405/405; e2e 6/6.
- **Phase 2d CP5 — mTLS acceptance suite + audit emission + revoked-cert gate.**
  Lands as a single checkpoint that closes Phase 2d. Six tests under
  the new [`tests/e2e/tls/`](tests/e2e/tls/) bucket (separate from
  the Phase 2c CP5 dockerised-sshd suite) wear the dedicated
  `e2e_tls` pytest marker and run via `make test-e2e-tls`. The bucket
  spins a real `uvicorn` subprocess with mTLS enforced (server cert
  + CA bundle minted from a session-shared
  [`LocalDevPKI`](src/wg_manager/pki.py) hierarchy pinned into the
  subprocess env via `PKI_LOCAL_DEV_*` so the test process + the API
  process share one trust root) against a SQLite-backed schema. The
  four ROADMAP acceptance criteria split into three
  always-on tests + one opt-in:
  - **Plain-HTTP refused** — raw-socket `GET / HTTP/1.1` never
    produces an HTTP status line; `httpx` against `http://…` raises
    `httpx.TransportError`.
  - **Expired client cert** — TLS handshake refuses a 2-second-TTL
    cert after a 4-second sleep; a follow-up assertion verifies the
    listener didn't crash. (Implementation note: enforcement happens
    at the TLS layer, not the middleware, because bypassing
    OpenSSL's date check requires non-stable Python knobs and TLS
    rejection terminates the handshake before any app code runs —
    the audit-line half of the original criterion is reserved for
    app-layer rejections, which CP5.3 covers.)
  - **Revoked cert → 401 + audit line** — full lifecycle: bootstrap
    admin issues a `cli` cert via `POST /certs` (writes a row in the
    audit registry), uses it (200 + `auth.admit` audit line),
    revokes it via `POST /certs/{id}/revoke` (CRL + row flip), uses
    it again (401 `"operator cert revoked"` + `auth.reject` audit
    line with `reason="operator-cert-revoked"` naming the same
    serial). The middleware reads `certificate.revoked` by
    serial-as-string on every request; a cert with no registry row
    is admitted (keeps the bootstrap chicken-and-egg path open).
  - **MySQL cert rotation under load** — opt-in via
    `WGM_CP5_MYSQL=1` because the full shape requires a TLS-enabled
    mysqld + a wg-manager `mysql-client` cert + admin creds for
    `ALTER INSTANCE RELOAD TLS`, substantially more bootstrap than
    the rest of the suite handles in-process. The default
    `make test-e2e-tls` invocation reports the test as skipped with
    a one-line runbook pointer.
  
  Feature additions that landed in support of CP5:
  - **`wg_manager.audit` named logger** + `_emit_audit` helper. Every
    `MTLSAuthMiddleware` decision (admit + every reject reason)
    emits one JSON record at WARNING level with `ts`, `event`, `cn`,
    `serial`, `role` (admit only), `reason` (reject only), `method`,
    `path`. Routable to syslog / SIEM by attaching a handler to the
    `wg_manager.audit` logger name without touching the module.
  - **Revoked-cert gate** in `MTLSAuthMiddleware.dispatch`. Consults
    the `certificate` table after the operator-registry admit, 401s
    if the row says `revoked=True`. A cert without a registry row
    is admitted on the strength of its operator row alone (bootstrap
    + legacy-cert path stays open).
  - **`tests/e2e/conftest.py` marker tightening** — the auto-tag
    hook now only marks tests that are *direct children* of
    `tests/e2e/`, so the `e2e` marker (sshd suite) and the
    `e2e_tls` marker (Phase 2d) stay cleanly separated.
  - Backend test suite **396 / 396 passing** in local mode (+7 from
    `TestAuditEmission` and `TestRevokedCertGate` in
    `tests/test_auth.py`); 6 e2e_tls tests pass in ~5 s on a warm
    laptop, 1 skipped pending the opt-in MySQL bootstrap.
  
  Docs sweep:
  - ROADMAP § Phase 2d header flipped to **shipped (2026-05-31)**;
    CP5 entry flipped to `[x]` with per-test summary + the
    architectural notes on the expired-cert and rotation-under-load
    interpretations.
  - SECURITY.md current-posture table gains three rows
    (per-request audit emission, revoked-cert gate, end-to-end
    acceptance suite); the hardening-recommendations preamble flips
    to "Phase 2d feature-complete".
  - THREAT_MODEL.md T-7 and T-8 cite CP5 alongside their original
    closing checkpoints (CP3.2 and CP2 respectively); T-11
    (audit-log gap) flips from "Phase 2e" to "Phase 2e (storage
    hardening) — partially mitigated in Phase 2d CP5".
  - README.md `## Tests` section grows the `make test-e2e-tls`
    entry; "Roadmap, security, and threat model" section reflects
    Phase 2d as shipped.
- **Phase 2d CP4.4 — docs sweep around the renewal flow.** No code
  changes. New
  [`docs/deploy/systemd-timer.md`](docs/deploy/systemd-timer.md)
  ships the production deployment pattern: unit files for
  `wg-manager-cert-renew.{service,timer}` (hourly with a 5-minute
  jitter), the API/worker bounce pattern after a successful
  rotation, per-cert-type threshold tuning guidance (defaults
  appropriate for 30-day service certs vs. 365-day operator
  certs), and a disaster-recovery runbook for "the timer hasn't
  run in a while". README's "MySQL TLS" section drops the
  "CP4.3 will ship..." aside and grows a "Cert renewal (Phase 2d
  CP4.3)" section that walks the renew CLI + dashboard Renew
  button + systemd-timer doc. SECURITY.md's current-posture table
  flips three rows to "Phase 2d shipped" (`App ↔ MySQL traffic`,
  `Cert HTTP surface + dashboard`, `Cert renewal automation`); the
  hardening recommendations now lead with `DATABASE_TLS_REQUIRED`
  and the systemd timer. THREAT_MODEL.md flips T-7 / T-8 / T-9 to
  **Closed in Phase 2d**, refreshes the system-overview diagram so
  the operator-facing arrows are labelled `mTLS` and `TLS+mTLS`
  rather than `HTTP*` / `SQL*`, and updates B-1 / B-2 to "shipped".
- **Phase 2d CP4.3 — `wg-manager certs renew` + dashboard surface.**
  Six pieces ship together:
  - Alembic 0012 adds three nullable string columns to ``certificate``
    (``out_cert_path`` / ``out_key_path`` / ``out_chain_path``). The
    CLI's ``certs issue`` flow now populates them when ``--out-cert``
    et al. are passed; ``POST /certs`` (which never writes to disk)
    leaves them ``NULL``.
  - New ``POST /certs/{id}/renew`` (admin only) mints a fresh leaf
    with the same identity as the source row — same ``cert_type``,
    CN, SANs, operator FK, and TTL window length — and records a
    *new* audit row alongside it (the original stays put as the
    audit trail). Returns the same ``CertificateIssueResponse``
    envelope as ``POST /certs``, so a dashboard renew button reuses
    the existing artefact-download panel verbatim. 422 on revoked
    rows; 404 on unknown IDs.
  - New ``wg-manager certs renew`` CLI with two modes: ``--id N``
    re-mints one row (writing to the row's stored ``out_*_path``
    triple unless ``--out-cert/--out-key/--out-chain`` are passed
    explicitly), and ``--due`` walks the registry and re-mints every
    non-revoked row whose lifetime has crossed
    ``--threshold-pct`` (default 50). ``--dry-run`` prints what
    *would* be renewed; rows missing ``out_*_path`` are skipped with
    a warning so the walker doesn't strand half-written files.
  - Dashboard inventory grew a per-row **Renew** button (admin
    only, hidden on revoked rows) that POSTs to the new endpoint
    and surfaces the freshly-issued PEMs in the existing
    artefact-download panel. The "last delivered cert" state is now
    lifted to the page level so both the Issue form and the Renew
    action feed into the same panel — operators get one consistent
    place to grab fresh credentials.
  - Schema additions: ``CertificateRead`` surfaces the three
    out-paths so the CLI/API responses can describe them; the
    dashboard's ``Certificate`` type literal mirrors.
  - Tests: 4 new alembic-0012 cases (column adds + null/path
    inserts + downgrade round-trip), 2 new CLI ``issue`` cases
    pinning path-recording, 8 new CLI ``renew`` cases (single-id
    happy path / explicit-out-override / unknown-id / revoked /
    missing-paths / due-noop / due-only-renews-past-threshold /
    due-dry-run), 7 new API renew cases (happy / TTL-preserved /
    operator-FK-preserved / 404 / 422-revoked / role × 2), 4 new
    vitest specs (Renew button gated / auditor-no-button / POST
    wiring / artefact-panel surfaces), and 1 new ``api.test.ts``
    case for ``api.renewCertificate``. Backend ``pytest`` 389/389
    green; vitest 40/40; ``tsc --noEmit`` clean for the new code
    (pre-existing ``lib/proxy.ts:124`` complaint tracked
    separately).
- **Phase 2d CP4.2 — docker-compose MySQL TLS + `mysql-client` cert
  type.** Three pieces ship together:
  - `docker/mysql/conf.d/wg-manager-tls.cnf` — my.cnf drop-in that
    sets `require_secure_transport=ON` and points mysqld at the
    Vault-issued server cert + CA bundle (`ssl-ca`, `ssl-cert`,
    `ssl-key`). The docker-compose `mysql` service now bind-mounts
    `./tls/mysql:/etc/mysql/certs:ro` + `./docker/mysql/conf.d:
    /etc/mysql/conf.d:ro` so the daemon comes up TLS-only on
    `make db-down && make db-up`.
  - New cert type `CertificateType.mysql_client` (wire value
    ``"mysql-client"``): `clientAuth` EKU, no operator FK, 30-day
    default. The app + worker present this to MySQL once
    `DATABASE_TLS_REQUIRED=true` (CP4.1). Threaded through
    `wg_manager.cli._CERT_PROFILES`, the parallel
    `wg_manager.routers.certs._CERT_PROFILES`, and the dashboard's
    `CertificateType` literal + Issue-form dropdown.
  - New `make mysql-tls-issue` target that mints the server-side
    cert into `tls/mysql/` so the docker-compose bind mount has
    something to map. `.gitignore` keeps a tracked `tls/mysql/`
    placeholder so a fresh clone has a directory for the mount to
    bind onto.
  - `docs/migrations/2d-mysql-tls.md` documents the full
    bootstrap → bounce → engine-flip flow plus a recovery runbook
    for the "cert expired, can't connect" case.
  - Tests: 3 new CLI cases in `tests/test_cli_certs.py` (PEM write +
    audit row + clientAuth EKU check), 1 new API case in
    `tests/test_certs_api.py`, 8 new config-shape cases in
    `tests/test_mysql_tls_config.py` (my.cnf drop-in fields,
    docker-compose mount paths + `:ro` flags, Makefile target body),
    and 1 vitest spec pinning the dashboard's cert-type dropdown
    order. Backend `pytest` 368/368 green; vitest 36/36; `tsc
    --noEmit` clean for the new code (pre-existing
    `lib/proxy.ts:124` complaint is tracked separately).
- **Phase 2d CP4.1 — engine TLS wiring + Settings.** New
  `DATABASE_TLS_REQUIRED` / `DATABASE_TLS_CA_PEM` /
  `DATABASE_TLS_CERT_PEM` / `DATABASE_TLS_KEY_PEM` Settings fields
  drive a new `wg_manager.db._resolve_mysql_ssl` helper that
  materialises pymysql's `ssl={ca, cert, key, check_hostname}`
  connect-args dict for MySQL/MariaDB URLs. `_build_engine` threads
  the result through `create_engine`'s `connect_args` so the app +
  worker present a Vault-issued client cert to MySQL when TLS is
  required. The helper refuses to start (clear-message
  `RuntimeError`) if any of the three PEM paths is unset or points
  at a non-existent file. SQLite URLs short-circuit to the legacy
  `check_same_thread=False` shape, so the hermetic test suite stays
  untouched (and `DATABASE_TLS_REQUIRED=false` remains the default
  for the same reason — pre-CP4 deployments keep working). 9 new
  tests in `tests/test_db_tls.py` pin the resolver (SQLite
  short-circuit, MySQL without TLS, MySQL happy path, missing-PEM
  per env var, missing-file rejection, engine fallback to
  module-level settings). Backend `pytest` 357/357 green in `local`
  mode. The matching server-side `require_secure_transport=ON` config
  lands in CP4.2 alongside the docker-compose mounts.
- **Phase 2d CP3.4 — `/certs` HTTP surface + dashboard page.** New
  `wg_manager.routers.certs` exposes four endpoints over the CP3.3
  audit registry: `GET /certs/whoami` (any operator) returns the
  cert subject the API actually saw on the live TLS scope plus the
  resolved `Operator` row — a 200 here is the visible proof a
  freshly-imported PKCS#12 was accepted by the mTLS listener and
  matched against an active operator row; `GET /certs` (admin or
  auditor) lists every audit row, live + revoked; `POST /certs`
  (admin) mints a new leaf via the configured `PKIBackend` and
  records the row in the same transaction — the private key is
  surfaced exactly once in the response body and `dashboard` certs
  additionally carry a base64 PKCS#12 the browser saves as a single
  import file; `POST /certs/{id}/revoke` (admin) flips the row and
  tells the backend CRL, idempotent so a dashboard retry after a
  flaky network is safe. The `certs_password` / `operator_cn` /
  default-SAN logic mirrors `wg-manager certs issue` byte-for-byte so
  the CLI and the API produce identical leafs. Role gating uses
  router-local `_RequireAdmin` / `_RequireAdminOrAuditor` deps
  composed on a single `_get_operator` reader for testability.
  Dashboard: new `/certificates` page with a "Who am I?" splash,
  an inventory table (live/revoked badges, per-row Revoke action
  visible only to admins), an Issue form (cert type → CN → SANs →
  TTL → operator CN → optional PKCS#12 password), and a post-issue
  artefact-download panel (cert / key / chain / PKCS#12 buttons).
  New nav entry "Certificates". Tests: 18 router tests
  (`tests/test_certs_api.py` — whoami × 2, list × 3, issue × 7,
  revoke × 6) covering each endpoint's happy path, role gating, and
  failure modes; 6 vitest specs
  (`web/__tests__/certificates.test.tsx`) covering the splash, the
  inventory + revoke wiring, and the admin-vs-auditor affordance
  surfaces. Backend `pytest` 348/348 green; vitest 35/35.
- **Phase 2d CP3.3 — `certificate` table + `wg-manager certs` CLI.**
  Alembic 0011 adds a metadata-only audit registry keyed on the
  cert's decimal-string serial (BigInteger / SQLite INT64 overflow
  on the 160-bit X.509 serial drove the switch from BigInteger). New
  `wg-manager certs issue --type {api,cli,dashboard,mysql}` wraps
  `wg_manager.pki`: writes the leaf PEM + private key + chain to
  operator-supplied paths (`0o600` on the key), records the audit
  row in the same transaction, and refuses to issue `cli`/`dashboard`
  certs for a CN that isn't a registered `Operator`. `dashboard` mints
  a browser-importable PKCS#12 archive via `--out-pkcs12`. New
  `wg-manager certs revoke --serial` calls
  `PKIBackend.revoke_cert` and flips the row's `revoked` / `revoked_at`
  flags atomically; `wg-manager certs list` prints the table as
  JSON. New `wg-manager operators add/list` is the direct-DB
  bootstrap glue that closes the chicken-and-egg between cert
  issuance (which needs an Operator row) and the API (which needs a
  registered client cert) without going through the CP3.2 env
  bootstrap. Retires `scripts/issue_dev_tls.py` + `make tls-issue-dev`;
  README + `.env.example` + `web/.env.example` + `__main__.py` error
  message rewritten around the new flow.
- **Phase 2d CP3.2 — operator-registry middleware tightening.**
  `wg_manager.auth.MTLSAuthMiddleware` now reads the CP3.1
  `operator` table on every cert-bearing request: unknown CN → 401
  `operator not registered`; `status='disabled'` → 401 `operator
  disabled`; `active` → admission with the resolved (detached)
  `Operator` snapshot stashed on `request.state.operator` alongside
  `cert_subject`. New `AUTH_BOOTSTRAP_OPERATOR_CN` / `_ROLE` env
  knobs let the very first cert self-register so an empty registry
  doesn't lock the operator out. New `require_role(*OperatorRole)`
  FastAPI dep returns 403 `role not permitted` when the row's role
  isn't in the allow-list; empty allow-list raises `ValueError` at
  factory build so a typo can't silently turn the gate into a
  passthrough.
- **Phase 2d CP3.1 — `operator` table.** Alembic 0010 adds the
  CP3.2 mTLS allow-list registry with a unique-CN index, a
  three-tier `OperatorRole` enum (admin / operator / auditor —
  defaults to `operator` for principle-of-least-privilege), and an
  `OperatorStatus` enum (active / disabled — disabling preserves the
  audit-log linkage).

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
  `TLS_KEY_PEM` / `TLS_CA_BUNDLE_PEM`. The throwaway
  `make tls-issue-dev` helper that originally shipped with CP2 has
  been retired — Phase 2d CP3.3's `wg-manager certs issue` is the
  production-shaped replacement (it also records the issuance in the
  `certificate` audit table). The previous `uvicorn --reload` shape
  is removed; there is no longer a sanctioned wg-manager command
  that serves plain HTTP.
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
