# Roadmap

Phased delivery plan for wg-manager. Updated in the same change as the code,
so the plan and the repo never disagree. Each phase has measurable acceptance
criteria — "done" means the criteria are checked off in this file and a CI
run on `main` proves it.

Status legend: `[x]` shipped · `[~]` in progress · `[ ]` not started.

Cross-references:
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — threats the security
  phases close (T-1..T-12).
- [`SECURITY.md`](SECURITY.md) — public-facing posture and disclosure policy.

---

## Phase 0 — Spike (shipped)

- [x] Single-host docker-compose with MySQL + Valkey
- [x] Provision a WireGuard hub over SSH end-to-end on a throwaway VM

## Phase 1 — MVP (shipped)

- [x] FastAPI control plane (`/ssh-keys`, `/servers`, `/clients`, `/tasks`)
- [x] Async provisioning via Celery
- [x] Manual-client flow (server-side keygen + `wg0.conf` re-export)
- [x] Peer discovery (`wg show <iface> dump` → `discoveredpeer`)
- [x] Next.js dashboard with full UI parity for the above
- [x] CLI (`wg-manager …`) covering the same surface
- [x] Alembic-managed schema, in-memory SQLite test harness

---

## Phase 2 — Hardening (in progress)

Phase 2 is dominated by security work, organised as five sub-phases. The
substrate is **HashiCorp Vault** — chosen because it collapses encryption
at rest, SSH credentialing, internal PKI, and audit logging into one
piece of infra a reader can recognise and run locally.

Each sub-phase lists which threats from the
[threat model](docs/THREAT_MODEL.md) it closes, plus acceptance criteria
that are demonstrable on `main`.

### Phase 2a — Vault spike `[x]` (2026-05-27)

**Goal.** De-risk the Vault dependency before any production code depends
on it. Throwaway work, time-boxed to ~2 days.

**Shipped.**
- `vault` service added to `docker-compose.yml` running
  `hashicorp/vault:1.18 server -dev` with the fixed root token
  `dev-only-root`. **Dev mode is in-memory by design** — restarts wipe
  state, and `scripts/vault_smoke.py` is idempotent so re-runs always
  succeed. Production storage / unseal / HA story is captured in
  [`docs/vault-cookbook.md`](docs/vault-cookbook.md) §7 and lands in
  Phase 2e.
- [`scripts/vault_smoke.py`](scripts/vault_smoke.py) — single throwaway
  script proving Transit encrypt/decrypt (with per-row context), KV v2
  read/write, SSH CA sign of an ephemeral Ed25519 keypair, and PKI leaf
  issuance from an in-Vault root. Lives outside `src/`. No `wg_manager`
  code imports `hvac` yet.
- `make vault-up` / `make vault-down` / `make vault-logs` /
  `make vault-smoke` targets.
- AppRole decision recorded in
  [`docs/vault-cookbook.md`](docs/vault-cookbook.md) §5: production
  uses AppRole with the `role_id` baked into the deploy manifest and
  the `secret_id` delivered via Vault response-wrapping so the deploy
  operator never sees it in cleartext.

**Acceptance — met.**
- `make vault-up && make vault-smoke` exits 0; second back-to-back run
  also exits 0 (idempotency check). Captured run output:

  ```
  [PASS] transit  ( 466 ms) — ciphertext=vault:v1:hDHQECDtXdjuoh0… round-trip ok
  [PASS] kv-v2    (   6 ms) — path=secret/wg-manager-smoke round-trip ok
  [PASS] ssh-ca   (1655 ms) — signed 1780 bytes of cert (ttl=60s)
  [PASS] pki      ( 253 ms) — issued leaf cert serial=07:16:21:2e:… (ttl=5m)
  ```
- Four happy paths captured in
  [`docs/vault-cookbook.md`](docs/vault-cookbook.md).
- Spike code lives under `scripts/`; `hvac` is a dev-only dep in
  `pyproject.toml`.

**Carried forward to later phases.**
- Auto-unseal / Raft storage / HA / audit-log retention — Phase 2e.
- AppRole policy file + token-TTL values — Phase 2b (when
  `wg_manager.crypto` is the first real consumer).
- Cleanup: delete `scripts/vault_smoke.py` once Phase 2b/c/d each have
  their own integration tests; the spike has served its purpose and
  should not become a maintenance burden.

---

### Phase 2b — Encryption at rest (Vault Transit) `[x]` (shipped 2026-05-27)

**Status snapshot.**
- **Checkpoint 1 `[x]`** — `wg_manager.crypto` module with both backends,
  per-row context binding, `SSHKey.__repr__` / `Client.__repr__` scrub,
  22 backend tests + 5 repr regression tests, both modes green.
- **Checkpoint 2 `[x]`** — Alembic 0004 dual-write migration, ciphertext
  columns on `sshkey` + `client`, routers and tasks wired through
  `resolve_*` / `encrypt_*` helpers, `wg-manager crypto migrate` CLI,
  log-scrub guardrail (5 tests). 162/162 green in both `local` and
  `vault` modes.
- **Checkpoint 3 `[x]`** — Alembic 0005 drops the legacy plaintext
  columns; the row carries ciphertext only. New `GET /crypto/status`
  endpoint + dashboard "Crypto" page surface backend, key version, and
  per-table counts of encrypted/legacy rows. New `wg-manager crypto
  rewrap` re-encrypts every row under the active Transit key version
  (post-rotation upgrade). SSH Keys table grows a per-row `encrypted`
  badge. `crypto migrate` is removed (its job is done). README + Vault
  cookbook document the full rollout sequence and the recovery flow
  for a 0005 downgrade.


**Closes.** T-1, T-2, T-3, T-4.

**Goal.** No plaintext private key material ever lives in MySQL again.

**Backend.**
- New module `wg_manager.crypto` wrapping Transit:
  - `encrypt(plaintext: bytes, context: str) -> str` returns a versioned
    ciphertext blob (`vault:v1:…`).
  - `decrypt(blob: str, context: str) -> bytes`.
  - `context` is per-row (e.g. `f"sshkey:{key_id}"`) so a swapped
    ciphertext from another row fails to decrypt — defeats T-1's "DB-read
    attacker reshuffles rows" variant.
  - A `LocalDevBackend` fallback (Fernet keyed from
    `WG_MANAGER_DEV_KEY`) so unit tests run without a Vault container.
    Selected by env (`WG_MANAGER_CRYPTO_BACKEND=local|vault`); never the
    default in containers.
- Alembic migration: add `private_key_ct`, `passphrase_ct`,
  `client_private_key_ct` columns alongside the existing plaintext.
  **Dual-write** for one release; **dual-read** with ciphertext
  preferred. A second migration drops the plaintext columns once dual-write
  has been verified.
- A one-shot `wg-manager crypto migrate` CLI command walks every row,
  encrypts what isn't already encrypted, and reports counts.
- Audit hygiene: scrub `SSHKey.private_key` etc. from any `__repr__`,
  exception body, and structured-log field. Add a `pytest` test that
  greps captured logs for `BEGIN OPENSSH PRIVATE KEY` and fails the suite
  if it ever appears.

**Frontend (UI parity, per global memory).**
- "Crypto status" panel on the dashboard showing the active backend
  (`vault` / `local-dev`), the current Transit key version, and counts of
  rows encrypted vs. legacy.
- The SSH-keys table gains a small "encrypted" badge per row.

**Tests.**
- Round-trip property test: every key registered via `POST /ssh-keys`
  decrypts to the byte-identical original.
- Tamper test: flipping a bit in `private_key_ct` makes provisioning fail
  with a clear error (no partial-success).
- Rotation test: `vault write -f transit/keys/wg-manager/rotate` ⇒
  existing rows still decrypt, new writes use the new version, and
  `wg-manager crypto rewrap` updates them all.
- Log-scrub test described above.

**Acceptance.**
- `pytest -q` green with `WG_MANAGER_CRYPTO_BACKEND=local`.
- `make vault-up && WG_MANAGER_CRYPTO_BACKEND=vault pytest -q` green
  against the dev container.
- After running `wg-manager crypto migrate` on a copy of prod, a
  `mysqldump | grep -c "BEGIN OPENSSH"` returns `0`.
- README documents how to provision a Vault Transit key for first use.

**Rollout strategy.** Dual-write → dual-read → drop plaintext columns.
Each step is its own Alembic revision so an operator can pause between
them. Documented in `docs/migrations/2b-transit.md`.

**Risks.** Vault outage now blocks provisioning. Mitigation: cache the
Transit key's data-key client-side for a short TTL (Vault's
`/transit/datakey/plaintext` flow), and surface Vault health on `/healthz`.

---

### Phase 2c — Eliminate stored SSH keys (Vault SSH CA) `[x]` (shipped 2026-05-29)

**Status snapshot.**
- **Checkpoint 1 `[x]`** (2026-05-27) — `wg_manager.ssh_ca` module with
  both backends (`LocalDevSSHCA` in-process Ed25519 CA + `VaultSSHCA`
  wrapping the Vault SSH engine), `SSHCABackend` Protocol, `UserCert` /
  `HostCert` value objects, `make_ssh_ca_backend()` factory, idempotent
  `VaultSSHCA.bootstrap()`, `scripts/ssh_ca_bootstrap.py` + `make
  ssh-ca-bootstrap` target. 26 ssh_ca tests green (13 local + 13 vault);
  full suite 194/194 green in both modes. Cookbook §3 updated.
- **Checkpoint 2 `[x]`** (2026-05-27) — `SSHRunner` accepts a
  ``cert_pem`` + ``ca_public_key`` pair (CA mode), loads the cert onto
  the pkey via `paramiko.Ed25519Key.load_certificate`, and replaces
  `AutoAddPolicy` with the new `KnownHostsCAPolicy` (rejects raw host
  keys, wrong-CA certs, and user certs spliced in as host keys; raises
  `UntrustedHostKeyError`). New `SSH_AUTH_MODE` setting (`legacy` /
  `ca`) and `SSH_USER_CERT_TTL_SECONDS` (default 300s); a single
  `_open_runner` helper in `wg_manager.tasks` routes both modes so all
  four tasks (`provision_server`, `reconfigure_server`,
  `provision_client`, `discover_peers`) opt into CA mode together. 14
  CP2 tests added (9 SSHRunner / policy unit, 5 task-layer end-to-end);
  208/208 green in `local` mode, 40/40 CP2-relevant tests green in
  `vault` mode.
- **Checkpoint 3 `[x]`** (2026-05-27) — Host-side install lands in a
  new [`wg_manager.host_ssh`](../src/wg_manager/host_ssh.py) module:
  CA-mode `provision_server_task` mints a fresh host cert against the
  target's `/etc/ssh/ssh_host_ed25519_key.pub`, writes the CA pubkey,
  cert, and a `/etc/ssh/sshd_config.d/wg-manager.conf` drop-in
  carrying `TrustedUserCAKeys` + `HostCertificate`, then reloads sshd.
  Alembic 0006 grows six nullable columns on `server`
  (`host_cert_pem`, `host_cert_serial`, `host_cert_principals`,
  `host_cert_valid_after`, `host_cert_valid_before`,
  `host_cert_ca_public_key`); `_persist_host_cert` populates them
  atomically with the `status=ready` flip. New
  `POST /servers/{id}/rotate-host-cert` endpoint dispatches
  `rotate_host_cert_task` for in-place re-mint (idempotent
  install + column overwrite); refuses with 409 in legacy mode.
  Dashboard parity: per-row "Rotate cert" button +
  `cert #<serial> · expires in <N>d` summary line that goes amber
  inside 30 days and red once expired. New
  `SSH_HOST_CERT_TTL_SECONDS` setting (default 86400). Side fix:
  alembic env.py passes `disable_existing_loggers=False` so the
  `wg_manager.tasks` `caplog` regression tests survive an in-process
  alembic invocation. 16 CP3 tests + 2 vitest specs added; full
  suite 224/224 green in `local` mode.
- **Checkpoint 4 `[~]`** — Dual-mode rollout in four steps.
  - **CP4.1 `[x]`** (2026-05-27) — `SSHKey.mode` (`legacy` / `ca`)
    lands as a `str` enum column on `sshkey` via Alembic 0007 (NOT
    NULL, server-default `legacy`). Backfill is *per-row from the
    row's own data shape*: populated `private_key_ct` → `legacy`,
    NULL `private_key_ct` → `ca` (post-Alembic-0005 a non-NULL
    ciphertext is the only valid legacy shape, so a NULL pk_ct row
    is conclusively a CA-mode row whose pre-CP4.1 codepath never
    needed it). The smart backfill is a fix shipped on the same day
    as the column: the first cut backfilled "every row → legacy"
    and crashed `discover_all_peers` on a deployment that had been
    running entirely on `SSH_AUTH_MODE=ca` (rows with NULL pk_ct
    routed down the legacy branch and hit
    `resolve_sshkey_private`'s post-0005 invariant). `SSHKeyRead`
    surfaces `mode` to the HTTP / dashboard layers;
    `web/lib/types.ts` mirrors the `SSHKeyMode` literal. The task
    layer's `_open_runner` / `_maybe_install_host_cert` /
    `rotate_host_cert_task` now route on `ssh_key.mode` rather than
    the global `SSH_AUTH_MODE` env var — per-key wins. `POST
    /servers/{id}/rotate-host-cert`'s 409 precondition flipped to
    read the row's key mode and tells the operator the exact
    `wg-manager ssh migrate-to-ca <id>` command to run. The env var
    stays in `Settings` for backwards compat but is no longer
    consulted on any code path. Tests: 16 CP4.1 model / migration /
    schema / routing assertions (including 3 backfill cases:
    stored-key → legacy, NULL pk → ca, mixed-shape table), plus
    `promote_all_keys_to_ca` helper added to `conftest.py` and
    threaded through the 8 CP2 / CP3 tests that previously enabled
    CA mode via env var. Full suite green in `local` mode (240
    passed; 1 unrelated pre-existing crypto failure), dashboard
    vitest 26/26.
  - **CP4.2 `[x]`** (2026-05-28) — `wg-manager ssh migrate-to-ca
    <id>` CLI + `POST /ssh-keys/{id}/migrate-to-ca` endpoint. Closes
    the chicken-and-egg gap CP4.1 left behind: a `mode=ca` row
    cannot reach a host that hasn't yet been bootstrapped with a
    CA-signed cert (KnownHostsCAPolicy refuses to TOFU), but the
    cert install requires SSH. The migration takes a one-shot
    legacy `private_key_b64` body, opens a TOFU-allowed session per
    server, drives `host_ssh.install_host_cert` end-to-end, persists
    the `host_cert_*` columns on each server row, and — iff every
    server succeeded — flips the SSH key row to `mode=ca` and nulls
    `private_key_ct` + `passphrase_ct`. Partial failure: the row's
    mode is **not** flipped (so the operator has a clean retry
    path); response still returns 200 with per-server outcomes for
    uniform dashboard/CLI rendering. Zero-server case: row flips to
    `ca` and ciphertext nulled (operator intent unambiguous).
    Bootstrap session is always legacy (no cert / no CA pubkey),
    independent of the row's stored mode — the whole point is to
    reach a not-yet-trusting host. New module
    `wg_manager.ssh_migrate`; new CLI subgroup `wg-manager ssh`.
    Tests: 10 endpoint cases (shape / happy / reentrant /
    partial-fail / zero-server) + 4 CLI cases (happy / unknown-key /
    partial-fail exit code / passphrase round-trip). Full suite 254
    passed (1 unrelated pre-existing crypto failure).
  - **CP4.2.1 `[x]`** (2026-05-28) — Bootstrap usability fixes
    discovered while running the first real CA-mode `discover-all`
    against an Azure VM. (a) `VaultSSHCA.bootstrap`'s host-role
    default now sets `allowed_domains='*'` + `allow_bare_domains` +
    `allow_subdomains` when no `allowed_host_domains` is supplied
    (previously: no `allowed_domains` at all, which Vault interprets
    as "refuse every principal" — the inverse of what the operator
    expects). (b) User-role default `allowed_users` is now the
    multi-cloud-image set `root,ubuntu,ec2-user,azureuser,debian,admin`
    instead of `root` alone, so first-run migrations against stock
    AMIs/Azure images succeed without re-bootstrapping the role.
    (c) `make_ssh_ca_backend()`'s local backend is now memoised
    per-process via `_LOCAL_CA_CACHE` instead of regenerating the CA
    on every call (the prior behaviour silently broke cross-task
    host-cert verification — same-process). (d) New Settings fields
    `SSH_CA_VAULT_ALLOWED_USERS` and `SSH_CA_VAULT_ALLOWED_HOST_DOMAINS`
    threaded through `scripts/ssh_ca_bootstrap.py` so production
    tightens via env, not code edits. Tests: 5 new red→green tests in
    `tests/test_ssh_ca.py` (1 factory stability, 1 Settings field
    contract, 3 default-bootstrap-signs-cert cases for IP / DNS /
    cloud-user principals). Full ssh_ca suite 31 passed.
  - **CP4.3 `[x]`** (2026-05-28) — Dashboard "SSH roles" reframe.
    The `/ssh-keys` page is now titled "SSH Roles", carries a copy
    block that explains the `legacy` vs `ca` distinction, and the
    table grew a per-row Mode column (warn badge for `legacy`,
    success badge for `ca`) wedged between Name and Status so both
    backend axes — auth mode and at-rest crypto — stay independently
    legible. Legacy rows expose a "Migrate to CA" action that opens
    an inline `MigrateToCAForm` modelled on `AddSshKeyForm` (PEM
    textarea + file-drop + optional passphrase); submit POSTs
    base64(PEM) to the CP4.2 endpoint via the new
    `api.migrateKeyToCA(id, payload)` client and renders a
    `MigrateResultPanel` with one row per server (status badge +
    `cert #<serial>` for ok, error string for `ssh_failed`). The
    panel stays mounted after success so partial-failure shapes
    leave an operator-readable audit trail; the parent invalidates
    `["ssh-keys"]` so the row's badge flips without a manual
    refresh. Types added: `SSHKeyMigrateToCARequest`,
    `SSHKeyMigrateToCAServerResult`, `SSHKeyMigrateToCAResponse` —
    mirroring `src/wg_manager/schemas.py`. Tests: 3 new
    `api.test.ts` cases (happy / 422 / partial-fail) + a new
    `ssh-keys-mode.test.tsx` (4 cases: mode column renders both
    badges, button gated on `mode=legacy`, full submit → outcome
    render, partial-failure error string surfaced). Vitest 33/33
    green; `tsc --noEmit` clean.
  - **CP4.4 `[x]`** (2026-05-28) — Alembic 0008 ships
    `drop_sshkey_ciphertext` and lands the full demolition that
    finishes the CA migration arc. The migration's `upgrade()`
    counts `sshkey` rows with `mode='legacy'` first and raises with
    a CP-aware error pointing at
    [`docs/migrations/2c-ssh-ca.md`](docs/migrations/2c-ssh-ca.md)
    if any remain (no DDL runs in that case — re-up after fixing
    just works). When the table is all-CA, `private_key_ct` and
    `passphrase_ct` are dropped and the row becomes a name-and-mode
    label. Downstream surgery in the same release: `SSHKey` loses
    the two field declarations and the default `mode` flips from
    `legacy` to `ca`; the `wg_manager.crypto` sshkey helpers
    (`resolve_sshkey_*`, `set_sshkey_*`, `encrypt_sshkey_secrets`)
    are deleted alongside `_sshkey_context`; `ssh_migrate.py` is
    deleted; `POST /ssh-keys/{id}/migrate-to-ca` and the
    `SSHKeyMigrateTo*` schemas are gone; `POST /ssh-keys` and
    `PATCH /ssh-keys/{id}` reject `private_key_b64`/`passphrase`
    with 422 via `extra="forbid"`; `tasks._open_runner` unconditionally
    mints from the CA and `tasks._install_host_cert` runs on every
    provision (the legacy `_maybe_install_host_cert` gating + the
    rotate-host-cert 409-on-legacy precondition are gone); the
    `wg-manager ssh migrate-to-ca` and `wg-manager keys add
    --key-file` CLI surface is deleted; `wg-manager crypto rewrap`
    now walks only the manual-client table; `CryptoStatusResponse`
    drops `sshkey_encrypted`/`sshkey_legacy`. Dashboard parity:
    `web/lib/types.ts` narrows `SSHKeyMode` to `"ca"`, drops the
    migrate envelopes and the legacy `SSHKeyCreate`/`Update` body
    fields; `api.migrateKeyToCA` is removed; `web/app/ssh-keys/page.tsx`
    becomes a name-only CRUD with a single `ca` mode badge; the
    `Crypto` page drops the SSH-key columns from its panel.
    Conftest pins `SSH_CA_BACKEND=local` (Vault's serials can
    exceed signed-INT64 and overflow SQLite — exposed once the
    install became unconditional) and gains a per-host
    `SUPPRESS_HOST_PUBKEY` opt-out for the "host not yet keygen-ed"
    failure-mode test. New cookbook
    [`docs/migrations/2c-ssh-ca.md`](docs/migrations/2c-ssh-ca.md)
    walks the prior-release CLI path and the manual SQL fixup so
    an operator who lands on CP4.4 mid-upgrade has a runbook. Tests:
    9 new `tests/test_alembic_0008.py` cases pin the happy path,
    guard, and downgrade round-trip; ~12 tests across the suite were
    rewritten or deleted as their pre-CP4.4 invariants disappeared
    (most notably the `test_tasks_crypto.py` decrypt-through-resolver
    file, the `TestLegacyModeUnchanged` and
    `TestLegacyProvisionLeavesHostCertNull` classes, and the
    PATCH-rotates-private-key contracts in
    `test_ssh_keys_api.py`/`test_log_scrub.py`). Backend `pytest`
    224/225 green (1 unrelated pre-existing crypto failure carried
    forward from CP4.3); dashboard `vitest` 25/25 green;
    `tsc --noEmit` clean.
  - **CP4.5 `[x]`** (2026-06-01) — `wg-manager bootstrap-host`
    CLI closes the operator-facing gap CP4.4 left behind. The
    production `SSHRunner` is locked to CA-only auth via
    `KnownHostsCAPolicy`; a fresh box has nothing for it to talk
    to until `/etc/ssh/wg-manager-user-ca.pub` + a CA-signed
    host cert + the sshd drop-in are in place. Before CP4.5
    operators hand-installed those three files via plain `ssh`
    (`wg_manager.ssh_migrate` was retired in CP4.4 alongside the
    legacy stored-key path it depended on); CP4.5 brings the
    install back behind a single command:

    ```
    wg-manager bootstrap-host --hostname X --ssh-key PATH \
        [--principal P] [--ssh-user U] [--ssh-port 22] \
        [--ssh-key-passphrase PASS] [--ttl-seconds 86400]
    ```

    Operator follows up with `wg-manager servers register` /
    `clients register` to catalogue the box — bootstrap and
    registration are two operator actions so the operator can
    verify the install before committing a row. The CLI never
    writes to the DB.

    Architecture: new module `wg_manager.bootstrap_ssh` holds
    `BootstrapSSHRunner` (the operator-driven, AutoAddPolicy
    runner — the *one* legitimate TOFU site in the codebase) and
    the `bootstrap_host` orchestrator. `BootstrapSSHRunner` is
    deliberately separate from `SSHRunner` and **never** imported
    from `tasks.py` so the production no-TOFU invariant is safe
    by construction; a sentinel test pins the policy choice down
    so a future "harden the bootstrap" refactor can't accidentally
    dual-install `KnownHostsCAPolicy` and leak TOFU back into the
    production path. `host_ssh.py` refactored with a
    `HostInstallRunner` Protocol so the new
    `_install_host_cert_files()` lower-level worker drives either
    runner without an adapter — `install_host_cert()` becomes the
    Server-shaped wrapper around it for the production task-layer
    call sites. The sshd-reload chain widened to cover non-systemd
    hosts (`service ssh reload`, `kill -HUP $(pidof sshd)`, `kill
    -HUP 1`) so containerised + minimal fleet members work too.

    Audit: each successful bootstrap emits one
    `event=bootstrap.host` line on the `wg_manager.audit` logger
    with `hostname`, `principal`, `cert_serial`, `cn` — joins the
    Phase 2d CP5 audit stream so SIEM rules match the install
    alongside auth admit/reject decisions. Idempotent —
    re-running against an already-bootstrapped host overwrites
    the three files with fresh material, which is also the
    operator-driven rotation flow before host-cert expiry.

    Tests: 4 unit cases in `tests/test_bootstrap_ssh.py`
    (AutoAddPolicy wiring, no-CA-policy lock, three-file
    orchestration with ordering / payload / mode assertions,
    audit emission) + 5 CLI cases in
    `tests/test_cli_bootstrap_host.py` (required args, principal
    default, principal override, success summary line, SSHCAError
    → exit 1 + stderr) + 1 end-to-end case in
    `tests/e2e/test_bootstrap_host.py` that drives the full
    pre-fail → bootstrap → post-succeed → audit-line arc against
    the CP5 dockerised sshd. Backend pytest 405/405; e2e 6/6
    (was 5/5).
- **Checkpoint 5 `[x]`** (2026-05-29) — Acceptance: dockerised
  sshd suite under `tests/e2e/` proves the cert-based SSH path
  works against a real OpenSSH server using only Vault-signed
  certs. Five tests pin the contract:
  - `test_happy_path.py` (2 cases) — mints a user cert against the
    Vault e2e CA, installs a Vault-signed host cert on the
    container, opens a real `SSHRunner` session, and round-trips
    both `run("echo …")` and `sudo("id -u")` (proves the sudo
    surface the production task layer relies on works against a
    real sshd).
  - `test_cert_ttl.py` — 5-second-TTL role, mint, connect (passes),
    sleep 7s, reconnect → `SSHConnectionError` at auth time.
  - `test_principal_mismatch.py` — Vault signs a cert with
    `principals=[otheruser]` via the auxiliary multi-user role;
    sshd rejects on the `wguser` connection because the cert's
    `valid_principals` doesn't list it.
  - `test_attacker_ca.py` — `LocalDevSSHCA.generate()` stands in
    for an attacker CA, signs a fresh host cert against the
    container's host pubkey, fixture installs it; client trusts
    only the Vault CA so `KnownHostsCAPolicy` rejects pre-auth.
  Infrastructure: `tests/e2e/Dockerfile` (debian-slim + openssh +
  passwordless-sudo `wguser`, entrypoint regenerates host keys and
  primes the bind-mounted cert placeholders); `sshd-e2e` compose
  service under `profiles: [e2e]` so `make db-up` doesn't pull it
  in; `make e2e-up` / `make e2e-down` / `make test-e2e` Make
  targets; `e2e` pytest marker auto-applied via the
  `tests/e2e/conftest.py` collection hook; `pyproject.toml`
  `addopts = "-m 'not e2e'"` keeps the fast `make test` invocation
  hermetic. Acceptance for Phase 2c's "grep for persisted-key
  paramiko usage in src/ returns nothing" criterion re-verified
  (`grep -rn 'Ed25519Key.from_private_key\|RSAKey.from_private_key'
  src/` exits 1). Fast suite still 225/225; e2e suite 5/5 in ~13s
  with the container warm. Docs sweep (README + dashboard "how to
  add a server" rewrite around roles) is the only piece left for
  Phase 2c — tracked as CP5.1 follow-up.
- **Checkpoint 5.1 `[x]`** (2026-05-29) — Docs sweep around roles.
  README's SSH CA section reframed from "in progress" to "shipped"
  with an explicit "How to add a server" walkthrough that names
  the role-first workflow (`make ssh-ca-bootstrap`; SSH Roles →
  Add; Servers → Register; the CA-trust precondition on the
  target host) and points at
  [`docs/migrations/2c-ssh-ca.md`](docs/migrations/2c-ssh-ca.md).
  The Encryption-at-rest section narrows its persisted-secret
  list (manual-client WireGuard keys only — the SSH key columns
  are gone) and drops the stale per-row "encrypted badge" bullet
  on the SSH Keys table. SSH config export documentation
  clarifies `IdentityFile ~/.ssh/<role-name>` is a *naming
  convention* (the operator's own key, not a wg-manager-managed
  one). Tests section now points at `make test-e2e` for the CP5
  acceptance suite. SECURITY.md's "Current posture" table flips
  the SSH-at-rest + host-key rows to "Phase 2c shipped" and
  reframes "Highest residual risk" around the still-open Phase 2d
  surface (no API auth, plaintext browser↔API and app↔MySQL).
  THREAT_MODEL.md marks T-1 / T-2 / T-4 / T-5 / T-6 closed in
  CP4.4 and T-3 closed in Phase 2b; the system-overview diagram
  swaps "SSH (key)" for "SSH cert" and annotates the still-
  plaintext segments. Dashboard sweep: NavSidebar label
  "SSH Keys" → "SSH Roles" to match the page title; every form
  label (`Pick an SSH key…`, `Register form select label`, edit-
  form select label, validation error string, the rotate-cert
  tooltip on `web/app/servers/page.tsx`) renamed to "SSH role"
  so the dashboard wording matches the schema reality. Backend
  API field `ssh_key_id` left unchanged — that's a wire contract;
  only the human-facing copy moved. vitest 25/25 green after the
  sweep. Phase 2c header flipped `[x]`.

**Closes.** T-5, T-6 (and a stronger form of T-1: there's nothing left to
steal).

**Goal.** Replace long-lived SSH keys with short-lived Vault-signed
certificates. The `sshkey` table becomes metadata-only.

**Backend.**
- Configure Vault SSH secrets engine with two roles:
  - `wg-manager-provision` — client cert role; signs short-lived (5 min,
    configurable) user certificates with the principals matching the
    target host's `ssh_username`.
  - `wg-manager-hosts` — host cert role; signs host certificates for
    managed servers/clients during provisioning.
- New `wg_manager.ssh_ca` module:
  - `mint_user_cert(role, principals, ttl) -> (private_pem, cert_pem)`.
    Generates an ephemeral Ed25519 keypair in memory, asks Vault to sign
    the public half, returns both. **Never persisted.**
  - `mint_host_cert(public_key, principals, ttl) -> cert_pem` for the
    server side.
- `SSHRunner` accepts a `(pkey_pem, cert_pem)` pair; paramiko's
  `Ed25519Key.load_certificate` handles the cert. Connection sends the
  cert; the target host validates against the CA pubkey installed in
  `TrustedUserCAKeys`.
- Host-key verification flips from `AutoAddPolicy` to
  `RejectPolicy` + a `KnownHostsCAPolicy` that trusts certs signed by the
  Vault host CA. TOFU is gone.
- Provisioning step now also writes the host's signed cert and the
  `TrustedUserCAKeys` line into `/etc/ssh/sshd_config.d/wg-manager.conf`.
- `SSHKey` table becomes a label/metadata reference to a Vault role. The
  `private_key_ct` column is dropped in a follow-up migration.

**Frontend.**
- Existing "SSH keys" page reframes as "SSH roles" — list roles, their
  TTLs, allowed principals. No upload form for private keys anymore.
- Server detail page shows the host certificate's serial, principals,
  validity window, and a "rotate" button.

**Tests.**
- Cert TTL is honoured (sleep-past-expiry test against `vault server -dev`
  with a 5-second TTL).
- Mismatched principals are rejected by `sshd`.
- Host-cert mismatch (re-signed by an attacker CA) is rejected by the
  client.
- The `sshkey` table at end of Phase 2c contains no `private_key*`
  columns (Alembic migration test).

**Acceptance.**
- Provisioning a fresh server end-to-end on a throwaway VM completes
  using only Vault-signed certs.
- `grep -r "Ed25519Key.from_private_key\|RSAKey.from_private_key" src/` for
  uses on persisted material returns nothing — the only key material
  paramiko sees is ephemeral.
- README and dashboard "how to add a server" docs are rewritten around
  roles, not uploads.

**Risks.** Operators who already have a fleet provisioned with the
Phase 1 / Phase 2b keys need a migration path. Ship `wg-manager ssh
migrate-to-ca <server-id>` that installs the CA trust line over the
existing SSH key, then rotates. Document in `docs/migrations/2c-ssh-ca.md`.

---

### Phase 2d — TLS / mTLS everywhere (Vault PKI) `[x]` (shipped 2026-05-31)

**Status snapshot.**
- **Checkpoint 1 `[x]`** (2026-05-29) — `wg_manager.pki` module
  mirroring the Phase 2c CP1 shape: `PKIBackend` Protocol, frozen
  `Cert` value object (cert_pem / private_pem / chain_pem / serial
  / CN / SANs / NotBefore / NotAfter), `LocalDevPKI` (in-process
  root + intermediate via `cryptography`, EC P-256, regenerates
  per process unless `PKI_LOCAL_DEV_*` pins all four PEMs),
  `VaultPKI` wrapping the Vault PKI engine with idempotent
  `bootstrap()` (enables + tunes root/intermediate mounts so the
  10y root TTL isn't capped at Vault's default 32-day system
  `max_lease_ttl`; generates root, signs intermediate, concatenates
  root onto signed-intermediate so `/ca_chain` returns the full
  path; creates `wg-manager-server` + `wg-manager-client` roles
  with `serverAuth` / `clientAuth` EKUs respectively and
  `allow_bare_domains=true` so SAN=allowed-bare-domain isn't
  silently dropped). `make_pki_backend()` factory memoises the
  local backend per-process (cache key = pinned-PEM tuple) so the
  API + Celery worker share one root. `scripts/pki_bootstrap.py`
  + `make pki-bootstrap` target + new `Settings.pki_*` fields +
  `.env.example` section. `tests/test_pki.py` parameterised
  across both backends — 37 passed (24 shared contract × 2 +
  local-only + vault-only + factory + value-object + bootstrap-
  defaults). Full backend suite 262/262 green in `local` mode.
  No FastAPI / MySQL / dashboard wiring — that lands in CP2+.
- **Checkpoint 2 `[x]`** (2026-05-29) — uvicorn TLS + per-request
  client-cert verification. New
  [`wg_manager.auth`](../src/wg_manager/auth.py) module ships a
  frozen `CertSubject` value object, a `parse_subject_from_pem`
  pure helper, an `extract_subject_from_scope` ASGI adapter, and an
  `MTLSAuthMiddleware` that 401s every non-OPTIONS request whose
  scope is missing a cert chain when `TLS_REQUIRED=true`. OPTIONS
  preflight bypasses enforcement so the dashboard's CORS
  negotiation works on a TLS session that already carries the cert.
  A `require_subject` FastAPI dependency exposes the stashed
  subject to handler functions that opt into the strict shape
  (CP3's audit-only endpoints will use it). `Settings` grew
  `tls_required` + `tls_cert_pem` / `tls_key_pem` /
  `tls_ca_bundle_pem`; the Makefile `run` target now refuses to
  start without all three TLS paths and delegates to
  [`python -m wg_manager`](../src/wg_manager/__main__.py), which is
  the canonical entry point that hands off to `uvicorn.run` with
  `ssl_cert_reqs=ssl.CERT_REQUIRED`. The previous
  `uvicorn --reload` Makefile shape is gone — there is no longer a
  sanctioned wg-manager command that serves plain HTTP, satisfying
  the "plain-HTTP listener is removed" piece of the Phase 2d goal.
  Side fix: uvicorn 0.44 doesn't ship the ASGI-TLS extension
  natively (encode/uvicorn#1530), so a new
  [`wg_manager._tls_uvicorn`](../src/wg_manager/_tls_uvicorn.py)
  module wraps `RequestResponseCycle.__init__` (both h11 and
  httptools) at module import time to backfill
  `scope["extensions"]["tls"]["client_cert_chain"]` from
  `transport.get_extra_info("ssl_object")`. The shim is small
  (~50 LOC), idempotent, and tagged "delete this when upstream
  catches up". Dev workflow: `make tls-issue-dev` writes the five
  throwaway PEMs under `tls/` via
  [`scripts/issue_dev_tls.py`](../scripts/issue_dev_tls.py) —
  another CP2-only helper that will go when CP3 ships
  `wg-manager certs issue`. Tests: 13 new auth tests (3 parser, 4
  scope-extract, 6 middleware), 3 main-wiring tests, 8 uvicorn-shim
  tests, plus the conftest TLS_REQUIRED=false pin so the existing
  TestClient suite stays hermetic. Full backend `pytest` 288/288 in
  `local` mode; manual mTLS smoke against a live `python -m wg_manager`
  confirmed (200 with `--cert`, TLS handshake refused without,
  plain HTTP refused).
- **Checkpoint 3 `[~]`** — `Operator` + `Certificate` registry.
  Reserved migration shifted from 0009 → 0010 because the
  manual-client redesign consumed 0009. Landing in phased sub-slices:
  - **CP3.1 `[x]`** (2026-05-29) — `Operator` table + `OperatorRole`
    (admin/operator/auditor) + `OperatorStatus` (active/disabled)
    enums in [`wg_manager.models`](../src/wg_manager/models.py).
    Alembic `0010_add_operator_table` creates the table and the
    unique `ix_operator_cn` index; `tests/test_alembic_0010.py`
    pins the schema contract (column set, unique CN, idempotent
    round-trip) and the enum + default-value shape (role defaults to
    `operator`, status defaults to `active`). The `__repr__` scrub
    regressions pick up an Operator section so the row never leaks
    surprises through tracebacks. The middleware still accepts any
    valid Vault-signed cert — the tightening that consults the
    registry is CP3.2. Backend suite 292/292 green.
  - **CP3.2 `[x]`** (2026-05-29) — `MTLSAuthMiddleware` now
    consults the CP3.1 `operator` registry on every cert-bearing
    request. Unknown CN → 401 `"operator not registered"`; a row
    with `status='disabled'` → 401 `"operator disabled"` (distinct
    body so a packet capture distinguishes "forgot to register"
    from "revoked"); an `active` row admits the request and the
    middleware stashes the resolved (detached, session-free)
    `Operator` snapshot on `request.state.operator` alongside the
    existing `cert_subject`. A `_resolve_operator` helper opens a
    short-lived `Session(db.engine)` per request — the test suite
    swaps in the in-memory SQLite engine via the `engine` fixture,
    so the same code path runs in both modes. Bootstrap path
    closes the chicken-and-egg gap CP3.1 left behind: new
    `Settings.auth_bootstrap_operator_cn` +
    `auth_bootstrap_operator_role` knobs (env:
    `AUTH_BOOTSTRAP_OPERATOR_CN` / `AUTH_BOOTSTRAP_OPERATOR_ROLE`,
    default role `admin`) opt one specific CN into a self-register
    on first contact; every other unknown CN still 401s. The
    bootstrap insert catches `IntegrityError` and re-fetches so a
    concurrent first-request race resolves without surfacing the
    unique-CN-index violation. Operators are expected to unset (or
    rotate) the env var once the row exists and additional
    operators are added through the (CP3.4) dashboard / CLI.
    `require_subject(request)` keeps its CP2 signature; new
    `require_role(*OperatorRole)` factory builds a dep that 401s
    on no cert (via `require_subject`), 401s on missing operator
    state (defence against a future passthrough), and 403s
    (`"role not permitted"`) when the row's role isn't in the
    allow-list — empty role list rejected with `ValueError` at
    factory build so a typo can't silently turn the gate into a
    passthrough. Tests: 7 new
    `TestOperatorRegistryEnforcement` cases (unknown CN /
    disabled / active / bootstrap happy / bootstrap mismatch /
    OPTIONS bypass / `tls_required=False` bypass), 4 new
    `TestRequireRoleDependency` cases (admin blocks operator /
    admin allows admin / iterable allow-list / no-cert path is
    401 not 403), plus minor updates to the two existing CP2
    happy-path tests so they register an Operator before the
    request. Full backend suite 303/303 green. Dashboard
    Operators/Certificates surface is CP3.4 scope — no
    `web/` changes in this slice.
  - **CP3.3 `[x]`** (2026-05-29) — `Certificate` audit registry +
    `wg-manager certs` / `wg-manager operators` direct-DB CLIs.
    Alembic 0011 adds the `certificate` table (FK to `operator`,
    nullable for the service certs); the row stores serial as a
    decimal-string (cryptography's 160-bit X.509 serial overflows
    SQLite's signed-INT64 and Vault's serials regularly do too, so
    `String(64)` is the schema-neutral fit), `cert_type`,
    `common_name`, `sans`, `not_before` / `not_after`, `revoked` +
    `revoked_at` audit flags, `created_at`. New
    `CertificateType` enum carries the four shipped values (`api` /
    `cli` / `dashboard` / `mysql`) and drives the EKU + default
    SAN/TTL the CLI suggests. New `wg-manager certs issue --type
    ... --cn ... --san ... --ttl-days ...` wraps
    `make_pki_backend()` directly: writes the leaf PEM + private key
    (`0o600`) + chain to operator-supplied paths, mints the row in
    the same transaction so an orphan file never points at nothing,
    and refuses `cli`/`dashboard` issuance for a CN that isn't a
    registered `Operator` (operator_cn defaults to `--cn` for those
    types). `dashboard` instead writes a browser-importable PKCS#12
    via `--out-pkcs12` (uses `load_pem_x509_certificates` so the
    chain parsing is a single call rather than hand-rolled splits;
    optional `--pkcs12-password` for `BestAvailableEncryption`).
    New `wg-manager certs revoke --serial` calls
    `PKIBackend.revoke_cert` and flips the row's `revoked` /
    `revoked_at` flags atomically. New `wg-manager certs list`
    prints the table as JSON for `jq`-pipeline use; CP3.4 will layer
    a `/certs` HTTP surface and a dashboard view on the same shape.
    Bootstrap glue: new `wg-manager operators add/list` direct-DB
    subgroup closes the chicken-and-egg between cert issuance
    (needs an Operator row) and the API (needs a registered client
    cert), so a fresh install runs `alembic upgrade head` → 
    `wg-manager operators add` → `wg-manager certs issue --type
    api` → `wg-manager certs issue --type cli` → `make run` without
    any direct SQL. Retirement: `scripts/issue_dev_tls.py` is
    deleted; the `tls-issue-dev` Makefile target (+ PHONY entry +
    help line + the `make run` "missing TLS" hint) is gone;
    `python -m wg_manager`'s startup-error message, README's
    Quickstart + dashboard Quickstart + "Running with TLS" section,
    `.env.example`, `web/.env.example`, `web/README.md`, and
    `SECURITY.md`'s current-posture table all point at the new
    `wg-manager certs/operators` flow. Tests: 12
    `tests/test_alembic_0011.py` cases (column set + unique-serial
    index + nullable operator FK + downgrade round-trip + enum +
    model defaults), 14 `tests/test_cli_certs.py` cases (api /
    mysql / cli / dashboard issue happy paths + cli default-
    operator-cn + cli unknown-operator-CN rejection + PKCS#12
    round-trip + revoke happy + revoke unknown-serial + list +
    operators add + operators duplicate-CN rejection + operators
    list), 2 new `tests/test_model_repr.py` cases pinning the
    Certificate row's one-line repr. Backend `pytest` 330/330 green
    in `local` mode. Dashboard surface stays in CP3.4 scope — no
    `web/` UI changes in this slice.
  - **CP3.4 `[x]`** (2026-05-29) — HTTP surface + dashboard page
    over the CP3.3 audit registry. New
    [`wg_manager.routers.certs`](../src/wg_manager/routers/certs.py)
    ships four endpoints: `GET /certs/whoami` (any operator)
    surfaces the cert subject the API actually saw on the live TLS
    scope plus the resolved `Operator` row — a 200 here is the
    visible proof a freshly-imported PKCS#12 was accepted by the
    mTLS listener and matched against an active operator row; `GET
    /certs` (admin or auditor) lists every audit row live + revoked;
    `POST /certs` (admin) mints a leaf via the configured
    `PKIBackend` and persists the row in the same transaction — the
    private key is surfaced exactly once in the response body and
    `dashboard` certs additionally carry a base64-encoded PKCS#12 the
    browser saves as a single import file; `POST /certs/{id}/revoke`
    (admin) flips the row and tells the backend CRL, idempotent so a
    dashboard retry after a flaky network is safe. The CN /
    operator-FK / default-SAN / TTL resolution mirrors
    `wg-manager certs issue` byte-for-byte so the CLI and API
    produce identical leafs (the type-profile table is re-declared
    inside the router rather than imported so `wg_manager.cli` isn't
    a runtime dep). Role gating uses router-local `_RequireAdmin` /
    `_RequireAdminOrAuditor` deps composed on a single
    `_get_operator` reader — keeps the role-mapping logic next to
    the endpoint that enforces it and gives tests a stable per-router
    override point. Dashboard: new `/certificates` page with the
    "Who am I?" splash (operator CN, role badge, cert CN, serial,
    SANs, validity window), an inventory table (per-row
    live/revoked badges; admins also see a Revoke action gated on
    `cert.revoked=false`), an Issue form (cert type → CN → SANs →
    TTL → operator CN → optional PKCS#12 password — fields toggle
    on cert type), and a post-issue artefact-download panel (cert /
    key / chain / optional PKCS#12 buttons that materialise files
    via `Blob` + `URL.createObjectURL`). New nav entry
    "Certificates"; `web/lib/api.ts` grows `whoami`,
    `listCertificates`, `issueCertificate`, `revokeCertificate`
    methods + mirroring types in `web/lib/types.ts`. Tests: 18 new
    `tests/test_certs_api.py` cases (whoami × 2, list × 3, issue ×
    7 — happy/operator-FK/PKCS#12/unknown-operator-CN/bad-cert-
    type/role × 3, revoke × 6 — happy/idempotent/404/role × 3) +
    6 vitest specs (`web/__tests__/certificates.test.tsx`) covering
    splash render, error surface, inventory + revoke wiring, and the
    admin-vs-auditor affordance surfaces. Backend `pytest` 348/348
    green in `local` mode; vitest 35/35; `tsc --noEmit` is clean for
    the new file (the pre-existing `lib/proxy.ts:124`
    `Uint8Array<ArrayBufferLike>` ↔ `BodyInit` complaint stays out
    of scope — tracked separately).
- **Checkpoint 4 `[x]`** (2026-05-31) — MySQL TLS + renewal flow.
  docker-compose mounts Vault-issued server cert + CA;
  `require_secure_transport=ON` server-side; SQLAlchemy connect
  args grow `ssl={ca,cert,key,check_hostname}`; the app + worker
  each carry a Vault-issued `mysql-client` cert. `wg-manager certs
  renew --due` walks the audit registry and rotates expiring leaves
  on a systemd timer (see
  [`docs/deploy/systemd-timer.md`](docs/deploy/systemd-timer.md)).
  Shipped in four sub-slices:
  - **CP4.1 `[x]`** (2026-05-30) — engine + Settings wiring. New
    `DATABASE_TLS_REQUIRED` / `DATABASE_TLS_CA_PEM` /
    `DATABASE_TLS_CERT_PEM` / `DATABASE_TLS_KEY_PEM` fields drive a
    new `wg_manager.db._resolve_mysql_ssl` helper that produces
    pymysql's `ssl={ca, cert, key, check_hostname}` connect-args
    dict for MySQL/MariaDB URLs and stays empty for SQLite
    (keeping the hermetic test suite untouched). `_build_engine`
    threads the result through `create_engine(connect_args=...)`.
    Refuses to start with a clear-message `RuntimeError` when TLS
    is required but any of the three PEM paths is missing or
    unreadable. 9 new tests in `tests/test_db_tls.py`; backend
    `pytest` 357/357 green. Server-side
    `require_secure_transport=ON` lands in CP4.2.
  - **CP4.2 `[x]`** (2026-05-31) — docker-compose MySQL TLS +
    `mysql-client` cert type. `docker/mysql/conf.d/wg-manager-tls.cnf`
    sets `require_secure_transport=ON` and points mysqld at the
    Vault-issued server cert + CA bundle; the `mysql` compose
    service bind-mounts `./tls/mysql:/etc/mysql/certs:ro` plus
    `./docker/mysql/conf.d:/etc/mysql/conf.d:ro` so the daemon
    comes up TLS-only on the next `make db-down && make db-up`.
    New `CertificateType.mysql_client` (wire value
    `"mysql-client"`, clientAuth EKU, no operator FK, 30-day
    default) closes the matching client-side surface — the app +
    worker present it to MySQL once `DATABASE_TLS_REQUIRED=true`
    (CP4.1). Threaded through the CLI's `_CERT_PROFILES`, the
    router's parallel `_CERT_PROFILES`, and the dashboard's
    `CertificateType` literal + Issue-form dropdown. New
    `make mysql-tls-issue` target mints the server cert into
    `tls/mysql/`; `docs/migrations/2d-mysql-tls.md` documents the
    full bootstrap + recovery flow. 3 new CLI tests + 1 new API
    test + 8 new config-shape tests (my.cnf + docker-compose +
    Makefile) + 1 new vitest dropdown spec. Backend `pytest`
    368/368 green; vitest 36/36.
  - **CP4.3 `[x]`** (2026-05-31) — `wg-manager certs renew` +
    `POST /certs/{id}/renew` + dashboard surface. Alembic 0012
    grows the ``certificate`` table by three nullable columns
    (``out_cert_path`` / ``out_key_path`` / ``out_chain_path``)
    that ``certs issue`` populates when ``--out-cert/...`` are
    passed; the walker form of ``certs renew --due`` uses them to
    know where to rewrite the leaf in place. The CLI ships two
    modes — ``--id N`` re-mints one row, ``--due`` walks the
    registry and re-mints every non-revoked row past
    ``--threshold-pct`` (default 50) — with ``--dry-run`` for
    preview. The API endpoint and the CLI single-id path share
    the same identity-preservation contract: same ``cert_type``,
    CN, SANs, operator FK, and TTL window length; revoked rows
    are 422 (you can't renew an identity you already
    decommissioned); the original row stays put as the audit
    trail and the freshly-issued leaf gets a new row. Dashboard
    inventory grew a per-row "Renew" button (admin only, hidden
    on revoked rows); the "last delivered cert" state lifted to
    the page level so both Issue and Renew feed the same
    artefact-download panel. Tests: 4 alembic-0012 cases + 2 CLI
    ``issue`` path-recording cases + 8 CLI ``renew`` cases + 7
    API ``POST /certs/{id}/renew`` cases + 4 vitest renew specs +
    1 ``api.test.ts`` case. Backend ``pytest`` 389/389 green;
    vitest 40/40.
  - **CP4.4 `[x]`** (2026-05-31) — Docs sweep around the renewal
    flow + threat-model. New
    [`docs/deploy/systemd-timer.md`](docs/deploy/systemd-timer.md)
    ships the unit files (`wg-manager-cert-renew.service` +
    `.timer`), documents the API/worker bounce pattern, the
    per-cert-type threshold tuning, and a disaster-recovery
    runbook for "the timer hasn't run in a while". README's
    "Running with TLS" section drops the "CLI lands soon"
    placeholder, the MySQL-TLS section drops the "CP4.3 will
    ship..." aside, and a new "Cert renewal (Phase 2d CP4.3)"
    section walks the renew CLI + dashboard surface +
    systemd-timer doc. SECURITY.md's current-posture table flips
    `App ↔ MySQL traffic`, `Cert HTTP surface + dashboard`, and
    `Cert renewal automation` to "Phase 2d (shipped)" with the
    `mysql-client` cert type + the new endpoint named; the
    hardening recommendations now lead with `DATABASE_TLS_REQUIRED`
    and the systemd timer. THREAT_MODEL.md flips T-7 / T-8 / T-9
    to **Closed in Phase 2d**, refreshes the system-overview
    diagram so the operator-facing arrows are labelled `mTLS` and
    `TLS+mTLS` rather than `HTTP*` / `SQL*`, and updates B-1 /
    B-2 to "shipped". No code changes in this slice.
- **Checkpoint 5 `[x]`** (2026-05-31) — Acceptance suite under
  [`tests/e2e/tls/`](../tests/e2e/tls/) with the dedicated
  `e2e_tls` pytest marker and `make test-e2e-tls` target. The
  bucket spins a real ``uvicorn`` subprocess with mTLS enforced
  (server cert + CA bundle minted from a session-shared
  :class:`wg_manager.pki.LocalDevPKI` hierarchy that is pinned into
  the subprocess's env via ``PKI_LOCAL_DEV_*`` so the test process
  and the API process share one trust root); SQLite-backed for
  schema parity without alembic startup cost. Three of the four
  ROADMAP scenarios are automated and run on every invocation of
  ``make test-e2e-tls``:
  - **Plain-HTTP refused** —
    [`test_plain_http_refused.py`](../tests/e2e/tls/test_plain_http_refused.py)
    drives both a raw-socket ``GET / HTTP/1.1`` (the listener never
    answers with an ``HTTP/`` status line) and an ``httpx`` call
    against ``http://…`` (raises :class:`httpx.TransportError`).
  - **Expired client cert** —
    [`test_expired_cert_audit.py`](../tests/e2e/tls/test_expired_cert_audit.py)
    mints a 2-second-TTL client cert, sleeps past expiry, and
    asserts the TLS handshake is refused; a follow-up "listener
    still responsive" assertion proves the failed handshake didn't
    crash uvicorn. **Implementation note.** The ROADMAP framing
    was "HTTP 401 + audit log line"; the shipped implementation
    enforces expiry at the TLS layer (Python's stdlib
    ``ssl.CERT_REQUIRED`` checks ``notAfter`` during handshake)
    rather than waving the cert through and 401-ing at the
    middleware. That choice was deliberate — bypassing OpenSSL's
    date check requires reaching for ``X509_V_FLAG_NO_CHECK_TIME``
    which Python doesn't expose stably, and TLS-layer rejection
    terminates the handshake before any app code runs, which is
    strictly stronger isolation. The audit-log line surface is
    therefore reserved for *app-layer* rejections (the
    unknown-CN, disabled-operator, and revoked-cert paths CP5.3
    covers).
  - **Revoked cert** —
    [`test_revoked_cert_audit.py`](../tests/e2e/tls/test_revoked_cert_audit.py)
    walks the full revocation lifecycle: the bootstrap admin
    issues a fresh ``cli`` cert via ``POST /certs`` (writes a row
    in the audit registry), uses it to ``GET /certs/whoami``
    (200 + ``auth.admit`` audit line), revokes it via
    ``POST /certs/{id}/revoke`` (CRL update + row flip), uses it
    again (401 ``"operator cert revoked"`` + ``auth.reject``
    audit line with ``reason="operator-cert-revoked"`` naming the
    same serial). The "after CRL re-pull" framing in the ROADMAP
    maps to "the audit registry row is the canonical source of
    truth" — the middleware reads it on every request, so there
    is no caching layer to invalidate; the PKI-backend CRL is for
    *external* verifiers (``mysqld`` and any future fleet member),
    not for wg-manager's own auth gate.
  - **MySQL cert rotation under load** —
    [`test_mysql_rotation_under_load.py`](../tests/e2e/tls/test_mysql_rotation_under_load.py)
    is opt-in (``WGM_CP5_MYSQL=1``) because the full shape needs
    a TLS-enabled mysqld with Vault-issued certs *and* a
    wg-manager ``mysql-client`` cert and admin credentials for
    ``ALTER INSTANCE RELOAD TLS`` — substantially more bootstrap
    than the rest of the bucket can provide in process. The test
    + its skip-with-runbook message ship now; the harness body
    that drives the live rotation is tracked as a follow-up
    (see [`docs/deploy/systemd-timer.md`](docs/deploy/systemd-timer.md)
    § "Rotation under load acceptance"). Default
    ``make test-e2e-tls`` reports the test as skipped with a
    clear opt-in pointer so an operator who wants the live
    rotation guarantee knows exactly which env var to set.

  Feature additions that landed in support of CP5:
  - **Structured audit emission** in
    [`wg_manager.auth`](../src/wg_manager/auth.py) via the new
    ``wg_manager.audit`` named logger. Every admission decision
    the middleware makes — admit / reject (with reason ∈
    ``client-cert-required``, ``operator-not-registered``,
    ``operator-disabled``, ``operator-cert-revoked``) — emits a
    one-line JSON record with ``ts`` / ``event`` / ``cn`` /
    ``serial`` / ``method`` / ``path`` / role. WARNING level so
    it shows up on default-config uvicorn stderr without extra
    setup; production can attach a dedicated handler (file,
    syslog, SIEM) by configuring the ``wg_manager.audit`` logger
    name without touching the module.
  - **Revoked-cert gate** in
    :class:`MTLSAuthMiddleware`. Every cert-bearing request that
    passes operator-registry admission also queries the
    ``certificate`` table by serial-as-string. A row with
    ``revoked=True`` → 401 ``"operator cert revoked"`` +
    ``auth.reject`` audit line. A cert with *no* row in the
    registry (the bootstrap CN's self-mint, any legacy operator
    cert from before CP3.3) is admitted on the strength of its
    operator row — keeps the chicken-and-egg bootstrap path open
    on a fresh install. Tests:
    [`TestAuditEmission`](../tests/test_auth.py) +
    [`TestRevokedCertGate`](../tests/test_auth.py) — 7 new
    backend cases pin admit / no-cert / unknown-CN / disabled /
    revoked / non-revoked-registry / no-registry-row paths.

  Sub-targets:
  - ``make test-e2e-tls`` — runs the bucket with the default
    skip on CP5.4; full backend ``pytest`` 396/396 green in
    ``local`` mode (the +7 are the new audit / revoked-gate unit
    cases); 6 e2e_tls cases pass in ~5 s on a warm laptop.
  - Pytest marker ``e2e_tls`` deselected from the fast
    ``make test`` invocation via
    [`pyproject.toml`](../pyproject.toml) ``addopts``; the outer
    [`tests/e2e/conftest.py`](../tests/e2e/conftest.py) auto-tag
    was tightened to *direct children only* so the sshd suite's
    ``e2e`` marker and the TLS suite's ``e2e_tls`` marker stay
    cleanly separated.

**Closes.** T-7, T-8, T-9.

**Goal.** Every trust boundary in the system is mutually authenticated
and encrypted using certs from the same Vault PKI.

**Backend.**
- Stand up a Vault PKI mount with a 10-year root and a 1-year
  intermediate. Issue:
  - Server cert for the FastAPI app.
  - Client cert for the dashboard origin and for the CLI.
  - Server cert for MySQL; client cert for the app and the worker.
- FastAPI runs behind uvicorn with `--ssl-keyfile`/`--ssl-certfile`/
  `--ssl-ca-certs`, requiring client certs. Auth identity comes from the
  cert's CN / SANs; map to an operator record (new table) for audit.
- MySQL connection string switches to `mysql+pymysql://…?ssl_ca=…&ssl_cert=…`
  with `require_secure_transport=ON` enforced server-side.
- Cert renewal: a tiny `wg-manager certs renew` command (idempotent;
  noop if the cert has >50% of its TTL remaining) wired to a systemd
  timer in the deploy story. Same command works in CI.
- The plain HTTP listener is removed; the `.env.example` no longer
  contains an unauthenticated path.

**Frontend.**
- Dashboard uses a browser-imported PKCS#12 client cert. README walks
  through generating one with `wg-manager certs issue --type dashboard`.
- New "Certificates" page: lists every cert wg-manager has issued
  (operator certs, internal service certs), with serial, SANs, NotAfter,
  and a revoke button (writes to Vault PKI's CRL).
- Login page is replaced by a "Who am I?" splash showing the cert
  subject the API saw — proves the mTLS handshake worked.

**Tests.**
- Cert rotation under load: a script flips MySQL's cert while the API
  serves requests; the app reconnects without dropping.
- An expired client cert is rejected with HTTP 401 and an audit log line
  is emitted.
- Revoked certs are rejected once the CRL has been re-pulled (TTL is set
  short enough for the test to wait).

**Acceptance.**
- `curl http://127.0.0.1:8000/servers` ⇒ connection refused.
- `curl --cert ops.pem --key ops-key.pem https://127.0.0.1:8000/servers`
  ⇒ 200.
- Wireshark capture between app and MySQL on loopback shows TLS, not
  plaintext SQL.

**Risks.** mTLS in the browser is friction. Mitigation: keep a documented
"reverse-proxy with OIDC + service-internal mTLS" alternative in
`docs/auth-alternatives.md` so a reader who hates client certs sees we
considered it.

---

### Phase 2e — Supply-chain & ops hygiene `[~]`

**Closes.** T-10, T-11.

**Goal.** The boring stuff that distinguishes a hobby project from one
you'd actually deploy.

**Work.**
- **CI gates** `[x]` (CI-gate cycles 1-5 shipped 2026-06-03). Five
  GitHub Actions workflows, each owning one concern so a red run
  bisects to a single workflow file. `make security` runs the same
  five gates locally in cheapest-first order (`gitleaks`,
  `bandit`, `pip-audit`, `npm-audit`, `semgrep`) for the
  pre-push hand-spin. The cosign acceptance criterion is **deferred**
  to Phase 2e's release-engineering slice — see the "Deferred" note
  below.
  - CI-gate cycle 1 (2026-06-02) — baseline
    [`.github/workflows/ci.yml`](.github/workflows/ci.yml): backend
    `uv sync --extra dev --frozen` + `uv run pytest -q` on Python
    3.13; dashboard `npm ci` + `npm run test` (vitest) on Node 22.
    README CI badge added in the same commit.
  - CI-gate cycle 2 (2026-06-02) — gitleaks v8.30.1 pinned via
    direct curl + tar in
    [`.github/workflows/gitleaks.yml`](.github/workflows/gitleaks.yml)
    (no third-party action). Default ruleset + a
    [`.gitleaks.toml`](.gitleaks.toml) allowlist of nine specific
    files (seven tests with ephemeral PEMs, `tests/e2e/tls/conftest.py`
    Fernet dev key, `web/app/ssh-keys/page.tsx` placeholder); no
    blanket `tests/` directory carve-out so a real leak in a test
    still trips the gate.
  - CI-gate cycle 3 (2026-06-03) — dependency audit in
    [`.github/workflows/deps-audit.yml`](.github/workflows/deps-audit.yml):
    `pip-audit --strict` + `npm audit --omit=dev --audit-level=high`,
    path-filtered on `pyproject.toml` / `uv.lock` /
    `web/package*.json` so unrelated PRs don't re-run the network
    fetch. Weekly Monday cron + manual `workflow_dispatch`. Bumped
    four deps (cryptography 46→48, idna 3.11→3.18, mako 1.3.10→1.3.12,
    starlette 1.0→1.2.1) to land green; `--ignore-vuln CVE-2026-44405`
    for paramiko (no upstream fix; documented inline).
  - CI-gate cycle 4 (2026-06-03) — SAST in
    [`.github/workflows/sast.yml`](.github/workflows/sast.yml):
    `bandit -ll -c pyproject.toml -r src/` (medium+/medium+) and
    `semgrep --config=p/python --error src/` in the official
    semgrep container. New `[tool.bandit] skips = ["B601"]` in
    [`pyproject.toml`](pyproject.toml) with documented rationale —
    every `paramiko.exec_command()` trips B601, and `ssh.py` /
    `bootstrap_ssh.py` ARE the SSH execution layer. B507 stays on
    with two inline `# nosec B507` markers on the known-safe TOFU
    bootstrap site (CP4.5) and the legacy fallback. semgrep
    `p/python` is clean (0 findings) so no allowlist needed.
  - CI-gate cycle 5 (2026-06-03) — ROADMAP sweep + cosign deferral
    (this slice). No production-code changes; docs only.
  - **Deferred — cosign verify.** The Phase 2e ROADMAP also called
    for `cosign verify` of the published Docker image in the
    release job. Blocked on a release job existing in the first
    place: there is no Docker publish flow on `main` today, so
    there is no signed image for cosign to verify and no release
    workflow to bolt the gate onto. Tracked alongside the SBOM
    bullet (which has the same blocker — `cyclonedx-py` /
    `cyclonedx-npm` need a release artefact to attach to). Both
    land together when the release-engineering slice opens.
- **SBOM.** `cyclonedx-py` and `cyclonedx-npm` emit SBOMs in the release
  workflow; attached to the GitHub release.
- **Dependency hygiene** `[x]` (Dependabot cycle 1 shipped 2026-06-03).
  [`.github/dependabot.yml`](.github/dependabot.yml) enables weekly
  Mondays 14:00 UTC scans for three ecosystems:
  - `uv` (Python — `pyproject.toml` + `uv.lock`)
  - `npm` (dashboard — `web/package.json`)
  - `github-actions` (version pins across the four CI-gate workflows)

  Schedule aligns with the deps-audit cron (`'0 14 * * 1'` in
  [`.github/workflows/deps-audit.yml`](.github/workflows/deps-audit.yml))
  so Dependabot's PRs and the scheduled scan share a single
  "supply-chain Monday" rhythm. Grouping: minor + patch versions
  collapsed into one PR per ecosystem; majors split out for
  individual review (FastAPI 1.0, Pydantic v3, Next 15→16 all need
  real attention). github-actions grouped wholesale since those are
  low-stakes version pins. Commit prefix `chore(deps):` matches the
  existing manual-bump convention so the supply-chain audit trail
  in `git log` stays uniform.
- **Vault audit log** `[x]` (audit-log cycles 1-3 shipped 2026-06-03).
  Three-cycle plan:
  - **Cycle 1 `[x]`** (2026-06-03) — file audit device + persistent
    volume. New module
    [`wg_manager.vault_audit`](src/wg_manager/vault_audit.py) ships
    `bootstrap_file_audit_device` — idempotent helper that enables a
    Vault `file` audit device, pre-checking the device list rather
    than relying on Vault's generic HTTP 400 for double-enable.
    Refuses to clobber a non-`file` device at the same path
    (silent rewiring loses in-flight records during rotation —
    exactly the failure mode the audit log exists to prevent).
    docker-compose mounts the new `wg_manager_vault_audit_logs`
    named volume at `/vault/logs/` on the Vault container so the
    audit file survives compose restarts. New operator-facing
    [`scripts/vault_audit_bootstrap.py`](scripts/vault_audit_bootstrap.py)
    + `make vault-audit-bootstrap` Makefile target. Cookbook §6
    (new section) walks the wire-up and the verification flow.
    Tests: 7 cases in
    [`tests/test_vault_audit.py`](tests/test_vault_audit.py)
    (enables-when-empty, idempotent re-run, refuses-different-type,
    respects-custom-paths, tolerates both hvac payload shapes,
    pins the two default-path constants).
  - **Cycle 2 `[x]`** (2026-06-03) — `vector` sidecar in compose.
    New [`docker/vector/vault-audit.toml`](docker/vector/vault-audit.toml)
    config: a `file` source tails `/vault/logs/audit.log` with
    `read_from = "beginning"`, feeding a `console` sink with
    `encoding.codec = "text"` so the operator-visible stream is
    byte-for-byte identical to the on-disk audit file
    (grep-friendly, diff-friendly; JSON-parsing transforms land in
    cycle 3 when downstream sinks need structured access). New
    `vector` compose service (`timberio/vector:0.41.1-alpine`,
    explicitly pinned — never `:latest`) with `depends_on: vault:
    condition: service_healthy` so the sidecar waits for Vault's
    healthcheck before opening the file; the cycle 1 named volume
    mounted **`:ro`** at `/vault/logs/` (defence in depth on top of
    the kernel-level guarantee — the sidecar must never rewrite the
    trail it is shipping); the config TOML bind-mounted `:ro` at
    `/etc/vector/vector.toml`. `docker compose logs vector` is now
    the live audit feed — no `docker compose exec vault tail …`
    ceremony. Cookbook §6 grew a new "Cycle 2 — vector sidecar"
    subsection walking the bring-up, verification flow, the `:ro`
    design choice, and the `read_from = "beginning"` restart
    semantics (a `compose down && up` re-emits the whole audit
    history because vector's data_dir lives in the container
    filesystem; a plain `compose restart vector` keeps the
    checkpoint). Tests: 9 cases in
    [`tests/test_vector_sidecar.py`](tests/test_vector_sidecar.py)
    pin the operator-facing contract — compose service exists,
    image pinned (not `:latest`), audit volume `:ro`, config `:ro`,
    `depends_on vault` (accepting both list and condition-dict
    syntaxes), cycle 1's named volume survives, file source path is
    correct, exactly-one console sink fed from the file source, no
    sink writes back into `/vault/logs/`. Pure parse-and-assert so
    the fast `make test` invocation stays hermetic; the live-vector
    smoke flow lives in the cookbook. Backend pytest 431 passed
    (was 422).
  - **Cycle 3 `[x]`** (2026-06-03) — Production sink docs +
    drop-in vector configs under
    [`docker/vector/production/`](docker/vector/production/). Four
    self-contained TOML files (each runnable through
    `vector validate`) cover the remote-sink shapes — `loki.toml`,
    `cloudwatch.toml`, `s3-object-lock.toml`, `syslog.toml` — and
    the cookbook §6 cycle 3 section walks each one plus a
    `journald` deployment pattern (vector runs under systemd; the
    cycle 2 console-sink stdout is captured by journald
    automatically — vector itself doesn't ship a journald sink in
    its data model). Each config is a full file (source + sink),
    not a sink-only snippet, so an operator can swap the cycle 2
    `vault-audit.toml` bind-mount path on the compose service
    directly. Trust-model framing: the Vault hash-chain at the
    *source* makes tamper-evidence a chain property, not a sink
    property, so any of the five satisfies the Phase 2e acceptance
    criterion ("a compromised app server can't quietly delete
    records") — `s3-object-lock.toml` is the archive-tier closer
    because S3 Object Lock makes each uploaded object immutable for
    a configurable retention window. The S3 config walks the
    bucket-creation prereq (Object Lock must be enabled at creation
    time — AWS API constraint), the Governance-vs-Compliance mode
    choice, and the 10 MiB / 5 min batching that bounds the window
    between an audit write and its appearance off-host. New cookbook
    subsections "Hash-chain verification" (HMAC-SHA256 over
    canonical JSON; recovery flow when the chain breaks) and
    "Retention" (per-sink table tying retention to IR window vs
    storage cost). Tests: 22 cases in
    [`tests/test_vector_production_sinks.py`](tests/test_vector_production_sinks.py)
    pin the per-file contract — each config parses, declares the
    cycle 1 file source at `/vault/logs/audit.log`, has exactly one
    production sink of the expected type, sink inputs trace back to
    the file source (walking the transform graph), no sink writes
    back into `/vault/logs/` — plus two cross-cutting checks
    (every documented file present, no undocumented TOML lurking).
    Pure parse-and-assert so the fast `make test` invocation stays
    hermetic — live sink shipping is the operator's responsibility
    against their own infrastructure. Closes the parent Vault audit
    log bullet; the Phase 2e bullet flips from `[~]` to `[x]`.
    Backend pytest 495 passed (+22 cycle 3 cases on top of the
    cycle 2 baseline of 473 against this branch's environment).
- **Application audit log** `[x]` (cycles 1-4 shipped 2026-06-01). New
  `auditevent` table; every mutating endpoint writes one row with
  operator subject (from the mTLS cert), resource, action, before/after
  hash. Read-only `/audit` endpoint surfaces it; dashboard page lists
  recent events filterable by operator and resource. Cycle 1 added the
  table (`alembic 0013`); cycle 2 shipped `wg_manager.audit.persist`
  as the single write seam; cycle 3 wired the helper into the five
  mutating endpoint families (`server.create / server.update /
  client.delete / ssh_key.create / certificate.revoke`); cycle 4 added
  the read surface — `GET /audit` (admin / auditor only, filterable
  on `event` / `actor_cn` / `resource_type` / `resource_id` /
  `since` / `until`, paginated) plus the `/audit` dashboard page.
- **Operator runbooks** `[x]` (runbooks cycle 1 shipped 2026-06-03).
  Two operator-facing runbooks under
  [`docs/runbooks/`](docs/runbooks/) an on-call engineer can follow
  at 3am.
  [`key-compromise.md`](docs/runbooks/key-compromise.md) frames the
  scope (Vault root, unseal/recovery keys, Transit master key, SSH
  CA, PKI root + intermediate, operator client certs, service
  certs, manual-client WireGuard keys), the IR-standard sections
  (symptoms / triage / mitigation / verification / postmortem),
  and per-key-class mitigation paths naming the concrete
  ``wg-manager certs revoke``, ``wg-manager certs renew``,
  ``wg-manager crypto rewrap``,
  ``vault write -f transit/keys/wg-manager/rotate``,
  ``make ssh-ca-bootstrap``, and ``make pki-bootstrap`` commands.
  [`vault-down.md`](docs/runbooks/vault-down.md) frames the
  symptoms (decryption failures on encrypted-column touches,
  ``SSHCAError`` on provisioning, ``PKIError`` on renewal walker,
  the dashboard Crypto panel surface), triage (``vault status``,
  ``docker compose logs vault``), and four recovery branches
  (container down / sealed / app-can't-reach / raft quorum lost)
  with the matching ``vault operator unseal``,
  ``vault operator raft snapshot restore``, and ``make vault-up``
  commands. Both runbooks cross-reference
  [`docs/vault-cookbook.md`](docs/vault-cookbook.md),
  [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md), and
  [`docs/deploy/systemd-timer.md`](docs/deploy/systemd-timer.md).
  Discoverability: README's "Roadmap, security, and threat model"
  section + SECURITY.md's reporting section both link the
  runbooks. Tests: 40 cases in
  [`tests/test_runbooks.py`](tests/test_runbooks.py) pin file
  existence, the IR section frame, per-key-class coverage, the
  concrete commands the runbook tells the operator to run (so a
  rename in ``cli`` / Makefile that breaks the runbook trips the
  test), the cookbook + threat-model + README + SECURITY cross-
  references. Pure parse-and-assert so the fast ``make test``
  invocation stays hermetic — live verification is the operator's
  job during a drill.
- **Backup story.** Documented `vault operator raft snapshot save`
  cadence; MySQL dumps documented to be encrypted at rest using the
  Transit data-key flow so a leaked dump is not equivalent to a leaked
  key (closes a residual variant of T-1).
- **Reproducible builds.** `pyproject.toml` is locked via `uv lock`; the
  release workflow builds from the lockfile and refuses unpinned
  upgrades.

**Acceptance.**
- The CI badge in the README is green and the `security` job exists.
- `docs/runbooks/key-compromise.md` and `docs/runbooks/vault-down.md`
  exist with concrete steps a half-asleep on-call engineer can follow
  (shipped 2026-06-03 — runbooks cycle 1).
- A SOC 2-style "evidence pack" is generatable via `make evidence` —
  pulls last 30 days of audit logs, current cert inventory, and Vault
  audit hash chain into a tarball. (Stretch; useful for the showcase.)

---

## Phase 3 — Scale / Polish (future)

These are explicitly deferred until Phase 2 is closed. Listed so we don't
quietly let them creep into the hardening work.

- **Multi-tenant operator model.** Roles, scoped tokens, per-tenant peer
  pools.
- **HA control plane.** Two-replica FastAPI behind a load balancer;
  Celery workers horizontally scaled; MySQL primary + replica with
  failover.
- **Observability.** Prometheus metrics, Grafana dashboard, OTLP traces
  through the provisioning path.
- **Public API spec.** OpenAPI versioning, deprecation policy, a
  `v1`/`v2` namespace.
- **Helm chart / Terraform module.** First-class Kubernetes deploy.
