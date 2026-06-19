# Changelog

All notable changes to wg-manager are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
for any tagged releases. Pre-tag work lands under `## [Unreleased]`.

## [Unreleased]

### Added

## [v0.4.0] - 2026-06-19

### Fixed

- **`SSH_CA_VAULT_ALLOWED_USERS` / `SSH_CA_VAULT_ALLOWED_HOST_DOMAINS`
  now actually take effect from `.env.prod`.** The prod overlay
  hardcoded a small env block on `bootstrap-substrate` and didn't
  forward the SSH-CA role allowlists, so an operator extending
  `SSH_CA_VAULT_ALLOWED_USERS` to add a custom login account (e.g.
  ``justinfudally``) saw their edit silently ignored — Compose's
  `--env-file` only loads values for YAML interpolation, not for
  container env. Vault then kept refusing to sign user certs with
  the new principal at client provision time
  (``<user> is not a valid value for valid_principals``).
  Adds the passthrough in `docker-compose.prod.yml` (mirroring the
  existing `DEFAULT_SUBNET` shape), the example entry in
  `.env.prod.example`, and a regression test in
  `tests/test_compose_prod_bootstrap.py` so a future env-block
  cleanup can't quietly regress this.

### Changed

- **Register-server flow can now bootstrap the host in the same
  task.** Replaces the standalone "Bootstrap host" dashboard action
  and `POST /bootstrap-host` endpoint that shipped in v0.3.x with
  a collapsible "Bootstrap this host first" section inside the
  Register-server form. When the operator pastes their OOB SSH
  private key there, `provision_server_task` opens **one**
  `BootstrapSSHRunner` session (TOFU + operator key) before the
  regular CA-mode provision session, laying down the SSH CA trust
  + signed host cert + sshd drop-in. One row, one task, one click
  for fresh boxes; same behaviour as today when the box was
  already bootstrapped (CLI path, baked AMI).

  - **`ServerCreate`** schema (`src/wg_manager/schemas.py`) gains
    optional `bootstrap_ssh_key_pem` + `bootstrap_ssh_key_passphrase`
    fields. `POST /servers` encrypts both via the crypto backend
    (Vault Transit in prod) before queueing and forwards the
    ciphertext to the task. Passphrase without PEM is rejected at
    the schema layer so the operator's intent isn't silently
    dropped.
  - **`provision_server_task`** (`src/wg_manager/tasks.py`) accepts
    the new encrypted-bootstrap kwargs, decrypts in worker memory,
    and runs `bootstrap_host()` before opening the CA-mode session.
    The bootstrap step is skipped entirely when no PEM was supplied;
    today's "you forgot to bootstrap" failure mode
    (`host cert signed by an untrusted CA`) is preserved verbatim.
  - **Dashboard `/servers`** (`web/app/servers/page.tsx`) drops the
    standalone "Bootstrap host" button; the bootstrap section now
    lives inside the Register form behind a `<details>` toggle,
    defaulting collapsed so the common (already-bootstrapped) case
    stays one click.
  - **Removed**: `POST /bootstrap-host`, `bootstrap_host_task`,
    `BootstrapHostRequest` / `BootstrapHostResponse` schemas,
    `api.bootstrapHost()` client method, and the matching tests.
    The CLI (`wg-manager bootstrap-host`) still exists for
    scripted/CI use that wants the install separate from
    registration.
  - **Docs**: `docs/deploy/single-host-prod.md` updates "Path A —
    Dashboard" to describe the combined Register-with-bootstrap
    flow; Path B (CLI) is unchanged.

## [v0.3.0] - 2026-06-05

**Release theme**: Vault production posture. Closes the largest
"Known limitations" entry in `single-host-prod.md` — Vault now
runs with a real **file storage backend** instead of `-dev` mode,
and an automated init+unseal layer keeps the operator UX identical
to v0.2.x (edit `.env.prod`, `make prod-up`, done). State persists
across container restarts, so the `bootstrap-host`-installed CA
pubkey on a target host stays valid through a Vault container
restart — the exact bug class that motivated this work.

### Added

- **Production-mode Vault with auto-init + auto-unseal (PR #54).**
  The prod overlay swaps `vault server -dev` (in-memory, fixed
  root token) for `vault server -config=/vault/config/vault.hcl`
  with file storage at `/vault/file` on the
  `wg_manager_vault_data` named volume.

  - **`docker/vault/vault.hcl`** — file storage, HTTP listener on
    `0.0.0.0:8200`, ui on, `disable_mlock = true` for portability.
    No listener TLS — Vault is the PKI source for every other
    cert in the stack, so the listener can't depend on a Vault-
    minted cert at boot. A dedicated listener-TLS cycle is the
    honest next step.
  - **`scripts/vault_init_unseal.sh`** — idempotent state machine
    that runs from `prod_bootstrap_substrate.sh` BEFORE the engine
    bootstraps. Probes `/v1/sys/init` + `/v1/sys/seal-status`. On
    uninit: calls `vault operator init` via the HTTP API with 5
    shares / 3 threshold, captures the JSON output to
    `${VAULT_INIT_FILE}` (default `/app/vault-init.json`) at mode
    0600 owned by UID 1001 (the wg-manager runtime UID), then
    unseals. On sealed: reads the same file and unseals. On
    unsealed: no-op.
  - **`docker/entrypoint-wg-manager.sh`** — tiny shim baked into
    the wg-manager image. Reads `vault-init.json` when present +
    non-empty, exports the `root_token` field as `VAULT_TOKEN`
    before `exec`-ing the CMD. First-boot tolerant (empty file
    → no-op).
  - **`docker-compose.prod.yml` vault service** drops `VAULT_DEV_*`
    + `VAULT_TOKEN` env (blanked to `""` so Compose's environment-
    map merge doesn't ride the dev compose's values through).
    `entrypoint: ["vault"]` bypasses the official image's
    `docker-entrypoint.sh` which would otherwise APPEND
    `-dev-listen-address` and race vault.hcl's listener.
    Healthcheck override accepts 501 (uninit) / 503 (sealed) as
    healthy via `?standbyok=true&sealedcode=204&uninitcode=204`
    so bootstrap-substrate's `depends_on:
    { vault: service_healthy }` trips on the listener being up
    rather than the substrate being bootstrapped.
  - **api / worker / bootstrap-app** lose their `VAULT_TOKEN`
    env — the entrypoint shim sources it from `vault-init.json`
    instead. All four containers bind-mount `vault-init.json`
    (substrate writable, the rest read-only).
  - **`.env.prod.example`** drops `VAULT_ROOT_TOKEN` (auto-
    generated now), adds optional `VAULT_KEY_SHARES` /
    `VAULT_KEY_THRESHOLD` (defaults 5 / 3), documents the backup
    story (back up `vault-init.json` alongside `.env.prod`).
  - **`single-host-prod.md` Known Limitations table** flips the
    "Vault in dev mode" row to "Vault unseal keys live on disk
    in `vault-init.json`" — the honest residual gap. Real
    cloud-KMS auto-unseal (transit / awskms / gcpckms) is the
    next step but out of scope without cloud creds. The "Where
    state lives" table grows the three-file backup story
    (`.env.prod` + `vault-init.json` + `tls/`).
  - **End-to-end verified on rv.vpn**: clean `make prod-up` from
    zero state brings all 7 services healthy. Smoke on
    `/healthz`, `/readyz`, `/tenants` (default-tenant
    `subnet_pool` reflects the operator's `DEFAULT_SUBNET`),
    `/crypto/status` (Vault Transit backend) all 200. **Critical
    restart test**: `docker restart wg_manager_vault` → sealed →
    re-run `bootstrap-substrate` → auto-unseals from existing
    `vault-init.json` → all engine bootstraps log "already
    present" → Phase 1 complete. Final status:
    `storage_type: file, initialized: true, sealed: false`.

  Five bugs surfaced + fixed during verification (the full diary
  is in PR #54's body): vault image's `docker-entrypoint.sh`
  mangling the `server` command, missing `urllib.error` import,
  unquoted heredoc backtick command-substitution,
  `vault-init.json` UID mismatch from the Makefile `touch`, and a
  duplicate stale wait loop in `prod_bootstrap_substrate.sh`.

  **Tests**: 47 new cases across three new files plus extensions
  to four existing files. Backend pytest **1027/1027** in local
  mode (was 989 on v0.2.x's merge).

- **`docs/deploy/single-host-prod.md` gained an "Onboarding a
  target host (SSH CA install)" section (PR #53).** Recipe for
  running `wg-manager bootstrap-host` from inside the prod stack
  via `docker compose run --rm`, mounting `~/.ssh` read-only so
  the operator's pre-existing key reaches the container without
  exposing the rest of `$HOME`. The full design + cert profiles
  still live in `docs/operator-guide.md` §3; this is a
  deployment-side recipe rather than a duplicate. Closes the gap
  a real operator hit on rv.vpn: after `make prod-up` returned
  and they curl'd the API successfully, the next step ("how do I
  get wg-manager onto my first hub box?") wasn't covered in the
  deploy doc.

## [v0.2.1] - 2026-06-05

**Patch release**: closes a single bug class the v0.2.0 verification on
rv.vpn surfaced — `DEFAULT_SUBNET` (and `DEFAULT_WG_PORT`) set in
`.env.prod` were silently ignored by the production stack. The v0.2.0
prod overlay never propagated those `${VAR}`s into the containers
that needed them; operators set the override, watched nothing
change, and saw the default tenant come up with the code-default
`10.9.0.0/24` regardless.

### Fixed

- **`DEFAULT_SUBNET` + `DEFAULT_WG_PORT` now flow from `.env.prod`
  through the prod overlay (PR #50 + PR #51).** The two PRs together
  cover the full data path: request-time + migration-time.

  - **PR #50** — pass the two env vars through to `api` + `worker`.
    Without this, `Settings.default_subnet` on the running api falls
    back to the code default (`config.py:60` = `10.9.0.0/24`) on
    every `POST /servers` payload that omits the `subnet` field. The
    dashboard's "New server" form pre-fills from this value too, so
    an operator who set the override in `.env.prod` would see the
    pre-fill ignore them.
  - **PR #51** — same passthrough for `bootstrap-app`. Alembic
    migration `0016_add_tenant_subnet_pool.py:68` reads
    `live_settings.default_subnet` AT MIGRATION TIME to backfill the
    default tenant's `subnet_pool`. The migration runs inside
    `bootstrap-app` (the container that does `alembic upgrade head`),
    NOT inside api/worker. So even after PR #50 fixed the request-
    time path, the default tenant's `subnet_pool` still came up at
    `10.9.0.0/24` on every fresh-volume boot because `bootstrap-app`
    was missing the env. PR #51 closes the loop.

  Verified end-to-end on rv.vpn after both PRs landed: with
  `DEFAULT_SUBNET=10.8.0.0/24` in `.env.prod`, `make prod-down -v` +
  `make prod-up` brings the default tenant up with
  `subnet_pool='10.8.0.0/24'` (confirmed via both
  `SELECT * FROM tenant` directly against MySQL and
  `GET /v1/tenants` through the mTLS API).

  Operator remediation on a stack already bootstrapped with the
  buggy v0.2.0 default:
  - **A.** `make prod-down -v` + `make prod-up` on v0.2.1 — re-runs
    migration 0016 against the env-corrected `bootstrap-app`. Wipes
    state.
  - **B.** Manual SQL — `UPDATE tenant SET subnet_pool='<your-cidr>'
    WHERE id=1`. Preserves state.

  `.env.prod.example` grew a documented `DEFAULT_SUBNET` +
  `DEFAULT_WG_PORT` block explaining when an operator overrides
  (overlapping VPN address space with another stack, conflicting
  host routes). Tests grew two parametrised cases pinning the
  passthrough on api + bootstrap-app so the bug class can't
  re-emerge silently.

## [v0.2.0] - 2026-06-05

**Release theme**: production deployability. The dev compose became
an actual production compose (overlay + self-bootstrap), the HA
control plane went from doc to demo profile, and the observability
+ multi-tenancy + API-versioning work that landed since v0.1.0 came
along for the ride. Every shipped path picked up a regression test
the end-to-end verification work surfaced.

`make prod-up` is the single command from a fresh checkout to a
fully usable production stack: edit five values in `.env.prod`,
wait ~90 seconds, get an mTLS API + Celery worker + Next.js
dashboard + hardened MySQL + Vault + Valkey on the box.

### Added

- **Vault Transit engine + master key auto-bootstrap.** Closes the
  last gap in `make prod-up`: `scripts/transit_bootstrap.py` is
  invoked by `scripts/prod_bootstrap_substrate.sh` so a fresh
  Vault gets the Transit mount + the `wg-manager` master key
  (`derived=True`) provisioned automatically. Before this, the
  dashboard's Crypto page 500'd with
  `no handler for route transit/keys/wg-manager` on first load
  because `VaultTransitBackend` is deliberately dumb and the
  cookbook documented Transit setup as a manual step. Also exposed
  as `make transit-bootstrap` for operators driving Vault by hand.

- **Linux portability fixes for the self-bootstrap (PR #47).** PR
  #46's self-bootstrap worked on Docker Desktop on Mac but failed
  on every step against a real Linux host. Four distinct fixes:

  - **Bootstrap containers declare `user: "0:0"`** so they can
    write to the bind-mounted `./tls` on Linux hosts where the
    operator's UID (typically 1000) doesn't match the wg-manager
    image's `wgmanager` UID (1001). Docker Desktop on Mac papers
    over the mismatch transparently — pure Linux doesn't. End-of-
    script `chown -R 1001:1001` puts the cert files back into the
    runtime UID so api/worker/web can read them.
  - **Bootstrap scripts chmod *.key files to `0644`** so `mysql:8`
    inside its container (UID 999) can read the server.key even
    though the file is owned by UID 1001. Without this, mysqld
    fails to load TLS and the app gets
    `SSL is required but the server doesn't support it` on every
    connection attempt.
  - **`WG_MANAGER_API_BIND_PORT` + `WG_MANAGER_WEB_BIND_PORT`**
    env overrides for operators running multiple stacks on one
    host (or fronting the API behind a reverse proxy that owns
    443).
  - **`.env.prod.example` now recommends `openssl rand -hex 32`**
    for `VALKEY_PASSWORD` + `MYSQL_APP_PASSWORD` — these values
    get interpolated into `redis://:${pw}@valkey:...` and
    `mysql+pymysql://wg:${pw}@mysql:...` URLs, and the previous
    `openssl rand -base64` recommendation produced strings with
    `/+=` characters that broke URL parsing at startup.

- **Self-bootstrapping `docker-compose.prod.yml`.** Edit `.env.prod`,
  run `make prod-up`, get a fully usable production-shaped stack on
  the first invocation — no manual cert minting, no shell exports,
  no separate `make migrate` step. The previous 9-step runbook
  collapses to "fill in 5 values, run one command".

  - **Two run-to-completion bootstrap containers** break the
    cert/MySQL chicken-and-egg cleanly via Compose's
    `service_completed_successfully` primitive:
    - `bootstrap-substrate` — waits for Vault healthy, runs the
      Vault PKI / SSH CA / audit bootstraps (each idempotent), mints
      the MySQL server + client cert pair (`--type mysql` +
      `--type mysql-client` for the correct EKU split), exits.
      mysql + valkey depend on it completing successfully.
    - `bootstrap-app` — waits for MySQL + valkey healthy, runs
      `alembic upgrade head`, registers the bootstrap operator,
      mints the API server cert + operator CLI client cert, exits.
      api + worker + web depend on it completing.
  - **`scripts/prod_bootstrap_substrate.sh`** +
    **`scripts/prod_bootstrap_app.sh`** are the two scripts the
    bootstrap containers exec. Both `set -euo pipefail` and guard
    every mutating step with a file-existence test, so re-running
    `make prod-up` against persistent state is a no-op (cert files
    present → skip mint; operator registered → skip; alembic at
    head → no-op).
  - **`alembic` moved from `dev` to runtime deps** so the wg-manager
    image bakes `/app/.venv/bin/alembic` — the bootstrap container
    needs it, and operators pulling
    `ghcr.io/jfudally/wg-manager:vX.Y.Z` shouldn't have to install
    dev deps to apply migrations.
  - **`make prod-up` gains `--wait`** so the command blocks until
    every service is healthy or exited 0. When the make target
    returns, the stack is fully usable end-to-end.
  - **`.env.prod.example`** now documents the operator identity
    (`BOOTSTRAP_OPERATOR_CN` required, `BOOTSTRAP_OPERATOR_ROLE`
    optional with default `admin`) and the API server cert subject
    (`API_SERVER_CN` + `API_SERVER_SANS`, both optional with
    localhost-friendly defaults). The old comment block that left
    `BOOTSTRAP_OPERATOR_CN` commented-out is gone — the prod stack
    requires it.
  - **Runbook rewrite** at `docs/deploy/single-host-prod.md`: the
    "Bootstrap (one command)" section is the canonical flow; the
    old 9-step manual flow is preserved as an "Advanced: manual
    bootstrap (for debugging)" section operators can fall back to
    when self-bootstrap fails partway and they want shell-level
    introspection.
  - **End-to-end verification** on a clean Docker host:
    `make prod-down -v` → strip `tls/` → `make prod-up`. Sequence:
    bootstrap-substrate exited → mysql + valkey healthy →
    bootstrap-app exited → api + worker + web healthy. Curl on
    `/v1/healthz` + `/v1/readyz` returns 200, `/v1/servers`
    authenticates via the operator cert and returns `[]`, dashboard
    returns 200. Re-running `make prod-up` is a clean no-op (all
    bootstrap steps log "already exists, skipping").
  - **Tests:** 16 compose-shape cases
    (`tests/test_compose_prod_bootstrap.py`) + 18 script-shape
    cases (`tests/test_prod_bootstrap_scripts.py`) = 34 new. The compose
    suite pins the dependency graph (the bootstrap ordering is
    encoded entirely in `depends_on` conditions, so a future edit
    that breaks the graph trips at test time). The scripts suite
    pins shebangs, `set -euo pipefail`, the substrate script's
    invocation of all three Vault bootstrap helpers, the app
    script's `alembic upgrade head` + `operators add` + the two
    cert mints, and the file-existence-guard pattern.

- **Phase 3d cycle 4a — docker-compose `ha` profile + nginx
  passthrough LB.** Materialises the two-replica + LB topology from
  `docs/deploy/ha-control-plane.md` on a single host so an operator
  can verify failover end-to-end before deploying a real two-host
  setup.

  - **Compose `ha` profile.** Three new services in
    `docker-compose.yml`, all gated behind `profiles: ["ha"]`:
    `api1` (host port 8001), `api2` (host port 8002), and `lb`
    (host port 8443, `nginx:1.27-alpine`). Both replicas build the
    existing Phase 2f `Dockerfile`, bind-mount the dev cert bundle
    in `tls/` read-only, and reuse the default-profile data tier
    (mysql + valkey + vault + vector — unprofiled so it comes up
    under both flows).
  - **nginx LB config** at `docker/nginx/wg-manager.conf` is
    `stream {}`-mode TCP passthrough — the HA topology forbids TLS
    termination at the LB so the mTLS handshake lands on the
    replica intact. Two upstreams (`api1:8000`, `api2:8000`) with
    passive `max_fails=3 fail_timeout=10s` checks, single listener
    on `8443`.
  - **Makefile** grew `ha-up` / `ha-down` / `ha-logs` mirroring the
    `db-up` family.
  - **Docs.** `docs/deploy/ha-control-plane.md` gained a "Running
    the ha profile locally" section with the three-endpoint table,
    a failover-smoke recipe, and the explicit list of what cycle
    4a does **not** ship (active `/readyz` probing at the LB, TLS
    termination at the LB, MySQL primary→replica plumbing).
  - **Tests:** 19 compose-shape cases
    (`tests/test_compose_ha_profile.py`) + 7 nginx-config cases
    (`tests/test_nginx_lb_config.py`) — pure YAML/text parse-and-
    assert, matches the Phase 2f `test_dockerfile.py` pattern. CI's
    image-build workflow remains the live compose validator; these
    tests pin the source-of-truth shape so a refactor that drops a
    service or breaks the passthrough contract trips before merge.

- **End-to-end verification of the prod overlay surfaced four bugs;
  all four fixed.** Walking the runbook on a clean Docker host
  exercised every shipped code path the overlay touches and turned
  up code-level shape mismatches between what the docs promised and
  what the code delivered. Each is fixed with a regression test.

  - **Compose `ports:` list merge** — the overlay's
    `127.0.0.1:3306:3306` mappings were being concatenated with the
    dev file's `0.0.0.0:3307:3306` instead of replacing it, so the
    second host-port bind failed silently. Fixed with Compose v2.20's
    `!override` tag on `mysql` / `valkey` / `vault` ports. Test
    fixtures grew a custom `ComposeLoader` so PyYAML tolerates the
    `!override` / `!reset` Compose-specific tags.
  - **PEM chain newline missing.** `VaultPKI._issue_leaf` joined the
    Vault `ca_chain` list with `"".join(...)` and `LocalDevPKI`
    used `intermediate_pem + root_pem`. When the upstream PEM
    lacked a trailing newline (Vault's modern API output), the
    result was `-----END CERTIFICATE----------BEGIN CERTIFICATE-----`
    on one line — rejected by strict consumers (`openssl x509`,
    Python `ssl.SSLContext.load_verify_locations`, pymysql's
    `ssl={ca: ...}`). New `wg_manager.pki._join_pems(*pems)` helper
    normalises to strict-parser-safe output and is used at both
    sites. 10 regression cases in `tests/test_pki_chain_join.py`.
  - **Alembic `env.py` ignored MySQL TLS args.**
    `engine_from_config(config_section, prefix="sqlalchemy.")` built
    its engine without the `connect_args = {"ssl": {...}}` dict
    `wg_manager.db._resolve_mysql_ssl` produces — so `make migrate`
    against a `require_secure_transport=ON` MySQL failed with
    `(3159) Connections using insecure transport are prohibited`.
    Fixed by importing `_resolve_mysql_ssl` and passing
    `connect_args=...` into `engine_from_config`. 3 regression
    cases in `tests/test_alembic_env_tls.py`.
  - **API healthcheck assumed `/healthz` bypasses mTLS at the TLS
    layer; uvicorn's `ssl.CERT_REQUIRED` says otherwise.** The
    Phase 3d cycle 1 doc claim is at the app layer
    (`MTLSAuthMiddleware` skips auth for `/healthz`), but uvicorn
    drops the TLS handshake first when no client cert is present.
    The overlay's healthcheck now presents the operator client
    cert (the `./tls` bind-mount already makes it available); the
    inline comment + the runbook's "Known limitations" table both
    flag the underlying doc-vs-implementation gap as planned
    follow-on work.

- **Production-shaped docker-compose overlay
  (`docker-compose.prod.yml`).** Adds an operator path from
  "dev stack on my laptop" to "single-host non-HA stack on a real
  box". Layers on top of the existing `docker-compose.yml` (which
  stays the dev file) via `docker compose -f docker-compose.yml
  -f docker-compose.prod.yml up` — or the new `make prod-up`
  wrapper.

  - **Three new services.** `api` (mTLS-enforcing FastAPI on public
    443), `worker` (Celery), `web` (Next.js dashboard on public
    3000). Both API + worker build the Phase 2f `Dockerfile`; web
    builds `web/Dockerfile`. All three pin `restart: always` so the
    box rebooting brings the stack with it.
  - **Production posture on the API + worker.** `TLS_REQUIRED=true`,
    `DATABASE_TLS_REQUIRED=true`, all three substrate backends
    (`CRYPTO_BACKEND` / `SSH_CA_BACKEND` / `PKI_BACKEND`) pinned to
    `vault`. The HA startup guard (Phase 3d cycle 1) rejects
    `local` + `TLS_REQUIRED=true` without pinned PEMs anyway —
    pinning to `vault` is the only honest production posture.
  - **Hardened data tier.** Overrides on `mysql` / `valkey` /
    `vault` source every secret from `${VAR}` interpolation
    (`.env.prod`) using Compose's `${VAR:?msg}` fail-loud syntax
    so a missing value blocks `compose up` instead of silently
    defaulting to a vulnerable string. The dev compose's well-
    known `dev-only-root` Vault token, `rootpw` MySQL root
    password, and unauthenticated Valkey are all replaced; data
    tier host port mappings drop to `127.0.0.1` only.
  - **`.env.prod.example`** documents every interpolation the
    overlay reads, with inline comments on how to generate strong
    values for each. Gitignore extended to keep the populated
    `.env.prod` out of the repo.
  - **`make prod-up` / `prod-down` / `prod-logs` / `prod-config`**
    wrappers around `docker compose --env-file .env.prod
    -f docker-compose.yml -f docker-compose.prod.yml ...`. The
    `prod-up` target guard refuses to start without `.env.prod`
    on disk.
  - **Operator runbook** at `docs/deploy/single-host-prod.md`
    covers the one-time bootstrap sequence (mint MySQL TLS bundle
    → bring up data tier → bootstrap Vault substrate → mint API
    + operator certs → apply migrations → restart api/worker/web),
    the day-2 reference (volume → state mapping, restart behaviour,
    backup commands), the documented limitations vs. fully
    production-ready (Vault still in dev mode, no reverse proxy,
    no in-stack Prometheus, single MySQL, single worker), and the
    upgrade-to-HA path.
  - **Tests:** 33 overlay-shape cases
    (`tests/test_compose_prod_overlay.py`) + 3 env-template cases
    (`tests/test_env_prod_example.py`) = 36 new. Pure parse-and-assert,
    matches the Phase 2f `test_dockerfile.py` and cycle 4a
    `test_compose_ha_profile.py` pattern. Pins: service presence
    (api/worker/web), restart-always, mTLS + DB-TLS + Vault
    backends, no hardcoded dev secrets, every `${VAR}` documented.

- **Phase 3d cycle 3 — per-row advisory locks on mutating Celery
  tasks.** Closes the multi-worker concurrency gap cycle 2
  flagged (BENIGN_OVERWRITE on contention). The 4 mutating tasks
  now serialize on a MySQL `GET_LOCK` advisory lock keyed on the
  row they mutate.

  - **Lock helper.** New `wg_manager.locks` module exposes
    `lock_name_for(scope, row_id)` (`wgm:server:7` shape) and
    `task_row_lock(session, scope, row_id, timeout_seconds=5)`
    context manager. On MySQL the lock uses
    `GET_LOCK(name, timeout)` + `RELEASE_LOCK(name)`; on SQLite
    (test suite) a no-op acquire that yields `True`. Failed
    acquire yields `False` — the caller decides whether to skip
    or retry. Connection-scoped so a worker crash leaves no
    stranded lock.
  - **Applied to the 4 mutating tasks.** `provision_server_task`,
    `rotate_host_cert_task`, `reconfigure_server_task` lock on
    `wgm:server:<server_id>`; `provision_client_task` locks on
    `wgm:client:<client_id>`. On contention the task returns
    `{"status": "skipped", "reason": "concurrent_run", ...}`
    without any SSH / DB-mutation side effects. Skipped result
    rides through the `GET /tasks/{id}` API so operators see the
    skip.
  - **Verdicts updated.** The 4 mutating tasks' Phase 3d cycle 2
    docstring stanzas flipped from `BENIGN_OVERWRITE` to
    `GUARDED_BY_ROW_LOCK`. The cycle 2 marker test still passes.
  - **Docs.** `docs/deploy/ha-control-plane.md` Celery section
    rewrote the per-task verdict table + added an "Advisory lock
    contract" subsection explaining the name shape, the
    `GET_LOCK` timeout, the SQLite no-op path, and the
    monkey-patch pattern tests use to exercise the contended
    branch.
  - **ROADMAP scope note.** Original ROADMAP cycle 3 wording was
    "MySQL primary + read-replica routing"; cycle 3 instead
    landed the advisory locks deferred from cycle 2 (more
    immediate safety win), with read-replica routing folded into
    cycle 4 alongside the compose ha-profile.
  - **Tests:** 8 lock-helper cases (`tests/test_locks.py`) + 8
    task-level integration cases (`tests/test_task_locks.py`)
    pinning the lock-acquired path (each task records the
    expected `(scope, row_id)`) and the contended path (each
    task returns `skipped` and fires zero SSH commands). Backend
    pytest 953/953 in `local` mode (was 937 on cycle 2's merge).

- **Phase 3d cycle 2 — Celery worker scaling guarantees.** Makes the
  Celery worker side safe to run as 2+ replicas behind the same
  broker. Codifies the at-least-once delivery contract every task is
  written against.

  - **Idempotency audit** of the 6 shipped tasks
    (provision_server, rotate_host_cert, reconfigure_server,
    provision_client, discover_peers, discover_all_peers). Verdict:
    4× `BENIGN_OVERWRITE` + 2× `NATURALLY_IDEMPOTENT`. No
    `NEEDS_GUARD` findings. Per-row advisory locks (the natural
    cycle 2 follow-on) deferred to cycle 3, which brings MySQL's
    `GET_LOCK()` into scope.
  - **`task_reject_on_worker_lost=True`** added to
    `celery_app.conf`. Pairs with the existing `task_acks_late=True`
    to form the at-least-once contract: a SIGKILL'd / OOM'd worker
    mid-task triggers broker requeue instead of silent task loss.
  - **Per-task contract pinned in docstrings.** Each task grew a
    `Phase 3d cycle 2` stanza naming its idempotency classification
    + reasoning. A regression test greps for the marker so a
    refactor that rewrites a task body without re-examining the
    audit trips a clear failure.
  - **No beat scheduler.** Zero periodic tasks exist in the
    codebase. The "single-beat vs distributed-beat" decision is
    deferred until a periodic task is actually needed (cert renewal
    sweep is the obvious first candidate).
  - **Docs.** `docs/deploy/ha-control-plane.md` grew a "Celery
    worker scaling" section with the at-least-once contract table,
    the per-task idempotency table, an "Adding a new task"
    checklist (matches the existing Statelessness checklist
    pattern), and the cycle 3 advisory-lock deferral note.
  - **Tests:** 9 new cases (`tests/test_celery_ha_config.py`) —
    config flags pinned, every task name registered with
    `celery_app`, every task's `__doc__` carries the cycle 2
    audit-verdict marker. Backend pytest 937/937 in `local` mode
    (was 928 on cycle 1's merge).

- **Phase 3d cycle 1 — statelessness audit + `/healthz` + `/readyz`
  + HA startup guards.** Foundational slice of Phase 3d (HA control
  plane). Verifies the API is safe to run as two+ replicas behind a
  load balancer and adds the probes the LB uses to route traffic.

  - **Statelessness audit.** Walked every module on the request
    path and classified module-level state. Verdict: the API is
    mostly stateless. Two genuine cross-replica hazards surfaced
    — the `LocalDevPKI` and `LocalDevSSHCA` per-process root-cert
    caches in dev backends would mint divergent roots across
    replicas if unpinned. Production (Vault for both) eliminates
    the hazard.
  - **Probe surface.** New `wg_manager.routers.health` ships
    `/healthz` (liveness — unconditional 200; does not touch the
    DB) and `/readyz` (readiness — 200 when MySQL is reachable,
    503 with per-dep status otherwise). Dual-mounted at `/v1` per
    Phase 3c. Both bypass mTLS via the new
    `MTLSAuthMiddleware.is_health_path` exemption (load balancers
    don't carry operator certs) and are exempt from the
    deprecation envelope (operational, not API surface).
  - **HA startup guards.** New
    `wg_manager.main._enforce_ha_startup_guards` hard-fails at
    `create_app()` time when `TLS_REQUIRED=true` AND
    `PKI_BACKEND=local` (or `SSH_CA_BACKEND=local`) without the
    corresponding `*_LOCAL_DEV_*` PEMs pinned. Error names the env
    vars to set so an operator fixes the misconfiguration without
    reading source. Dev posture (`TLS_REQUIRED=false`) is
    permitted to run the local backends unpinned.
  - **Deployment doc.** New `docs/deploy/ha-control-plane.md`
    captures the topology (passthrough LB, no session stickiness,
    mTLS termination at the replica), the probe contract (why two
    probes, not one), a Statelessness checklist for future
    maintainers, and an nginx LB example.
  - **Tests:** 9 health-probe cases (`tests/test_health.py`) + 5
    startup-guard cases (`tests/test_ha_startup_guards.py`). Two
    existing `test_main_tls_wiring.py` cases updated to pin
    `PKI_BACKEND=vault` + `SSH_CA_BACKEND=vault` since they
    exercise production posture and would otherwise trip the new
    guard. Backend pytest 928/928 in `local` mode (was 914 on
    Phase 3c's merge).

- **Phase 3c — public API versioning (`/v1` namespace + deprecation
  policy).** Every router that shipped under an unprefixed path is
  now **dual-mounted** at the same path under `/v1`. Existing
  integrations keep working unchanged; new callers opt into the
  explicit version. The CLI and dashboard BFF are cut over to
  `/v1`; third-party callers have until the operator-configured
  sunset date to migrate.

  - **Dual mount.** `/ssh-keys`, `/servers`, `/clients`, `/certs`,
    `/tenants`, `/audit`, `/crypto`, `/tasks` all answer at both
    `/<resource>` and `/v1/<resource>`. Identical handler, identical
    response body + status.
  - **Deprecation envelope** (RFC 9745). Every legacy-path response
    carries `Deprecation: true`, `Sunset: <date>`, and
    `Link: <doc>; rel="deprecation"`. New
    `wg_manager.api_versioning.DeprecationMiddleware` stamps the
    headers and emits one `api.deprecation` audit line per legacy
    hit so operators can SIEM-query for callers still on the legacy
    surface. The sunset date and link target are operator-tunable
    via `API_LEGACY_SUNSET_DATE` + `API_DEPRECATION_DOC_URL` settings.
  - **Versioned OpenAPI surface.** `/v1/openapi.json` filters the
    spec to `/v1/*` paths only and pins `info.version = "1.0"`. The
    existing `/openapi.json` continues to surface both spaces.
  - **CLI cutover.** `cli._make_http_client` suffixes the base URL
    with `/v1` so every existing call site (which uses relative
    `/ssh-keys` etc) lands on the versioned namespace.
  - **Dashboard BFF cutover.** `lib/proxy.forwardToUpstream` rewrites
    every inbound `/api/proxy/<path>` to `<upstream>/v1/<path>`.
    Strips an existing `v1/` prefix so callers that pre-pended it
    don't get a double prefix.
  - **Docs.** New `docs/api-versioning.md` walks the deprecation
    envelope, the semver contract, the cutover guidance, and the
    removal timeline.
  - **Tests:** 13 new versioning cases
    (`tests/test_api_versioning.py`) — dual mount, deprecation
    headers on legacy / absent on v1, audit emission, OpenAPI
    filtering — plus 1 new vitest case pinning the BFF's no-double-
    prefix guard. Backend pytest 914/914 in `local` mode (was 901
    on Phase 3b's close); vitest 57/57; `tsc --noEmit` clean.

- **Phase 3b cycle 5 — explicit tenant on resource POSTs + tenant SAN on
  certs.** Closes Phase 3b. Cycle 4 inherited the server's tenant from
  the SSH key; cycle 5 makes the resolution explicit. Cycle 3 added
  per-operator tenant scope from the `OperatorTenant` join; cycle 5
  lets non-operator service identities (CI runners, automation
  accounts) carry a tenant binding via a `tenant:<slug>` SAN baked
  into the leaf.

  - **Resource POST tenant resolution.** `POST /ssh-keys`,
    `POST /servers` accept an optional `tenant_id` in the body. The
    new `wg_manager.tenant_scope.resolve_create_tenant` helper
    centralises the four decision branches: super-admin without
    `tenant_id` → default tenant (id=1); single-tenant operator
    without `tenant_id` → auto-derive; multi-tenant operator
    without `tenant_id` → 422 demanding an explicit choice (body
    names every candidate so the dashboard can render the select
    widget straight from the error); no-tenant operator → 403. The
    resolved tenant must permit the operator's per-tenant
    `admin`/`operator` role; `auditor` 403s. Servers' cycle 4
    pool-containment check now runs against the *resolved* tenant,
    not the SSH key's.
  - **Tenant SAN convention on `cli` / `dashboard` certs.**
    `wg-manager certs issue --type cli --tenant acme` (and the
    matching `POST /certs` with `tenant_slug: "acme"`) appends a
    `tenant:acme` DNS-SAN to the leaf and populates
    `Certificate.tenant_id` on the audit row. Refused on the three
    server-EKU cert types (`api`, `mysql`, `mysql-client`).
    Unknown slug → 422.
  - **Dashboard parity.** `SSHKeyCreate.tenant_id` + `ServerCreate.tenant_id`
    + `CertificateIssueRequest.tenant_slug` added to
    `web/lib/types.ts`. Certificates page Issue form grows a
    "Tenant slug (optional)" input that appears only for cli /
    dashboard types and rides through to the POST body. Backend's
    422 / 403 errors render in the existing Alert pattern.
  - **Conftest seed.** The in-memory engine fixture now seeds the
    default tenant at id=1 to mirror Alembic 0014; existing test
    helpers that re-inserted the default tenant became upserts.
  - **Tests:** 12 new resource-resolution cases
    (`tests/test_resource_tenant_resolution.py`) + 7 new tenant-SAN
    cases (`tests/test_cert_tenant_san.py`) + 2 new vitest specs
    for the cert form. Backend pytest 901 passed in `local` mode
    (was 882 on cycle 4's merge); vitest 56/56; `tsc --noEmit` clean.
  - **Phase 3b closes here.** Cycles 1-5 shipped; every bullet on
    the Phase 3b sub-roadmap is `[x]`. ROADMAP header updated.

- **Phase 3b cycle 4 — per-tenant peer pools (IPAM).** Each tenant
  carries its own `subnet_pool` CIDR; every server's `subnet` must
  lie inside the pool, and two tenants' pools must be disjoint —
  so a client IP in one tenant cannot collide with a client IP in
  another. Closes the "IP collisions between tenants" half of the
  Phase 3b design lock.

  - **Schema.** `Tenant` grows a `subnet_pool` NOT NULL VARCHAR(64)
    column via Alembic 0016. The migration back-fills the reserved
    `id=1` default tenant with `Settings.default_subnet` so a v0.1.0
    deployment keeps every existing server inside its tenant's pool
    without operator action; any other tenant rows added between
    cycles 2 and 4 back-fill to the RFC1918 fallback `10.0.0.0/8`
    (the largest private block — operators tighten via PATCH).
  - **IPAM helpers** in `wg_manager.ipam`: `subnet_in_pool(subnet,
    pool)` (strict containment check) + `pools_overlap(a, b)`
    (overlap check). The existing `allocate_client_ip` walks the
    server's subnet unchanged; cross-tenant non-collision falls out
    of pools being disjoint by construction.
  - **CLI.** `wg-manager tenants create --subnet-pool 10.42.0.0/16`
    stores the pool; without the flag the row carries the model
    default. Overlap with an existing tenant is rejected with a
    non-zero exit + a message naming the colliding tenant. `tenants
    list/get` JSON output grows the `subnet_pool` field.
  - **HTTP.** `TenantCreate` body grows optional `subnet_pool`;
    `TenantRead` surfaces it; new `PATCH /tenants/{slug}` accepts a
    `TenantUpdate` body to widen/narrow the pool. Overlap is
    rejected with HTTP 409 (and excludes the row being updated on
    PATCH so an in-place narrow doesn't self-collide). Malformed
    CIDR → 422.
  - **Per-server pool enforcement.** `POST /servers` rejects a
    `subnet` that lies outside the resolved tenant's pool with HTTP
    422; the existing default-subnet path inherits the SSH key's
    tenant so a v0.1.0 deployment keeps working. The row's
    `tenant_id` is populated from the resolved tenant.
  - **Dashboard parity.** Tenants page inventory grows a "Subnet
    pool" column; create form grows a `Subnet pool (optional)`
    input; the per-tenant detail panel header surfaces the pool in
    a monospace span. `Tenant` / `TenantCreate` / new `TenantUpdate`
    types updated; new `api.updateTenant` method.
  - **Tests:** 9 new alembic-0016 cases (`tests/test_alembic_0016.py`)
    + 18 new plumbing cases (`tests/test_tenant_subnet_pool.py`)
    covering CLI create/list/get with pool, API POST + overlap
    rejection, IPAM helpers, per-server pool enforcement, and
    cross-tenant non-collision. 2 new vitest specs covering the
    inventory subnet column + the create-form pool submission.
    Backend pytest 882/882 in `local` mode (was 855 on cycle 3's
    merge); vitest 54/54; `tsc --noEmit` clean.

- **Phase 3b cycle 3 — tenant-aware filtering + per-tenant role gate.**
  The first cycle that **actually enforces** the multi-tenant model.
  Cycles 1 + 2 shipped pure schema groundwork; cycle 3 reads the
  `OperatorTenant` join at request time and uses it to narrow every
  list query, gate every mutation, and tag every audit event with
  the affected resource's tenant.

  - **Middleware tenant resolution.** `MTLSAuthMiddleware.dispatch`
    now also reads the operator's `OperatorTenant` join rows once
    per admitted request and stashes
    `request.state.tenant_ids` / `tenant_roles` / `is_super_admin`.
    Super-admin = global `Operator.role == admin` per the ROADMAP
    design lock — bypasses every per-tenant gate. The `OPTIONS`
    preflight and `TLS_REQUIRED=false` passthrough branches both
    leave the slots as `None` so handlers can distinguish "auth
    disabled" from "auth admitted with empty set".
  - **Tenant scope helper** (`wg_manager.tenant_scope`). New
    `TenantScope` frozen value object + `get_tenant_scope` FastAPI
    dependency + `scope_filter(scope, Model)` (returns a
    `Model.tenant_id IN (...)` expression, or `None` when no filter
    applies) + `require_tenant_role(scope, tenant_id, *allowed)`
    (HTTP 403 unless the operator has one of `allowed` per-tenant
    roles on `tenant_id`; super-admin bypass).
  - **List filtering applied** to `/servers`, `/clients`,
    `/ssh-keys`. Non-super-admin operators see only the rows whose
    `tenant_id` is in their `OperatorTenant` join set; an operator
    with no joins gets `[]` (not 403). Super-admin sees every row.
  - **404-on-out-of-scope** for the single-row `GET` /
    `PATCH` / `DELETE` shapes — the existence of a row in another
    tenant is never leaked to a probing operator.
  - **Per-tenant role gate** on `PATCH` / `DELETE` of `/servers`,
    `/clients`, `/ssh-keys`. `admin` and `operator` per-tenant roles
    admit; `auditor` 403s. Super-admin bypasses.
  - **AuditEvent.tenant_id populated.** `audit.persist()` grew an
    optional `tenant_id` kwarg; the servers / clients / ssh_keys /
    certs mutating endpoints thread the resource's `tenant_id`
    through so an auditor reviewing the trail can filter per
    tenant. The audit log line emitted alongside the row also
    carries `tenant_id`.
  - **Dashboard surface.** `Server` / `Client` / `SSHKey` /
    `Certificate` schemas + TypeScript types grow an optional
    `tenant_id` field so the dashboard can render tenant tags. The
    deeper "tenant picker on resource create" + per-list tenant
    column polish lands in cycle 5 alongside the IPAM partitioning.
  - **Tests:** 6 new middleware tenant-resolution cases
    (`TestTenantSetResolution` in `tests/test_auth.py`), 25 new
    cases in `tests/test_tenant_scope.py` covering the value
    object, `scope_filter`, `require_tenant_role`, server list +
    get-by-id + patch + delete scoping, and audit-event tenant_id
    population. Backend pytest 855 passed in `local` mode (was 824
    on cycle 2's merge); vitest 52/52; `tsc --noEmit` clean.

- **Phase 3b cycle 2 — `OperatorTenant` join + tenant CRUD surface.**
  Cycle 1 shipped the `Tenant` row + nullable FKs. Cycle 2 layers the
  many-to-many association: one operator can be attached to many
  tenants, one tenant can host many operators, and the **per-tenant
  role** lives on the join — so a user can be `admin` in their own
  tenant and `auditor` in another without two separate operator
  rows. **Zero behaviour change for callers** — the auth middleware
  still consults the operator's *global* role; cycle 3 is what
  flips per-tenant enforcement on.

  - New `OperatorTenant` SQLModel: `id` / `operator_id` FK /
    `tenant_id` FK / `role` / `created_at`. Unique constraint on
    `(operator_id, tenant_id)` so a duplicate attach is rejected at
    the DB layer as the last line of defence.
  - Alembic 0015 creates the join table + back-fills one row per
    existing operator pointing at the default tenant (id=1) and
    mirroring the operator's existing global role as the
    per-tenant role. Idempotent upgrade → downgrade → upgrade
    round-trip.
  - **CLI surface.** New `wg-manager tenants create/list/get` +
    `wg-manager operators attach-tenant/detach-tenant/list-tenants`
    direct-DB subcommands. Mirrors the `wg-manager operators
    add/list` shape (works before the API listener is up — same
    canonical bootstrap path).
  - **HTTP surface.** New `/tenants` router exposes the CLI shape
    over mTLS: `GET /tenants`, `GET /tenants/{slug}` (admin or
    auditor); `POST /tenants` (admin); `POST /tenants/{slug}/operators`,
    `DELETE /tenants/{slug}/operators/{cn}` (admin);
    `GET /tenants/{slug}/operators` (admin or auditor). Role
    gating mirrors `/certs` byte-for-byte.
  - **Dashboard parity.** New `web/app/tenants` page with the
    tenant inventory table, a Create form, a per-tenant detail
    panel rendering the attached-operator table with per-tenant
    role badges, an Attach form, and per-row Detach buttons. New
    "Tenants" nav entry; new `Tenant`, `TenantCreate`,
    `OperatorTenantRead`, `OperatorTenantAttachRequest` types and
    matching `api.*Tenant*` methods.
  - 16 new alembic test cases (`tests/test_alembic_0015.py`) — join
    table shape, FK references, unique constraint at the DB layer,
    per-row backfill from each of the three operator roles + the
    two-operator-count sanity, downgrade + idempotent round-trip,
    model-surface defaults + repr safety.
  - 16 new CLI test cases (`tests/test_cli_tenants.py`) — tenants
    create / list / get happy + failure paths, slug derivation from
    name, duplicate-slug refused; operators attach/detach/list-tenants
    happy + unknown-cn / unknown-tenant / duplicate-pair errors.
  - 21 new API test cases (`tests/test_tenants_api.py`) — list +
    detail + create (admin / auditor / plain operator role gates;
    duplicate slug → 409; slug-from-name derivation); attach
    (happy / unknown-cn → 422 / unknown-tenant → 404 / duplicate
    → 409 / default-role / auditor 403); detach (happy / unknown
    pair → 404 / auditor 403); per-tenant operator list.
  - 6 new vitest specs (`web/__tests__/tenants.test.tsx`) — list
    render, empty state, create form POST, per-tenant detail
    operator table, attach form POST, detach DELETE.
  - Fix-along: `tests/test_alembic_0014.py`'s downgrade-round-trip
    tests pinned to the explicit pre-revision name instead of
    `-1` — `-1` silently turned into "downgrade only 0015" once
    0015 landed on top, and the prior tests would have looked
    green while testing nothing.

- **Phase 3b cycle 1 — multi-tenant schema groundwork.** Opens
  Phase 3b. **Zero behaviour change** — pure schema migration so
  operators upgrade a v0.1.0 deployment without re-issuing certs
  or re-bootstrapping. Cycles 2-5 layer enforcement on top.

  - New `Tenant` SQLModel: `id` / `name` (unique) / `slug`
    (unique) / `created_at`.
  - Alembic 0014 creates the `tenant` table, inserts a `default`
    tenant row at id=1, adds a **nullable** `tenant_id` FK
    column + index to each of the six tenanted resource tables
    (`operator`, `server`, `client`, `sshkey`, `certificate`,
    `auditevent`), and back-fills every existing row to the
    default tenant. Nullable for cycle 1 so the migration is
    non-breaking; cycle 3 will tighten to NOT NULL once auth-side
    filtering enforces the invariant.
  - 25 new test cases in `tests/test_alembic_0014.py`: tenant
    table shape (3), default tenant row inserted at id=1,
    `tenant_id` column added to each of 6 tables × 3 assertions =
    18 parametrised, FK references `tenant(id)`, back-fill from
    prior-revision data assigns existing rows to default tenant,
    downgrade reverses cleanly + idempotent round-trip.
  - ROADMAP grew a Phase 3b sub-phase with the locked design
    decisions (namespace-style tenancy, OperatorTenant join,
    incremental enforcement) and the 5-cycle plan; cycle 1
    flipped to `[~]` in progress.

- **Phase 3a cycle 3 — cert-lifecycle dashboard + alerting recipes.**
  Closes Phase 3a (observability). A v0.1.0 operator can now
  answer "which certs are due for renewal this week?" and "should
  on-call be paged right now?" from Grafana + Prometheus alone.

  - New gauge metric `wg_manager_cert_not_after_seconds{serial,
    cn, cert_type}` emitted by a custom
    `CertificateLifecycleCollector` that walks the `certificate`
    table on every scrape. Revoked rows excluded (emitting their
    expiry would either fire noisy "expiring soon" alerts on
    decommissioned certs, or mask the absence of a real
    replacement).
  - New `docs/observability/grafana-cert-lifecycle.json` dashboard
    with 5 panels: nearest-expiry top-20 table, expiring-in-7-days
    + expiring-in-30-days stats by cert type, lifecycle event-rate
    timeseries (issue / renew / revoke), active cert count by type.
  - New `docs/observability/prometheus-alerts.yaml` ships three
    alerting rules:
    - `Wg5xxSurge` — 5xx fraction > 5% over 5m
    - `WgVaultLatencyHigh` — Vault round-trip p95 > 2s for 5m
    - `WgCertExpiringSoon` — non-revoked cert TTL < 7 days
    Each rule includes a `runbook` annotation pointing at the
    corresponding wg-manager runbook so Alertmanager templates can
    render clickable links in the page payload.
  - `docs/observability.md` grew Cert-lifecycle + Alerting-recipes
    sections covering the new metric, useful PromQL recipes, the
    dashboard panels, and the alert tuning knobs.
  - 20 new test cases:
    `tests/test_cert_lifecycle_collector.py` × 4 (gauge appears on
    /metrics, includes active certs, excludes revoked, carries
    cn+cert_type labels);
    `tests/test_grafana_cert_lifecycle.py` × 5 (file exists, valid
    JSON, top-level shape, panels cover the cert gauge + lifecycle
    counters);
    `tests/test_prometheus_alerts.py` × 11 (file exists, valid
    YAML, all three alerts present, exprs reference the canonical
    metrics, every alert has expr + annotations.summary).

- **Phase 3a cycle 2 — OTLP trace exporter on the provisioning path.**
  Three span families covering the full provisioning trace: Celery
  task root spans (auto-instrumented), Vault round-trip sub-spans
  (cycle 1's `vault_call` extended to start a span at the same
  wrap site), and SSH command sub-spans (new `ssh_span` helper
  wrapped around `SSHRunner.run` / `.sudo`).

  - New `wg_manager.tracing` module sets up the OTel SDK with four
    exporter modes (`none` default = zero overhead, `console` for
    dev, `otlp-http` for production, `memory` for tests).
  - Cycle 1's `vault_call` context manager extended to also start
    a `vault.<engine>.<operation>` span — one wrap site, two
    streams. A metric-only deployment and a metric+trace
    deployment never drift apart.
  - New `ssh_span(operation, **attrs)` helper wraps
    `SSHRunner.run` and `SSHRunner.sudo` so the trace shows every
    command-exec as a sub-span under the parent Celery task.
  - `CeleryInstrumentor()` instruments every task automatically.
  - `setup_tracing` invoked at import time from both
    `wg_manager.main` (API) and `wg_manager.celery_app` (worker)
    so spans land under whichever process executed them.
  - **Cycle 1 gap closure**: `tests/test_call_sites_traced.py`
    greps the source for every expected `vault_call(...)` +
    `ssh_span(...)` + `setup_tracing` invocation. The cycle 1
    commit shipped a gap where the ROADMAP claimed Vault wraps
    were in place but no test pinned the source-level contract;
    cycle 2 closes that gap so the same drift can't recur silently.
  - `docs/observability.md` grew a Tracing section: span topology
    diagram, sample OTLP collector config, Honeycomb / Jaeger /
    Tempo pointers, worker-vs-API setup parity.
  - 21 new test cases: `tests/test_tracing.py` × 11 (behavioural —
    exporter selection, vault_call span emission + attributes +
    ERROR status, ssh_span helper, Celery instrumentor); plus
    `tests/test_call_sites_traced.py` × 10 (source-level grep
    pinning every wrap site).
  - New runtime deps: `opentelemetry-api`, `opentelemetry-sdk`,
    `opentelemetry-exporter-otlp-proto-http`,
    `opentelemetry-instrumentation-celery`.
  - New Settings fields: `otel_exporter`,
    `otel_exporter_otlp_endpoint`, `otel_service_name`.

- **Phase 3a cycle 1 — Prometheus metrics + Grafana dashboard.**
  Opens Phase 3 (Scale / Polish). v0.1.0 operators can now answer
  "is wg-manager healthy right now?" from Prometheus + Grafana,
  not log greps.

  - New `wg_manager.metrics` module declares nine metric families:
    HTTP (`requests_total` + `request_duration_seconds`), Celery
    (`tasks_total` + `task_duration_seconds`), Vault round-trips
    (`requests_total` + `request_duration_seconds`), and cert
    lifecycle (`certs_issued_total` + `_revoked_total` +
    `_renewed_total`).
  - `MetricsMiddleware` (ASGI) records every HTTP request,
    skipping OPTIONS preflight and `/metrics` itself. The path
    label uses the FastAPI **route template**, not the raw URL,
    so cardinality stays bounded by the route table.
  - Celery `task_prerun` + `task_postrun` signal handlers record
    every task automatically — the side-effect import lives in
    `celery_app.py` so the metrics fire under the worker process,
    not just the API.
  - `vault_call(engine, operation)` context manager records
    latency + outcome (`ok` / `error`) on every Vault round-trip.
    Call sites in `crypto` / `ssh_ca` / `pki` get a one-line wrap.
  - `GET /metrics` endpoint exposes the Prometheus text format on
    the existing mTLS listener. Scrapers configure a client cert
    the same way operators do — keeping the security posture
    uniform.
  - `docs/observability/grafana-dashboard.json` ships a starter
    dashboard with 7 panels covering every metric family (HTTP
    request rate + p95 latency, Celery throughput + p95 duration,
    Vault round-trip latency + rate, cert lifecycle events).
    Importable via Grafana UI's Upload JSON flow.
  - `docs/observability.md` walks the scrape config, metric
    families, dashboard panels, and the three instrumentation
    patterns for future call sites.
  - New `prometheus-client>=0.20.0` runtime dependency.
  - 26 new test cases:
    `tests/test_metrics.py` × 18 (metric family declarations + labels,
    `/metrics` endpoint shape, middleware records-a-request +
    route-template-not-raw-path + skips OPTIONS + skips /metrics,
    vault_call records ok/error/duration, Celery signal
    registration);
    `tests/test_grafana_dashboard.py` × 8 (file exists, valid JSON,
    has title + panels, every metric family covered by a PromQL
    query in at least one panel).

## [v0.1.0] - 2026-06-03

### Added

- **Phase 2f cycle 4 — SBOM generation + attestation + release-asset
  attachment.** Closes the Phase 2e SBOM bullet and the final
  Phase 2f cycle. **Phase 2 is closed.** Every published release now
  ships with two CycloneDX 1.5 JSON SBOMs covering the runtime dep
  closure of each image, delivered two ways for the verify path the
  consumer prefers.

  - The release workflow's API job runs `cyclonedx-py environment`
    against the synced `.venv` (`uv sync --frozen --no-dev` matches
    the production image content) and emits `sbom-api.cdx.json`.
    The web job runs `@cyclonedx/cyclonedx-npm --omit dev` against
    `web/node_modules` after `npm ci` and emits `sbom-web.cdx.json`.
  - **In-toto attestation on the image**: `cosign attest --yes
    --type cyclonedx --predicate sbom-*.cdx.json
    "${IMAGE}@${DIGEST}"` binds each SBOM to the immutable image
    digest. Same Fulcio identity as the cycle 3 signature, so a
    future `cosign verify-attestation` gate proves SBOM provenance
    from the canonical workflow path.
  - **Release asset**: both SBOMs upload as workflow artifacts and
    the `release` job downloads + attaches them via
    `gh release create … sbom-*.cdx.json`. The release page now
    leads with a "Supply-chain attestation" section covering the
    canonical `cosign verify` invocation + SBOM filenames.
  - `docs/release.md` grows a "Software Bill of Materials" section
    covering both delivery paths, the `cosign verify-attestation
    --type cyclonedx` flow, and a `jq`-based recipe for diffing
    SBOMs between two releases.
  - 7 new test cases extending
    `tests/test_release_workflow.py`'s `TestSbomGeneration`:
    cyclonedx-py + cyclonedx-npm referenced, `cosign attest` step
    with `--type cyclonedx` predicate, SBOMs uploaded via
    `actions/upload-artifact`, release job uses
    `actions/download-artifact`, `gh release create` lists the
    `.cdx.json` files as positional asset arguments.

- **Phase 2f cycle 3 — cosign keyless signing + verify gate.**
  Closes Phase 2e's "Deferred — cosign verify" bullet. Every image
  the release workflow publishes is now signed with cosign keyless
  OIDC against GitHub Actions' Fulcio issuer; a separate verify
  workflow proves the signatures verify against the canonical
  identity.

  - `.github/workflows/release.yml` extended: each
    `build-and-push-*` job installs `sigstore/cosign-installer@v3`
    and runs `cosign sign --yes "${IMAGE}@${DIGEST}"` against the
    immutable digest the push step emits. Signing the digest (not
    the tag) means a future re-tag inherits the signature.
  - New `.github/workflows/image-verify.yml` is the consumer-side
    gate. Runs on `workflow_dispatch` (with a `tag` input,
    defaults to `latest`) and on a daily 14:00 UTC cron. **Not**
    on push/PR — verification before the first release is cut
    would always fail. Two jobs (verify-api + verify-web) run
    `cosign verify` with `--certificate-identity-regexp` pinned to
    the canonical release workflow path in this repo (catches
    fork-workflow / stolen-token / malicious-mirror signatures)
    and `--certificate-oidc-issuer` pinned to GitHub Actions'
    Fulcio issuer (catches Fulcio certs from other OIDC
    providers).
  - The cron failure mode is exactly the alerting trigger an
    operator wants: a previously-verified image no longer verifies
    → someone tampered with it after publish.
  - `docs/release.md` grows a "Verifying a published image"
    section covering the downstream-pull flow + the CI workflow
    path + what the identity binding catches.
  - 16 new test cases:
    [`tests/test_image_verify_workflow.py`](tests/test_image_verify_workflow.py)
    × 11 (workflow exists, triggers on dispatch + schedule but
    NOT push/PR, dispatch takes `tag` input, contents-read
    least-privilege perms, installs cosign, calls `cosign verify`,
    pins identity regexp + OIDC issuer, covers both images); plus
    5 cases extending `tests/test_release_workflow.py`'s
    `TestCosignSigning` (installs cosign, signs pushed images,
    `--yes` flag, signs by digest not tag).

- **Phase 2f cycle 2 — tagged release workflow + GHCR publish.**
  Closes the second of four Phase 2f cycles. A `git push origin
  v<X.Y.Z>` now produces published images at
  `ghcr.io/<owner>/wg-manager:v<X.Y.Z>` (and `-web`) plus a GitHub
  release with notes extracted from `CHANGELOG.md`'s matching
  `## [v<X.Y.Z>]` section.

  - New `.github/workflows/release.yml` with four jobs:
    `extract-notes` (parses CHANGELOG via the new helper), two
    parallel build-and-push jobs for the API + web Dockerfiles,
    and a `release` job that creates the GitHub release via
    `gh release create --verify-tag`. `docker/metadata-action`
    derives semver / SHA / latest tags from the git ref.
    Permissions: `contents: write` + `packages: write` +
    `id-token: write` (cycle 3 layers cosign keyless signing on
    the same workflow). Concurrency is **not**
    `cancel-in-progress` — partial GHCR pushes are messier than
    a stuck job.
  - New `scripts/extract_changelog.py` walks `CHANGELOG.md` and
    returns the body of the `## [vX.Y.Z]` section matching the tag
    being released. Fails the workflow loudly when the heading is
    missing — operators promote `## [Unreleased]` to the versioned
    heading before tagging.
  - New `make release-notes VERSION=vX.Y.Z` wraps the extractor
    for local preview.
  - New `docs/release.md` operator runbook walks the
    promote-Unreleased → tag → workflow flow and two recovery
    paths for a mid-flight failure.
  - 24 new test cases:
    [`tests/test_extract_changelog.py`](tests/test_extract_changelog.py)
    × 8 (section matching, version-prefix normalisation,
    missing-version exit, CLI happy + error paths);
    [`tests/test_release_workflow.py`](tests/test_release_workflow.py)
    × 16 (workflow shape, triggers, permissions, GHCR target,
    metadata-action, push: true, both Dockerfiles, extractor
    shell-out, release creation, no cancel-in-progress).

- **Phase 2f cycle 1 — Dockerfiles + image-build CI gate.** Opens
  the release-engineering work-stream that Phase 2e deferred (signed
  Docker image publish, cosign verify, SBOM attachment). Cycle 1
  ships the foundation; cycles 2-4 publish, sign, and SBOM on top.

  - Multi-stage [`Dockerfile`](Dockerfile) — Python 3.13-slim-
    bookworm builder runs ``uv sync --frozen --no-dev`` against the
    locked deps, slim runtime carries only ``.venv`` + ``src/`` and
    drops to non-root ``wgmanager`` user UID 1001.
    ``python -m wg_manager`` is the default CMD.
  - Multi-stage [`web/Dockerfile`](web/Dockerfile) — Node 22-slim
    builder runs ``npm ci`` + ``npm run build``, runtime copies the
    ``.next/standalone`` bundle and runs as non-root ``nextjs`` UID
    1001. ``web/next.config.ts`` flipped to ``output: "standalone"``
    so the standalone copy has something to copy.
  - New [`.github/workflows/image-build.yml`](.github/workflows/image-build.yml)
    builds both images on every PR + push to ``main`` via
    ``docker/build-push-action@v6`` with GHA layer cache. ``push:
    false`` pinned so cycle 1 explicitly does not publish (cycle 2
    territory). Path-filtered to dep manifests + source dirs so
    code-only PRs skip the ~3-min image build.
  - **Latent build bugs surfaced + fixed**: the tailwindcss v3→v4
    dependabot bump left ``next dev`` working but ``next build``
    broken. (a) PostCSS plugin moved to ``@tailwindcss/postcss`` —
    [`web/postcss.config.mjs`](web/postcss.config.mjs) updated.
    (b) v3 ``@tailwind base/components/utilities`` directives
    dropped — [`web/app/globals.css`](web/app/globals.css)
    migrated to ``@import "tailwindcss"`` + ``@theme`` block with
    ``--color-*`` tokens replacing the ``tailwind.config.ts``
    ``theme.extend.colors`` block. (c) Pre-existing
    ``web/lib/proxy.ts:124`` ``Uint8Array<ArrayBufferLike>`` ↔
    ``BodyInit`` complaint (flagged out-of-scope in 2d CP3.4)
    blocks ``next build`` — patched with the documented type
    workaround. None of this regressed before cycle 1 because the
    existing CI runs vitest only (not ``next build``).
  - 26 new test cases: [`tests/test_dockerfile.py`](tests/test_dockerfile.py)
    × 18 (Dockerfile existence, multi-stage shape, slim base,
    Python 3.13 pin, uv ``--frozen``, non-root user, WORKDIR,
    default CMD; same shape for web/Dockerfile + standalone-output
    check on next.config.ts); [`tests/test_image_build_workflow.py`](tests/test_image_build_workflow.py)
    × 8 (workflow exists with descriptive name, triggers on PR +
    push to main, path-filtered, uses ``docker/build-push-action``,
    references both Dockerfiles by path, pins ``push: false``,
    cancels-in-progress concurrency, contents-read least-privilege
    permissions). Pure parse-and-assert — the live ``docker build``
    is what the CI workflow runs.

  Backend pytest 632/632 green (was 606 on Phase 2e cycle 4).
  Vitest 46/46. Local smoke: both ``docker build`` invocations
  succeed.

- **Phase 2e cycle 4 — `wg-manager evidence pack` SOC 2 evidence
  tarball.** Closes the ROADMAP Phase 2e stretch acceptance bullet.
  New `wg-manager evidence pack --output PATH --since-days N
  --vault-audit-log PATH` CLI command + `wg_manager.evidence`
  module assemble a tar.gz an auditor can verify end-to-end.

  - Pack contents: `audit_events.json` (auditevent table filtered
    to last N days), `certificates.json` + `operators.json` (full
    registry dumps — current state, no date filter), `vault_audit.log`
    (Vault audit file sliced to the same window by parsing each
    line's `time` field), `vault_audit_integrity.json` (per-line
    JSON parseability + `time` field presence + request/response
    `request.id` pairing — honest about being **structural only**
    because Vault does not ship a cryptographic chain across audit
    records), `system.json` (wg-manager version, git commit,
    alembic head), `MANIFEST.md` (operator-facing index), and
    `SHA256SUMS` (gnu-coreutils-shape file enumerating per-file
    sha256 so the tarball is internally self-verifying via
    `sha256sum -c`).
  - New `make evidence` Make target wraps the CLI with a timestamped
    output path under `evidence/`. The default `--vault-audit-log`
    path matches the docker-compose `vault` service mount; production
    deployments override.
  - Graceful handling of a missing Vault audit log file (a production
    stack may not co-locate the log with the host running
    `make evidence`): the integrity report flags `ok: false` with
    `reason: "missing"` rather than crashing the pack.
  - 18 new test cases:
    [`tests/test_evidence_pack.py`](tests/test_evidence_pack.py) × 13
    pin tarball shape (7 required files), content (since-days
    filter on auditevent + Vault audit log, certs + operators full
    dump, system info keys), integrity report (well-formed log,
    malformed JSON, missing file), and MANIFEST + SHA256SUMS self-
    verification (every artifact listed, hashes match actual file
    bytes).
    [`tests/test_makefile_evidence.py`](tests/test_makefile_evidence.py)
    × 5 pin the make target's shape.

- **Phase 2e reproducible-builds cycle 3 — lockfile parity CI gate.**
  Closes the "refuses unpinned upgrades" half of the ROADMAP
  reproducible-builds bullet. The release-workflow half (and the
  blocked cosign + SBOM acceptance criteria) stays deferred to a
  future release-engineering slice — no Docker publish flow exists
  on `main` yet to bolt a release job onto.

  - New
    [`.github/workflows/lockfile.yml`](.github/workflows/lockfile.yml)
    runs `uv lock --check` against pyproject.toml + uv.lock and
    `npm ci --dry-run` against web/package.json +
    web/package-lock.json on every push to main + every PR that
    touches a dep manifest (path-filtered so code-only PRs don't
    re-run the gate). The triple drift pattern that landed at merge
    time on dependabot PRs #15/#16/#17 (tailwindcss / tailwind-
    merge / jsdom bumped in sibling PRs leaving the three open PRs'
    lockfiles stale) is now caught at PR-open time.
  - New `make lockfiles` target runs the same two commands locally
    so a pre-push hand-spin reproduces a CI failure byte-for-byte.
    Slots alongside `make security` as the pre-push gate set.
  - 13 cases in
    [`tests/test_lockfile_workflow.py`](tests/test_lockfile_workflow.py)
    pin the workflow's shape (file existence, descriptive name,
    triggers on push + path-filtered PRs, two jobs running the
    `uv lock --check` + `npm ci --dry-run` commands,
    cancels-in-progress concurrency, contents-read least-privilege
    permissions) and the Makefile target (declaration + recipe body
    + help frame). Pure parse-and-assert so the fast `make test`
    invocation stays hermetic.

- **Phase 2e backup cycle 2 — encrypted DB dumps + Vault raft
  snapshots + restore runbook.** Closes a residual variant of T-1
  (a leaked MySQL dump is no longer equivalent to a leaked database)
  and ships the cadence + restore drill the on-call needs after
  cycle 1's `vault-down.md` / `key-compromise.md` send them here.

  - `wg-manager db backup --encrypt` wraps the existing JSON dump in
    a per-backup AES-256-GCM envelope. The DEK is wrapped via
    `wg_manager.crypto.make_backend()` — production deployments with
    Vault Transit get the Transit data-key flow without extra
    configuration; tests use the LocalDevBackend Fernet wrap. The
    on-disk envelope records `{version, encrypted, created_at,
    context, dek_ct, nonce_b64, ciphertext_b64}`. `db restore
    --decrypt` inverts. Mode-mismatch ergonomics: passing
    `--decrypt` against a plain backup (or omitting it on an
    encrypted backup) errors clearly rather than dying inside
    AES-GCM.
  - New `make backup-vault` target wraps `vault operator raft
    snapshot save` against the dev compose container. Production
    operators run the raw `vault` CLI against their own Vault
    address — both paths land in the runbook.
  - New `docs/runbooks/backup-restore.md` covers scope, cadence
    (MySQL every 6h, Vault every 1h as default tables), take-a-
    backup steps for both halves, the **restore order** (Vault
    first, then MySQL), verification end-to-end, and a first-time
    restore-drill checklist against a throwaway compose stack.
  - New "Backup timer" section in `docs/deploy/systemd-timer.md`
    ships `wg-manager-backup.service` + `.timer` plus
    `vault-snapshot.service` + `.timer` unit-file templates with a
    backup-side disaster-recovery walkthrough.
  - 29 new test cases:
    [`tests/test_db_backup_encrypt.py`](tests/test_db_backup_encrypt.py)
    × 10 (envelope shape, round-trip, three tamper paths, mode
    mismatch, backend integration);
    [`tests/test_makefile_backup.py`](tests/test_makefile_backup.py)
    × 5 (target declaration, raft snapshot wrapping, dev-compose
    target, snapshots path, help line); 14 new cases extending
    [`tests/test_runbooks.py`](tests/test_runbooks.py) (runbook
    existence, IR section frame, required commands, cross-references,
    README + SECURITY discoverability, systemd-timer subsection).
  - Discoverability: README's runbooks bullet now lists three
    runbooks; SECURITY.md's "Operator runbooks" section gains the
    backup-restore link. ROADMAP's backup-story bullet flips to
    shipped.

- **Phase 2e runbooks cycle 1 — operator runbooks for key compromise
  and Vault outage.** First slice of the Phase 2e ops-hygiene
  closeout. Two operator-facing runbooks under
  [`docs/runbooks/`](docs/runbooks/) that an on-call engineer can
  follow at 3am — both organised around the IR-standard frame
  (symptoms → triage → mitigation/recovery → verification →
  postmortem) and naming concrete commands rather than abstract
  steps.

  - [`docs/runbooks/key-compromise.md`](docs/runbooks/key-compromise.md)
    scopes the trust roots in play (Vault root token, unseal /
    recovery keys, Transit master key, SSH CA, PKI root +
    intermediate, operator client certs, service certs, manual-
    client WireGuard keys) and ships a per-key-class mitigation
    section naming `wg-manager certs revoke / list / renew`,
    `wg-manager crypto rewrap`,
    `vault write -f transit/keys/wg-manager/rotate`,
    `make ssh-ca-bootstrap`, `make pki-bootstrap`, and
    `wg-manager clients reprovision`. Verification section ties
    closure to observable artefacts in the
    [`wg_manager.audit`](src/wg_manager/auth.py) JSON stream and
    [`GET /crypto/status`](src/wg_manager/routers/crypto.py).
  - [`docs/runbooks/vault-down.md`](docs/runbooks/vault-down.md)
    names the symptoms (`hvac.exceptions.VaultError` at the
    encrypted-column touch point, `SSHCAError` at user-cert mint,
    `PKIError` at the renewal walker), triage (`vault status`,
    `docker compose logs vault`, audit-log snapshot before
    recovery), and four recovery branches — A: container down
    (`make vault-up` + state-loss caveat); B: sealed
    (`vault operator unseal` quorum); C: app can't reach (token /
    AppRole / network diagnosis); D: raft quorum lost
    (`vault operator raft snapshot restore`).
  - Discoverability: README's "Roadmap, security, and threat
    model" section + SECURITY.md's reporting section both link the
    runbooks. ROADMAP's Phase 2e acceptance bullet for the
    runbooks now reads "shipped 2026-06-03".
  - Tests: 40 cases in
    [`tests/test_runbooks.py`](tests/test_runbooks.py) pin file
    existence at the documented paths, the IR section frame, per-
    key-class coverage, the concrete commands the runbook tells
    the operator to run (so a rename in `cli` / Makefile that
    breaks the runbook trips the test), and the cookbook +
    threat-model + README + SECURITY cross-references. Pure
    parse-and-assert so the fast `make test` invocation stays
    hermetic.

- **Phase 2e audit-log cycle 3 — production sink docs close the
  Vault-audit work-stream.** Third and final slice of the three-cycle
  Vault-audit work-stream. Cycle 1 enabled the file audit device,
  cycle 2 added the dev-visibility sidecar, cycle 3 documents the
  production off-host shipping options as drop-in vector configs.
  After this cycle the parent ROADMAP "Vault audit log" bullet
  flips from `[~]` to `[x]`.

  - New
    [`docker/vector/production/`](docker/vector/production/)
    directory with four self-contained vector configs — each a
    complete source + sink file so an operator can
    `vector validate` it standalone before swapping it into a
    deployment. The four configs map to the four remote-sink
    shapes Phase 2e calls out:

    - [`loki.toml`](docker/vector/production/loki.toml) — Grafana
      Labs aggregation tenant. Includes a `remap` transform that
      parses Vault's JSON-per-line records so Loki labels can
      reference parsed fields. Three fixed low-cardinality labels
      (`app=vault`, `source=audit`, `cluster=$CLUSTER_NAME`) keep
      Loki's index cost bounded.
    - [`cloudwatch.toml`](docker/vector/production/cloudwatch.toml)
      — AWS CloudWatch Logs. Per-host stream, group/stream
      auto-create defaults to true (operator-friendly for fresh
      deploys; flip to false in Terraform-managed environments).
    - [`s3-object-lock.toml`](docker/vector/production/s3-object-lock.toml)
      — S3 with bucket-level Object Lock. The **archive-tier closer**
      for the Phase 2e acceptance criterion ("a compromised app
      server can't quietly delete records") — Object Lock makes
      each uploaded object immutable for a configurable retention
      window. Batches at 10 MiB / 5 min to bound the off-host
      gap. gzip-compressed, date-partitioned key layout for
      grep + Athena workflows.
    - [`syslog.toml`](docker/vector/production/syslog.toml) — TCP
      socket sink for an existing centralised
      rsyslog/syslog-ng/Splunk-syslog collector. Defaults to TCP
      (delivery confirmation + back-pressure) over UDP
      (silent-drop risk under collector overload).

  - docs/vault-cookbook.md §6 grows a "Cycle 3 — production sinks"
    subsection walking each of the five options — the four files
    above plus a `journald` deployment pattern (vector runs under
    systemd; cycle 2's console-sink stdout lands in journald
    automatically — vector itself doesn't ship a journald sink in
    its data model). Adds two cross-cutting subsections:

    - **Hash-chain verification.** Vault's audit log hash-chains
      every record (HMAC-SHA256 over the canonical JSON encoding,
      each line's hash incorporates the previous line's), so
      downstream tampering is detectable by replaying the chain.
      Documents the recovery flow when the chain breaks.
    - **Retention.** Per-sink table tying retention to the
      incident-response window vs storage cost calculus.

    The S3 walkthrough includes the bucket-creation prereq
    (Object Lock must be enabled at creation time — AWS API
    constraint, can't be enabled retroactively), the Governance-
    vs-Compliance mode choice, and the cost calculus (Glacier
    Instant-Retrieval for >30-day retention).

  - Tests: 22 cases in
    [`tests/test_vector_production_sinks.py`](tests/test_vector_production_sinks.py)
    pin the per-file contract — parametrised across all four
    configs, each one validates: parses as TOML, declares the
    cycle 1 file source at `/vault/logs/audit.log`, has exactly
    one production sink of the expected type, sink inputs trace
    back to the file source (walking the transform graph for the
    Loki case), no sink writes back into `/vault/logs/`. Plus
    two cross-cutting tests pinning the directory contents:
    every documented file is present, no undocumented TOML
    lurks. Pure parse-and-assert so the fast `make test` stays
    hermetic — live sink shipping is the operator's
    responsibility against their own infrastructure; the cookbook
    walks the smoke flow per sink. Backend pytest 495 passed
    (+22 cycle 3 cases on top of the cycle 2 baseline of 473
    against this branch's environment).

  - ROADMAP "Vault audit log" bullet flipped `[~] → [x]`; cycle 3
    flipped `[ ] → [x]`. No production-code changes — this is the
    acceptance-criterion closer for the Phase 2e bullet, which is
    docs-only by design.

- **Phase 2e audit-log cycle 2 — vector sidecar tails Vault audit
  log.** Second slice of the three-cycle Vault-audit work-stream.
  Cycle 1 enabled the file audit device and a persistent volume;
  cycle 2 makes the audit trail visible without an
  `exec vault tail` round-trip — `docker compose logs vector` is now
  the live audit feed. Cycle 3 (still open) documents the
  production-grade off-host sinks (Loki / CloudWatch / S3 + Object
  Lock).

  - New
    [`docker/vector/vault-audit.toml`](docker/vector/vault-audit.toml)
    config: a `file` source tailing `/vault/logs/audit.log` with
    `read_from = "beginning"`, feeding a `console` sink with
    `encoding.codec = "text"`. The text codec passes Vault's JSON-
    per-line records through untouched so the operator-visible
    stream is byte-for-byte identical to the on-disk audit file —
    grep-friendly, diff-friendly. JSON-parsing transforms land in
    cycle 3 when downstream sinks (Loki labels, CloudWatch fields)
    need structured access.

  - docker-compose now declares a `vector` service
    (`timberio/vector:0.41.1-alpine`, explicitly pinned — never
    `:latest`) with `depends_on: vault: condition: service_healthy`
    so the sidecar starts only after Vault's healthcheck passes and
    the audit volume is visible. The `wg_manager_vault_audit_logs`
    named volume is mounted **`:ro`** on the sidecar (defence in
    depth on top of the kernel-level guarantee — the sidecar must
    never rewrite the trail it is shipping); the config TOML is
    bind-mounted `:ro` at `/etc/vector/vector.toml`.

  - docs/vault-cookbook.md §6 grows a new "Cycle 2 — vector sidecar"
    subsection walking the wire-up, the verification flow
    (`docker compose up -d vector` → write to Vault → read
    `docker compose logs vector`), the `:ro` design choice, and the
    `read_from = "beginning"` restart semantics. The cycle 3 preview
    in the same section is sharpened from "vector / fluent-bit /
    promtail" handwaving to "join (not replace) the console sink
    with the production sink" — the operator path is now concrete.

  - Tests: 9 cases in
    [`tests/test_vector_sidecar.py`](tests/test_vector_sidecar.py)
    pinning the operator-facing contract — compose service exists,
    image is pinned (not `:latest`), audit volume is `:ro`, config
    is bind-mounted `:ro`, `depends_on vault` (accepting both list
    and condition-dict syntaxes), cycle 1's named volume survives,
    plus three cases pinning the TOML shape (file source path,
    exactly-one console sink fed from the file source, no sink
    writes back into `/vault/logs`). Pure parse-and-assert so the
    fast `make test` invocation stays hermetic; the live-vector
    smoke flow lives in the cookbook. Backend pytest 431 passed
    (was 422).

- **Phase 2e audit-log cycle 1 — Vault file audit device + volume.**
  First slice of the three-cycle Vault-audit work-stream. Vault's
  audit devices are the canonical record of every API call the server
  processes; in the Phase 2a dev compose, no device was enabled, so
  the history was lost on every container restart. Cycle 1 lands the
  device + the writable volume; cycle 2 will wire a `vector` sidecar
  for off-host visibility; cycle 3 documents the production sink
  options.

  - New module
    [`wg_manager.vault_audit`](src/wg_manager/vault_audit.py) ships
    `bootstrap_file_audit_device(client, *, device_path, log_file_path)`
    — idempotent helper that enables a Vault `file` audit device.
    Pre-checks the existing audit-device list rather than relying on
    Vault's generic HTTP 400 for double-enable (the error doesn't
    distinguish "already enabled" from "options conflict"). Refuses
    to overwrite a non-`file` device at the same path — silent
    rewiring would lose in-flight records during the file-handle
    rotation, exactly the failure mode the audit log exists to
    prevent. Default device path `file`, default in-container log
    file `/vault/logs/audit.log`. Tolerates both hvac payload shapes
    (`{"data": {...}}` envelope vs un-wrapped) so a Vault / hvac
    version bump doesn't silently break the gate.

  - New operator-facing entry point
    [`scripts/vault_audit_bootstrap.py`](scripts/vault_audit_bootstrap.py)
    + `make vault-audit-bootstrap` Makefile target. Single-line
    stdout — `audit device path=file log_file=/vault/logs/audit.log: enabled`
    or `... already present` — so CI logs read cleanly.

  - docker-compose now mounts a new `wg_manager_vault_audit_logs`
    named volume at `/vault/logs/` on the Vault container so the
    audit file survives compose restarts. The dev compose stack does
    **not** auto-enable the device — that lands as an operator-driven
    `make vault-audit-bootstrap` step so the wire-up is visible in
    the cookbook rather than a magic container hook.

  - docs/vault-cookbook.md grows a new §6 "Audit logs (Phase 2e)"
    walking the cycle-1 wire-up, the verification flow
    (`docker compose exec vault tail /vault/logs/audit.log`), reset
    semantics (the in-memory Vault loses its device on restart;
    re-run `make vault-audit-bootstrap`), and a short production-
    path preview. Sections 7 and 8 are the renumbered "Open operator
    concerns" and "Why Vault" sections; the two existing cross-refs
    (`§6 → §7` in ROADMAP and the cookbook self-ref) are updated in
    the same commit so navigation stays correct.

  - Tests: 7 cases in
    [`tests/test_vault_audit.py`](tests/test_vault_audit.py)
    pinning the four behavioural contracts — enables when empty,
    idempotent re-run, refuses different device type, respects
    custom paths — plus tolerance for both hvac payload shapes and
    two constant-default pins so the docs and the code can't drift.
    Backend pytest 422 passed (was 415).

- **Phase 2e Dependabot cycle 1 — supply-chain dep automation.** Closes
  the Phase 2e "Dependency hygiene" ROADMAP bullet. New
  [`.github/dependabot.yml`](.github/dependabot.yml) wires three
  ecosystems for weekly Mondays 14:00 UTC:

  - `uv` (Python — `pyproject.toml` + `uv.lock`)
  - `npm` (dashboard — `web/package.json`)
  - `github-actions` (version pins across the four CI-gate workflows)

  The schedule deliberately aligns with the deps-audit cron
  (`'0 14 * * 1'` in
  [`.github/workflows/deps-audit.yml`](.github/workflows/deps-audit.yml))
  so Dependabot's bump PRs and the scheduled `pip-audit` /
  `npm audit` scan share one "supply-chain Monday" rhythm — bump
  first, scan re-verifies the same surface a few hours later in
  case anything new dropped overnight.

  Grouping strategy keeps review noise tractable for a solo
  maintainer: minor + patch versions collapse into a single PR per
  ecosystem (`python-minor-patch`, `npm-minor-patch`,
  `actions-all`); majors split out for individual review because
  FastAPI 1.0, Pydantic v3, Next.js 15→16, and friends all need
  real attention rather than auto-merge. Open-PR limit is the
  Dependabot default (5) for `uv` / `npm`, dropped to 3 for
  `github-actions` since those are mostly version pins.

  Commit-message prefix `chore(deps)` with scope inclusion matches
  the existing manual-bump convention (e.g.
  `fc6796f chore(deps): add pyyaml to dev dependencies in uv.lock`)
  so the supply-chain audit trail in `git log` stays uniform whether
  the bump came from a human or Dependabot. Labels (`dependencies`
  + per-ecosystem) keep the PR list filterable.

  Docs-only outside the config file: ROADMAP § Phase 2e "Dependency
  hygiene" flipped `[x]` with the cycle reference; this entry lands
  the rationale in the changelog. No production-code changes.

- **Phase 2e CI-gate cycles 1-5 — GitHub Actions security gates.**
  Five workflows landed across two days (2026-06-02 → 2026-06-03)
  closing the Phase 2e "CI gates" ROADMAP bullet — every push to
  `main` and every PR now runs five independent jobs that bisect
  cleanly to a single workflow file when one trips. `make security`
  runs the same five gates locally in cheapest-first order so a
  pre-push hand-spin matches CI byte-for-byte.

  - **Cycle 1** —
    [`ci.yml`](.github/workflows/ci.yml). Backend job: `uv sync
    --extra dev --frozen` + `uv run pytest -q` on Python 3.13.
    Dashboard job: `npm ci` + `npm run test` (vitest) on Node 22.
    README badge added to surface workflow status. Side fix:
    `tests/test_main_tls_wiring.py::test_options_preflight_succeeds_under_tls_required`
    was depending on a local `.env` for `CORS_ORIGINS`; pinned via
    `monkeypatch.setenv` so the test is hermetic.
  - **Cycle 2** —
    [`gitleaks.yml`](.github/workflows/gitleaks.yml). Gitleaks
    v8.30.1 pinned via direct curl + tar (no third-party action);
    `--source . --no-banner --redact --verbose`; full-history scan
    (`fetch-depth: 0`). New [`.gitleaks.toml`](.gitleaks.toml)
    extends the default ruleset with a nine-file allowlist (seven
    tests with ephemeral PEMs, `tests/e2e/tls/conftest.py` Fernet
    dev key, `web/app/ssh-keys/page.tsx` placeholder) — deliberately
    file-scoped, no blanket `tests/` carve-out so a real leak in a
    test still trips the gate.
  - **Cycle 3** —
    [`deps-audit.yml`](.github/workflows/deps-audit.yml). pip-audit
    job (`uv run --frozen --with pip-audit pip-audit --strict
    --ignore-vuln CVE-2026-44405`) + npm audit job (`npm audit
    --omit=dev --audit-level=high`). Path-filtered on
    `pyproject.toml` / `uv.lock` / `web/package*.json` so unrelated
    PRs skip the network fetch; weekly Monday cron + manual
    `workflow_dispatch` for the unprompted scan. Landed alongside
    a dep bump (cryptography 46.0.6→48.0.0, idna 3.11→3.18,
    mako 1.3.10→1.3.12, starlette 1.0.0→1.2.1) to close four of
    the five CVEs the strict run flagged; the fifth
    (paramiko CVE-2026-44405) has no upstream fix yet and is
    explicitly ignored with the inline rationale.
  - **Cycle 4** — [`sast.yml`](.github/workflows/sast.yml). bandit
    job (`bandit -ll -c pyproject.toml -r src/` — medium+/medium+)
    + semgrep job (`semgrep --config=p/python --error
    --metrics=off src/` in the official `semgrep/semgrep:latest`
    container). New `[tool.bandit]` config in
    [`pyproject.toml`](pyproject.toml) skips B601 globally
    (paramiko exec IS the SSH layer's purpose — keeping the rule
    on would burn ~6 markers across two files for zero signal)
    with documented rationale in the section header. B507 stays
    enabled and catches genuine `AutoAddPolicy` regressions; the
    two known-safe sites carry per-line `# nosec B507`:
    `bootstrap_ssh.py:192` (the one legitimate TOFU site per
    CP4.5) and `ssh.py:391` (legacy fallback). semgrep `p/python`
    is clean on the current tree — no allowlist needed.
  - **Cycle 5** — ROADMAP sweep + cosign deferral. Flips the
    Phase 2e header from `[ ]` to `[~]` (CI gates + audit log
    shipped; SBOM / Dependabot / Vault audit off-host / Backup
    story / Reproducible builds still open). The CI-gates bullet
    is now `[x]` with a per-cycle breakdown; cosign verify is
    documented as **deferred** with the reason — no Docker
    publish flow exists on `main`, so there is no signed image
    for cosign to verify and no release workflow to bolt the
    gate onto. Tracked alongside the SBOM bullet (same blocker:
    cyclonedx tools need a release artefact to attach to). Both
    land when the release-engineering slice opens. Docs-only;
    no production-code changes.

  Local invocations: `make gitleaks`, `make pip-audit`,
  `make npm-audit`, `make bandit`, `make semgrep`, and
  `make security` (runs all five in cheapest-first order:
  gitleaks → bandit → pip-audit → npm-audit → semgrep). All five
  workflows green on `main` as of the cycle 5 push.

- **Phase 2e cycle 4 — `GET /audit` endpoint + dashboard page.** Closes
  the read side of the application audit log. Cycles 1-3 wrote rows
  to `auditevent`; cycle 4 exposes them over HTTP and renders them in
  the dashboard.

  - Backend [`routers/audit.py`](src/wg_manager/routers/audit.py) ships
    `GET /audit` (admin / auditor only, plain operators get 403 via
    the same `_RequireAdminOrAuditor` dep `GET /certs` uses). Filters:
    `event`, `actor_cn`, `resource_type`, `resource_id`, `since`
    (inclusive), `until` (exclusive). Pagination: `limit` (default
    100, max 500) + `offset` (≥ 0). Ordering is `ts DESC, id DESC` so
    the dashboard reads newest-first with a deterministic tiebreaker
    for rows sharing the same microsecond.

  - Response envelope `AuditEventListResponse` carries `items` +
    `total` + `limit` + `offset` — the dashboard renders a real
    "Showing X-Y of Z" line without a second request. Per-row
    `AuditEventRead` mirrors the storage shape with one intentional
    difference: `payload` is decoded back into a `dict` (rather than
    the compact-JSON string the column stores) so every consumer
    agrees on the wire shape rather than each re-parsing locally.

  - Dashboard [`web/app/audit/page.tsx`](web/app/audit/page.tsx)
    renders the filter card + paged table. Filter inputs cover the
    five exact-match filters plus the time window; Prev/Next walk by
    the server-echoed limit so the buttons stay aligned with the
    actual page boundary. Added to the left nav as "Audit log".

  - Tests: 19 backend cases in
    [`tests/test_audit_api.py`](tests/test_audit_api.py) (role gating,
    response shape, ordering, every filter individually + combined,
    pagination defaults / walk / validation) and 6 vitest cases in
    [`web/__tests__/audit.test.tsx`](web/__tests__/audit.test.tsx)
    (row rendering, empty state, filter wiring for `event` +
    `actor_cn`, Next advances offset, Prev disabled on page 1).
    Backend pytest 457/457 (was 438/438); vitest 46/46 (was 40/40).

- **Phase 2e cycle 3 — `audit.persist` wired into mutating endpoints.**
  Cycle 2 shipped the helper; cycle 3 plumbs it into the five mutating
  endpoint families called out in the plan, one per resource:

  - `POST /servers` ([`routers/servers.py`](src/wg_manager/routers/servers.py)) → `server.create`
  - `PATCH /servers/{id}` → `server.update` (captures pre-mutation row dict)
  - `DELETE /clients/{id}` ([`routers/clients.py`](src/wg_manager/routers/clients.py)) → `client.delete`
  - `POST /ssh-keys` ([`routers/ssh_keys.py`](src/wg_manager/routers/ssh_keys.py)) → `ssh_key.create`
  - `POST /certs/{id}/revoke` ([`routers/certs.py`](src/wg_manager/routers/certs.py)) → `certificate.revoke`

  Each handler now picks up the same transaction shape: capture
  `before` dict if applicable, `session.add → session.flush →
  session.refresh`, `audit.persist(...)`, then `session.commit()`. The
  audit row lives or dies alongside the mutation it records — a
  rolled-back mutation never leaves an orphan audit row, and an
  audit-write failure rolls back the mutation.

  New helper [`audit.actor_from_request(request)`](src/wg_manager/audit.py)
  extracts `actor_cn` / `actor_serial` / `actor_role` off
  `request.state.operator` and `request.state.cert_subject` (populated
  by `MTLSAuthMiddleware`), returning `None` fields when the
  middleware is in passthrough mode. Endpoints call
  `**audit.actor_from_request(request)` without branching for the
  test path. Idempotent revoke on `POST /certs/{id}/revoke` skips the
  audit row on the no-op retry so the application audit trail stays
  one-row-per-event.

  Tests: 8 cases in
  [`tests/test_audit_wiring.py`](tests/test_audit_wiring.py) — two
  for `actor_from_request` (populated + empty `request.state`), one
  per wired endpoint asserting event slug / resource binding / hash
  polarity, plus an idempotent-revoke assertion that a second
  retry doesn't double-write the audit row. Backend pytest 438/438
  (was 430/430).

- **Phase 2e cycle 2 — `wg_manager.audit` module + `persist()` helper.**
  Cycle 1's table needed a writer; cycle 2 introduces the single seam
  every mutating endpoint will go through. New module
  [`wg_manager.audit`](src/wg_manager/audit.py) exposes
  `audit_logger` (the named logger),
  [`emit(event, **fields)`](src/wg_manager/audit.py) (log-only, the
  CP5 path), [`canonical_json_hash(obj)`](src/wg_manager/audit.py)
  (sorted-key compact-JSON SHA-256), and
  [`persist(session, …)`](src/wg_manager/audit.py) which inserts one
  `AuditEvent` row **and** emits the same identity on the audit
  logger. The caller's session owns the transaction — `persist`
  flushes but never commits, so an audit failure rolls back the
  mutation it would have recorded and vice versa.

  Backward compat: [`wg_manager.auth`](src/wg_manager/auth.py)
  re-exports `audit_logger` and `_emit_audit` from the new module so
  [`bootstrap_ssh.py`](src/wg_manager/bootstrap_ssh.py) and any
  in-flight SIEM rule parsing the CP5 stream keep working unchanged.
  A regression test in
  [`tests/test_audit_persist.py`](tests/test_audit_persist.py) freezes
  the timestamp and compares `audit.emit(...)` to
  `auth._emit_audit(...)` byte-for-byte so the CP5 acceptance suite
  stays load-bearing.

  Tests: 18 cases — five for `canonical_json_hash` (order independence,
  hex shape, `None` round-trip, `datetime` fallback, exact-bytes
  construction), four for `emit` (log line shape, microsecond
  `ts`, byte-identical with the legacy helper, `_emit_audit`
  re-export), nine for `persist` (row shape, hashes, the three
  legitimate row shapes from cycle 1, payload JSON encoding, NULL
  payload, matching log line, no commit). Backend pytest 430/430
  (was 412/412).

- **Phase 2e cycle 1 — `auditevent` table.** First slice of the
  application audit log. Phase 2d CP5 ships per-request audit lines
  to stderr via the `wg_manager.audit` named logger (admit / reject /
  bootstrap-host); cycle 1 introduces the persisted-mutations
  counterpart that the upcoming `/audit` endpoint and dashboard page
  will read from. Schema lands as
  [`alembic/versions/0013_add_audit_event_table.py`](alembic/versions/0013_add_audit_event_table.py)
  + [`AuditEvent`](src/wg_manager/models.py) — `id, ts, event,
  actor_cn, actor_serial, actor_role, resource_type, resource_id,
  action, before_hash, after_hash, payload, request_id` — backed by
  four indexes (`ts`, `event`, `actor_cn`, and a composite
  `(resource_type, resource_id)` so `GET /audit?resource_type=server
  &resource_id=7` is a single index scan). Hash-only design: rows
  carry SHA-256 of the canonical-JSON pre/post-mutation, never the
  raw row, so the registry stays safe to ship in backups for the
  same reason [`Certificate`](src/wg_manager/models.py) doesn't
  store PEM bodies. No call sites yet — `wg_manager.audit.persist()`
  + per-endpoint wiring land in cycle 2 / cycle 3. Backend pytest
  412/412 (was 405/405).

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
