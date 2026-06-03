# Changelog

All notable changes to wg-manager are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
for any tagged releases. Pre-tag work lands under `## [Unreleased]`.

## [Unreleased]

### Added

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
