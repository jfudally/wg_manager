# Runbook — Vault down

You are reading this because wg-manager's Vault dependency is
unreachable, sealed, or has lost quorum, and the symptoms below match
what you are seeing. Vault is wg-manager's security substrate
(Phase 2a–2e): Transit, SSH CA, PKI, and the audit log all live
there. If Vault is down, the control plane degrades hard.

This runbook gets you back to a usable state. It does not cover the
"Vault is up but a specific key was compromised" scenario — that is
[`key-compromise.md`](key-compromise.md).

Companion docs you will reach for:

- [`docs/vault-cookbook.md`](../vault-cookbook.md) — the canonical
  Vault command reference. §7 covers the production-Vault story
  (file/raft storage, auto-unseal, audit log shipping) you will need
  if you have moved off the dev container.
- [`docs/deploy/systemd-timer.md`](../deploy/systemd-timer.md) —
  bouncing the API and worker after Vault comes back, and the
  consequences of letting the cert-renewal timer skip a run.

---

## Symptoms / Detection

You are probably here because one of these tripped:

- `GET /crypto/status` returns 500 with a Vault-shaped error in the
  traceback (`hvac.exceptions.VaultError`,
  `hvac.exceptions.VaultDown`, or a bare `ConnectionRefusedError`
  against `127.0.0.1:8200`).
- The provisioning workers (Celery) are failing every task with
  `SSHCAError` at the user-cert mint step — the SSH CA backend
  cannot reach Vault to sign the ephemeral keypair.
- `wg-manager certs renew --due` is failing with a `PKIError` —
  the leaf-issuance round-trip cannot complete.
- The dashboard's Crypto page renders "backend unavailable" and
  the Certificates page either shows a stale list or 500s on issue.
- `docker compose ps` shows the `vault` service as `exited` or
  `restarting`; `docker compose logs vault` is the next thing to
  look at.
- The Vault container is up but `vault status` reports
  `Sealed: true` (production Vault only — the dev container auto-
  unseals at boot).

The decryption-side failures are the loudest because they trip on
every API request that touches an encrypted row. SSH-CA and PKI
failures only surface when something tries to mint — provision a
server, issue a cert, run the renewal walker. The audit-log
sidecar (`vector`) failing silently is also possible if Vault is
the only thing the file source has to tail.

---

## Immediate triage (first 2 minutes)

1. **Confirm the symptom.** Is Vault actually unreachable, or did
   the app lose its token?

   ```bash
   # Against the dev container:
   docker compose exec vault vault status

   # Against production Vault:
   VAULT_ADDR=https://vault.internal:8200 vault status
   ```

   Read the output before doing anything else — the next step
   depends on which row of the [Recovery](#recovery) table you are
   in.

2. **Check the container, if you are on the dev stack.**

   ```bash
   docker compose ps vault
   docker compose logs --tail=200 vault
   ```

   Common dev-container failure modes:
   - Volume mount missing → entrypoint exits before the listener
     binds.
   - `VAULT_DEV_ROOT_TOKEN_ID` got changed in a `.env` override and
     the `vault_audit_bootstrap` script's token no longer matches.

3. **Decide the blast radius.** While you triage, the app is
   degraded. If the deployment serves end-users, decide whether to
   put it in read-only mode (degraded but partially functional —
   GETs on encrypted rows 500, but cached / not-yet-touched data
   still flows) or take it fully down. Document the choice in your
   incident file.

4. **Snapshot the audit trail before recovery.** If Vault crashed
   uncleanly, the in-flight audit lines may be the most recent
   record of what was happening when it went down:

   ```bash
   docker compose exec vault cat /vault/logs/audit.log \
       > /tmp/vault-audit-pre-recovery-$(date +%s).log
   ```

   Vault audit lines are hash-chained — see
   [`docs/vault-cookbook.md`](../vault-cookbook.md) §6 for the
   verification flow once you are out of the woods.

---

## Recovery

Pick the row that matches what `vault status` told you in triage.

### A — Container down (dev stack)

Symptoms: `docker compose ps vault` shows `exited` /
`restarting` / not present.

```bash
make vault-up                              # restart the container
make vault-audit-bootstrap                 # re-enable file audit device
# bounce the app + worker so they re-establish hvac.Client sessions:
docker compose restart api worker          # if dockerised
# or: systemctl restart wg-manager-api wg-manager-worker  # if systemd
```

The dev container is in-memory by design — state from before the
restart is gone. You will need to:

- Re-run `make ssh-ca-bootstrap` (recreates `wg-manager-provision` +
  `wg-manager-hosts` SSH roles).
- Re-run `make pki-bootstrap` (recreates the PKI mounts + roles).
- Re-issue service certs the app + worker need
  (`wg-manager certs issue --type api`, `--type mysql-client`).

Every encrypted row in `client.private_key_ct` is now undecryptable
— the Transit master key was lost with the container. Reprovision
every manual client (`wg-manager clients reprovision <ID>`) to
generate fresh keypairs that the new Vault can encrypt.

If you do not want to lose state every time, move to production
Vault — see [`docs/vault-cookbook.md`](../vault-cookbook.md) §7 for
the file/raft storage flow.

### B — Container up but Vault sealed (production)

Symptoms: `vault status` reports `Sealed: true`. Common after a
host restart or a manual seal.

```bash
# Repeat until the threshold is met — one quorum member per command:
vault operator unseal <KEY-SHARE-1>
vault operator unseal <KEY-SHARE-2>
vault operator unseal <KEY-SHARE-3>
# ...

# Confirm:
vault status      # Sealed: false
```

If you are using auto-unseal, the unseal happens at Vault startup
against the KMS-backed wrapper key. A Vault that is still sealed
after restart means the KMS call is failing — check IAM / network
to the KMS provider before reaching for the manual unseal flow.

Once unsealed:

```bash
# Bounce the app + worker so they re-authenticate:
systemctl restart wg-manager-api wg-manager-worker
# or: docker compose restart api worker
```

### C — Container up, Vault unsealed, app still failing

The app cannot talk to Vault even though Vault is healthy. Almost
always a token / network issue.

1. Inspect the app's view of Vault:

   ```bash
   docker compose exec api env | grep -E 'CRYPTO_VAULT_|VAULT_'
   ```

   The address and token / AppRole credentials should match the
   running Vault.

2. If the app is using a static token (dev / legacy) and that
   token has expired, mint a fresh one (`vault token create -ttl=…`)
   and inject it. AppRole is the production path — the operator's
   `secret_id` may need a re-wrap if it expired
   (see [`docs/vault-cookbook.md`](../vault-cookbook.md) §5).

3. Network: from the app's host,
   `curl -fsS $VAULT_ADDR/v1/sys/health` should return 200. If it
   doesn't, the problem is between the app and Vault — firewall,
   DNS, or TLS chain mismatch (the app validates Vault's leaf
   against the configured trust bundle).

### D — Raft quorum lost (production HA)

Symptoms: `vault status` reports `Raft Applied Index` stuck or
errors about quorum. Recoverable from a snapshot.

```bash
# Restore from the most recent snapshot. -force is required if the
# current cluster has data the snapshot does not — confirm you want
# to overwrite before passing it:
vault operator raft snapshot restore -force /path/to/snapshot.snap

# Verify cluster health after restore:
vault operator raft list-peers
vault status
```

After restore, the chain of recent Transit / PKI / SSH-CA
operations between the snapshot and now is **lost**. Run the
[Verification](#verification) section in full — every key version
the app expects must still be readable.

Snapshot cadence + the restore drill itself live in
[`docs/vault-cookbook.md`](../vault-cookbook.md) §7. If you do not
have a recent snapshot, this row collapses into the
[Container down](#a-container-down-dev-stack) row above with the
attached pain of lost state.

---

## Verification

You have not closed the incident until each of these is true:

- `vault status` reports `Sealed: false`, `Initialized: true`,
  and a sane `HA Mode` for the storage backend you are running.
- `GET /crypto/status` returns 200 with the expected backend and
  Transit key version. `client_legacy == 0` (the post-Phase-2b
  invariant) must still hold.
- A test SSH provisioning task succeeds:
  `wg-manager servers reprovision <ID>` against a known-good
  server completes without `SSHCAError`. (Skip if there is no safe
  server to reprovision; instead inspect a recent worker log line
  for `event=ssh.cert.mint`.)
- A test cert issuance succeeds:
  `wg-manager certs issue --type api --cn healthcheck.test
  --ttl-days 1` returns a cert that
  `cryptography.x509.load_pem_x509_certificate` will parse. Revoke
  it (`wg-manager certs revoke --serial <SERIAL>`) once verified.
- `docker compose logs vector` (or your production audit log
  shipper) is once again streaming Vault audit lines, and the
  hash chain across the restart point verifies (see the
  cookbook §6 verification flow). A break in the chain means the
  audit device was re-enabled with a different file path or the
  outage spanned a log rotation — recoverable but worth flagging.
- The incident file is current.

---

## Postmortem checklist

Within one business day:

- [ ] Capture the timeline: first symptom → confirmed Vault was
      down → recovery complete → verification. Include which
      Recovery row you ended up in.
- [ ] If the recovery row was [Container down](#a-container-down-dev-stack),
      ask: should this environment have been on production Vault?
      Dev Vault losing state under an outage is by design.
- [ ] If the recovery row was [Raft quorum lost](#d-raft-quorum-lost-production-ha),
      confirm the snapshot cadence is fast enough. A snapshot older
      than the outage window is a documented gap.
- [ ] Identify the *first* signal that should have paged on-call
      earlier. The `/crypto/status` 500 is visible to operators but
      not necessarily alerting yet; the audit-log sidecar going
      silent should fire an alert that paged before users saw 500s.
- [ ] Confirm the Vault audit log between the last clean session
      and the outage is intact (hash chain verifies, no gaps).
      Anything missing is a Phase 2e cycle 3 follow-up — the
      production sink configs in
      [`docker/vector/production/`](../../docker/vector/production/)
      ship audit lines off-host so a fully-rooted Vault still
      leaves an external trail.
- [ ] If any cert TTL was crossed during the outage (renewals
      missed), confirm the systemd-timer caught up after recovery
      and no leaf is now expired. See
      [`docs/deploy/systemd-timer.md`](../deploy/systemd-timer.md)
      "the timer hasn't run in a while" subsection.
- [ ] If the runbook itself was wrong or missing a step, patch it
      in the same PR as the incident writeup.
