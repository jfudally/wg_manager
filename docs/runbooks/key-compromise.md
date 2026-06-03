# Runbook — Key compromise

You are reading this because a trust root wg-manager depends on is
suspected leaked, lost, or exposed to someone who should not have
seen it. Read [Scope](#scope) first to pick the row that matches your
situation, then go straight to the matching row's
[Mitigation](#mitigation) sub-section. Triage is the same for every
key class; mitigation is not.

This runbook covers wg-manager's own trust roots only. WireGuard peer
public keys are not secret; this runbook does not apply to them.

Companion docs you will reach for during the response:

- [`docs/vault-cookbook.md`](../vault-cookbook.md) — the canonical
  Vault command reference; every Transit / SSH-CA / PKI / audit-log
  step in this runbook lifts from there.
- [`docs/THREAT_MODEL.md`](../THREAT_MODEL.md) — what each key
  protects and which threats its loss reopens.
- [`docs/deploy/systemd-timer.md`](../deploy/systemd-timer.md) —
  bouncing the API + worker after a cert rotation, which most of the
  Mitigation paths require.
- [`SECURITY.md`](../../SECURITY.md) — the disclosure address; if
  you discovered the compromise externally, report it before reading
  further.

---

## Scope

| Key class                          | Where it lives                                           | Loss = |
| ---------------------------------- | -------------------------------------------------------- | ------ |
| Vault root token                   | docker-compose env (dev) / ops vault (prod)              | Full control of every other key below. **Most severe.** |
| Vault unseal / recovery keys       | Operator hands (Shamir) / KMS (auto-unseal)              | Attacker can unseal a stolen storage backend. |
| Transit master key (`wg-manager`)  | Inside Vault, never extractable                          | Decrypt every manual-client WireGuard private key at rest. |
| SSH CA private key                 | Inside Vault SSH engine, never extractable               | Mint user + host certs for the managed fleet (= root on every server). |
| PKI root + intermediate            | Inside Vault PKI engine, never extractable               | Mint trusted leaves for API / dashboard / CLI / MySQL. |
| Operator client cert (`cli` / `dashboard`) | Operator laptop, PKCS#12 keystore                | Impersonate that operator's role (admin / operator / auditor). |
| Service cert (`api` / `mysql-client` / `mysql-server`) | App host filesystem                  | Impersonate that service to its peer. |
| Manual-client WireGuard private key | `client` table, Transit-encrypted at rest               | Read traffic of one specific manual client. |

A leaked **root token** is a leak of every row below it — work top-down.

---

## Symptoms / Detection

You are probably reading this because one of these tripped:

- An operator reports a laptop / keystore was stolen, or a PKCS#12
  was emailed/Slacked/screenshared.
- A backup tarball, container image, or `mysqldump` left the
  controlled environment (S3 bucket public, repo push, dev-env
  snapshot shared externally).
- `docker compose logs vector` (the Phase 2e cycle 2 audit feed
  tailing `/vault/logs/audit.log`) shows Vault operations from an
  unexpected source IP or with an unfamiliar `display_name`.
- The `wg_manager.audit` JSON stream shows `event=auth.admit`
  decisions for a `cn` that should not have a cert.
- A CI run or a leaked secret-scanner alert flagged a Vault token,
  PEM, or PKCS#12 in a commit.
- `GET /certs` shows a cert with a serial you do not recognise.

Any of the above is enough — escalate to triage before you have
proof of exploitation. Cost of a false alarm: one cert rotation.
Cost of a missed real one: see the Scope table.

---

## Immediate triage (first 5 minutes)

These steps are the same regardless of which key class is in scope.
Run them in order; do not pause for postmortem framing.

1. **Stop the bleed at the network edge.**
   - If the compromise is a stolen operator laptop or a leaked
     PKCS#12, get the cert serial from the operator (or from
     `wg-manager certs list`) before doing anything else.
   - If the compromise is the Vault root token, *immediately* take
     the host off any network you do not control end-to-end.
2. **Snapshot the audit trail.** Before you rotate, copy the Vault
   audit log to a separate host so the rotation activity does not
   bury the attacker's prior activity:

   ```bash
   docker compose exec vault cat /vault/logs/audit.log \
       > /tmp/vault-audit-$(date +%s).log
   ```

   See [`docs/vault-cookbook.md`](../vault-cookbook.md) §6 for the
   hash-chain verification flow that will tell you whether the file
   has been tampered with.
3. **Pull the cert registry snapshot.**

   ```bash
   wg-manager certs list > /tmp/cert-inventory-$(date +%s).json
   ```

   This is the "before" picture for the postmortem.
4. **Open a channel.** Even if you are the sole operator, write the
   incident in a file (`incidents/YYYY-MM-DD-key-compromise.md`) as
   you go — what you saw, what you did, what time. The postmortem
   becomes trivial; trying to reconstruct timestamps the next day
   is not.
5. **Pick the matching Mitigation row below.** Top-down if multiple
   classes are in scope.

---

## Mitigation

Every step is idempotent — re-running a rotate / revoke is safe and
sometimes necessary if the first attempt was interrupted.

### Vault root token leaked

If you are running the dev container (`make vault-up`), the root
token is `dev-only-root` and is baked into compose. There is no
"rotation" — destroy the dev environment and rebuild:

```bash
make vault-down
docker volume rm wg_manager_vault_audit_logs   # if you want a clean trail
make vault-up
make vault-audit-bootstrap                     # re-enable file audit device
make ssh-ca-bootstrap                          # re-create SSH roles
make pki-bootstrap                             # re-create PKI mounts + roles
```

Then re-issue every cert from the [Operator / service cert revoked
or leaked](#operator-or-service-cert-revoked-or-leaked) row, because
the PKI hierarchy changed underneath them.

In production:

1. Revoke the leaked token: `vault token revoke <token>`.
2. Generate a fresh root token using the Shamir unseal keys
   (`vault operator generate-root`). This requires a quorum of unseal
   key holders — see [`docs/vault-cookbook.md`](../vault-cookbook.md)
   §7 for the production-Vault story.
3. Rotate every AppRole `secret_id` (the app + worker re-fetch
   theirs from the deploy manifest's response-wrapping flow).
4. Audit-log review: every Vault operation since the suspected leak
   timestamp. Anything you did not initiate is an attacker action.
   Rotate any key the attacker touched per the matching row below.

### Vault unseal / recovery keys leaked

The leaked share alone does not unseal Vault — Shamir needs a
quorum. But assume the attacker has the others too:

1. Generate a new root key:
   `vault operator rekey -init -key-shares=N -key-threshold=K`.
2. Distribute new unseal keys via the same trusted channel the
   originals used (separate physical envelopes, separate KMS
   accounts — never one channel).
3. Destroy the prior unseal-key envelopes in the presence of a
   witness. Record the destruction in the incident file.

If you are using auto-unseal (KMS-backed), rotate the KMS key
material directly via the KMS-provider's flow; Vault will pick up
the new wrapper on next start.

### Transit master key leaked

The Transit master key never leaves Vault, so a "leak" here means
either the Vault server was rooted or a snapshot of the storage
backend was exfiltrated. Either way:

1. Rotate the Transit key — bumps the version, new writes use the
   new version:

   ```bash
   docker compose exec -e VAULT_TOKEN=dev-only-root vault \
       vault write -f transit/keys/wg-manager/rotate
   ```

   Production: same command without the compose wrapper, against
   your production Vault address and a token / AppRole login with
   `update` on `transit/keys/wg-manager/rotate`.
2. Rewrap every encrypted row so the data store lands on the new
   version (and the old version can be safely disabled afterwards):

   ```bash
   wg-manager crypto rewrap
   ```

   The CLI walks the `client` table (manual-client WireGuard private
   keys) and is the only consumer left after Phase 2c CP4.4 dropped
   the SSH-key ciphertext columns.
3. Disable the leaked Transit key version once rewrap is complete:

   ```bash
   docker compose exec -e VAULT_TOKEN=dev-only-root vault \
       vault write transit/keys/wg-manager/config min_decryption_version=2
   ```

   Anything still pointing at v1 will start failing decrypt — confirm
   `GET /crypto/status` reports zero legacy rows first.
4. If the attacker had Vault for any window: assume they decrypted
   every manual-client WireGuard private key in scope at the time.
   Re-generate the affected clients
   (`wg-manager clients reprovision <id>`) so the on-wire keys roll
   to material the attacker has never seen.

### SSH CA private key leaked

The SSH CA's private key lives inside Vault's SSH secrets engine
and never leaves. A "leak" means Vault itself was compromised — treat
this row as a strict superset of the root-token row above. After the
Vault-side rotation in the root-token row, you also need to:

1. Re-bootstrap the SSH CA roles:

   ```bash
   make ssh-ca-bootstrap
   ```

   This rotates `wg-manager-provision` (user cert role) and
   `wg-manager-hosts` (host cert role) idempotently. The CA public
   key changes; every managed host's `/etc/ssh/wg-manager-user-ca.pub`
   is now stale.
2. Re-bootstrap every managed host:

   ```bash
   wg-manager bootstrap-host --hostname X --ssh-key PATH
   ```

   Use a temporary operator SSH key (separate from the wg-manager
   trust chain) because the new CA is not yet trusted. Repeat for
   every row in `wg-manager servers list`.
3. Treat every server in the fleet as potentially-rooted. The
   attacker had the ability to mint user certs for `root` against
   every host's principal set during the window of compromise.
   Decide per-host whether to reprovision from a known-good image
   or accept the risk in writing.

### PKI root or intermediate leaked

Same Vault-rooted superset framing as the SSH CA. After the Vault
rotation:

1. Re-bootstrap the PKI hierarchy. This rotates the root, the
   intermediate, and both leaf-issuing roles:

   ```bash
   make pki-bootstrap
   ```

   The CA chain (`/v1/pki/ca_chain`) changes; every cert previously
   issued has lost its trust anchor.
2. Re-issue every active cert from the audit registry. The fastest
   path is the renewal walker — it preserves identity (CN, SANs,
   operator FK, TTL window length) while minting fresh material
   against the new chain:

   ```bash
   wg-manager certs renew --due --threshold-pct 100
   ```

   `--threshold-pct 100` makes the walker treat every non-revoked
   row as due.
3. Bounce the API and worker so they pick up the new
   `mysql-client` and TLS server certs. See
   [`docs/deploy/systemd-timer.md`](../deploy/systemd-timer.md) for
   the recommended restart pattern.
4. The browser-imported PKCS#12 on every operator's laptop is now
   untrusted by the new chain. Issue and distribute fresh
   `dashboard` PKCS#12 bundles via:

   ```bash
   wg-manager certs issue --type dashboard --cn ops@example.com \
       --out-pkcs12 /tmp/ops.p12 --pkcs12-password '...'
   ```

   Operators import the new PKCS#12 and re-attempt
   `GET /certs/whoami` to confirm.

### Operator or service cert revoked or leaked

This is the most common compromise shape and the easiest to recover
from — the PKI hierarchy itself is intact.

1. Identify the cert row. The CN or serial is enough:

   ```bash
   wg-manager certs list | jq '.[] | select(.common_name == "ops@example.com")'
   ```

2. Revoke. This calls the PKI backend CRL endpoint and flips
   `certificate.revoked = true` atomically:

   ```bash
   wg-manager certs revoke --serial <SERIAL>
   ```

   The middleware reads the registry on every request, so the next
   request bearing the revoked serial gets 401 with `auth.reject
   reason=operator-cert-revoked` in the audit feed.
3. Issue a replacement of the same type (preserving CN / SANs):

   ```bash
   wg-manager certs renew --id <REPLACED-ROW-ID>
   ```

   Or, if the leak makes the original identity itself unsafe (e.g.
   the operator is no longer trusted), `wg-manager certs issue`
   with a fresh CN.
4. Distribute the replacement via a trusted channel (not the same
   channel that leaked the original). The CLI prints the
   leaf / key / chain to `--out-cert/--out-key/--out-chain` paths
   and the dashboard type additionally writes a PKCS#12.
5. **Service cert** (`api` / `mysql-client` / `mysql-server`):
   bounce the consuming process after replacement.
   See [`docs/deploy/systemd-timer.md`](../deploy/systemd-timer.md).

### Manual-client WireGuard private key suspected leaked

A specific peer's traffic is the blast radius — the rest of the
fleet is unaffected.

1. Reprovision the client. This regenerates the keypair, re-wraps
   the new private key with Transit, and exports a fresh
   `wg0.conf`:

   ```bash
   wg-manager clients reprovision <CLIENT-ID>
   ```

2. Distribute the new `wg0.conf` to the legitimate peer via a
   trusted channel.
3. The old public key remains on the server's `wg0.conf` until the
   reprovision flow re-exports the server config — confirm
   `wg-manager servers reprovision <SERVER-ID>` has run (it is
   chained into `clients reprovision` by default).

---

## Verification

You have not closed the incident until each of these is true:

- `wg-manager certs list` shows the leaked serials with
  `revoked: true` and a non-null `revoked_at`.
- A request bearing a revoked cert lands a 401 with
  `auth.reject reason=operator-cert-revoked` in the
  `wg_manager.audit` JSON stream.
- For Transit rotation: `GET /crypto/status` reports the active key
  version is the post-rotation one and `client_legacy == 0`.
- For SSH-CA / PKI rotation: a fresh `wg-manager bootstrap-host` or
  `wg-manager certs issue --type api` succeeds against the new
  chain, and `GET /certs/whoami` from a freshly-imported PKCS#12
  returns 200.
- The Vault audit log between the suspected-leak timestamp and now
  has been read end-to-end. Any operation you cannot attribute is
  treated as attacker activity and the corresponding key is rotated
  per its row above.
- The incident file is current — every action, every timestamp,
  every command.

---

## Postmortem checklist

Within one business day of closing the incident:

- [ ] Capture the timeline: leak → detection → first response →
      mitigation complete → verification.
- [ ] Identify the *first* defence that should have caught this
      earlier. (Audit-log alert that did not fire? Cert scanner
      that did not run? Documentation that did not exist?)
- [ ] Decide whether the affected key class needs a *shorter* TTL
      going forward. Phase 2d ships with a 30-day default on most
      cert types and 5 minutes on user certs — if the compromise
      window made you uncomfortable, the TTL is a knob.
- [ ] If the runbook itself was wrong or unclear at any step, file
      a patch in the same PR as the incident writeup. Stale
      runbooks are worse than no runbooks.
- [ ] Confirm `docs/THREAT_MODEL.md`'s "Closed in" column still
      matches reality after the rotation. If the compromise re-
      opened a closed row, update the table.
- [ ] If the leak involved a backup or a snapshot, file a follow-up
      to revisit the backup-encryption story (Phase 2e cycle 2
      tracks the Transit-encrypted MySQL dump flow).
- [ ] Post-mortem document linked from the incident file is shared
      with anyone who depends on wg-manager — internally or
      otherwise.
