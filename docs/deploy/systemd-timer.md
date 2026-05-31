# Cert renewal via systemd timer

This guide wires Phase 2d CP4.3's ``wg-manager certs renew --due``
into a systemd timer that runs on the control-plane host. The
walker form is idempotent — re-running it after a recent successful
renewal is a no-op because each row's elapsed fraction drops below
the threshold — so a tight interval (every hour) is the recommended
default. Rotating before half of the issued lifetime is gone gives
plenty of headroom to debug a failed renewal before the cert
expires.

## What gets renewed

``wg-manager certs renew --due`` walks the ``certificate`` audit
table and re-mints every non-revoked row whose

```
elapsed = now - not_before
window  = not_after - not_before
```

ratio ``elapsed / window`` is at or past ``--threshold-pct`` (default
50). For each due row:

- The PKI backend signs a fresh leaf with the same identity
  (``cert_type`` / ``common_name`` / SANs / TTL window length).
- The new leaf overwrites the on-disk PEM at the row's stored
  ``out_*_path`` triple (CP4.3 column add via Alembic 0012).
- A new audit row is recorded; the source row stays put as the
  rotation trail.

Rows missing ``out_*_path`` (typically issued via ``POST /certs``
rather than the CLI) are skipped under ``--due`` with a warning so
the walker doesn't write half-files. Re-issue them through
``wg-manager certs issue --out-cert ... --out-key ... --out-chain ...``
to opt into walker renewal.

## Files

Drop two units under ``/etc/systemd/system/``:

**`/etc/systemd/system/wg-manager-cert-renew.service`**

```ini
[Unit]
Description=wg-manager — renew issued certs
Documentation=https://github.com/your-org/wg-manager/blob/main/docs/deploy/systemd-timer.md
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=wg-manager
Group=wg-manager
EnvironmentFile=/etc/wg-manager/wg-manager.env
ExecStart=/opt/wg-manager/.venv/bin/wg-manager certs renew --due --threshold-pct 50
# Restart the API + worker only when the renewer actually wrote new
# files. ExecStartPost runs unconditionally on success — we make it a
# no-op when nothing changed by guarding on the on-disk mtime.
ExecStartPost=/opt/wg-manager/bin/maybe-bounce-services.sh
StandardOutput=journal
StandardError=journal
```

**`/etc/systemd/system/wg-manager-cert-renew.timer`**

```ini
[Unit]
Description=wg-manager — hourly cert renewal sweep
Documentation=https://github.com/your-org/wg-manager/blob/main/docs/deploy/systemd-timer.md

[Timer]
# Hourly with a 5-minute jitter so multiple control planes don't
# stampede the PKI backend at the top of the hour.
OnCalendar=hourly
RandomizedDelaySec=5min
Persistent=true
Unit=wg-manager-cert-renew.service

[Install]
WantedBy=timers.target
```

Enable + start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now wg-manager-cert-renew.timer
sudo systemctl list-timers wg-manager-cert-renew.timer
```

## Bouncing the API + worker after a rotation

A renewed leaf is on disk, but the running ``uvicorn`` process holds
the *old* private key in memory (it's loaded at socket-bind time by
the asyncio TLS context). Two safe patterns:

**Pattern A — restart on any rotation.** Simplest. Write
``maybe-bounce-services.sh`` to ``sudo systemctl restart
wg-manager-api wg-manager-worker`` whenever the renewer logged a
``renewed`` line. The downside is one ~2-second downtime per
renewal — fine for a single-node control plane, not great for HA.

**Pattern B — graceful reload.** uvicorn supports
``SIGHUP``-driven config reload via ``--reload-include`` /
``--reload-signal``; pair that with an ``ExecReload=/bin/kill -HUP
$MAINPID`` on the API unit so the renewer can ``systemctl reload
wg-manager-api`` instead of restarting. The worker side gracefully
finishes in-flight tasks if you ``systemctl reload
wg-manager-worker`` (Celery handles SIGHUP as a warm reload).

The repository ships pattern A as the documented default because
the wg-manager control plane isn't latency-sensitive — peer-discovery
and provisioning tasks tolerate a brief gap.

## Smoke

After the first scheduled run:

```bash
sudo journalctl -u wg-manager-cert-renew.service --since '15 min ago'
```

Look for one ``renewed id=... -> new id=...`` line per cert that
crossed the threshold, plus a final ``summary: renewed=N skipped=M
scanned=K`` line. ``skipped`` should match the count of API-issued
rows in your inventory; if it climbs, that's a hint that an operator
is minting via ``POST /certs`` and forgetting to re-issue via the CLI.

## Tuning the threshold

A lower ``--threshold-pct`` rotates more often and gives more
headroom before expiry; a higher one is less churn. The default
``50`` is the cert-manager / smallstep convention. For 30-day
leaves that's a 15-day rotation window — fine for the MySQL + API
fleet. For the 365-day operator CLI / dashboard certs, ``--
threshold-pct 75`` (≈3-month rotation) is a friendlier cadence so
operators don't get prompted to re-import a fresh PKCS#12 every
six months.

The renewer is per-cert — there's no global threshold — so run two
units back-to-back if you need different cadences per cert type:

```ini
# /etc/systemd/system/wg-manager-cert-renew-services.service
ExecStart=/opt/wg-manager/.venv/bin/wg-manager certs renew --due --threshold-pct 50

# /etc/systemd/system/wg-manager-cert-renew-operators.service
ExecStart=/opt/wg-manager/.venv/bin/wg-manager certs renew --due --threshold-pct 75
```

(Both walk the full registry; the threshold is what decides which
rows actually mint.)

## Disaster recovery

If the renewer hasn't run in a while (e.g. host was offline):

1. ``--dry-run`` first to see which rows are due:
   ``wg-manager certs renew --due --dry-run``
2. If any cert has already expired (``not_after`` in the past),
   ``--due`` still picks it up; the new leaf's window starts at
   ``now`` so the rotation immediately fixes the expiry.
3. If a renewal fails (PKI backend down, disk full), the source
   row stays untouched — no half-rotated state to clean up.
4. Re-run by hand: ``sudo systemctl start
   wg-manager-cert-renew.service``.
