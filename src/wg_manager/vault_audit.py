"""Vault file audit-device bootstrap (Phase 2e).

Vault's audit devices are the canonical record of every API call the
server processes — admin actions, key writes, cert issuance, the lot.
In Phase 2a's dev compose, no audit device is enabled by default, so
that history is lost on every container restart. This module ships a
single helper that enables a ``file``-type audit device pointing at a
path inside the container's persistent volume; cycle 2 then layers a
``vector`` sidecar on top to tail and ship the file off-host.

The helper is deliberately small and idempotent: it pre-checks the
existing audit-device list rather than relying on Vault's "path is
already in use" error, because Vault's API rejects double-enable with
a generic HTTP 400 that doesn't distinguish "already enabled" from
"options conflict". Pre-checking the list is unambiguous and lets us
return a meaningful boolean to the caller.

Reasoned scope:

* If no device exists at the target path → enable it.
* If a ``file`` device is already at the path → no-op, return False.
* If a different device type (syslog / socket) is at the path → also
  no-op. Silently rewiring an existing audit device would lose
  in-flight records during the rotation, exactly the failure mode the
  audit log exists to prevent. Operator must migrate manually.
"""

from __future__ import annotations

import logging
from typing import Any

import hvac

_LOG = logging.getLogger(__name__)

#: Vault audit-device mount path. ``"file"`` mirrors HashiCorp's docs
#: convention so the cookbook can name it without translation.
DEFAULT_AUDIT_DEVICE_PATH = "file"

#: In-container path of the audit log file. The docker-compose ``vault``
#: service mounts the ``wg_manager_vault_audit_logs`` named volume at
#: ``/vault/logs/``; the file sits inside that directory so the volume
#: + the audit device + (cycle 2) the vector tail all reference the
#: same on-disk location.
DEFAULT_LOG_FILE_PATH = "/vault/logs/audit.log"


def bootstrap_file_audit_device(
    client: hvac.Client,
    *,
    device_path: str = DEFAULT_AUDIT_DEVICE_PATH,
    log_file_path: str = DEFAULT_LOG_FILE_PATH,
) -> bool:
    """Enable a Vault file audit device. Idempotent.

    :param client: An authenticated :class:`hvac.Client`.
    :param device_path: Vault audit-device mount path (the URL fragment
        Vault uses in ``/sys/audit/<path>``). Defaults to
        :data:`DEFAULT_AUDIT_DEVICE_PATH`.
    :param log_file_path: In-container path where Vault writes the
        audit records. Must be on a writable volume the Vault process
        can reach. Defaults to :data:`DEFAULT_LOG_FILE_PATH`.
    :returns: ``True`` if the helper enabled the device on this call;
        ``False`` if a device was already present at ``device_path``
        (regardless of its type or options).
    :raises hvac.exceptions.VaultError: If the live enable call fails
        for any reason other than "already enabled".

    The helper does not validate that an existing device matches the
    requested options — by design. If an operator has hand-tuned a
    pre-existing device, the helper backs off and lets them keep it.
    """
    devices = _list_enabled_audit_devices(client)
    key = f"{device_path}/"
    if key in devices:
        _LOG.info(
            "audit device already enabled at path=%s; skipping bootstrap",
            device_path,
        )
        return False

    client.sys.enable_audit_device(
        device_type="file",
        path=device_path,
        options={"file_path": log_file_path},
    )
    _LOG.info(
        "enabled file audit device path=%s log_file=%s",
        device_path,
        log_file_path,
    )
    return True


def _list_enabled_audit_devices(client: hvac.Client) -> dict[str, Any]:
    """Return the audit-device map, tolerating both hvac payload shapes.

    ``hvac.api.system_backend.audit.list_enabled_audit_devices`` has,
    across releases, returned either the raw Vault API payload (devices
    at the top level) or a wrapped ``{"data": {...}}`` envelope. We
    accept both so a Vault / hvac version bump doesn't silently break
    the gate.
    """
    raw = client.sys.list_enabled_audit_devices() or {}
    if "data" in raw and isinstance(raw["data"], dict):
        return raw["data"]
    return raw
