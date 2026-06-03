"""Unit tests for :mod:`wg_manager.vault_audit`.

Phase 2e audit-log cycle 1 — pin the bootstrap helper's contract: a
file audit device is enabled if and only if no device already exists
at the target path. Idempotent re-runs are a hard requirement because
the helper is meant to be runnable from compose-up, ``make`` targets,
and operator-driven re-bootstraps without special-casing prior state.

These tests use an ``hvac.Client``-shaped ``MagicMock`` — Vault's
audit device API is small enough that mocking is the right
granularity. A live-Vault smoke test lives in
``scripts/vault_audit_bootstrap.py`` and runs under ``make
vault-audit-bootstrap``; it is intentionally not gated to the pytest
suite (no operator wants ``make test`` to require a running Vault).
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from wg_manager.vault_audit import (
    DEFAULT_AUDIT_DEVICE_PATH,
    DEFAULT_LOG_FILE_PATH,
    bootstrap_file_audit_device,
)


class TestBootstrapFileAuditDevice:
    """Pin the four behavioural contracts the helper must hold.

    The helper is consulted by ``scripts/vault_audit_bootstrap.py`` on
    every ``make vault-audit-bootstrap`` invocation; any deviation from
    these contracts would land as a regression on the operator-facing
    side, so the unit tests are the right place to keep them honest.
    """

    def test_enables_when_no_device_at_path(self) -> None:
        """Empty audit-device list ⇒ enable_audit_device gets called."""
        client = MagicMock()
        client.sys.list_enabled_audit_devices.return_value = {"data": {}}

        result = bootstrap_file_audit_device(client)

        assert result is True
        client.sys.enable_audit_device.assert_called_once_with(
            device_type="file",
            path=DEFAULT_AUDIT_DEVICE_PATH,
            options={"file_path": DEFAULT_LOG_FILE_PATH},
        )

    def test_idempotent_when_device_already_present(self) -> None:
        """Existing file device at the path ⇒ no-op, returns False."""
        client = MagicMock()
        client.sys.list_enabled_audit_devices.return_value = {
            "data": {
                "file/": {
                    "type": "file",
                    "options": {"file_path": DEFAULT_LOG_FILE_PATH},
                },
            },
        }

        result = bootstrap_file_audit_device(client)

        assert result is False
        client.sys.enable_audit_device.assert_not_called()

    def test_refuses_to_clobber_different_device_type(self) -> None:
        """If syslog/socket lives at the path, helper backs off.

        Operator intervention is required to migrate. The contract is
        deliberately conservative: silently rewiring an existing audit
        device would create a gap in the audit trail (Vault rotates
        the file handle, in-flight records can be lost) — exactly the
        outcome the audit log exists to prevent.
        """
        client = MagicMock()
        client.sys.list_enabled_audit_devices.return_value = {
            "data": {"file/": {"type": "syslog"}},
        }

        result = bootstrap_file_audit_device(client)

        assert result is False
        client.sys.enable_audit_device.assert_not_called()

    def test_respects_custom_paths(self) -> None:
        """Caller-supplied device_path + log_file_path are honoured."""
        client = MagicMock()
        client.sys.list_enabled_audit_devices.return_value = {"data": {}}

        bootstrap_file_audit_device(
            client,
            device_path="audit-file",
            log_file_path="/var/log/vault/audit.log",
        )

        client.sys.enable_audit_device.assert_called_once_with(
            device_type="file",
            path="audit-file",
            options={"file_path": "/var/log/vault/audit.log"},
        )

    def test_handles_response_without_data_wrapper(self) -> None:
        """Tolerate hvac versions that return the list un-wrapped.

        ``hvac.api.system_backend.audit.list_enabled_audit_devices``
        returns the raw Vault API payload; some Vault versions surface
        devices at the top level rather than under ``"data"``. The
        helper accepts both shapes so a Vault server upgrade doesn't
        silently break the gate.
        """
        client = MagicMock()
        client.sys.list_enabled_audit_devices.return_value = {
            "file/": {"type": "file"},
        }

        result = bootstrap_file_audit_device(client)

        assert result is False
        client.sys.enable_audit_device.assert_not_called()


class TestDefaults:
    """Pin the default mount path + log file location.

    These are written into the cookbook + the dev compose volume mount
    + the systemd timer story; if they drift the docs drift with them.
    A failing test here means the docs need to update too.
    """

    def test_default_device_path_is_file(self) -> None:
        assert DEFAULT_AUDIT_DEVICE_PATH == "file"

    def test_default_log_file_path_matches_compose_mount(self) -> None:
        # docker-compose.yml mounts the named volume at /vault/logs;
        # the audit file sits inside that directory.
        assert DEFAULT_LOG_FILE_PATH == "/vault/logs/audit.log"
