"""Phase 3d cycle 1 — HA startup guards.

The :mod:`wg_manager.pki` ``LocalDevPKI`` and :mod:`wg_manager.ssh_ca`
``LocalDevSSHCA`` backends generate a **fresh in-process keypair**
when no ``*_LOCAL_DEV_*`` PEMs are pinned in the environment. That's
fine for the test suite (one process, one root) but catastrophic in
production with two API replicas: each replica mints its own root,
so a cert issued by replica A is unverifiable by replica B.

Cycle 1 adds a startup guard that hard-fails when the operator
selects a ``local`` backend in production posture (``TLS_REQUIRED=
true``) *without* pinning the PEM material. The guard runs once at
``create_app()`` time so a misconfigured deployment crashes at boot
instead of silently producing per-replica divergent CAs that only
manifest as auth failures at the worst possible moment.
"""

from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clear_pki_pins(monkeypatch: pytest.MonkeyPatch) -> None:
    """Drop every ``PKI_LOCAL_DEV_*`` env var on the test process."""
    for key in (
        "PKI_LOCAL_DEV_ROOT_PEM",
        "PKI_LOCAL_DEV_ROOT_KEY_PEM",
        "PKI_LOCAL_DEV_INT_PEM",
        "PKI_LOCAL_DEV_INT_KEY_PEM",
    ):
        monkeypatch.delenv(key, raising=False)


def _clear_ssh_ca_pins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SSH_CA_LOCAL_DEV_PEM", raising=False)


# ---------------------------------------------------------------------------
# Production posture + dev backend + no pinned PEMs → startup error
# ---------------------------------------------------------------------------


class TestProductionPostureBlocksUnpinnedLocalDevPKI:
    """``TLS_REQUIRED=true`` + ``PKI_BACKEND=local`` + no
    ``PKI_LOCAL_DEV_*`` pins → ``create_app`` raises ``RuntimeError``.

    The error names the env vars to set so an operator can fix the
    misconfiguration without reading source."""

    def test_create_app_raises_on_unpinned_local_pki(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TLS_REQUIRED", "true")
        monkeypatch.setenv("PKI_BACKEND", "local")
        monkeypatch.setenv("SSH_CA_BACKEND", "vault")  # not the test
        _clear_pki_pins(monkeypatch)

        from wg_manager.main import create_app

        with pytest.raises(RuntimeError) as excinfo:
            create_app()
        msg = str(excinfo.value)
        assert "PKI_BACKEND=local" in msg or "PKI" in msg
        # The error names at least one of the env vars to set.
        assert "PKI_LOCAL_DEV_ROOT_PEM" in msg

    def test_create_app_raises_on_unpinned_local_ssh_ca(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TLS_REQUIRED", "true")
        monkeypatch.setenv("PKI_BACKEND", "vault")
        monkeypatch.setenv("SSH_CA_BACKEND", "local")
        _clear_ssh_ca_pins(monkeypatch)

        from wg_manager.main import create_app

        with pytest.raises(RuntimeError) as excinfo:
            create_app()
        msg = str(excinfo.value)
        assert "SSH_CA_BACKEND=local" in msg or "SSH CA" in msg.upper()


# ---------------------------------------------------------------------------
# Permitted configurations boot cleanly
# ---------------------------------------------------------------------------


class TestPermittedConfigurationsBoot:
    """Three permitted shapes:
    1. Dev posture (``TLS_REQUIRED=false``) — anything goes; tests live here.
    2. Production posture + Vault backends — the canonical production deploy.
    3. Production posture + ``local`` backends + pinned PEMs — the LocalDevPKI
       e2e test harness uses this; pinning the PEMs across replicas makes
       the dev backend cross-replica safe.
    """

    def test_dev_posture_unpinned_local_pki_is_allowed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The test suite runs in this shape — no guard."""
        monkeypatch.setenv("TLS_REQUIRED", "false")
        monkeypatch.setenv("PKI_BACKEND", "local")
        monkeypatch.setenv("SSH_CA_BACKEND", "local")
        _clear_pki_pins(monkeypatch)
        _clear_ssh_ca_pins(monkeypatch)

        from wg_manager.main import create_app

        app = create_app()
        assert app is not None

    def test_production_posture_with_vault_backends_is_allowed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TLS_REQUIRED", "true")
        monkeypatch.setenv("PKI_BACKEND", "vault")
        monkeypatch.setenv("SSH_CA_BACKEND", "vault")
        _clear_pki_pins(monkeypatch)
        _clear_ssh_ca_pins(monkeypatch)

        from wg_manager.main import create_app

        app = create_app()
        assert app is not None

    def test_production_posture_with_pinned_local_pki_is_allowed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TLS_REQUIRED", "true")
        monkeypatch.setenv("PKI_BACKEND", "local")
        monkeypatch.setenv("SSH_CA_BACKEND", "vault")
        # Pin the four PKI PEMs — values don't have to parse for this
        # boot guard; the guard only checks presence.
        monkeypatch.setenv("PKI_LOCAL_DEV_ROOT_PEM", "pem")
        monkeypatch.setenv("PKI_LOCAL_DEV_ROOT_KEY_PEM", "pem")
        monkeypatch.setenv("PKI_LOCAL_DEV_INT_PEM", "pem")
        monkeypatch.setenv("PKI_LOCAL_DEV_INT_KEY_PEM", "pem")
        _clear_ssh_ca_pins(monkeypatch)

        from wg_manager.main import create_app

        app = create_app()
        assert app is not None
