"""Source-level verification that the cycle 2 wraps are actually in
place (Phase 3a cycle 2 safety net).

Cycle 1 shipped a gap: the ROADMAP + CHANGELOG claimed the four
Vault round-trips in ``crypto`` / ``ssh_ca`` / ``pki`` were wrapped
in ``vault_call``, but only the context manager itself was tested —
no test proved any production call site went through it. The user
caught it by opening ``pki.py``.

This file is the safety net. It greps the source for the wrap
patterns that ``test_tracing.py`` proves work in isolation. If a
future refactor removes a wrap from a steady-state call site, the
matching assertion here trips before merge.

Pattern: each test reads one source file's text and asserts the
expected wrap is present. The matchers are intentionally loose —
they look for the *engine* + *operation* combination, not the exact
indentation — so a stylistic edit doesn't trip the test, but a real
removal does.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src" / "wg_manager"


@pytest.fixture(scope="module")
def crypto_src() -> str:
    return (SRC / "crypto.py").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def ssh_ca_src() -> str:
    return (SRC / "ssh_ca.py").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def pki_src() -> str:
    return (SRC / "pki.py").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def ssh_src() -> str:
    return (SRC / "ssh.py").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Vault round-trips — the cycle 1 gap
# ---------------------------------------------------------------------------


class TestCryptoVaultWraps:
    """Every steady-state Vault round-trip in VaultTransitBackend must
    be wrapped in ``vault_call``. The bootstrap helpers
    (``enable_secrets_engine``, ``create_key``) are intentionally
    unwrapped — they're one-shot setup, not part of the operator's
    live-traffic metrics."""

    def test_encrypt_is_wrapped(self, crypto_src: str) -> None:
        assert 'vault_call(engine="transit", operation="encrypt")' in crypto_src

    def test_decrypt_is_wrapped(self, crypto_src: str) -> None:
        assert 'vault_call(engine="transit", operation="decrypt")' in crypto_src

    def test_rotate_is_wrapped(self, crypto_src: str) -> None:
        assert 'vault_call(engine="transit", operation="rotate")' in crypto_src

    def test_read_key_is_wrapped(self, crypto_src: str) -> None:
        assert 'vault_call(engine="transit", operation="read")' in crypto_src


class TestSshCaVaultWraps:
    def test_sign_ssh_key_is_wrapped(self, ssh_ca_src: str) -> None:
        """``ssh_ca.VaultSSHCA._sign`` is the single call site that
        signs every user + host cert. The wrap dispatches engine
        ``ssh`` with operation ``sign-user`` or ``sign-host`` based
        on the cert type."""
        assert 'vault_call(engine="ssh"' in ssh_ca_src
        # Both user + host paths must produce a span.
        assert "sign-user" in ssh_ca_src or "sign_user" in ssh_ca_src
        assert "sign-host" in ssh_ca_src or "sign_host" in ssh_ca_src


class TestPkiVaultWraps:
    def test_issue_is_wrapped(self, pki_src: str) -> None:
        """``_issue`` is the single call site that mints every leaf
        cert. The wrap landed on it so both server + client cert
        flows inherit the span."""
        assert 'vault_call(engine="pki", operation="issue")' in pki_src

    def test_revoke_is_wrapped(self, pki_src: str) -> None:
        assert 'vault_call(engine="pki", operation="revoke")' in pki_src

    def test_crl_read_is_wrapped(self, pki_src: str) -> None:
        assert 'vault_call(engine="pki", operation="read-crl")' in pki_src


# ---------------------------------------------------------------------------
# SSH connections / commands — new in cycle 2
# ---------------------------------------------------------------------------


class TestSshSpanWraps:
    """``SSHRunner.run`` and ``SSHRunner.sudo`` are the two
    steady-state command-execution points. Both must wrap the
    paramiko call in an ``ssh_span`` so a provisioning trace shows
    every command as a sub-span."""

    def test_run_is_wrapped(self, ssh_src: str) -> None:
        assert "ssh_span(" in ssh_src, (
            "wg_manager.ssh must import + use ssh_span around the "
            "command-exec path"
        )
        # The span operation name should be ``run`` so traces stay
        # readable.
        assert 'ssh_span("run"' in ssh_src or 'ssh_span(operation="run"' in ssh_src

    def test_sudo_is_wrapped(self, ssh_src: str) -> None:
        assert (
            'ssh_span("sudo"' in ssh_src
            or 'ssh_span(operation="sudo"' in ssh_src
        )


# ---------------------------------------------------------------------------
# Tracing setup invocation — must run at module import time
# ---------------------------------------------------------------------------


class TestTracingSetupInvoked:
    """``setup_tracing`` reads ``OTEL_EXPORTER`` from settings and
    installs the right provider. It must be called at module import
    time from both the API and the Celery worker entrypoints —
    otherwise the spans land nowhere."""

    def test_api_invokes_setup_tracing(self) -> None:
        main_src = (SRC / "main.py").read_text(encoding="utf-8")
        assert (
            "setup_tracing" in main_src or "from wg_manager.tracing" in main_src
        ), "wg_manager.main must invoke tracing setup at import time"

    def test_worker_invokes_setup_tracing(self) -> None:
        celery_src = (SRC / "celery_app.py").read_text(encoding="utf-8")
        assert "setup_tracing" in celery_src or "wg_manager.tracing" in celery_src, (
            "wg_manager.celery_app must invoke tracing setup at import "
            "time so spans land under the worker process too"
        )
