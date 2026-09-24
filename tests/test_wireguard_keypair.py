"""Regression tests for :func:`wg_manager.wireguard._ensure_keypair`.

These tests execute the exact shell commands ``_ensure_keypair`` would send
over SSH, but locally against a temp directory standing in for
``/etc/wireguard``. That exercises the real ``sh`` / ``wg`` semantics (file
tests, redirects, pipes) instead of string-matching a fake, which is how the
"privatekey present, publickey missing" bug slipped through originally.

Skipped when the ``wg`` binary (wireguard-tools) isn't on ``PATH``.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from wg_manager.ssh import CommandResult, SSHCommandError
from wg_manager.wireguard import _ensure_keypair

pytestmark = pytest.mark.skipif(
    shutil.which("wg") is None, reason="wireguard-tools (`wg`) not installed"
)


class LocalShellRunner:
    """Minimal ``SSHRunner`` stand-in that runs commands in a local shell.

    Every occurrence of ``/etc/wireguard`` is rewritten to ``wg_dir`` so the
    commands touch a sandbox rather than the real host config. ``sudo`` is a
    passthrough — the sandbox is owned by the test user.
    """

    def __init__(self, wg_dir: Path) -> None:
        self.wg_dir = wg_dir

    def run(self, cmd: str, check: bool = True) -> CommandResult:
        """Run ``cmd`` via ``sh -c`` with the wireguard path sandboxed.

        :raises SSHCommandError: If ``check`` is true and ``cmd`` exits non-zero,
            mirroring :meth:`wg_manager.ssh.SSHRunner.run`.
        """
        local = cmd.replace("/etc/wireguard", str(self.wg_dir))
        proc = subprocess.run(["sh", "-c", local], capture_output=True, text=True)
        result = CommandResult(cmd=cmd, rc=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)
        if check and proc.returncode != 0:
            raise SSHCommandError(cmd, proc.returncode, proc.stdout, proc.stderr)
        return result

    def sudo(self, cmd: str, check: bool = True) -> CommandResult:
        """Same as :meth:`run`; privilege escalation is irrelevant in the sandbox."""
        return self.run(cmd, check=check)


def _derive_pubkey(private_key: str) -> str:
    """Return the WireGuard public key for ``private_key`` using the real ``wg`` tool."""
    return subprocess.run(
        ["wg", "pubkey"], input=private_key, capture_output=True, text=True, check=True
    ).stdout.strip()


def _genkey() -> str:
    """Generate a fresh WireGuard private key with the real ``wg`` tool."""
    return subprocess.run(["wg", "genkey"], capture_output=True, text=True, check=True).stdout


def test_fresh_host_generates_keypair(tmp_path: Path) -> None:
    """With no keys on disk, a keypair is generated and the matching pubkey returned."""
    wg_dir = tmp_path / "wireguard"

    pubkey = _ensure_keypair(LocalShellRunner(wg_dir))

    private_key = (wg_dir / "privatekey").read_text()
    assert pubkey == _derive_pubkey(private_key)
    assert (wg_dir / "publickey").read_text().strip() == pubkey


def test_existing_privatekey_without_publickey_is_repaired(tmp_path: Path) -> None:
    """Regression: a host with ``privatekey`` but no ``publickey`` must not fail.

    Seen provisioning pihole-0: the old guard skipped generation because
    ``privatekey`` existed, then ``cat /etc/wireguard/publickey`` failed with
    "No such file or directory". The existing private key must be preserved
    (so already-registered peers stay valid) and the pubkey derived from it.
    """
    wg_dir = tmp_path / "wireguard"
    wg_dir.mkdir()
    private_key = _genkey()
    (wg_dir / "privatekey").write_text(private_key)

    pubkey = _ensure_keypair(LocalShellRunner(wg_dir))

    assert pubkey == _derive_pubkey(private_key)
    assert (wg_dir / "privatekey").read_text() == private_key
    assert (wg_dir / "publickey").read_text().strip() == pubkey


def test_stale_publickey_is_corrected_from_privatekey(tmp_path: Path) -> None:
    """A ``publickey`` that doesn't match ``privatekey`` is rewritten, not trusted.

    The private key is the source of truth for the interface; reporting a
    mismatched pubkey to the control plane would register a peer that can
    never complete a handshake.
    """
    wg_dir = tmp_path / "wireguard"
    wg_dir.mkdir()
    private_key = _genkey()
    (wg_dir / "privatekey").write_text(private_key)
    (wg_dir / "publickey").write_text(_derive_pubkey(_genkey()) + "\n")

    pubkey = _ensure_keypair(LocalShellRunner(wg_dir))

    assert pubkey == _derive_pubkey(private_key)
    assert (wg_dir / "publickey").read_text().strip() == pubkey


def test_rerun_keeps_keypair_stable(tmp_path: Path) -> None:
    """Idempotency: a second call returns the same pubkey and leaves the key intact."""
    wg_dir = tmp_path / "wireguard"
    runner = LocalShellRunner(wg_dir)

    first = _ensure_keypair(runner)
    private_key = (wg_dir / "privatekey").read_text()
    second = _ensure_keypair(runner)

    assert first == second
    assert (wg_dir / "privatekey").read_text() == private_key
