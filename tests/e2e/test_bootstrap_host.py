"""End-to-end proof for the Phase 2c CP4.5 ``bootstrap_host`` flow.

Pins the contract: a fresh box that the production
:class:`~wg_manager.ssh.SSHRunner` (CA-only auth, no TOFU) cannot
talk to becomes a box it *can* talk to after one call to
:func:`~wg_manager.bootstrap_ssh.bootstrap_host` against a real
dockerised sshd.

Test arc:

1. **Pre-bootstrap probe.** Open a production :class:`SSHRunner`
   against the container with a Vault-minted user cert and the
   Vault CA pubkey. :class:`KnownHostsCAPolicy` rejects because the
   container's host cert at the canonical path
   ``/etc/ssh/ssh_host_ed25519_key-cert.pub`` is empty / signed by
   the wrong CA (we deliberately clear the per-session shape the
   other e2e tests use).

2. **Bootstrap.** Construct a :class:`BootstrapSSHRunner` against
   the container using a one-shot seed SSH key the fixture
   installs into ``wguser``'s ``authorized_keys``. Call
   :func:`bootstrap_host` to lay down the CA pubkey, a freshly
   Vault-minted host cert, and the sshd drop-in. Reload sshd.

3. **Post-bootstrap probe.** Re-open the production runner. This
   time the host cert is in place and CA-signed by the Vault CA,
   so :class:`KnownHostsCAPolicy` admits.

4. **Audit.** Exactly one ``bootstrap.host`` audit line was emitted
   on the ``wg_manager.audit`` logger.

The test deliberately *does not* reuse the existing
``installed_host_cert`` fixture — that one writes the host cert to
the bind-mounted ``/wg-manager-e2e/`` path which the container's
default drop-in references. The bootstrap flow writes to the
canonical ``/etc/ssh/`` paths and ships its own drop-in, so we
take over the container's sshd config layer for this test.
"""

from __future__ import annotations

import json
import logging
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wg_manager.bootstrap_ssh import BootstrapSSHRunner, bootstrap_host
from wg_manager.ssh import SSHConnectionError, SSHRunner
from wg_manager.ssh_ca import VaultSSHCA

from tests.e2e.conftest import (
    E2E_CONTAINER,
    E2EEnv,
)


def _docker(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    """Run a docker command against the e2e container, raising on failure.

    Centralised wrapper so failure modes (docker missing, container
    down) surface with a single consistent shape rather than ad-hoc
    ``subprocess.run`` calls scattered through the test body.
    """
    return subprocess.run(
        list(args),
        capture_output=True,
        text=True,
        check=True,
        input=input_text,
    )


@pytest.fixture()
def seed_key(tmp_path: Path) -> tuple[Path, str]:
    """Generate a fresh ed25519 keypair and return ``(private_path, openssh_pub_line)``.

    The CLI / bootstrap runner consumes the private key off disk; the
    OpenSSH-format public line is what we install into ``wguser``'s
    ``authorized_keys`` so the bootstrap session has something to
    auth against. Generated per-test so a flaky prior run never
    leaves a stale pubkey behind.
    """
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    private_path = tmp_path / "bootstrap_seed"
    private_path.write_bytes(pem)
    private_path.chmod(0o600)
    pub_line = pub.decode("ascii") + " bootstrap-e2e-seed"
    return private_path, pub_line


@pytest.fixture()
def container_bootstrap_state(
    sshd_container: E2EEnv, seed_key: tuple[Path, str]
) -> Iterator[E2EEnv]:
    """Set up the container so the bootstrap flow has a foothold.

    Three operations:

    1. **Install the seed pubkey into ``wguser``'s
       ``authorized_keys``** so the :class:`BootstrapSSHRunner` can
       open an SSH session before any CA trust is in place.
    2. **Clear / disable the default drop-in at
       ``/etc/ssh/sshd_config.d/wg-manager-e2e.conf``** so the
       canonical bootstrap drop-in (at
       ``/etc/ssh/sshd_config.d/wg-manager.conf``) wins. Two
       ``HostCertificate`` lines in sshd's effective config would
       make sshd refuse to start; renaming the default out of the
       way avoids the collision.
    3. **Clear ``/etc/ssh/wg-manager-user-ca.pub`` and
       ``/etc/ssh/ssh_host_ed25519_key-cert.pub``** so the
       production runner's pre-bootstrap probe genuinely sees no
       valid host cert. If either lingered from a prior test, the
       pre-bootstrap rejection would be flaky.
    4. **Reload sshd** so the config changes are in effect before
       the test runs.

    Function-scoped so each test starts from the same known-good
    "fresh box" state. The previous e2e fixture
    (``installed_host_cert``) is intentionally NOT invoked here —
    we want the bootstrap flow to do the install itself.

    Yields the same :class:`E2EEnv` handle :func:`sshd_container`
    yielded, untouched.
    """
    _, pub_line = seed_key

    # 1. Install authorized_keys via docker exec.
    _docker(
        "docker",
        "exec",
        E2E_CONTAINER,
        "sh",
        "-c",
        "install -d -m 0700 -o wguser -g wguser /home/wguser/.ssh",
    )
    _docker(
        "docker",
        "exec",
        "-i",
        E2E_CONTAINER,
        "tee",
        "/home/wguser/.ssh/authorized_keys",
        input_text=pub_line + "\n",
    )
    _docker(
        "docker",
        "exec",
        E2E_CONTAINER,
        "sh",
        "-c",
        "chmod 0600 /home/wguser/.ssh/authorized_keys && "
        "chown wguser:wguser /home/wguser/.ssh/authorized_keys",
    )

    # 2. Move the default drop-in out of sshd's config-search path
    #    so the bootstrap-written drop-in's HostCertificate wins.
    _docker(
        "docker",
        "exec",
        E2E_CONTAINER,
        "sh",
        "-c",
        # ``true`` so we don't fail if the file isn't present (e.g.
        # a prior run already moved it).
        "mv -f /etc/ssh/sshd_config.d/wg-manager-e2e.conf "
        "/etc/ssh/wg-manager-e2e.conf.bak 2>/dev/null || true",
    )

    # 3. Clear any prior bootstrap artefacts at the canonical paths.
    _docker(
        "docker",
        "exec",
        E2E_CONTAINER,
        "sh",
        "-c",
        "rm -f /etc/ssh/wg-manager-user-ca.pub "
        "/etc/ssh/ssh_host_ed25519_key-cert.pub "
        "/etc/ssh/sshd_config.d/wg-manager.conf",
    )

    # 4. Reload sshd so the dropped drop-in stops being read.
    _docker(
        "docker",
        "exec",
        E2E_CONTAINER,
        "sh",
        "-c",
        "kill -HUP 1",
    )

    yield sshd_container

    # Teardown: restore the e2e drop-in and remove the bootstrap
    # artefacts so the other e2e tests in the suite (which expect the
    # default-drop-in shape) keep working when run after us. Best-
    # effort: don't fail the test on a cleanup hiccup.
    try:
        _docker(
            "docker",
            "exec",
            E2E_CONTAINER,
            "sh",
            "-c",
            "rm -f /etc/ssh/wg-manager-user-ca.pub "
            "/etc/ssh/ssh_host_ed25519_key-cert.pub "
            "/etc/ssh/sshd_config.d/wg-manager.conf "
            "/home/wguser/.ssh/authorized_keys",
        )
        _docker(
            "docker",
            "exec",
            E2E_CONTAINER,
            "sh",
            "-c",
            "mv -f /etc/ssh/wg-manager-e2e.conf.bak "
            "/etc/ssh/sshd_config.d/wg-manager-e2e.conf 2>/dev/null || true",
        )
        _docker(
            "docker",
            "exec",
            E2E_CONTAINER,
            "sh",
            "-c",
            "kill -HUP 1",
        )
    except subprocess.CalledProcessError:
        pass


def test_bootstrap_flow_against_real_sshd(
    container_bootstrap_state: E2EEnv,
    vault_ssh_ca: VaultSSHCA,
    seed_key: tuple[Path, str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The full pre-fail → bootstrap → post-succeed → audit-line arc.

    This is the contract test for CP4.5 — proves the unit-tested
    pieces actually compose into the operator-visible behaviour
    against a real OpenSSH server.
    """
    env = container_bootstrap_state
    private_path, _ = seed_key

    # ---------- 1. Pre-bootstrap: production runner rejects. ----------
    pre_user_cert = vault_ssh_ca.mint_user_cert(
        principals=[env.username], ttl_seconds=300
    )
    pre_runner = SSHRunner(
        host=env.host,
        port=env.port,
        username=env.username,
        pkey_pem=pre_user_cert.private_pem,
        cert_pem=pre_user_cert.cert_pem,
        ca_public_key=vault_ssh_ca.ca_public_key,
    )
    with pytest.raises(SSHConnectionError) as exc_info:
        with pre_runner:
            pass
    # The exact message string is paramiko-version-dependent; assert
    # the wg-manager exception type and that the underlying cause
    # surfaces (either "no certificate" or an explicit "untrusted")
    # so a future paramiko upgrade doesn't make the test silently
    # pass on a different rejection path.
    assert "fail" in str(exc_info.value).lower() or "untrust" in str(
        exc_info.value
    ).lower() or "cert" in str(exc_info.value).lower()

    # ---------- 2. Bootstrap: TOFU once via the seed key. ----------
    boot_runner = BootstrapSSHRunner(
        host=env.host,
        port=env.port,
        username=env.username,
        key_path=private_path,
    )
    with caplog.at_level(logging.WARNING, logger="wg_manager.audit"):
        with boot_runner as session:
            cert = bootstrap_host(
                runner=session,
                hostname=env.host,
                # Container's host cert principal is fixed by the
                # e2e fixture's hostname_principal — pass that so
                # KnownHostsCAPolicy admits on the post-bootstrap
                # probe (which dials env.host, but the cert
                # principal is what's baked in).
                principal=env.hostname_principal,
                ca=vault_ssh_ca,
                ttl_seconds=300,
                cn=env.username,
            )

    # ---------- 3. Post-bootstrap: production runner succeeds. ----------
    post_user_cert = vault_ssh_ca.mint_user_cert(
        principals=[env.username], ttl_seconds=300
    )
    post_runner = SSHRunner(
        host=env.host,
        port=env.port,
        username=env.username,
        pkey_pem=post_user_cert.private_pem,
        cert_pem=post_user_cert.cert_pem,
        ca_public_key=vault_ssh_ca.ca_public_key,
    )
    with post_runner as session:
        result = session.run("echo wg-manager-bootstrap-post-ok")
        assert result.rc == 0
        assert result.stdout.strip() == "wg-manager-bootstrap-post-ok"

    # ---------- 4. Audit: exactly one bootstrap.host line. ----------
    audit_records = [
        json.loads(rec.getMessage())
        for rec in caplog.records
        if rec.name == "wg_manager.audit"
    ]
    bootstrap_lines = [
        r for r in audit_records if r.get("event") == "bootstrap.host"
    ]
    assert len(bootstrap_lines) == 1, (
        f"expected exactly one bootstrap.host audit line, got "
        f"{len(bootstrap_lines)}: {bootstrap_lines!r}"
    )
    record = bootstrap_lines[0]
    assert record["hostname"] == env.host
    assert record["principal"] == env.hostname_principal
    assert record["cert_serial"] == str(cert.serial)
    assert record["cn"] == env.username
