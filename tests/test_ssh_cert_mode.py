"""Tests for Phase 2c CP2: SSHRunner cert-based auth + host policies.

CP2's runner-level deliverables:

* :class:`SSHRunner` accepts an optional ``cert_pem`` parameter; when
  supplied, the runner loads the cert onto the private key via
  ``paramiko.Ed25519Key.load_certificate`` so the server sees a
  ``ssh-ed25519-cert-v01@openssh.com`` authentication attempt.
* The runner installs :class:`KnownHostsCAPolicy` (a new wg-manager
  policy) when given a CA public key, so a host that presents a
  CA-signed host certificate is trusted *without* TOFU. Legacy mode
  (no ``cert_pem``, no ``ca_public_key``) keeps the historical
  ``AutoAddPolicy`` to avoid breaking existing tests / deployments
  until CP3 + CP4 finish the migration.
* When ``ca_public_key`` is supplied but the server offers a raw key
  or a cert signed by a different CA, the policy raises so the
  connection is refused — this is the "TOFU is gone" guarantee from
  the roadmap.

These tests don't talk to a real sshd. The runner-construction tests
monkey-patch ``paramiko.SSHClient`` to capture the policy / pkey
passed in; the policy unit tests build synthetic
``paramiko.Ed25519Key`` objects, attach a host cert to ``public_blob``
via ``load_certificate``, and feed them straight to the policy's
``missing_host_key`` hook. Real end-to-end provisioning against a
dockerised sshd lands in CP5.
"""

from __future__ import annotations

import io
from typing import Any

import paramiko
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wg_manager.ssh import (
    KnownHostsCAPolicy,
    SSHRunner,
    UntrustedHostKeyError,
)
from wg_manager.ssh_ca import LocalDevSSHCA


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ed25519_pair() -> tuple[Ed25519PrivateKey, str, str]:
    """Generate an Ed25519 keypair and return ``(key, private_pem, public_openssh)``."""
    key = Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    public_openssh = (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        )
        .decode("ascii")
    )
    return key, private_pem, public_openssh


def _paramiko_key_with_cert(private_pem: str, cert_pem: str) -> paramiko.Ed25519Key:
    """Build a paramiko ``Ed25519Key`` carrying ``cert_pem`` on ``public_blob``."""
    pkey = paramiko.Ed25519Key.from_private_key(io.StringIO(private_pem))
    pkey.load_certificate(cert_pem)
    return pkey


def _paramiko_key_no_cert(private_pem: str) -> paramiko.Ed25519Key:
    """Build a paramiko ``Ed25519Key`` with no certificate attached."""
    return paramiko.Ed25519Key.from_private_key(io.StringIO(private_pem))


# ---------------------------------------------------------------------------
# KnownHostsCAPolicy unit tests
# ---------------------------------------------------------------------------


class TestKnownHostsCAPolicy:
    """Policy must accept CA-signed host certs and reject everything else."""

    def test_accepts_host_cert_signed_by_trusted_ca(self) -> None:
        """The happy path: sshd presented an Ed25519 host cert signed by our CA."""
        ca = LocalDevSSHCA.generate()
        _, host_private_pem, host_public_openssh = _ed25519_pair()
        host_cert = ca.mint_host_cert(
            public_key_openssh=host_public_openssh,
            principals=["hub.example.com"],
            ttl_seconds=60,
        )
        offered = _paramiko_key_with_cert(host_private_pem, host_cert.cert_pem)

        policy = KnownHostsCAPolicy(ca_public_key=ca.ca_public_key)
        # missing_host_key returns None on accept, raises on reject.
        policy.missing_host_key(client=None, hostname="hub.example.com", key=offered)

    def test_rejects_raw_host_key_with_no_cert(self) -> None:
        """A server that hasn't installed a host cert must not be trusted."""
        ca = LocalDevSSHCA.generate()
        _, host_private_pem, _ = _ed25519_pair()
        offered = _paramiko_key_no_cert(host_private_pem)

        policy = KnownHostsCAPolicy(ca_public_key=ca.ca_public_key)
        with pytest.raises(UntrustedHostKeyError):
            policy.missing_host_key(
                client=None, hostname="hub.example.com", key=offered
            )

    def test_rejects_cert_signed_by_different_ca(self) -> None:
        """A cert from someone else's CA is exactly what this policy exists to stop."""
        trusted_ca = LocalDevSSHCA.generate()
        attacker_ca = LocalDevSSHCA.generate()
        _, host_private_pem, host_public_openssh = _ed25519_pair()
        attacker_cert = attacker_ca.mint_host_cert(
            public_key_openssh=host_public_openssh,
            principals=["hub.example.com"],
            ttl_seconds=60,
        )
        offered = _paramiko_key_with_cert(host_private_pem, attacker_cert.cert_pem)

        policy = KnownHostsCAPolicy(ca_public_key=trusted_ca.ca_public_key)
        with pytest.raises(UntrustedHostKeyError):
            policy.missing_host_key(
                client=None, hostname="hub.example.com", key=offered
            )

    def test_rejects_user_cert_offered_as_host_key(self) -> None:
        """A user cert with the same key body must not pass — type mismatch is part of the contract.

        sshd would never offer a user cert as its host key, but a hostile
        intermediary might try to splice one in. Reject defensively.
        """
        ca = LocalDevSSHCA.generate()
        user_cert = ca.mint_user_cert(principals=["root"], ttl_seconds=60)
        offered = _paramiko_key_with_cert(user_cert.private_pem, user_cert.cert_pem)

        policy = KnownHostsCAPolicy(ca_public_key=ca.ca_public_key)
        with pytest.raises(UntrustedHostKeyError):
            policy.missing_host_key(
                client=None, hostname="hub.example.com", key=offered
            )


# ---------------------------------------------------------------------------
# SSHRunner cert-mode wiring
# ---------------------------------------------------------------------------


class _RecorderClient:
    """Stand-in for ``paramiko.SSHClient`` that captures everything ``__enter__`` sets up.

    SSHRunner instantiates ``paramiko.SSHClient`` and configures it before
    calling ``.connect()``. We replace the constructor so the runner's
    ``__enter__`` exercises every configuration path without ever opening a
    socket — the recorder snapshots the policy and the key passed to
    ``connect()`` so the test can make assertions on them.
    """

    def __init__(self) -> None:
        self.policy: paramiko.MissingHostKeyPolicy | None = None
        self.connect_kwargs: dict[str, Any] = {}
        self.closed: bool = False

    def set_missing_host_key_policy(
        self, policy: paramiko.MissingHostKeyPolicy
    ) -> None:
        self.policy = policy

    def connect(self, **kwargs: Any) -> None:
        self.connect_kwargs = kwargs

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def recorder(monkeypatch: pytest.MonkeyPatch) -> _RecorderClient:
    """Swap ``paramiko.SSHClient`` for a recorder so we can introspect setup."""
    instance = _RecorderClient()
    monkeypatch.setattr(
        "wg_manager.ssh.paramiko.SSHClient",
        lambda: instance,
    )
    return instance


class TestSSHRunnerCertMode:
    """``SSHRunner`` must wire cert auth + the right policy when CA mode is requested."""

    def test_cert_mode_attaches_cert_to_pkey(self, recorder: _RecorderClient) -> None:
        """The pkey passed to ``connect`` must carry the signed cert as public_blob."""
        ca = LocalDevSSHCA.generate()
        user_cert = ca.mint_user_cert(principals=["root"], ttl_seconds=60)

        runner = SSHRunner(
            host="hub.example.com",
            port=22,
            username="root",
            pkey_pem=user_cert.private_pem,
            cert_pem=user_cert.cert_pem,
            ca_public_key=ca.ca_public_key,
        )
        with runner:
            pass

        pkey = recorder.connect_kwargs["pkey"]
        assert isinstance(pkey, paramiko.Ed25519Key)
        # public_blob is the cert paramiko will offer during authentication.
        assert pkey.public_blob is not None, (
            "cert was not attached to the pkey — load_certificate was never called"
        )
        assert pkey.public_blob.key_type == "ssh-ed25519-cert-v01@openssh.com"

    def test_cert_mode_uses_known_hosts_ca_policy(
        self, recorder: _RecorderClient
    ) -> None:
        """In CA mode the runner must replace AutoAddPolicy with KnownHostsCAPolicy."""
        ca = LocalDevSSHCA.generate()
        user_cert = ca.mint_user_cert(principals=["root"], ttl_seconds=60)

        runner = SSHRunner(
            host="hub.example.com",
            port=22,
            username="root",
            pkey_pem=user_cert.private_pem,
            cert_pem=user_cert.cert_pem,
            ca_public_key=ca.ca_public_key,
        )
        with runner:
            pass

        assert isinstance(recorder.policy, KnownHostsCAPolicy)
        # The CA pubkey must be bound to the policy, not silently dropped.
        assert recorder.policy.ca_public_key.split()[1] == (
            ca.ca_public_key.split()[1]
        )

    def test_legacy_mode_unchanged(self, recorder: _RecorderClient) -> None:
        """Without ``cert_pem`` the runner keeps the historical AutoAddPolicy.

        CP2 introduces a capability; it must not break the existing
        legacy-key call sites that the Phase 1 / Phase 2b call sites
        still rely on. CP3/CP4 flip the default.
        """
        _, private_pem, _ = _ed25519_pair()
        runner = SSHRunner(
            host="legacy.example.com",
            port=22,
            username="ubuntu",
            pkey_pem=private_pem,
        )
        with runner:
            pass

        assert isinstance(recorder.policy, paramiko.AutoAddPolicy)
        assert "pkey" in recorder.connect_kwargs
        assert recorder.connect_kwargs["pkey"].public_blob is None

    def test_cert_pem_without_ca_public_key_is_rejected(self) -> None:
        """Cert auth without a host-trust policy is a footgun — reject the construction.

        If we accept ``cert_pem`` but no ``ca_public_key`` we'd be doing
        cert-based client auth against an unauthenticated host (back to
        TOFU). That defeats half of CP2's goal, so fail fast at
        construction.
        """
        ca = LocalDevSSHCA.generate()
        user_cert = ca.mint_user_cert(principals=["root"], ttl_seconds=60)

        with pytest.raises(ValueError, match="ca_public_key"):
            SSHRunner(
                host="hub.example.com",
                port=22,
                username="root",
                pkey_pem=user_cert.private_pem,
                cert_pem=user_cert.cert_pem,
            )

    def test_ca_public_key_without_cert_pem_is_rejected(self) -> None:
        """Symmetric: trusting a CA but not presenting a cert is also wrong."""
        ca = LocalDevSSHCA.generate()
        _, private_pem, _ = _ed25519_pair()
        with pytest.raises(ValueError, match="cert_pem"):
            SSHRunner(
                host="hub.example.com",
                port=22,
                username="root",
                pkey_pem=private_pem,
                ca_public_key=ca.ca_public_key,
            )
