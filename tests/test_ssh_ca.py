"""Tests for :mod:`wg_manager.ssh_ca` — Phase 2c SSH CA layer.

Both :class:`LocalDevSSHCA` (in-process throwaway ed25519 CA) and
:class:`VaultSSHCA` (hvac → Vault SSH secrets engine) implement the
same :class:`SSHCABackend` protocol. The parameterised matrix in
:class:`TestSSHCABackends` proves they share observable behaviour —
ephemeral keypair generation, principal/TTL honouring, signature by
the backend's advertised CA, log scrubbing — so callers in
``wg_manager.tasks`` and ``wg_manager.ssh`` never need to know which
backend is active.

Vault-backed cases are auto-skipped when no Vault is reachable at
``$VAULT_ADDR`` (default ``http://127.0.0.1:8200``). The plain
``pytest -q`` run stays hermetic; ``make vault-up`` + ``pytest -q``
exercises the full matrix. Phase 2c acceptance requires both modes
green, mirroring the Phase 2b pattern documented in ``docs/vault-cookbook.md``.

Log-scrub guardrail mirrors the Phase 2b ``test_log_scrub`` test:
private-key bodies and signed cert blobs must never appear in
captured ``logging`` output, because they would let a log-read
attacker replay an unexpired user cert.
"""

from __future__ import annotations

import logging
import os
import time

import hvac
import pytest
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    SSHCertificate,
    SSHCertificateType,
    load_ssh_public_identity,
)
from hvac.exceptions import InvalidRequest as HvacInvalidRequest

from wg_manager.config import Settings
from wg_manager.ssh_ca import (
    HostCert,
    LocalDevSSHCA,
    SSHCABackend,
    SSHCAError,
    UserCert,
    VaultSSHCA,
    make_ssh_ca_backend,
)


# ---------------------------------------------------------------------------
# Vault availability probe (copy of test_crypto.py pattern; intentional dup —
# we don't want a test-helpers import graph for two callers).
# ---------------------------------------------------------------------------

_VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
_VAULT_TOKEN = os.environ.get("VAULT_TOKEN", "dev-only-root")


def _vault_reachable() -> bool:
    """Return ``True`` if a Vault listener answers at ``$VAULT_ADDR``."""
    try:
        resp = requests.get(f"{_VAULT_ADDR}/v1/sys/health", timeout=0.5)
        return resp.status_code < 500
    except requests.RequestException:
        return False


_VAULT_AVAILABLE = _vault_reachable()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def local_ssh_ca() -> LocalDevSSHCA:
    """A LocalDevSSHCA seeded with a freshly-generated CA keypair.

    Each test gets its own in-process CA so a test that rotates / regenerates
    can't contaminate the next test's expected ``ca_public_key``.
    """
    return LocalDevSSHCA.generate()


@pytest.fixture
def vault_ssh_ca(request: pytest.FixtureRequest) -> VaultSSHCA:
    """A VaultSSHCA bound to per-test roles in the dev container.

    Each test mounts its own SSH secrets engine at a per-test path so the
    CA keypair created by ``submit_ca_information`` and the two role
    definitions can't leak across tests. The mount is left in place — Vault
    dev mode wipes it on restart, and the next test gets its own path
    anyway.
    """
    if not _VAULT_AVAILABLE:
        pytest.skip(f"Vault not reachable at {_VAULT_ADDR}")
    client = hvac.Client(url=_VAULT_ADDR, token=_VAULT_TOKEN)

    suffix = (
        request.node.name.replace("[", "-")
        .replace("]", "")
        .replace("/", "-")
        .lower()
    )
    mount = f"ssh-test-{suffix}"[:64]

    try:
        client.sys.enable_secrets_engine(backend_type="ssh", path=mount)
    except HvacInvalidRequest as exc:
        if "path is already in use" not in str(exc):
            raise

    try:
        client.secrets.ssh.submit_ca_information(
            generate_signing_key=True, mount_point=mount
        )
    except HvacInvalidRequest as exc:
        if "keys are already configured" not in str(exc):
            raise

    return VaultSSHCA.bootstrap(
        client=client,
        mount_point=mount,
        user_role="wg-manager-provision",
        host_role="wg-manager-hosts",
        user_default_ttl="60s",
        host_default_ttl="60s",
        allowed_users="root,deploy",
        allowed_host_domains="example.com",
    )


@pytest.fixture(params=["local", "vault"])
def ssh_ca(request: pytest.FixtureRequest) -> SSHCABackend:
    """Parameterised fixture yielding each backend in turn."""
    return request.getfixturevalue(f"{request.param}_ssh_ca")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_cert(cert_pem: str) -> SSHCertificate:
    """Parse an OpenSSH cert body. Raises if it isn't a cert at all."""
    identity = load_ssh_public_identity(cert_pem.encode())
    if not isinstance(identity, SSHCertificate):
        raise AssertionError(f"expected SSHCertificate, got {type(identity).__name__}")
    return identity


def _public_openssh(private_pem: str) -> bytes:
    """Return the OpenSSH-formatted public half of ``private_pem``."""
    key = serialization.load_ssh_private_key(private_pem.encode(), password=None)
    return key.public_key().public_bytes(  # type: ignore[union-attr]
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )


# ---------------------------------------------------------------------------
# Shared contract — both backends must satisfy these
# ---------------------------------------------------------------------------


class TestSSHCABackends:
    """Behaviours every backend must satisfy."""

    def test_mint_user_cert_returns_pair(self, ssh_ca: SSHCABackend) -> None:
        cert = ssh_ca.mint_user_cert(principals=["root"], ttl_seconds=60)
        assert isinstance(cert, UserCert)
        assert cert.private_pem.startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
        assert cert.cert_pem.startswith("ssh-ed25519-cert-v01@openssh.com ")

    def test_user_cert_parses_and_is_user_type(self, ssh_ca: SSHCABackend) -> None:
        cert = ssh_ca.mint_user_cert(principals=["root"], ttl_seconds=60)
        parsed = _parse_cert(cert.cert_pem)
        assert parsed.type == SSHCertificateType.USER

    def test_user_cert_principals_match_request(self, ssh_ca: SSHCABackend) -> None:
        cert = ssh_ca.mint_user_cert(
            principals=["root", "deploy"], ttl_seconds=60
        )
        parsed = _parse_cert(cert.cert_pem)
        # principals come back as raw bytes; normalise.
        got = [p.decode() if isinstance(p, bytes) else p for p in parsed.valid_principals]
        assert sorted(got) == ["deploy", "root"]

    def test_user_cert_ttl_honoured(self, ssh_ca: SSHCABackend) -> None:
        """The cert expires within ``ttl_seconds`` of now and is valid now.

        Vault adds a 30s skew tolerance to ``valid_after`` (so the raw
        lifetime can exceed ``ttl_seconds``); the actual security
        invariant we care about is "the cert doesn't outlive the
        requested TTL". The local backend pins both bounds exactly.
        """
        before = int(time.time())
        cert = ssh_ca.mint_user_cert(principals=["root"], ttl_seconds=60)
        parsed = _parse_cert(cert.cert_pem)
        # cryptography exposes Unix seconds (int) for valid_after / valid_before.
        valid_after_ts = parsed.valid_after
        valid_before_ts = parsed.valid_before
        slack = 5
        assert valid_before_ts <= before + 60 + slack, (
            f"cert outlives requested ttl: valid_before={valid_before_ts}, now={before}"
        )
        assert valid_after_ts <= before + slack, (
            f"cert is not valid yet: valid_after={valid_after_ts}, now={before}"
        )
        # valid_before in the returned dataclass must mirror the cert body so
        # callers don't need to re-parse the cert to schedule a renew.
        assert int(cert.valid_before.timestamp()) == valid_before_ts

    def test_user_cert_pubkey_matches_private(self, ssh_ca: SSHCABackend) -> None:
        """The cert must sign the same pubkey the ephemeral private goes with."""
        cert = ssh_ca.mint_user_cert(principals=["root"], ttl_seconds=60)
        parsed = _parse_cert(cert.cert_pem)
        embedded_pub = parsed.public_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        )
        derived_pub = _public_openssh(cert.private_pem)
        # Compare the wire-format pubkey body (the base64 chunk), ignoring
        # the algo prefix and any trailing comment.
        assert embedded_pub.split(b" ")[1] == derived_pub.split(b" ")[1]

    def test_user_cert_signed_by_ca(self, ssh_ca: SSHCABackend) -> None:
        """The cert's signature key must equal the backend's advertised CA."""
        cert = ssh_ca.mint_user_cert(principals=["root"], ttl_seconds=60)
        parsed = _parse_cert(cert.cert_pem)
        ca_advertised = ssh_ca.ca_public_key.strip().split()[1]
        signing_key_blob = parsed.signature_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        )
        assert signing_key_blob.split(b" ")[1].decode() == ca_advertised

    def test_two_mints_produce_distinct_certs(self, ssh_ca: SSHCABackend) -> None:
        a = ssh_ca.mint_user_cert(principals=["root"], ttl_seconds=60)
        b = ssh_ca.mint_user_cert(principals=["root"], ttl_seconds=60)
        # Fresh ephemeral keypair per mint, fresh serial.
        assert a.private_pem != b.private_pem
        assert a.cert_pem != b.cert_pem

    def test_mint_host_cert_returns_host_type(self, ssh_ca: SSHCABackend) -> None:
        # The caller already has a host pubkey on disk — emulate it.
        host_priv = Ed25519PrivateKey.generate()
        host_pub = (
            host_priv.public_key()
            .public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH,
            )
            .decode()
        )
        cert = ssh_ca.mint_host_cert(
            public_key_openssh=host_pub,
            principals=["wg-host-1.example.com"],
            ttl_seconds=60,
        )
        assert isinstance(cert, HostCert)
        parsed = _parse_cert(cert.cert_pem)
        assert parsed.type == SSHCertificateType.HOST
        got = [p.decode() if isinstance(p, bytes) else p for p in parsed.valid_principals]
        assert got == ["wg-host-1.example.com"]

    def test_log_scrub_no_cert_body_in_logs(
        self,
        ssh_ca: SSHCABackend,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A successful mint must not leak the private PEM or signed cert.

        Phase 2c mirrors the Phase 2b guardrail in ``test_log_scrub.py``.
        If this fails, the implementation is logging the secret it just
        produced — a log-read attacker could replay the cert until expiry.
        """
        caplog.set_level(logging.DEBUG, logger="wg_manager.ssh_ca")
        cert = ssh_ca.mint_user_cert(principals=["root"], ttl_seconds=60)
        joined = "\n".join(r.getMessage() for r in caplog.records)
        assert "BEGIN OPENSSH PRIVATE KEY" not in joined
        assert "ssh-ed25519-cert-v01@openssh.com" not in joined
        # Sanity — ensure the cert really was produced (no false positive
        # caused by the mint silently failing).
        assert cert.cert_pem


# ---------------------------------------------------------------------------
# LocalDevSSHCA-specific
# ---------------------------------------------------------------------------


class TestLocalDevSSHCA:
    """Behaviours specific to the in-process dev backend."""

    def test_from_pem_round_trips(self) -> None:
        """An operator-supplied CA PEM must reload to the same advertised CA."""
        ca = LocalDevSSHCA.generate()
        same = LocalDevSSHCA.from_pem(ca.ca_private_pem)
        assert same.ca_public_key.split()[1] == ca.ca_public_key.split()[1]

    def test_generate_returns_distinct_cas(self) -> None:
        a = LocalDevSSHCA.generate()
        b = LocalDevSSHCA.generate()
        assert a.ca_public_key != b.ca_public_key


# ---------------------------------------------------------------------------
# VaultSSHCA-specific
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _VAULT_AVAILABLE, reason="Vault not reachable")
class TestVaultSSHCA:
    """Behaviours that depend on the real Vault SSH secrets engine."""

    def test_principal_outside_allowed_set_rejected(
        self, vault_ssh_ca: VaultSSHCA
    ) -> None:
        """Vault enforces ``allowed_users`` — asking for an unknown principal
        should raise :class:`SSHCAError`, not return a usable cert."""
        with pytest.raises(SSHCAError):
            vault_ssh_ca.mint_user_cert(
                principals=["nobody-who-was-never-allowed"], ttl_seconds=60
            )

    def test_ttl_above_max_rejected(self, vault_ssh_ca: VaultSSHCA) -> None:
        """The bootstrap pinned ``max_ttl=60s``; ask for a year."""
        with pytest.raises(SSHCAError):
            vault_ssh_ca.mint_user_cert(
                principals=["root"], ttl_seconds=60 * 60 * 24 * 365
            )


# ---------------------------------------------------------------------------
# Factory selection
# ---------------------------------------------------------------------------


class TestMakeSSHCABackend:
    """``make_ssh_ca_backend()`` reads settings and returns the right backend."""

    def test_local_backend_selected_by_settings(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SSH_CA_BACKEND", "local")
        # No CA PEM supplied → auto-generate (dev/test only).
        monkeypatch.delenv("SSH_CA_LOCAL_DEV_PEM", raising=False)
        backend = make_ssh_ca_backend(Settings())
        assert isinstance(backend, LocalDevSSHCA)
        cert = backend.mint_user_cert(principals=["root"], ttl_seconds=60)
        assert cert.cert_pem.startswith("ssh-ed25519-cert-v01@openssh.com ")

    def test_local_backend_honours_supplied_pem(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When an operator supplies a CA PEM, ``make_ssh_ca_backend`` must
        load that exact CA — proves operators can pin a stable dev CA across
        restarts when they want one."""
        ca = LocalDevSSHCA.generate()
        monkeypatch.setenv("SSH_CA_BACKEND", "local")
        monkeypatch.setenv("SSH_CA_LOCAL_DEV_PEM", ca.ca_private_pem)
        backend = make_ssh_ca_backend(Settings())
        assert isinstance(backend, LocalDevSSHCA)
        assert backend.ca_public_key.split()[1] == ca.ca_public_key.split()[1]

    def test_vault_backend_selected_by_settings(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``make_ssh_ca_backend`` constructs a :class:`VaultSSHCA` against
        an already-bootstrapped mount. Bootstrap inline so this test
        doesn't quietly depend on ``make ssh-ca-bootstrap`` having been
        run out of band."""
        if not _VAULT_AVAILABLE:
            pytest.skip(f"Vault not reachable at {_VAULT_ADDR}")
        mount = "ssh-factory-test"
        client = hvac.Client(url=_VAULT_ADDR, token=_VAULT_TOKEN)
        try:
            client.sys.enable_secrets_engine(backend_type="ssh", path=mount)
        except HvacInvalidRequest as exc:
            if "path is already in use" not in str(exc):
                raise
        try:
            client.secrets.ssh.submit_ca_information(
                generate_signing_key=True, mount_point=mount
            )
        except HvacInvalidRequest as exc:
            if "keys are already configured" not in str(exc):
                raise

        monkeypatch.setenv("SSH_CA_BACKEND", "vault")
        monkeypatch.setenv("VAULT_ADDR", _VAULT_ADDR)
        monkeypatch.setenv("VAULT_TOKEN", _VAULT_TOKEN)
        monkeypatch.setenv("SSH_CA_VAULT_MOUNT", mount)
        monkeypatch.setenv("SSH_CA_VAULT_USER_ROLE", "wg-manager-provision")
        monkeypatch.setenv("SSH_CA_VAULT_HOST_ROLE", "wg-manager-hosts")
        backend = make_ssh_ca_backend(Settings())
        assert isinstance(backend, VaultSSHCA)

    def test_unknown_backend_value_is_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SSH_CA_BACKEND", "magical-realism")
        with pytest.raises(ValueError, match="magical-realism"):
            make_ssh_ca_backend(Settings())

    def test_local_backend_stable_across_calls(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Two calls to ``make_ssh_ca_backend`` with the local backend and
        no pinned PEM must return backends advertising the *same* CA
        public key.

        Regression test for the 2026-05-28 lockout: previously each call
        generated a fresh in-memory CA, so a host cert installed by one
        call could not be verified by the next. The docstring on
        :class:`LocalDevSSHCA` advertises "regenerated on every restart" —
        per-call regeneration violates that contract.
        """
        monkeypatch.setenv("SSH_CA_BACKEND", "local")
        monkeypatch.delenv("SSH_CA_LOCAL_DEV_PEM", raising=False)
        first = make_ssh_ca_backend(Settings())
        second = make_ssh_ca_backend(Settings())
        assert first.ca_public_key == second.ca_public_key, (
            "local backend regenerated the CA between calls — "
            "host certs installed by one call cannot be verified by the next"
        )


# ---------------------------------------------------------------------------
# Settings exposes operator-tunable defaults for the Vault SSH CA roles
# ---------------------------------------------------------------------------


class TestVaultSSHCASettings:
    """The ``make ssh-ca-bootstrap`` script reads these to configure roles."""

    def test_settings_exposes_allowed_users(self) -> None:
        """``ssh_ca_vault_allowed_users`` must exist on Settings so the
        bootstrap script can thread an operator-configured list through to
        Vault.

        Default must be permissive enough that the common cloud-image
        usernames (``azureuser``, ``ubuntu``, ``ec2-user``) work
        out-of-the-box, otherwise the first ``discover-all`` against a
        cloud VM fails with "is not a valid value for valid_principals"
        — the exact 2026-05-28 symptom.
        """
        s = Settings()
        allowed = s.ssh_ca_vault_allowed_users
        assert isinstance(allowed, str) and allowed.strip()
        names = {u.strip() for u in allowed.split(",") if u.strip()}
        for required in ("root", "azureuser", "ubuntu", "ec2-user"):
            assert required in names, (
                f"{required!r} missing from default ssh_ca_vault_allowed_users "
                f"({allowed!r}); cloud-image VMs using {required} won't be "
                f"reachable via CA-mode SSH"
            )


# ---------------------------------------------------------------------------
# VaultSSHCA.bootstrap defaults must be usable out of the box
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _VAULT_AVAILABLE, reason="Vault not reachable")
class TestVaultSSHCABootstrapDefaults:
    """The bootstrap defaults must produce roles that actually sign certs.

    The 2026-05-28 incident hit two role-misconfiguration cliffs in
    succession (host role: no ``allowed_domains`` → refuses any
    principal; user role: ``allowed_users="root"`` → refuses
    ``azureuser``). Both are bootstrap defaults the operator would
    have to override blindly to fix. These tests pin the contract:
    "bootstrap with the documented defaults and then mint a host cert
    for an arbitrary host principal".
    """

    def _bootstrap_default(
        self, mount_suffix: str, **overrides: object
    ) -> VaultSSHCA:
        """Bootstrap a per-test mount with all defaults left implicit.

        Returns the constructed backend so the test can call ``mint_*``.
        """
        client = hvac.Client(url=_VAULT_ADDR, token=_VAULT_TOKEN)
        mount = f"ssh-bootstrap-default-{mount_suffix}"[:64]
        try:
            client.sys.enable_secrets_engine(backend_type="ssh", path=mount)
        except HvacInvalidRequest as exc:
            if "path is already in use" not in str(exc):
                raise
        return VaultSSHCA.bootstrap(
            client=client,
            mount_point=mount,
            user_role="wg-manager-provision",
            host_role="wg-manager-hosts",
            **overrides,  # type: ignore[arg-type]
        )

    def test_default_bootstrap_signs_host_cert_for_ip_principal(self) -> None:
        """Host role created with the default args must sign a host cert
        for an IP-only principal.

        Real symptom: ``vault refused to sign (host, principals=['<ip>']):
        role is not configured to allow any principals``. This test fails
        today because the bootstrap skips configuring ``allowed_domains``
        when the caller doesn't pass ``allowed_host_domains``.
        """
        backend = self._bootstrap_default(mount_suffix="ip-principal")
        host_priv = Ed25519PrivateKey.generate()
        host_pub = (
            host_priv.public_key()
            .public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH,
            )
            .decode()
        )
        cert = backend.mint_host_cert(
            public_key_openssh=host_pub,
            principals=["192.0.2.42"],
            ttl_seconds=60,
        )
        assert cert.cert_pem.startswith("ssh-ed25519-cert-v01@openssh.com ")

    def test_default_bootstrap_signs_host_cert_for_arbitrary_domain(self) -> None:
        """Same shape, with a DNS-style principal — proves the permissive
        default isn't IP-specific."""
        backend = self._bootstrap_default(mount_suffix="dns-principal")
        host_priv = Ed25519PrivateKey.generate()
        host_pub = (
            host_priv.public_key()
            .public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH,
            )
            .decode()
        )
        cert = backend.mint_host_cert(
            public_key_openssh=host_pub,
            principals=["wg-host-7.cloud-provider.internal"],
            ttl_seconds=60,
        )
        assert cert.cert_pem.startswith("ssh-ed25519-cert-v01@openssh.com ")

    def test_default_bootstrap_signs_user_cert_for_cloud_image_principal(
        self,
    ) -> None:
        """User role's default ``allowed_users`` must include the common
        cloud-image accounts. Specifically ``azureuser`` is the trigger
        case from the 2026-05-28 incident.

        Fails today because the bootstrap's ``allowed_users`` default is
        the single string ``"root"``.
        """
        backend = self._bootstrap_default(mount_suffix="cloud-user")
        cert = backend.mint_user_cert(principals=["azureuser"], ttl_seconds=60)
        assert cert.cert_pem.startswith("ssh-ed25519-cert-v01@openssh.com ")
