"""Phase 2c SSH Certificate Authority layer.

The whole point of this module is that wg-manager never persists an SSH
private key again. The worker mints a fresh ephemeral Ed25519 keypair
**in memory**, asks an SSH CA to sign the public half into a short-lived
certificate, presents the (private, cert) pair to ``paramiko`` for one
session, and drops both on the floor. A DB-read attacker (T-1 in
``docs/THREAT_MODEL.md``) finds nothing usable; an attacker who steals a
log line gets a cert that expires in seconds.

Two backends implement :class:`SSHCABackend`:

* :class:`LocalDevSSHCA` — an in-process throwaway CA. Used by the test
  suite and by developers who don't want a Vault container in the loop.
  **Not** safe for production: the CA private key lives in process
  memory. The first :func:`make_ssh_ca_backend` call generates (or
  loads) the CA and every later call in the same process returns the
  same instance (see :data:`_LOCAL_CA_CACHE`); on a *new* process the
  CA is fresh again unless the operator pinned one via
  ``SSH_CA_LOCAL_DEV_PEM``. Multi-process dev (API + Celery worker)
  therefore requires the pin — otherwise the worker and the API each
  hold a different CA and CA-mode SSH breaks on the second hop.
* :class:`VaultSSHCA` — wraps the Vault SSH secrets engine. The CA
  private key never leaves Vault; we hold only the public half and a
  token that can request signatures from the configured roles. This is
  the production path.

Both implementations advertise their CA public key in OpenSSH
``ssh-ed25519 AAAA…`` form via :attr:`SSHCABackend.ca_public_key`,
which the provisioning step writes to ``TrustedUserCAKeys`` on managed
hosts so that sshd accepts certs from the right authority.

Mirrors the structure of :mod:`wg_manager.crypto`: a ``Protocol``
contract, a dev backend with a ``generate``/``from_pem`` factory pair,
a Vault backend with a ``bootstrap`` classmethod, and a
:func:`make_ssh_ca_backend` selector keyed off :class:`Settings`.
"""

from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol, runtime_checkable

import hvac
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    SSHCertificateBuilder,
    SSHCertificateType,
    load_ssh_public_identity,
)
from hvac.exceptions import InvalidPath, InvalidRequest, VaultError

from wg_manager.config import Settings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class SSHCAError(RuntimeError):
    """Raised when the CA refuses to mint, or returns an unusable cert.

    Wraps the underlying Vault / cryptography exception so callers (Celery
    tasks, the migration CLI, the rotate endpoint) catch a single
    project-named error type rather than re-raising
    :class:`hvac.exceptions.InvalidRequest`.
    """


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class UserCert:
    """A freshly-minted user certificate plus the ephemeral private key it signs.

    :ivar private_pem: OpenSSH-formatted Ed25519 private key. The CA only
        ever saw the public half. Hold onto this for the duration of the
        SSH session and let it fall out of scope afterwards.
    :ivar cert_pem: OpenSSH-formatted certificate
        (``ssh-ed25519-cert-v01@openssh.com …``).
    :ivar valid_after: When the cert becomes valid. Always set to ``now``
        by both backends so this is mostly informational.
    :ivar valid_before: When the cert expires. Callers that want to renew
        proactively should sleep until ``valid_before - jitter``.
    :ivar serial: The cert serial as recorded by the CA. Useful for the
        audit log (Phase 2e).
    :ivar principals: The principal list embedded in the cert; copied here
        so callers don't need to re-parse the cert for it.
    """

    private_pem: str
    cert_pem: str
    valid_after: datetime
    valid_before: datetime
    serial: int
    principals: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class HostCert:
    """A host certificate that should be installed in ``/etc/ssh/`` on the target.

    Unlike :class:`UserCert` there is no private key to ship — the caller
    supplied the public key to be signed, and the host already has the
    matching private key on disk.

    :ivar cert_pem: OpenSSH-formatted host cert
        (``ssh-ed25519-cert-v01@openssh.com …``).
    :ivar valid_after: When the cert becomes valid.
    :ivar valid_before: Expiry — surfaced in the dashboard so operators
        can spot certs approaching renewal.
    :ivar serial: The cert serial as recorded by the CA.
    :ivar principals: Hostnames / SANs embedded in the cert.
    """

    cert_pem: str
    valid_after: datetime
    valid_before: datetime
    serial: int
    principals: tuple[str, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class SSHCABackend(Protocol):
    """Minimum surface every SSH CA backend must implement."""

    name: str

    @property
    def ca_public_key(self) -> str:
        """Return the CA's public key in single-line OpenSSH format.

        The string must be safe to drop straight into
        ``/etc/ssh/wg-manager-user-ca.pub`` and referenced from
        ``TrustedUserCAKeys`` in ``sshd_config``.
        """
        ...

    def mint_user_cert(
        self, *, principals: list[str], ttl_seconds: int
    ) -> UserCert:
        """Generate an ephemeral Ed25519 keypair, sign its public half, return both."""
        ...

    def mint_host_cert(
        self,
        *,
        public_key_openssh: str,
        principals: list[str],
        ttl_seconds: int,
    ) -> HostCert:
        """Sign ``public_key_openssh`` as a host cert.

        Caller supplies the host's existing public key — never the private
        key.
        """
        ...


# ---------------------------------------------------------------------------
# LocalDevSSHCA
# ---------------------------------------------------------------------------


def _new_ephemeral_pair() -> tuple[Ed25519PrivateKey, bytes]:
    """Generate an Ed25519 private key and return ``(key, openssh_pubkey)``."""
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    return key, pub


def _private_pem(key: Ed25519PrivateKey) -> str:
    """Serialise ``key`` to an unencrypted OpenSSH PEM string."""
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


class LocalDevSSHCA:
    """In-process Ed25519 CA. Dev/test backend only.

    The CA private key lives in this process's memory. Use
    :meth:`generate` for an ephemeral CA (the test fixture path) or
    :meth:`from_pem` when an operator pins one via
    ``SSH_CA_LOCAL_DEV_PEM`` for cross-restart stability.

    **Production deployments must use :class:`VaultSSHCA` instead.** This
    backend logs nothing about the keys it produces (see the log-scrub
    test in ``tests/test_ssh_ca.py``).
    """

    name = "local"

    def __init__(self, ca_private_key: Ed25519PrivateKey) -> None:
        """Bind to an already-loaded CA private key.

        Prefer :meth:`generate` or :meth:`from_pem`; this constructor is
        public mostly so tests can inject a known CA.
        """
        self._ca_private = ca_private_key
        self._ca_public_openssh = (
            ca_private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH,
            )
            .decode("ascii")
        )

    @classmethod
    def generate(cls) -> "LocalDevSSHCA":
        """Create a backend backed by a fresh, in-memory Ed25519 CA."""
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_pem(cls, pem: str) -> "LocalDevSSHCA":
        """Load a CA from an OpenSSH PEM body.

        :raises SSHCAError: If ``pem`` isn't a valid Ed25519 OpenSSH private
            key.
        """
        try:
            key = serialization.load_ssh_private_key(pem.encode(), password=None)
        except (ValueError, TypeError) as exc:
            raise SSHCAError(f"could not load CA PEM: {exc}") from exc
        if not isinstance(key, Ed25519PrivateKey):
            raise SSHCAError(
                f"SSH CA must be ed25519, got {type(key).__name__}"
            )
        return cls(key)

    @property
    def ca_public_key(self) -> str:
        """The CA's public key in single-line OpenSSH form."""
        return self._ca_public_openssh

    @property
    def ca_private_pem(self) -> str:
        """The CA's private key in OpenSSH PEM form.

        Exposed so an operator can copy the auto-generated CA out of one
        test run and pin it via ``SSH_CA_LOCAL_DEV_PEM`` for the next.
        Production must never call this — :class:`VaultSSHCA` doesn't
        expose the equivalent because the key never leaves Vault.
        """
        return _private_pem(self._ca_private)

    def mint_user_cert(
        self, *, principals: list[str], ttl_seconds: int
    ) -> UserCert:
        """Sign a fresh ephemeral keypair as a short-lived user cert."""
        ephemeral, _pub = _new_ephemeral_pair()
        valid_after = int(time.time())
        valid_before = valid_after + ttl_seconds
        serial = secrets.randbits(63)
        builder = (
            SSHCertificateBuilder()
            .public_key(ephemeral.public_key())
            .type(SSHCertificateType.USER)
            .serial(serial)
            .key_id(f"wg-manager-user-{serial}".encode())
            .valid_principals([p.encode() for p in principals])
            .valid_after(valid_after)
            .valid_before(valid_before)
            .add_extension(b"permit-pty", b"")
        )
        try:
            cert = builder.sign(self._ca_private)
        except (ValueError, TypeError) as exc:
            raise SSHCAError(f"failed to sign user cert: {exc}") from exc
        return UserCert(
            private_pem=_private_pem(ephemeral),
            cert_pem=cert.public_bytes().decode("ascii"),
            valid_after=datetime.fromtimestamp(valid_after, tz=timezone.utc),
            valid_before=datetime.fromtimestamp(valid_before, tz=timezone.utc),
            serial=serial,
            principals=tuple(principals),
        )

    def mint_host_cert(
        self,
        *,
        public_key_openssh: str,
        principals: list[str],
        ttl_seconds: int,
    ) -> HostCert:
        """Sign ``public_key_openssh`` as a host cert."""
        try:
            pub = load_ssh_public_identity(public_key_openssh.encode())
        except (ValueError, TypeError) as exc:
            raise SSHCAError(f"host public key is not parseable: {exc}") from exc
        valid_after = int(time.time())
        valid_before = valid_after + ttl_seconds
        serial = secrets.randbits(63)
        builder = (
            SSHCertificateBuilder()
            .public_key(pub)
            .type(SSHCertificateType.HOST)
            .serial(serial)
            .key_id(f"wg-manager-host-{serial}".encode())
            .valid_principals([p.encode() for p in principals])
            .valid_after(valid_after)
            .valid_before(valid_before)
        )
        try:
            cert = builder.sign(self._ca_private)
        except (ValueError, TypeError) as exc:
            raise SSHCAError(f"failed to sign host cert: {exc}") from exc
        return HostCert(
            cert_pem=cert.public_bytes().decode("ascii"),
            valid_after=datetime.fromtimestamp(valid_after, tz=timezone.utc),
            valid_before=datetime.fromtimestamp(valid_before, tz=timezone.utc),
            serial=serial,
            principals=tuple(principals),
        )


# ---------------------------------------------------------------------------
# VaultSSHCA
# ---------------------------------------------------------------------------


class VaultSSHCA:
    """Vault SSH secrets engine backend.

    The CA private key never leaves Vault; we hold an authenticated
    :class:`hvac.Client` and the mount + role names that
    :meth:`bootstrap` (or an operator running ``make ssh-ca-bootstrap``)
    previously configured. Each :meth:`mint_user_cert` /
    :meth:`mint_host_cert` makes one Vault round-trip.

    :ivar name: Discriminator surfaced on :class:`SSHCABackend`.
    """

    name = "vault"

    def __init__(
        self,
        *,
        client: hvac.Client,
        mount_point: str,
        user_role: str,
        host_role: str,
        ca_public_key: str,
    ) -> None:
        """Bind to an already-configured engine. Prefer :meth:`bootstrap`."""
        self._client = client
        self._mount = mount_point
        self._user_role = user_role
        self._host_role = host_role
        self._ca_public = ca_public_key.strip()

    @classmethod
    def bootstrap(
        cls,
        *,
        client: hvac.Client,
        mount_point: str,
        user_role: str,
        host_role: str,
        user_default_ttl: str = "5m",
        host_default_ttl: str = "24h",
        allowed_users: str = "root,ubuntu,ec2-user,azureuser,debian,admin",
        allowed_host_domains: str = "",
    ) -> "VaultSSHCA":
        """Configure the SSH engine and two roles idempotently, then return a backend.

        Safe to call repeatedly: the SSH mount and CA are left alone if
        already present, and ``create_role`` is upsert-shaped on Vault's
        side so re-running with the same parameters is a no-op.

        :param client: An authenticated :class:`hvac.Client`.
        :param mount_point: Vault path under which the SSH engine lives.
        :param user_role: Role name used for short-lived operator user certs.
        :param host_role: Role name used to sign managed-host host certs.
        :param user_default_ttl: Default + max TTL on the user role.
            Phase 2c keeps this short (5 minutes) so a stolen cert dies on
            its own.
        :param host_default_ttl: Default + max TTL on the host role.
            Host certs rotate slower than user certs; the
            ``POST /servers/{id}/rotate-host-cert`` endpoint (Checkpoint 3)
            triggers an explicit re-sign before expiry.
        :param allowed_users: Comma-separated list of legal user-cert
            principals. Default covers the common cloud-image accounts
            (``root`` for bare-metal/self-managed boxes, ``ubuntu`` for
            Ubuntu AMIs/Multipass, ``ec2-user`` for Amazon Linux,
            ``azureuser`` for Azure Marketplace images, ``debian`` for
            Debian AMIs, ``admin`` for some Debian/CIS hardened images)
            so a first-run ``wg-manager ssh migrate-to-ca`` against any
            mainstream VM succeeds without forcing the operator to
            re-bootstrap the role. Production deployments should tighten
            this to the specific accounts in use.
        :param allowed_host_domains: ``allowed_domains`` for the host role.
            Empty (the default) is interpreted as "any principal" —
            ``allowed_domains='*'`` with ``allow_bare_domains=True`` and
            ``allow_subdomains=True`` — so the bootstrap is usable
            against IP-only fleets (the 2026-05-28 cloud-VM lockout was
            caused by the prior "no restriction" default actually
            translating to "Vault refuses every principal"). Production
            deployments with stable DNS should set this to a real
            domain list (e.g. ``"prod.example.com"``).
        :raises SSHCAError: If Vault rejects the mount / CA / role
            configuration for a reason other than "already exists".
        """
        try:
            try:
                client.sys.enable_secrets_engine(
                    backend_type="ssh", path=mount_point
                )
            except InvalidRequest as exc:
                if "path is already in use" not in str(exc):
                    raise

            try:
                client.secrets.ssh.submit_ca_information(
                    generate_signing_key=True, mount_point=mount_point
                )
            except InvalidRequest as exc:
                if "keys are already configured" not in str(exc):
                    raise

            client.secrets.ssh.create_role(
                name=user_role,
                key_type="ca",
                allow_user_certificates=True,
                allow_host_certificates=False,
                default_user=allowed_users.split(",")[0],
                allowed_users=allowed_users,
                default_extensions={"permit-pty": ""},
                allowed_extensions="permit-pty",
                ttl=user_default_ttl,
                max_ttl=user_default_ttl,
                mount_point=mount_point,
            )

            host_payload: dict[str, object] = {
                "name": host_role,
                "key_type": "ca",
                "allow_user_certificates": False,
                "allow_host_certificates": True,
                "ttl": host_default_ttl,
                "max_ttl": host_default_ttl,
                "mount_point": mount_point,
            }
            if allowed_host_domains:
                host_payload["allowed_domains"] = allowed_host_domains
                host_payload["allow_subdomains"] = True
            else:
                # Vault refuses to sign a host cert unless the role
                # whitelists the requested principal in some way; an
                # unset ``allowed_domains`` therefore means "no host
                # cert is signable", not "any host cert is signable" —
                # the opposite of what an operator running ``make
                # ssh-ca-bootstrap`` against a clean Vault expects.
                # Bridge that by treating the empty-domain default as
                # "any principal": ``*`` + bare + subdomains covers
                # IP-only fleets, internal DNS, and FQDNs uniformly.
                host_payload["allowed_domains"] = "*"
                host_payload["allow_bare_domains"] = True
                host_payload["allow_subdomains"] = True
            client.secrets.ssh.create_role(**host_payload)  # type: ignore[arg-type]
        except VaultError as exc:
            raise SSHCAError(f"bootstrap failed at {mount_point!r}: {exc}") from exc

        ca_public = cls._read_ca_public_key(client, mount_point)
        return cls(
            client=client,
            mount_point=mount_point,
            user_role=user_role,
            host_role=host_role,
            ca_public_key=ca_public,
        )

    @staticmethod
    def _read_ca_public_key(client: hvac.Client, mount_point: str) -> str:
        """Fetch the CA's advertised public key from ``/<mount>/public_key``.

        hvac doesn't wrap this read endpoint, so we go through the raw
        adapter. The response body is the OpenSSH single-line public key.
        """
        try:
            resp = client.adapter.get(f"/v1/{mount_point}/public_key")
        except InvalidPath as exc:  # pragma: no cover — bootstrap precondition
            raise SSHCAError(
                f"SSH CA at {mount_point!r} has no public key configured"
            ) from exc
        # Some response shapes give us a Response object, others give a
        # parsed dict (older hvac). Cover both.
        text = getattr(resp, "text", None)
        if text is None:
            text = str(resp)
        return text.strip()

    @property
    def ca_public_key(self) -> str:
        """The CA's OpenSSH-formatted public key."""
        return self._ca_public

    def _sign(
        self, *, role: str, public_key_openssh: str, principals: list[str],
        ttl_seconds: int, cert_type: str,
    ) -> tuple[str, int, int, int]:
        """Single Vault sign round-trip. Returns ``(signed, serial, va, vb)``.

        ``serial`` / ``va`` / ``vb`` are pulled from the cert body by
        :func:`load_ssh_public_identity` rather than the API response —
        the API surfaces them on ``data`` but the field names have moved
        across Vault versions and the cert itself is authoritative.
        """
        try:
            resp = self._client.secrets.ssh.sign_ssh_key(
                name=role,
                public_key=public_key_openssh,
                valid_principals=",".join(principals),
                cert_type=cert_type,
                ttl=f"{ttl_seconds}s",
                mount_point=self._mount,
            )
        except VaultError as exc:
            raise SSHCAError(
                f"vault refused to sign ({cert_type}, principals={principals!r}): {exc}"
            ) from exc
        signed_key = str(resp["data"]["signed_key"]).strip()
        if not signed_key.startswith("ssh-ed25519-cert-v01@openssh.com "):
            raise SSHCAError(
                f"unexpected cert algo from vault: {signed_key.split()[0]!r}"
            )
        try:
            parsed = load_ssh_public_identity(signed_key.encode())
        except (ValueError, TypeError) as exc:
            raise SSHCAError(f"vault returned an unparseable cert: {exc}") from exc
        # cryptography exposes valid_after / valid_before as Unix seconds (int).
        return signed_key, int(parsed.serial), int(parsed.valid_after), int(parsed.valid_before)  # type: ignore[union-attr]

    def mint_user_cert(
        self, *, principals: list[str], ttl_seconds: int
    ) -> UserCert:
        """Mint an ephemeral keypair locally, ask Vault to sign the pubkey."""
        ephemeral, pub = _new_ephemeral_pair()
        signed, serial, va, vb = self._sign(
            role=self._user_role,
            public_key_openssh=pub.decode("ascii"),
            principals=principals,
            ttl_seconds=ttl_seconds,
            cert_type="user",
        )
        return UserCert(
            private_pem=_private_pem(ephemeral),
            cert_pem=signed,
            valid_after=datetime.fromtimestamp(va, tz=timezone.utc),
            valid_before=datetime.fromtimestamp(vb, tz=timezone.utc),
            serial=serial,
            principals=tuple(principals),
        )

    def mint_host_cert(
        self,
        *,
        public_key_openssh: str,
        principals: list[str],
        ttl_seconds: int,
    ) -> HostCert:
        """Ask Vault to sign ``public_key_openssh`` as a host cert."""
        signed, serial, va, vb = self._sign(
            role=self._host_role,
            public_key_openssh=public_key_openssh,
            principals=principals,
            ttl_seconds=ttl_seconds,
            cert_type="host",
        )
        return HostCert(
            cert_pem=signed,
            valid_after=datetime.fromtimestamp(va, tz=timezone.utc),
            valid_before=datetime.fromtimestamp(vb, tz=timezone.utc),
            serial=serial,
            principals=tuple(principals),
        )


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


# Per-process cache for :class:`LocalDevSSHCA` instances returned by the
# factory. Keyed by the ``ssh_ca_local_dev_pem`` value (or ``None`` when
# the operator hasn't pinned one), so:
#
# * Two factory calls with the same (or no) pinned PEM return the *same*
#   backend — host certs installed by one call can be verified by the
#   next. This fixes the 2026-05-28 lockout, where each factory call
#   generated a fresh in-memory CA and the resulting host certs were
#   immediately untrustable by the next session.
# * Pinning a new PEM still produces a new backend (a different cache
#   key), so the existing
#   :func:`test_local_backend_honours_supplied_pem` contract holds.
#
# Cache is process-local on purpose — :class:`LocalDevSSHCA` is a
# dev-only backend whose private key never leaves memory, so sharing
# across processes would require persisting the key (which defeats the
# "throwaway" framing). The right answer for multi-process dev is to
# pin ``SSH_CA_LOCAL_DEV_PEM``; the right answer for prod is Vault.
_LOCAL_CA_CACHE: dict[str | None, LocalDevSSHCA] = {}


def make_ssh_ca_backend(settings: Settings | None = None) -> SSHCABackend:
    """Return the backend selected by ``settings.ssh_ca_backend``.

    Mirrors :func:`wg_manager.crypto.make_backend` so the two layers feel
    the same to read.

    The local backend is memoised per-process (see :data:`_LOCAL_CA_CACHE`):
    the first call generates (or loads) the CA, every subsequent call
    with the same PEM returns the same backend instance. Without this,
    each factory call regenerated the CA, which silently broke host-cert
    verification the moment the second factory call ran.

    :param settings: Optional explicit settings instance; defaults to a
        fresh :class:`Settings` (which re-reads ``.env`` and environment).
    :raises ValueError: If ``ssh_ca_backend`` isn't one of ``"local"`` /
        ``"vault"``.
    :raises SSHCAError: If the selected backend can't be constructed
        (Vault unreachable, malformed CA PEM, …).
    """
    if settings is None:
        settings = Settings()
    backend = settings.ssh_ca_backend.lower()
    if backend == "local":
        pem = settings.ssh_ca_local_dev_pem
        cached = _LOCAL_CA_CACHE.get(pem)
        if cached is not None:
            return cached
        ca = LocalDevSSHCA.from_pem(pem) if pem else LocalDevSSHCA.generate()
        _LOCAL_CA_CACHE[pem] = ca
        return ca
    if backend == "vault":
        if not settings.crypto_vault_token:
            raise SSHCAError(
                "VAULT_TOKEN (or CRYPTO_VAULT_TOKEN) is required for the vault SSH CA backend"
            )
        client = hvac.Client(
            url=settings.crypto_vault_addr, token=settings.crypto_vault_token
        )
        ca_public = VaultSSHCA._read_ca_public_key(client, settings.ssh_ca_vault_mount)
        return VaultSSHCA(
            client=client,
            mount_point=settings.ssh_ca_vault_mount,
            user_role=settings.ssh_ca_vault_user_role,
            host_role=settings.ssh_ca_vault_host_role,
            ca_public_key=ca_public,
        )
    raise ValueError(
        f"unknown SSH CA backend {settings.ssh_ca_backend!r}; expected 'local' or 'vault'"
    )
