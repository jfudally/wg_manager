"""Phase 2c CP3 — host-side SSH CA install.

Lives next to :mod:`wg_manager.wireguard` (which knows about WireGuard
on the host) and :mod:`wg_manager.ssh_ca` (which knows about the CA);
this module is the seam between them: it teaches the *target host* to
trust the CA and to advertise a CA-signed host certificate of its own,
so the new flow from Phase 2c CP2 (cert-based client auth +
:class:`~wg_manager.ssh.KnownHostsCAPolicy` host trust) actually has a
host certificate to verify against.

The single public entry point is :func:`install_host_cert`, called by:

* :func:`wg_manager.tasks.provision_server_task` after a successful
  provisioning round (so a newly-registered hub is born CA-aware), and
* the new ``POST /servers/{id}/rotate-host-cert`` endpoint /
  :func:`wg_manager.tasks.rotate_host_cert_task` (CP3.3) for in-place
  rotation before expiry.

Idempotent by construction — every write target is overwritten in
place, so re-running the helper is the rotation flow.
"""

from __future__ import annotations

import logging
from typing import Protocol, runtime_checkable

from wg_manager.models import Server
from wg_manager.ssh import CommandResult, SSHRunner
from wg_manager.ssh_ca import HostCert, SSHCABackend

logger = logging.getLogger(__name__)


@runtime_checkable
class HostInstallRunner(Protocol):
    """Minimal surface :func:`_install_host_cert_files` needs from a runner.

    Both :class:`wg_manager.ssh.SSHRunner` (production / CA-mode) and
    :class:`wg_manager.bootstrap_ssh.BootstrapSSHRunner` (operator-
    driven bootstrap / TOFU) implement this shape, so the lower-level
    install helper can drive either without knowing which auth path
    opened the session.

    The protocol is intentionally narrower than either runner's full
    public surface — only the operations the install helper actually
    calls live here. Adding new methods to either runner has no
    impact on the protocol or its callers.
    """

    def sudo(self, cmd: str, check: bool = True) -> CommandResult:
        """Execute ``cmd`` under ``sudo -n``."""
        ...

    def write_file(
        self,
        path: str,
        content: str,
        mode: str = "644",
        sudo: bool = True,
    ) -> CommandResult:
        """Write ``content`` to remote ``path``."""
        ...


class HostCertInstallError(RuntimeError):
    """Raised when the host-side CA install can't make forward progress.

    Distinct exception type so the Celery task layer (see
    :data:`wg_manager.tasks._SSH_EXPECTED_ERRORS`) catches it as an
    expected failure mode and emits a tidy single-line log + clean
    task failure, rather than a 30-frame traceback.
    """


# Where on the target host wg-manager writes the CA pubkey, the signed
# host cert, and the sshd drop-in. Public so tests can pin them and so
# operator-facing docs can grep them in one place.
#
# Paths chosen to match OpenSSH conventions:
#  * ``ssh_host_ed25519_key-cert.pub`` is sshd's default companion to
#    ``ssh_host_ed25519_key``; sshd will pick it up automatically even
#    without an explicit ``HostCertificate`` directive on most distros,
#    but we still set the directive so the behaviour is explicit.
#  * Drop-ins under ``/etc/ssh/sshd_config.d/`` are sourced by every
#    modern distro's stock ``sshd_config``, so wg-manager's policy
#    layers on top of distro defaults without editing the main file.
HOST_CA_PUB_PATH = "/etc/ssh/wg-manager-user-ca.pub"
HOST_CERT_PATH = "/etc/ssh/ssh_host_ed25519_key-cert.pub"
SSHD_DROPIN_PATH = "/etc/ssh/sshd_config.d/wg-manager.conf"
HOST_PUBKEY_PROBE = "/etc/ssh/ssh_host_ed25519_key.pub"


_SSHD_DROPIN_TEMPLATE = """\
# Managed by wg-manager (Phase 2c CP3). Do not hand-edit.
#
# TrustedUserCAKeys tells sshd to accept user certificates signed by
# the listed CA(s) as a substitute for entries in authorized_keys.
# HostCertificate makes sshd present a CA-signed host certificate
# during the SSH handshake so clients using KnownHostsCAPolicy can
# verify the host without TOFU.
TrustedUserCAKeys {ca_pub}
HostCertificate {host_cert}
"""


def _read_host_pubkey(runner: HostInstallRunner) -> str:
    """Return the host's existing OpenSSH ed25519 public key.

    Reads ``/etc/ssh/ssh_host_ed25519_key.pub`` via ``sudo cat`` and
    strips whitespace. Modern distros generate this file at sshd
    install time; a missing / empty value means the host has no
    ed25519 host key yet and the caller should generate one before
    trying to mint a host cert against it.
    """
    result = runner.sudo(f"cat {HOST_PUBKEY_PROBE}")
    body = result.stdout.strip()
    if not body:
        raise HostCertInstallError(
            f"target host has no ed25519 host public key at "
            f"{HOST_PUBKEY_PROBE!r}; run `ssh-keygen -A` on the host "
            f"before re-running provisioning"
        )
    return body


def _install_host_cert_files(
    *,
    runner: HostInstallRunner,
    ca: SSHCABackend,
    principal: str,
    ttl_seconds: int,
) -> HostCert:
    """Lower-level "lay down the three files + reload sshd" worker.

    Factored out of :func:`install_host_cert` in Phase 2c CP4.5 so
    the new operator-driven bootstrap path (which has no
    :class:`Server` row yet — the whole point is to *prepare* a host
    for registration) can reuse the same wire-level behaviour without
    fabricating a stub row. The Server-shaped wrapper
    (:func:`install_host_cert`) is kept for the production task layer's
    call sites; both end up here.

    Accepts the :class:`HostInstallRunner` protocol rather than a
    concrete runner type so the same code path drives both
    :class:`wg_manager.ssh.SSHRunner` (production / CA mode) and
    :class:`wg_manager.bootstrap_ssh.BootstrapSSHRunner` (operator /
    TOFU) — no adapter, no special-case branch.

    :param runner: Open SSH runner bound to the target host. The
        caller is responsible for entering it as a context manager
        before calling this helper.
    :type runner: HostInstallRunner
    :param ca: An :class:`SSHCABackend` that can sign host certs.
    :type ca: SSHCABackend
    :param principal: The hostname / DNS name the cert is bound to.
        Production callers pass the :attr:`Server.hostname` value;
        bootstrap callers pass the operator-supplied ``--hostname``.
    :type principal: str
    :param ttl_seconds: TTL the cert request asks the CA for. Vault
        caps this at the role's ``max_ttl``; the local backend
        honours it verbatim.
    :type ttl_seconds: int
    :return: The :class:`HostCert` the CA returned (serial, principals,
        validity window).
    :rtype: HostCert
    :raises HostCertInstallError: If the host has no ed25519 host
        pubkey yet (re-run ``ssh-keygen -A`` on the host first).
    :raises wg_manager.ssh_ca.SSHCAError: If the CA refuses to sign.
    """
    host_pubkey = _read_host_pubkey(runner)
    cert = ca.mint_host_cert(
        public_key_openssh=host_pubkey,
        principals=[principal],
        ttl_seconds=ttl_seconds,
    )

    # Write the three files. ``mode`` differs because the CA pubkey
    # and the host cert are world-readable on real sshd hosts (they
    # have to be — sshd reads them as root but other tooling expects
    # to be able to inspect them), while the drop-in is also 644 to
    # match OpenSSH's stock config files.
    runner.write_file(
        HOST_CA_PUB_PATH, ca.ca_public_key + "\n", mode="644", sudo=True
    )
    runner.write_file(
        HOST_CERT_PATH, cert.cert_pem + "\n", mode="644", sudo=True
    )
    runner.write_file(
        SSHD_DROPIN_PATH,
        _SSHD_DROPIN_TEMPLATE.format(
            ca_pub=HOST_CA_PUB_PATH, host_cert=HOST_CERT_PATH
        ),
        mode="644",
        sudo=True,
    )

    # ``reload`` is the right verb (not ``restart``): it re-reads
    # config without dropping the current session. If reload fails
    # because the unit isn't running yet, fall back to ``restart``
    # via a shell-side OR. The four-step chain covers distros that
    # name the unit ``sshd`` (RHEL / Amazon Linux) and ``ssh``
    # (Debian / Ubuntu).
    runner.sudo(
        "sh -c 'systemctl reload sshd || systemctl restart sshd "
        "|| systemctl reload ssh || systemctl restart ssh'"
    )
    return cert


def install_host_cert(
    *,
    runner: SSHRunner,
    server: Server,
    ca: SSHCABackend,
    ttl_seconds: int,
) -> HostCert:
    """Install a fresh CA-signed host cert on the target host.

    Side effects on the target host (all idempotent — re-running
    overwrites in place):

    1. Writes the CA's public key to :data:`HOST_CA_PUB_PATH`.
    2. Mints a host cert against the host's existing ed25519 pubkey,
       with the server row's ``hostname`` as the cert principal.
    3. Writes the cert body to :data:`HOST_CERT_PATH`.
    4. Writes a sshd drop-in at :data:`SSHD_DROPIN_PATH` that wires
       both into sshd's config via ``TrustedUserCAKeys`` and
       ``HostCertificate``.
    5. Reloads ``sshd`` so the new directives take effect on the next
       connection.

    The :class:`Server` row passed in is *not* mutated — populating
    the CP3.1 host_cert columns is the caller's responsibility (see
    :func:`wg_manager.tasks.provision_server_task`). Keeping this
    helper single-purpose lets the rotation endpoint reuse it without
    re-implementing the install half.

    :param runner: Open SSH runner bound to the target host. The
        caller is responsible for entering it as a context manager.
    :param server: The :class:`Server` row whose hostname is used as
        the cert principal.
    :param ca: An :class:`SSHCABackend` (local-dev or vault) that can
        sign host certs.
    :param ttl_seconds: TTL the cert request asks the CA for. Vault
        caps this at the role's ``max_ttl``; the local backend
        honours it verbatim.
    :return: The :class:`HostCert` the CA returned. Carries serial,
        principals, and validity window — the caller persists these
        into the row's host_cert columns.
    :raises RuntimeError: If the host has no ed25519 host pubkey yet.
    :raises wg_manager.ssh_ca.SSHCAError: If the CA refuses to sign.
    """
    return _install_host_cert_files(
        runner=runner,
        ca=ca,
        principal=server.hostname,
        ttl_seconds=ttl_seconds,
    )
