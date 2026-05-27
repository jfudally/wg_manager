"""Thin paramiko wrapper used by the provisioning layer.

Phase 2c CP2 adds a second authentication mode alongside the historical
private-key path: when an operator supplies a short-lived user
certificate (and the public key of the SSH CA that signed the host
cert installed on the target), :class:`SSHRunner` switches to
cert-based client auth and refuses to TOFU unknown hosts.

Two new collaborators support that mode:

* :class:`KnownHostsCAPolicy` — a paramiko ``MissingHostKeyPolicy`` that
  accepts a server's offered key only if it carries a host certificate
  signed by the operator-supplied CA. Replaces the legacy
  ``AutoAddPolicy`` (TOFU) when CA mode is in effect.
* :class:`UntrustedHostKeyError` — the project-named exception raised
  by that policy on rejection, so callers (the Celery task layer) can
  catch a single tidy type rather than ``paramiko.SSHException``.

Legacy mode (no ``cert_pem`` / ``ca_public_key`` passed) is unchanged.
CP3 installs host certs on managed servers; CP4 flips the per-row
mode to ``ca`` in the DB so the runner is always called in CP2 mode.
"""

from __future__ import annotations

import io
import shlex
import socket
from dataclasses import dataclass
from types import TracebackType
from typing import Any

import paramiko
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import (
    SSHCertificate,
    SSHCertificateType,
    load_ssh_public_identity,
)


class SSHConnectionError(RuntimeError):
    """Raised when the SSH session cannot be established.

    Wraps the underlying ``paramiko`` / socket exception so callers (e.g.
    Celery tasks) can catch a single, clearly-named error type and surface
    a concise message instead of re-raising a low-level networking
    exception with a 30-frame traceback.

    :ivar host: The target host that we failed to connect to.
    :ivar port: The TCP port we attempted.
    """

    def __init__(self, message: str, *, host: str = "", port: int = 0) -> None:
        super().__init__(message)
        self.host = host
        self.port = port


class SSHCommandError(RuntimeError):
    """Raised when a remote command exits non-zero.

    :ivar cmd: The command that was executed.
    :ivar rc: Remote exit code.
    :ivar stdout: Captured standard output.
    :ivar stderr: Captured standard error.
    """

    def __init__(self, cmd: str, rc: int, stdout: str, stderr: str) -> None:
        super().__init__(f"command {cmd!r} failed (rc={rc}): {stderr.strip()}")
        self.cmd = cmd
        self.rc = rc
        self.stdout = stdout
        self.stderr = stderr


class UntrustedHostKeyError(paramiko.SSHException):
    """Raised by :class:`KnownHostsCAPolicy` when the host's offered key is rejected.

    Subclass of :class:`paramiko.SSHException` so paramiko's internal
    machinery treats it as an SSH failure (closes the transport,
    propagates to ``connect()``); we also surface it as a wg-manager
    error type so the task layer's
    :data:`wg_manager.tasks._SSH_EXPECTED_ERRORS` tuple can include it
    without depending on paramiko's class hierarchy.

    :ivar hostname: The host whose offered key was rejected.
    :ivar reason: Short human-readable description of *why* (no cert,
        wrong signer, wrong cert type). Useful for the audit log added
        in Phase 2e.
    """

    def __init__(self, hostname: str, reason: str) -> None:
        super().__init__(
            f"host {hostname!r} offered an untrusted key: {reason}"
        )
        self.hostname = hostname
        self.reason = reason


@dataclass(slots=True)
class CommandResult:
    """Outcome of a single remote command."""

    cmd: str
    rc: int
    stdout: str
    stderr: str


def _load_pkey(pkey_pem: str, passphrase: str | None) -> paramiko.PKey:
    """Parse a PEM-encoded private key, auto-detecting the algorithm.

    :param pkey_pem: The PEM body.
    :type pkey_pem: str
    :param passphrase: Optional passphrase protecting the key.
    :type passphrase: str | None
    :return: A paramiko ``PKey`` instance.
    :rtype: paramiko.PKey
    :raises ValueError: If the key could not be parsed by any supported loader.
    """
    loaders: list[type[paramiko.PKey]] = [paramiko.Ed25519Key, paramiko.RSAKey]
    last_error: Exception | None = None
    for loader in loaders:
        try:
            return loader.from_private_key(io.StringIO(pkey_pem), password=passphrase)
        except paramiko.SSHException as exc:
            last_error = exc
    raise ValueError(f"could not parse SSH private key: {last_error}")


def _ca_pubkey_body(openssh_line: str) -> str:
    """Return the base64 body of an OpenSSH-format public key.

    The OpenSSH single-line format is ``<algo> <base64-body> [comment]``;
    we compare CAs by the base64 body only so an operator pasting the
    same key with or without a comment matches identically.
    """
    parts = openssh_line.strip().split()
    if len(parts) < 2:
        raise ValueError(f"malformed CA public key: {openssh_line!r}")
    return parts[1]


class KnownHostsCAPolicy(paramiko.MissingHostKeyPolicy):
    """Trust a host iff it offers an Ed25519 host cert signed by ``ca_public_key``.

    Replaces :class:`paramiko.AutoAddPolicy` for CA-mode sessions.
    Paramiko calls :meth:`missing_host_key` whenever the offered host
    key isn't in the application's ``HostKeys`` store — which is
    *always*, for us, since wg-manager doesn't maintain a
    ``known_hosts`` file. We use that callback as the trust hook.

    Verification rules (must all hold to accept):

    1. The offered key carries a certificate
       (``key.public_blob.key_type ==
       'ssh-ed25519-cert-v01@openssh.com'``).
    2. The certificate is of HOST type (rejects a user cert spliced in
       by a hostile intermediary).
    3. The certificate's signing key matches the CA pubkey body the
       policy was constructed with.

    Anything else raises :class:`UntrustedHostKeyError`.

    The cert's principals / TTL are NOT enforced here — sshd enforces
    them on the wire and our CA bootstrap (see
    :class:`wg_manager.ssh_ca.VaultSSHCA.bootstrap`) constrains the
    issuance role. This policy's job is "is the *signer* the right CA".

    :ivar ca_public_key: The OpenSSH-format CA public key passed to
        the constructor. Stored verbatim so callers can read it back
        (the runner-mode tests do this).
    """

    def __init__(self, ca_public_key: str) -> None:
        """Bind to ``ca_public_key`` (one-line OpenSSH format)."""
        self.ca_public_key = ca_public_key
        self._ca_body = _ca_pubkey_body(ca_public_key)

    def missing_host_key(
        self,
        client: paramiko.SSHClient | None,
        hostname: str,
        key: paramiko.PKey,
    ) -> None:
        """Accept (return) iff ``key`` carries a host cert signed by our CA.

        :raises UntrustedHostKeyError: On any verification failure. The
            message names the host and the specific reason so the
            operator can tell "we forgot to install the host cert"
            apart from "an attacker swapped the cert for one signed by
            a different CA".
        """
        blob = getattr(key, "public_blob", None)
        if blob is None:
            raise UntrustedHostKeyError(
                hostname, "server offered no certificate (TOFU is disabled)"
            )
        if blob.key_type != "ssh-ed25519-cert-v01@openssh.com":
            raise UntrustedHostKeyError(
                hostname,
                f"unsupported cert type {blob.key_type!r}; expected ed25519 host cert",
            )

        # Reassemble the cert text and parse it through cryptography so
        # we can ask for the signing key. paramiko's PublicBlob.key_blob
        # is the binary body; the canonical OpenSSH line is
        # "<key_type> <base64-of-blob>".
        import base64

        cert_line = (
            blob.key_type
            + " "
            + base64.b64encode(blob.key_blob).decode("ascii")
        )
        try:
            cert = load_ssh_public_identity(cert_line.encode())
        except (ValueError, TypeError) as exc:
            raise UntrustedHostKeyError(
                hostname, f"could not parse offered cert: {exc}"
            ) from exc
        if not isinstance(cert, SSHCertificate):
            raise UntrustedHostKeyError(
                hostname,
                f"offered material is not an SSH certificate: {type(cert).__name__}",
            )
        if cert.type != SSHCertificateType.HOST:
            raise UntrustedHostKeyError(
                hostname,
                "offered certificate is a user cert, not a host cert",
            )

        signer_blob = cert.signature_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        )
        try:
            signer_body = signer_blob.split(b" ")[1].decode("ascii")
        except IndexError as exc:  # pragma: no cover — defensive
            raise UntrustedHostKeyError(
                hostname, "could not extract signer key body"
            ) from exc

        if signer_body != self._ca_body:
            raise UntrustedHostKeyError(
                hostname,
                "host cert signed by an untrusted CA",
            )
        # Accept by returning.


class SSHRunner:
    """Context-managed SSH session exposing ``run``, ``sudo`` and ``write_file``.

    Two authentication modes:

    * **Legacy** (default) — a long-lived private key from the
      ``sshkey`` table; the runner uses :class:`paramiko.AutoAddPolicy`
      for host-key acceptance (TOFU). This path is still wired up
      because Phase 2c rolls out per-row in CP4; until the last legacy
      row is migrated the runner has to keep dialing them.
    * **CA mode** — pass ``cert_pem`` and ``ca_public_key`` together.
      The runner loads the cert onto the pkey so paramiko offers
      ``ssh-ed25519-cert-v01@openssh.com`` auth, and installs
      :class:`KnownHostsCAPolicy` so the connection refuses any host
      that doesn't present a CA-signed host cert. TOFU is gone.

    Passing one of ``cert_pem`` / ``ca_public_key`` without the other
    is a configuration error and rejected at construction time —
    accepting it would either re-introduce TOFU or break cert auth
    silently.
    """

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        pkey_pem: str,
        passphrase: str | None = None,
        connect_timeout: float = 15.0,
        *,
        cert_pem: str | None = None,
        ca_public_key: str | None = None,
    ) -> None:
        """Initialise the runner.

        :param host: Target SSH host.
        :type host: str
        :param port: Target SSH port.
        :type port: int
        :param username: Remote username.
        :type username: str
        :param pkey_pem: PEM-encoded private key. In CA mode this is
            the ephemeral key produced by
            :meth:`wg_manager.ssh_ca.SSHCABackend.mint_user_cert`; in
            legacy mode it is the stored ``sshkey.private_key_ct``
            decrypted via :mod:`wg_manager.crypto`.
        :type pkey_pem: str
        :param passphrase: Optional key passphrase. Ignored in CA mode
            (ephemeral keys are never encrypted).
        :type passphrase: str | None
        :param connect_timeout: Seconds to wait for the TCP handshake, SSH
            banner exchange, and authentication. Without this, paramiko's
            default is "no timeout" — i.e., a dead host hangs Celery workers
            forever.
        :type connect_timeout: float
        :param cert_pem: OpenSSH-formatted user certificate
            (``ssh-ed25519-cert-v01@openssh.com …``) the client will
            present during authentication. Pair with ``ca_public_key``.
        :type cert_pem: str | None
        :param ca_public_key: OpenSSH-formatted public key of the SSH
            CA. Used to build a :class:`KnownHostsCAPolicy` so the
            runner trusts the remote host iff its presented host cert
            is signed by this CA. Pair with ``cert_pem``.
        :type ca_public_key: str | None
        :raises ValueError: If exactly one of ``cert_pem`` /
            ``ca_public_key`` is supplied — see the class docstring for
            why this combination is rejected.
        """
        if (cert_pem is None) != (ca_public_key is None):
            missing = "ca_public_key" if cert_pem is not None else "cert_pem"
            raise ValueError(
                f"SSHRunner CA mode requires both cert_pem and ca_public_key; "
                f"missing {missing}"
            )
        self.host = host
        self.port = port
        self.username = username
        self.pkey_pem = pkey_pem
        self.passphrase = passphrase
        self.connect_timeout = connect_timeout
        self.cert_pem = cert_pem
        self.ca_public_key = ca_public_key
        self._client: paramiko.SSHClient | None = None

    def __enter__(self) -> SSHRunner:
        """Open the underlying paramiko client.

        Connection-time failures (TCP timeout, SSH banner timeout, auth
        rejection, refused connection, ...) are caught and re-raised as
        :class:`SSHConnectionError` so callers can handle a single tidy
        exception type. The traceback chain is preserved via ``from exc``
        for debugging; callers that want a quiet log can read ``str(exc)``.

        In CA mode, host-key rejection by :class:`KnownHostsCAPolicy`
        propagates as :class:`UntrustedHostKeyError` (subclass of
        ``paramiko.SSHException``) wrapped in
        :class:`SSHConnectionError` for the same reason.

        :return: The runner itself.
        :rtype: SSHRunner
        :raises SSHConnectionError: When the SSH session cannot be opened.
        """
        client = paramiko.SSHClient()
        if self.ca_public_key is not None:
            client.set_missing_host_key_policy(
                KnownHostsCAPolicy(self.ca_public_key)
            )
        else:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        pkey = _load_pkey(self.pkey_pem, self.passphrase)
        if self.cert_pem is not None:
            # load_certificate attaches the OpenSSH cert as ``public_blob``;
            # paramiko then offers ``ssh-ed25519-cert-v01@openssh.com``
            # during authentication rather than the raw pubkey.
            pkey.load_certificate(self.cert_pem)
        try:
            client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                pkey=pkey,
                look_for_keys=False,
                allow_agent=False,
                timeout=self.connect_timeout,
                banner_timeout=self.connect_timeout,
                auth_timeout=self.connect_timeout,
            )
        except (socket.timeout, TimeoutError) as exc:
            raise SSHConnectionError(
                f"SSH connection to {self.host}:{self.port} timed out after "
                f"{self.connect_timeout}s",
                host=self.host,
                port=self.port,
            ) from exc
        except paramiko.AuthenticationException as exc:
            raise SSHConnectionError(
                f"SSH authentication failed for {self.username}@{self.host}: {exc}",
                host=self.host,
                port=self.port,
            ) from exc
        except (paramiko.SSHException, OSError) as exc:
            raise SSHConnectionError(
                f"SSH connection to {self.host}:{self.port} failed: {exc}",
                host=self.host,
                port=self.port,
            ) from exc
        self._client = client
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Close the underlying paramiko client."""
        if self._client is not None:
            self._client.close()
            self._client = None

    def run(self, cmd: str, check: bool = True) -> CommandResult:
        """Execute a command on the remote host.

        :param cmd: Shell command to execute.
        :type cmd: str
        :param check: When true, raise :class:`SSHCommandError` on non-zero rc.
        :type check: bool
        :return: Captured command output.
        :rtype: CommandResult
        :raises SSHCommandError: If ``check`` is true and the command failed.
        :raises RuntimeError: If the runner is used outside a ``with`` block.
        """
        if self._client is None:
            raise RuntimeError("SSHRunner must be used as a context manager")
        stdin, stdout, stderr = self._client.exec_command(cmd)
        stdin.close()
        out_bytes: bytes = stdout.read()
        err_bytes: bytes = stderr.read()
        rc: int = stdout.channel.recv_exit_status()
        result = CommandResult(
            cmd=cmd,
            rc=rc,
            stdout=out_bytes.decode("utf-8", errors="replace"),
            stderr=err_bytes.decode("utf-8", errors="replace"),
        )
        if check and rc != 0:
            raise SSHCommandError(cmd, rc, result.stdout, result.stderr)
        return result

    def sudo(self, cmd: str, check: bool = True) -> CommandResult:
        """Execute a command under ``sudo -n``.

        :param cmd: Shell command to run as root.
        :type cmd: str
        :param check: When true, raise on non-zero exit.
        :type check: bool
        :return: Captured command output.
        :rtype: CommandResult
        """
        return self.run(f"sudo -n {cmd}", check=check)

    def write_file(
        self,
        path: str,
        content: str,
        mode: str = "644",
        sudo: bool = True,
    ) -> CommandResult:
        """Write ``content`` to a remote file via ``tee``.

        The contents are piped over stdin using a quoted heredoc so embedded
        quotes and shell metacharacters are preserved.

        :param path: Absolute remote path.
        :type path: str
        :param content: File body to write.
        :type content: str
        :param mode: Octal mode string applied via ``chmod`` afterwards.
        :type mode: str
        :param sudo: Whether to run ``tee``/``chmod`` under ``sudo``.
        :type sudo: bool
        :return: Result of the ``tee`` invocation.
        :rtype: CommandResult
        """
        quoted = shlex.quote(path)
        tee = f"tee {quoted} > /dev/null"
        chmod = f"chmod {mode} {quoted}"
        if sudo:
            tee = f"sudo -n {tee}"
            chmod = f"sudo -n {chmod}"
        if self._client is None:
            raise RuntimeError("SSHRunner must be used as a context manager")
        stdin, stdout, stderr = self._client.exec_command(tee)
        stdin.write(content)
        stdin.channel.shutdown_write()
        out_bytes: bytes = stdout.read()
        err_bytes: bytes = stderr.read()
        rc: int = stdout.channel.recv_exit_status()
        result = CommandResult(
            cmd=tee,
            rc=rc,
            stdout=out_bytes.decode("utf-8", errors="replace"),
            stderr=err_bytes.decode("utf-8", errors="replace"),
        )
        if rc != 0:
            raise SSHCommandError(tee, rc, result.stdout, result.stderr)
        self.run(chmod)
        return result

    # Helper so tests can introspect opened clients if ever needed.
    @property
    def client(self) -> Any:
        """Expose the underlying paramiko client (``None`` until entered)."""
        return self._client
