"""Phase 2c CP4.5 — operator-driven host bootstrap SSH runner.

This module exists so that wg-manager's production SSH path
(:class:`wg_manager.ssh.SSHRunner` + :class:`KnownHostsCAPolicy`) can
stay strictly no-TOFU while still leaving a legitimate door for the
*very first* contact with a fresh host. CP4.4 made the production
runner refuse any host that doesn't present a CA-signed host cert —
which is strictly stronger security, but means a brand-new VM has
nothing for wg-manager to talk to until ``/etc/ssh/wg-manager-user-ca.pub``,
the signed host cert, and the sshd drop-in are in place. The previous
mechanism for doing that install (the deleted ``wg_manager.ssh_migrate``
module) was retired alongside the legacy stored-key path; this module
is its replacement.

Design rules baked in:

* **Separate module, separate class.** The bootstrap runner is *never*
  imported from :mod:`wg_manager.tasks` or :class:`SSHRunner`. The
  no-TOFU invariant in :mod:`wg_manager.ssh` is therefore safe by
  construction — nothing in the production path can silently flip
  back to TOFU because there is no code path that reaches a
  :class:`paramiko.AutoAddPolicy` from the production runner.
* **Long-lived operator-supplied private key.** The operator provides
  the key path on the command line (``--ssh-key``); the runner reads
  the PEM file inside :meth:`__enter__` and never holds the bytes on
  the instance any longer than necessary.
* **AutoAddPolicy + no client cert.** This is the *one* legitimate
  TOFU site in the codebase; the bootstrap call is exactly the
  moment an operator is consciously trusting a fresh box for the
  first time so the rest of the platform can trust it without TOFU
  thereafter.
* **No password auth, no agent, no key-search.** The dependencies on
  the local environment are kept to "the key file you pointed me at
  and nothing else" so a CI / non-interactive invocation behaves the
  same as a developer running it by hand.

Surface mirrors :class:`wg_manager.ssh.SSHRunner` deliberately
(``__enter__`` / ``run`` / ``sudo`` / ``write_file``) so it can be
fed straight into :func:`wg_manager.host_ssh.install_host_cert`
without an adapter — the helper there is the canonical "lay down
CA + host cert + drop-in" code path and we want both runners to use
it.
"""

from __future__ import annotations

import io
import shlex
import socket
from pathlib import Path
from types import TracebackType
from typing import Any

import paramiko

from wg_manager.ssh import (
    CommandResult,
    SSHCommandError,
    SSHConnectionError,
)


def _load_pkey_from_path(
    key_path: Path | str, passphrase: str | None
) -> paramiko.PKey:
    """Read ``key_path`` and parse it as an SSH private key.

    Mirrors the auto-detect loop in :func:`wg_manager.ssh._load_pkey`
    but reads the PEM body off disk rather than taking it as a string
    — the bootstrap runner accepts a path because operators typically
    keep their long-lived OOB key in a file (``~/.ssh/id_ed25519``)
    rather than as an env var.

    :param key_path: Path to the PEM-encoded private key on disk.
    :type key_path: Path | str
    :param passphrase: Optional passphrase protecting the key. ``None``
        when the key is unencrypted (the common case for an operator's
        loopback key).
    :type passphrase: str | None
    :return: A :class:`paramiko.PKey` ready for ``client.connect``.
    :rtype: paramiko.PKey
    :raises ValueError: If the file can't be parsed by any of the
        supported loaders (Ed25519, RSA).
    """
    pem = Path(key_path).read_text()
    loaders: list[type[paramiko.PKey]] = [
        paramiko.Ed25519Key,
        paramiko.RSAKey,
    ]
    last_error: Exception | None = None
    for loader in loaders:
        try:
            return loader.from_private_key(
                io.StringIO(pem), password=passphrase
            )
        except paramiko.SSHException as exc:
            last_error = exc
    raise ValueError(
        f"could not parse SSH private key at {key_path!r}: {last_error}"
    )


class BootstrapSSHRunner:
    """TOFU-permitting SSH session used **only** during host bootstrap.

    Mirrors the public surface of :class:`wg_manager.ssh.SSHRunner`
    (``__enter__`` / ``__exit__`` / ``run`` / ``sudo`` / ``write_file``)
    so :func:`wg_manager.host_ssh.install_host_cert` can drive either
    runner without an adapter. The differences are deliberately
    narrow:

    * Auth: a long-lived operator-supplied private key, no cert.
    * Host-key policy: :class:`paramiko.AutoAddPolicy` (TOFU).

    The runner is constructed cheaply (no I/O, no key parse) so a
    caller that needs to inspect the wire-level shape — the CLI's
    ``bootstrap-host`` command — can build it once and pass it to
    the orchestrator. The actual SSH session is opened only in
    :meth:`__enter__`.
    """

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        key_path: Path | str,
        passphrase: str | None = None,
        connect_timeout: float = 15.0,
    ) -> None:
        """Capture the connection coordinates and key path.

        :param host: Hostname or IP of the target host.
        :type host: str
        :param port: SSH port (almost always 22; configurable so the
            operator can dial a non-standard port without a
            command-line escape hatch).
        :type port: int
        :param username: Remote user account the operator's key is
            authorised against. Must already be on the box and have
            ``sudo`` rights for the bootstrap install to succeed.
        :type username: str
        :param key_path: Path to the operator's private key PEM.
            Loaded inside :meth:`__enter__` so the key bytes aren't
            held on the instance any longer than the session itself.
        :type key_path: Path | str
        :param passphrase: Optional passphrase protecting the key.
            Defaults to ``None`` (unencrypted key, the common case
            for an operator's loopback key).
        :type passphrase: str | None
        :param connect_timeout: Seconds to wait for TCP handshake,
            SSH banner exchange, and authentication. Matches the
            production runner's default so a dead host fails fast
            either way.
        :type connect_timeout: float
        """
        self.host = host
        self.port = port
        self.username = username
        self.key_path = Path(key_path)
        self.passphrase = passphrase
        self.connect_timeout = connect_timeout
        self._client: paramiko.SSHClient | None = None

    def __enter__(self) -> BootstrapSSHRunner:
        """Open the paramiko client and authenticate with the operator key.

        Reads the key PEM off disk inside the body so the file
        contents are scoped to the session lifetime — once the
        context exits the only reference is the (already-loaded)
        ``paramiko.PKey`` on the client, which goes out of scope
        with it.

        Wraps connection-time failures in :class:`SSHConnectionError`
        for symmetry with :class:`wg_manager.ssh.SSHRunner`, so the
        CLI layer can ``except SSHConnectionError`` once and cover
        either runner.

        :return: The runner itself.
        :rtype: BootstrapSSHRunner
        :raises SSHConnectionError: When the SSH session cannot be
            opened (TCP timeout, banner timeout, auth rejection,
            refused connection, ...).
        """
        client = paramiko.SSHClient()
        # The bootstrap call is the *one* place wg-manager intentionally
        # allows TOFU: we are seeding the host with the CA + host cert
        # that the production runner subsequently uses to refuse TOFU.
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        pkey = _load_pkey_from_path(self.key_path, self.passphrase)
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
                f"SSH authentication failed for "
                f"{self.username}@{self.host}: {exc}",
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
        """Execute ``cmd`` on the remote host and return the result.

        Mirrors :meth:`wg_manager.ssh.SSHRunner.run` so the install
        helper in :mod:`wg_manager.host_ssh` can drive either runner
        without an adapter.

        :param cmd: Shell command to execute on the remote host.
        :type cmd: str
        :param check: When ``True`` (the default), a non-zero exit
            status raises :class:`SSHCommandError`. Pass ``False`` to
            inspect the result manually.
        :type check: bool
        :return: Captured command output (stdout / stderr / rc).
        :rtype: CommandResult
        :raises SSHCommandError: When ``check`` is true and the
            command exits non-zero.
        :raises RuntimeError: When the runner is used outside a
            ``with`` block.
        """
        if self._client is None:
            raise RuntimeError(
                "BootstrapSSHRunner must be used as a context manager"
            )
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
        """Execute ``cmd`` as root via ``sudo -n``.

        Non-interactive ``sudo`` is required — the bootstrap path
        runs unattended (CLI or CI), so a host that demands a sudo
        password fails fast with a clear error rather than hanging.

        :param cmd: Shell command to run under sudo.
        :type cmd: str
        :param check: When ``True``, raise on non-zero exit.
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

        Stdin-pipe form (rather than escape-and-echo) so embedded
        quotes, newlines, and shell metacharacters survive intact.
        Optionally elevates via ``sudo -n`` for paths only root can
        write (the typical case for ``/etc/ssh/...`` during bootstrap).

        :param path: Absolute remote path to write.
        :type path: str
        :param content: File body to write.
        :type content: str
        :param mode: Octal mode string applied via ``chmod`` after
            the write. Defaults to ``"644"`` (world-readable, root-
            writable) to match OpenSSH config-file conventions.
        :type mode: str
        :param sudo: When ``True`` (default), wrap ``tee`` + ``chmod``
            with ``sudo -n``. ``False`` for files the operator user
            can write directly.
        :type sudo: bool
        :return: Result of the ``tee`` invocation.
        :rtype: CommandResult
        :raises SSHCommandError: When ``tee`` exits non-zero.
        :raises RuntimeError: When the runner is used outside a
            ``with`` block.
        """
        quoted = shlex.quote(path)
        tee = f"tee {quoted} > /dev/null"
        chmod = f"chmod {mode} {quoted}"
        if sudo:
            tee = f"sudo -n {tee}"
            chmod = f"sudo -n {chmod}"
        if self._client is None:
            raise RuntimeError(
                "BootstrapSSHRunner must be used as a context manager"
            )
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

    @property
    def client(self) -> Any:
        """Expose the underlying paramiko client (``None`` until entered)."""
        return self._client
