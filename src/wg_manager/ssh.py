"""Thin paramiko wrapper used by the provisioning layer."""

from __future__ import annotations

import io
import shlex
import socket
from dataclasses import dataclass
from types import TracebackType
from typing import Any

import paramiko


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


class SSHRunner:
    """Context-managed SSH session exposing ``run``, ``sudo`` and ``write_file``."""

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        pkey_pem: str,
        passphrase: str | None = None,
        connect_timeout: float = 15.0,
    ) -> None:
        """Initialise the runner.

        :param host: Target SSH host.
        :type host: str
        :param port: Target SSH port.
        :type port: int
        :param username: Remote username.
        :type username: str
        :param pkey_pem: PEM-encoded private key.
        :type pkey_pem: str
        :param passphrase: Optional key passphrase.
        :type passphrase: str | None
        :param connect_timeout: Seconds to wait for the TCP handshake, SSH
            banner exchange, and authentication. Without this, paramiko's
            default is "no timeout" — i.e., a dead host hangs Celery workers
            forever.
        :type connect_timeout: float
        """
        self.host = host
        self.port = port
        self.username = username
        self.pkey_pem = pkey_pem
        self.passphrase = passphrase
        self.connect_timeout = connect_timeout
        self._client: paramiko.SSHClient | None = None

    def __enter__(self) -> SSHRunner:
        """Open the underlying paramiko client.

        Connection-time failures (TCP timeout, SSH banner timeout, auth
        rejection, refused connection, ...) are caught and re-raised as
        :class:`SSHConnectionError` so callers can handle a single tidy
        exception type. The traceback chain is preserved via ``from exc``
        for debugging; callers that want a quiet log can read ``str(exc)``.

        :return: The runner itself.
        :rtype: SSHRunner
        :raises SSHConnectionError: When the SSH session cannot be opened.
        """
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        pkey = _load_pkey(self.pkey_pem, self.passphrase)
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
