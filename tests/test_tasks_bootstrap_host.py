"""Tests for :func:`wg_manager.tasks.bootstrap_host_task`.

The API/UI bootstrap path (this cycle) lets an operator drop a fresh
host into the wg-manager universe without shelling into the prod
stack. The flow is:

    UI form  →  POST /bootstrap-host  →  Celery task  →  SSH install

The task is the only place the operator's long-lived SSH key bytes
exist in plaintext: the router encrypts them with the crypto backend
before queueing so the broker only ever sees ciphertext, and the task
decrypts in-memory, opens one :class:`BootstrapSSHRunner` session,
runs the same :func:`bootstrap_host` helper the CLI uses, and lets
the PEM fall out of scope.

These unit tests pin:

* The task decrypts the PEM using the configured crypto backend and
  passes the *plaintext* PEM to a fresh runner — never writes it
  to disk, never recycles it across runs.
* The task drives :func:`bootstrap_host` with the right principal /
  TTL / CA backend (the live one from
  :func:`make_ssh_ca_backend`), and returns the cert serial /
  principals / validity to the caller so the dashboard can render
  a confirmation card.
* SSH-side failures (TOFU-stage auth, sudo, missing host pubkey, CA
  refusal) are caught and converted to clean ``RuntimeError`` task
  failures so the operator sees a one-line message in the polling
  UI instead of a 30-frame traceback.
"""

from __future__ import annotations

import contextlib
from typing import Any
from unittest import mock

import pytest

from wg_manager.crypto import make_backend
from wg_manager.ssh import SSHConnectionError
from wg_manager.ssh_ca import HostCert, make_ssh_ca_backend


# A valid OpenSSH-format ed25519 host pubkey body so the LocalDevSSHCA
# can mint a real host cert against it; mirrors the fixture used in
# tests/test_tasks_host_cert.py.
_HOST_PUBKEY = (
    "ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAINcv8wY+y8d0KcKZ6t6S/n7JoYx7M3jzqu7K2YgQGvD7"
    " root@bootstrap-target.example.com"
)


class _RecordingRunner:
    """Stand-in for :class:`BootstrapSSHRunner` used to capture inputs.

    Records the ``key_pem`` it was constructed with so the test can
    assert that the task hands the decrypted PEM straight in. The
    runner satisfies the context-manager protocol so the task's
    ``with BootstrapSSHRunner(...) as session:`` block doesn't need
    special-casing.
    """

    CONSTRUCTIONS: list[dict[str, Any]] = []

    def __init__(self, **kwargs: Any) -> None:
        _RecordingRunner.CONSTRUCTIONS.append(kwargs)
        self.kwargs = kwargs

    def __enter__(self) -> "_RecordingRunner":
        return self

    def __exit__(self, *_: Any) -> None:
        return None

    def sudo(self, cmd: str, check: bool = True) -> Any:
        # The install helper probes for the host pubkey; return our canned
        # value when that path appears, otherwise a generic 0-rc result.
        class _Result:
            def __init__(self, rc: int, stdout: str, stderr: str) -> None:
                self.rc, self.stdout, self.stderr = rc, stdout, stderr

        if "ssh_host_ed25519_key.pub" in cmd:
            return _Result(0, _HOST_PUBKEY + "\n", "")
        return _Result(0, "", "")

    def run(self, cmd: str, check: bool = True) -> Any:
        class _Result:
            def __init__(self, rc: int, stdout: str, stderr: str) -> None:
                self.rc, self.stdout, self.stderr = rc, stdout, stderr

        return _Result(0, "", "")

    def write_file(
        self, path: str, content: str, mode: str = "644", sudo: bool = True
    ) -> Any:
        class _Result:
            def __init__(self, rc: int, stdout: str, stderr: str) -> None:
                self.rc, self.stdout, self.stderr = rc, stdout, stderr

        return _Result(0, "", "")


@pytest.fixture(autouse=True)
def _reset_recording_runner() -> None:
    """Drop any inputs captured by a previous test."""
    _RecordingRunner.CONSTRUCTIONS = []


def _encrypt_pem(pem: str) -> tuple[str, str]:
    """Encrypt ``pem`` with the test crypto backend.

    Returns ``(ciphertext, context)`` — the same shape the router
    will queue. The context string is what binds ciphertext to a
    domain (vault's transit engine refuses to decrypt under a wrong
    context); for the bootstrap task we use a fixed identifier so
    the task knows which context to decrypt against.
    """
    ciphertext = make_backend().encrypt(pem.encode("utf-8"), context="bootstrap-host")
    return ciphertext, "bootstrap-host"


class TestBootstrapHostTask:
    """``bootstrap_host_task`` decrypts the PEM, runs install, returns cert."""

    def test_decrypts_pem_and_passes_to_runner(
        self, client: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The PEM ciphertext is decrypted; the plaintext lands on the runner.

        The router-side will encrypt the operator's PEM before
        queueing — the broker never sees plaintext key material.
        The task is then responsible for decrypting + handing the
        clear PEM to a runner that lives only for the duration of
        the bootstrap session.
        """
        from wg_manager import tasks as tasks_module

        # Swap the bootstrap runner with our recorder so we can pin the
        # PEM the task hands it.
        monkeypatch.setattr(
            tasks_module, "BootstrapSSHRunner", _RecordingRunner
        )

        plaintext_pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKE\n-----END OPENSSH PRIVATE KEY-----\n"
        ciphertext, context = _encrypt_pem(plaintext_pem)

        result = tasks_module.bootstrap_host_task.apply(
            kwargs={
                "hostname": "bootstrap-target.example.com",
                "ssh_port": 22,
                "ssh_user": "ubuntu",
                "principal": "bootstrap-target.example.com",
                "ttl_seconds": 86400,
                "connect_timeout": 15.0,
                "pem_ciphertext": ciphertext,
                "pem_context": context,
                "passphrase_ciphertext": None,
                "passphrase_context": None,
            }
        ).get()

        # Runner was built with the decrypted PEM, no key_path.
        assert len(_RecordingRunner.CONSTRUCTIONS) == 1
        built = _RecordingRunner.CONSTRUCTIONS[0]
        assert built["key_pem"] == plaintext_pem
        assert built.get("key_path") is None
        assert built["host"] == "bootstrap-target.example.com"
        assert built["username"] == "ubuntu"

        # Task returns the cert metadata so the dashboard can show
        # serial + validity.
        assert result["status"] == "ok"
        assert isinstance(result["cert_serial"], int)
        assert result["principals"] == ["bootstrap-target.example.com"]
        assert "valid_after" in result and "valid_before" in result

    def test_uses_separate_principal_when_supplied(
        self, client: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``principal`` overrides ``hostname`` for the cert subject.

        Mirrors the CLI's ``--principal`` flag: an operator can dial
        the box by public IP but bind the cert to its internal DNS
        name. Pin the contract so a future refactor that drops the
        param doesn't silently bind both fields to ``hostname``.
        """
        from wg_manager import tasks as tasks_module

        captured: dict[str, Any] = {}

        def fake_bootstrap_host(*, runner, hostname, principal, ca, ttl_seconds, cn=""):
            captured["principal"] = principal
            captured["hostname"] = hostname
            return HostCert(
                cert_pem="ssh-ed25519-cert-v01@openssh.com TEST\n",
                valid_after=__import__("datetime").datetime(2026, 1, 1, tzinfo=__import__("datetime").timezone.utc),
                valid_before=__import__("datetime").datetime(2026, 1, 2, tzinfo=__import__("datetime").timezone.utc),
                serial=1234,
                principals=(principal,),
            )

        monkeypatch.setattr(
            tasks_module, "BootstrapSSHRunner", _RecordingRunner
        )
        monkeypatch.setattr(tasks_module, "bootstrap_host", fake_bootstrap_host)

        ciphertext, context = _encrypt_pem("fake-pem")
        tasks_module.bootstrap_host_task.apply(
            kwargs={
                "hostname": "65.52.211.113",
                "ssh_port": 22,
                "ssh_user": "azureuser",
                "principal": "vpn-az-east.internal",
                "ttl_seconds": 86400,
                "connect_timeout": 15.0,
                "pem_ciphertext": ciphertext,
                "pem_context": context,
                "passphrase_ciphertext": None,
                "passphrase_context": None,
            }
        ).get()

        assert captured["hostname"] == "65.52.211.113"
        assert captured["principal"] == "vpn-az-east.internal"

    def test_ssh_connection_failure_is_clean_runtime_error(
        self, client: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """SSH-stage failures surface as one-line ``RuntimeError`` failures.

        The polling UI shows the task's failure message verbatim; a
        30-frame paramiko traceback would dump raw socket internals
        into the operator's browser. The task layer is the right
        place to wrap.
        """
        from wg_manager import tasks as tasks_module

        class _BrokenRunner(_RecordingRunner):
            def __enter__(self) -> "_BrokenRunner":
                raise SSHConnectionError(
                    "SSH authentication failed for ubuntu@target: bad key",
                    host="target",
                    port=22,
                )

        monkeypatch.setattr(tasks_module, "BootstrapSSHRunner", _BrokenRunner)

        ciphertext, context = _encrypt_pem("fake-pem")
        with pytest.raises(RuntimeError) as excinfo:
            tasks_module.bootstrap_host_task.apply(
                kwargs={
                    "hostname": "target",
                    "ssh_port": 22,
                    "ssh_user": "ubuntu",
                    "principal": "target",
                    "ttl_seconds": 86400,
                    "connect_timeout": 15.0,
                    "pem_ciphertext": ciphertext,
                    "pem_context": context,
                    "passphrase_ciphertext": None,
                    "passphrase_context": None,
                }
            ).get()
        assert "bootstrap" in str(excinfo.value).lower()
        assert "target" in str(excinfo.value)
