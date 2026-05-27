"""Regression tests for model ``__repr__`` / ``__str__`` redaction.

A surprising number of secret leaks happen through traceback frames,
``logging`` calls that interpolate ``%r``, and IDE/debugger watch
windows — all of which call ``repr()`` on the offending object. The
default Pydantic / SQLModel repr dumps every field, so without an
override a row that carries ciphertext in TEXT columns would print
that blob into every traceback. The blob itself is not plaintext, but
it is a few hundred bytes of base64 noise that crowds out useful
debug info; the override collapses it to ``<set>`` / ``None``.

Post-Phase-2b the row no longer has plaintext columns at all, so
there is no plaintext to redact. The override still matters because:

* It keeps the repr short (one line, not 6 lines of base64).
* It guards against a future regression that adds a new secret-bearing
  column without a matching repr update.
"""

from __future__ import annotations

import logging

import pytest

from wg_manager.crypto import (
    LocalDevBackend,
    encrypt_client_private_key,
    encrypt_sshkey_secrets,
)
from wg_manager.models import Client, SSHKey


_PEM = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "supersecret-body-bytes-that-should-never-appear-in-logs\n"
    "-----END OPENSSH PRIVATE KEY-----\n"
)

_TEST_FERNET_KEY = b"6BR-12U4QDta_TTnZnieCyvMU5VzRSnUqbH6hA80Ihw="


@pytest.fixture()
def backend() -> LocalDevBackend:
    return LocalDevBackend(_TEST_FERNET_KEY)


class TestSSHKeyRedaction:
    def test_repr_collapses_ciphertext_columns(
        self, backend: LocalDevBackend
    ) -> None:
        """The ciphertext column body must not flood the repr."""
        row = SSHKey(id=1, name="lab")
        encrypt_sshkey_secrets(
            backend, row, private_key=_PEM, passphrase="hunter2"
        )
        rendered = repr(row)
        # The actual ciphertext body is base64 noise — repr must not
        # dump it (the dashboard panel surfaces "encrypted" status more
        # usefully). We check via the literal blob content.
        assert row.private_key_ct is not None
        assert row.private_key_ct not in rendered
        assert row.passphrase_ct is not None
        assert row.passphrase_ct not in rendered
        # Identifying metadata is still helpful for debugging.
        assert "lab" in rendered
        # The collapsed marker shows whether the column is populated.
        assert "<set>" in rendered

    def test_repr_does_not_leak_plaintext_under_percent_r(
        self,
        backend: LocalDevBackend,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """``logger.error("…%r", row)`` is the most common leak vector."""
        row = SSHKey(id=1, name="lab")
        encrypt_sshkey_secrets(
            backend, row, private_key=_PEM, passphrase="hunter2"
        )
        logger = logging.getLogger("wg_manager.test_repr")
        with caplog.at_level(logging.DEBUG, logger="wg_manager.test_repr"):
            logger.error("ssh key was %r", row)
            logger.error("ssh key was %s", row)
        captured = caplog.text
        assert "supersecret-body-bytes" not in captured
        assert "BEGIN OPENSSH" not in captured
        assert "hunter2" not in captured

    def test_repr_with_null_columns(self) -> None:
        """A row with no ciphertext columns set still has a clean repr."""
        row = SSHKey(id=1, name="lab")
        rendered = repr(row)
        assert "<set>" not in rendered
        assert "None" in rendered


class TestClientRedaction:
    def test_manual_client_repr_collapses_ciphertext(
        self, backend: LocalDevBackend
    ) -> None:
        row = Client(
            id=1,
            name="phone",
            server_id=1,
            address="10.9.0.42/32",
            public_key="PUBLIC-KEY-OK-TO-LOG",
            is_manual=True,
        )
        encrypt_client_private_key(
            backend, row, private_key="MANUAL-CLIENT-WG-SECRET"
        )
        rendered = repr(row)
        assert "MANUAL-CLIENT-WG-SECRET" not in rendered
        assert row.private_key_ct is not None
        assert row.private_key_ct not in rendered
        # Public key and identifiers are fine to log — they're not secret.
        assert "phone" in rendered
        assert "PUBLIC-KEY-OK-TO-LOG" in rendered
        assert "<set>" in rendered

    def test_ssh_provisioned_client_repr_handles_null(self) -> None:
        """SSH-provisioned clients have ``private_key_ct=None`` — repr must not crash."""
        row = Client(
            id=1,
            name="laptop",
            server_id=1,
            address="10.9.0.7/32",
            public_key="PUBLIC-LAPTOP",
            is_manual=False,
        )
        rendered = repr(row)
        assert "laptop" in rendered
        assert "<set>" not in rendered
