"""Regression tests for model ``__repr__`` / ``__str__`` redaction.

A surprising number of secret leaks happen through traceback frames,
``logging`` calls that interpolate ``%r``, and IDE/debugger watch
windows — all of which call ``repr()`` on the offending object. The
default Pydantic / SQLModel repr dumps every field, so without an
override a row that carries ciphertext in TEXT columns would print
that blob into every traceback. The blob itself is not plaintext, but
it is a few hundred bytes of base64 noise that crowds out useful
debug info; the override collapses it to ``<set>`` / ``None``.

Phase 2c CP4.4 dropped the sshkey ciphertext columns entirely — the
row is name-and-mode only — so the historical "SSH key repr scrub"
suite collapses to a single shape check (no surprising state on the
repr line). The manual-client side still carries
:attr:`Client.private_key_ct`, so its scrub regressions are
unchanged.
"""

from __future__ import annotations

import pytest

from wg_manager.crypto import LocalDevBackend, encrypt_client_private_key
from wg_manager.models import Client, SSHKey


_TEST_FERNET_KEY = b"6BR-12U4QDta_TTnZnieCyvMU5VzRSnUqbH6hA80Ihw="


@pytest.fixture()
def backend() -> LocalDevBackend:
    return LocalDevBackend(_TEST_FERNET_KEY)


class TestSSHKeyRedaction:
    def test_repr_is_short_and_includes_identifying_metadata(self) -> None:
        """Post-CP4.4 the SSHKey repr should fit on one line and name the row."""
        row = SSHKey(id=1, name="lab")
        rendered = repr(row)
        # No multi-line blob noise.
        assert "\n" not in rendered
        # The row's id and name should be visible — they're not secret.
        assert "lab" in rendered
        # Sanity: no leftover field references from the pre-CP4.4 schema.
        assert "private_key_ct" not in rendered
        assert "passphrase_ct" not in rendered


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
