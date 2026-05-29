"""Regression tests for model ``__repr__`` / ``__str__`` redaction.

A surprising number of secret leaks happen through traceback frames,
``logging`` calls that interpolate ``%r``, and IDE/debugger watch
windows — all of which call ``repr()`` on the offending object. The
default Pydantic / SQLModel repr dumps every field, so without an
override a row that carries ciphertext in TEXT columns would print
that blob into every traceback. The blob itself is not plaintext, but
it is a few hundred bytes of base64 noise that crowds out useful
debug info; the override collapses it to ``<set>`` / ``None``.

After Alembic 0008 (sshkey ciphertext columns gone) and 0009
(manual-client private-key ciphertext column gone), no wg-manager row
carries persisted secret material. These tests still pin the
"repr stays short and identifies the row" shape so a future regression
that re-adds ciphertext can't silently start leaking it through
tracebacks.
"""

from __future__ import annotations

from wg_manager.models import Client, SSHKey


class TestSSHKeyRedaction:
    def test_repr_is_short_and_includes_identifying_metadata(self) -> None:
        """The SSHKey repr should fit on one line and name the row."""
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
    def test_manual_client_repr_is_short_and_identifies_row(self) -> None:
        """Post-Alembic-0009 manual clients carry no secret material;
        the repr names the row and shows its public key (safe to log)
        without any ciphertext placeholders that would imply otherwise.
        """
        row = Client(
            id=1,
            name="phone",
            server_id=1,
            address="10.9.0.42/32",
            public_key="PUBLIC-KEY-OK-TO-LOG",
            is_manual=True,
        )
        rendered = repr(row)
        # One-line repr; identifies the row.
        assert "\n" not in rendered
        assert "phone" in rendered
        assert "PUBLIC-KEY-OK-TO-LOG" in rendered
        # No leftover references to the dropped ciphertext column —
        # neither in plaintext nor a placeholder like "<set>".
        assert "private_key_ct" not in rendered
        assert "<set>" not in rendered

    def test_ssh_provisioned_client_repr_is_short(self) -> None:
        """SSH-provisioned clients have always lacked stored secret
        material; the repr should still be short and identify the row."""
        row = Client(
            id=1,
            name="laptop",
            server_id=1,
            address="10.9.0.7/32",
            public_key="PUBLIC-LAPTOP",
            is_manual=False,
        )
        rendered = repr(row)
        assert "\n" not in rendered
        assert "laptop" in rendered
        assert "private_key_ct" not in rendered
