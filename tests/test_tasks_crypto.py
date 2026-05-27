"""End-to-end proof that Celery tasks read SSH credentials via the
encrypted ciphertext columns.

Post-Phase-2b the plaintext column no longer exists (Alembic 0005
dropped it), so every read must come back through
:func:`wg_manager.crypto.resolve_sshkey_private`. A regression that
tried to ``getattr(row, "private_key")`` would now raise — but
catching it at the Python layer is exactly what we want, so this test
proves the task layer asks for the decrypted plaintext rather than
the column.

The :class:`FakeSSHRunner.KEYS_USED` recorder (populated in
``tests/conftest.py``) records the PEM body each ``SSHRunner`` was
constructed with, which is the seam we check.
"""

from __future__ import annotations

import base64

from fastapi.testclient import TestClient

from tests.conftest import FakeSSHRunner


_SAMPLE_PEM = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "ciphertext-only-readback-canary\n"
    "-----END OPENSSH PRIVATE KEY-----\n"
)
_SAMPLE_PEM_B64 = base64.b64encode(_SAMPLE_PEM.encode("utf-8")).decode("ascii")


class TestTasksReadCiphertext:
    def test_server_provision_decrypts_through_resolver(
        self, client: TestClient
    ) -> None:
        """Provision flow: register SSH key + server via API, reprovision,
        then verify the FakeSSHRunner was constructed with the decrypted
        PEM body. The row carries only ciphertext post-0005, so a green
        result means ``resolve_sshkey_private`` was called and returned
        the right plaintext.
        """
        key_resp = client.post(
            "/ssh-keys",
            json={"name": "lab", "private_key_b64": _SAMPLE_PEM_B64},
        )
        assert key_resp.status_code == 201, key_resp.text
        key_id = int(key_resp.json()["id"])

        server_resp = client.post(
            "/servers",
            json={
                "hostname": "hub.example.com",
                "ssh_username": "ubuntu",
                "ssh_key_id": key_id,
                "endpoint_host": "hub.example.com",
            },
        )
        assert server_resp.status_code == 202, server_resp.text
        server_id = int(server_resp.json()["server"]["id"])

        FakeSSHRunner.KEYS_USED.clear()
        reprov = client.post(f"/servers/{server_id}/reprovision")
        assert reprov.status_code == 202, reprov.text

        # At least one runner was constructed with our decrypted PEM.
        used_pems = [pem for (_h, pem, _pp) in FakeSSHRunner.KEYS_USED]
        assert _SAMPLE_PEM in used_pems, (
            "task layer did not decrypt the ciphertext — runner saw: "
            f"{used_pems!r}"
        )
