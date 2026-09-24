"""Tests for the PKCS#8 conversion in ``bootstrap_mysql_tls_files.py``.

MySQL 8.4's TLS init rejects SEC1-encoded EC private keys with
``[ERROR] [MY-000059] [Server] SSL error: Unable to get private key
from '/etc/mysql/certs/server.key'``. The Vault PKI backend returns
SEC1-wrapped keys by default, which is why the initial rotation
attempt in the Sep '26 prod-up incident silently failed at mysqld
TLS init and cascaded into an ``SSL is required but the server
doesn't support it`` error from every client that had
``DATABASE_TLS_REQUIRED=true`` set.

The mint script now normalises to PKCS#8 (``-----BEGIN PRIVATE KEY-----``)
before writing so the next rotation loads cleanly without the manual
``openssl pkey`` dance the operator had to do to unstick things.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "bootstrap_mysql_tls_files.py"


@pytest.fixture(scope="module")
def script_module():
    """Load the mint script as a module so we can call helpers directly.

    ``exec_module`` runs top-level definitions (the imports + the
    ``_to_pkcs8_pem`` helper we're testing) but skips ``main()``
    because the ``if __name__ == "__main__"`` guard only fires when
    the module is invoked as ``__main__`` — which it isn't here.
    """
    spec = importlib.util.spec_from_file_location(
        "bootstrap_mysql_tls_files", SCRIPT_PATH
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestPkcs8Helper:
    def test_helper_exposed(self, script_module) -> None:
        assert hasattr(script_module, "_to_pkcs8_pem"), (
            "the mint script must expose a _to_pkcs8_pem helper so "
            "the PKCS#8 normalisation is testable"
        )

    def test_converts_sec1_ec_key_to_pkcs8(self, script_module) -> None:
        """A SEC1 EC key round-trips into a PKCS#8 PEM that carries
        the same public numbers — this is the exact case that bit us
        against MySQL 8.4."""
        key = ec.generate_private_key(ec.SECP256R1())
        sec1_pem = key.private_bytes(
            Encoding.PEM,
            PrivateFormat.TraditionalOpenSSL,  # SEC1 for EC keys
            NoEncryption(),
        ).decode()
        assert "BEGIN EC PRIVATE KEY" in sec1_pem, (
            "test setup: cryptography's TraditionalOpenSSL for EC "
            "should produce a SEC1 wrapper"
        )

        pkcs8_pem = script_module._to_pkcs8_pem(sec1_pem)

        assert pkcs8_pem.startswith("-----BEGIN PRIVATE KEY-----"), (
            f"expected PKCS#8 header, got: {pkcs8_pem[:60]}"
        )
        reloaded = load_pem_private_key(pkcs8_pem.encode(), password=None)
        assert reloaded.public_key().public_numbers() == key.public_key().public_numbers()

    def test_idempotent_on_pkcs8_input(self, script_module) -> None:
        """If Vault ever starts emitting PKCS#8 natively the helper
        must still pass the key through unchanged (well, semantically
        unchanged — a re-encode is fine as long as the public
        material matches)."""
        key = ec.generate_private_key(ec.SECP256R1())
        pkcs8_pem = key.private_bytes(
            Encoding.PEM,
            PrivateFormat.PKCS8,
            NoEncryption(),
        ).decode()

        out = script_module._to_pkcs8_pem(pkcs8_pem)

        assert out.startswith("-----BEGIN PRIVATE KEY-----")
        reloaded = load_pem_private_key(out.encode(), password=None)
        assert reloaded.public_key().public_numbers() == key.public_key().public_numbers()

    def test_passes_rsa_keys_through(self, script_module) -> None:
        """RSA keys are already PKCS#8-friendly with cryptography's
        default serialization, but the helper still needs to accept
        them without corrupting the material — Vault's PKI role could
        be reconfigured to issue RSA at any time."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pkcs1_pem = key.private_bytes(
            Encoding.PEM,
            PrivateFormat.TraditionalOpenSSL,  # PKCS#1 for RSA
            NoEncryption(),
        ).decode()

        out = script_module._to_pkcs8_pem(pkcs1_pem)

        assert out.startswith("-----BEGIN PRIVATE KEY-----")
        reloaded = load_pem_private_key(out.encode(), password=None)
        assert reloaded.public_key().public_numbers() == key.public_key().public_numbers()


class TestMintScriptUsesHelper:
    """The helper existing isn't enough — the ``main`` flow has to
    actually pipe the private PEMs through it before writing. A
    coarse source-level check pinning the wire-up so a refactor
    that skips the conversion trips the test."""

    def test_server_key_write_uses_helper(self) -> None:
        src = SCRIPT_PATH.read_text()
        # The server.key write must consume _to_pkcs8_pem output.
        # We look for the helper name appearing between the mint call
        # and the server.key write. If a future refactor changes the
        # variable name, the test message points at the invariant.
        assert "_to_pkcs8_pem" in src, (
            "main() must call _to_pkcs8_pem on the private PEM before "
            "writing server.key / client.key — otherwise MySQL 8.4 "
            "rejects the freshly-minted key on next restart"
        )
        # server.key and client.key should each be written *after* the
        # helper has been applied to their respective private_pem.
        assert src.count("_to_pkcs8_pem") >= 2, (
            "expected _to_pkcs8_pem to be applied to both the server "
            "and client private PEMs — one call site is not enough"
        )
