"""Regression tests for the PKI chain-PEM newline bug.

The ``chain_pem`` field on a freshly-minted :class:`Cert` carries the
issuing CA chain so consumers (uvicorn for the API listener, pymysql
for the MySQL TLS connect args, the Phase 2d CP3 PKCS#12 helper) can
build a complete trust chain. Both backends used to concatenate the
intermediate + root certs with plain string ``+``:

.. code:: python

    chain_pem = self.intermediate_pem + self.root_pem   # LocalDevPKI
    chain_pem = "".join(ca_chain)                       # VaultPKI

When ``intermediate_pem`` ends with ``-----END CERTIFICATE-----`` (no
trailing newline), the resulting blob looks like
``-----END CERTIFICATE----------BEGIN CERTIFICATE-----`` on a single
line. PyOpenSSL and OpenSSL's strict PEM parser reject this — they
require the ``-----BEGIN`` line of each block to be at the start of a
line. The leniency of ``cryptography.x509.load_pem_x509_certificates``
hides the bug from tests until a strict consumer (pymysql's
``ssl={"ca": path}`` connect arg) actually loads the file. This test
pins the contract that the chain PEM is strict-OpenSSL-loadable.

End-to-end verification on a clean docker host caught this — the API
service's pymysql connection failed with ``SSLError: [X509] PEM lib
(_ssl.c)`` because the malformed ``ca-bundle.crt`` couldn't be loaded
into the SSL context.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path

import pytest
from cryptography import x509

from wg_manager.pki import LocalDevPKI, _join_pems


# ---------------------------------------------------------------------------
# Helper unit tests — exercise the bug shape directly.
#
# The Vault PKI API has been observed to return ``ca_chain`` entries
# without a trailing newline on the ``-----END CERTIFICATE-----`` line.
# When the old code did ``"".join(ca_chain)``, two adjacent certs
# produced ``-----END CERTIFICATE----------BEGIN CERTIFICATE-----`` on
# a single line — strict PEM parsers reject this.
# ---------------------------------------------------------------------------


_GOOD_PEM_NO_TAIL_NEWLINE = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBoTCCAUegAwIBAgIUERgnXgxxxxxxxxxxxxxxxxx==\n"
    "-----END CERTIFICATE-----"
)
_GOOD_PEM_WITH_TAIL_NEWLINE = _GOOD_PEM_NO_TAIL_NEWLINE + "\n"


class TestJoinPemsHelper:
    """``_join_pems`` is the seam both backends use to compose a
    chain blob. The strict invariant: the result has ``\\n`` between
    every pair of PEM blocks and ends with ``\\n``."""

    def test_two_pems_no_trailing_newline(self) -> None:
        # The exact bug shape: two ``-----END CERTIFICATE-----`` lines
        # that don't end with a newline. Old ``"".join(...)`` produced
        # malformed output here; the helper must inject the separator.
        result = _join_pems(
            _GOOD_PEM_NO_TAIL_NEWLINE, _GOOD_PEM_NO_TAIL_NEWLINE
        )
        # Every BEGIN must follow a newline (or be at byte 0).
        for idx in range(len(result)):
            if result.startswith("-----BEGIN", idx) and idx != 0:
                assert result[idx - 1] == "\n", (
                    f"BEGIN marker at byte {idx} not preceded by a "
                    f"newline. Context: {result[max(0, idx-30):idx+30]!r}"
                )

    def test_two_pems_with_trailing_newline(self) -> None:
        # Inputs that already end with ``\n`` must not produce
        # ``\n\n``-shaped junk between them (a strict parser tolerates
        # it but it's noisy).
        result = _join_pems(
            _GOOD_PEM_WITH_TAIL_NEWLINE, _GOOD_PEM_WITH_TAIL_NEWLINE
        )
        assert "\n\n\n" not in result, (
            "_join_pems must not produce triple-newline separators."
        )

    def test_empty_input_returns_empty(self) -> None:
        # Vault may return an empty ``ca_chain`` for a root-only mint.
        # The helper must not produce a stray ``\n`` in that case.
        assert _join_pems() == ""

    def test_result_ends_with_newline(self) -> None:
        # Downstream consumers (file writers, file append) expect
        # PEM blobs to end with a newline.
        result = _join_pems(_GOOD_PEM_NO_TAIL_NEWLINE)
        assert result.endswith("\n"), (
            "_join_pems output must end with a newline."
        )

    def test_filters_empty_strings(self) -> None:
        # Vault can return ``""`` entries inside ``ca_chain`` for some
        # versions; helper should treat them as no-ops rather than
        # injecting bare ``\n``s.
        result = _join_pems("", _GOOD_PEM_NO_TAIL_NEWLINE, "")
        # Exactly one BEGIN block, and the result is well-formed.
        assert result.count("-----BEGIN CERTIFICATE-----") == 1
        assert "\n\n\n" not in result


# ---------------------------------------------------------------------------
# Integration tests against LocalDevPKI — ensures the lenient backend
# still produces strict-parseable output after the bug fix.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def issued_chain() -> str:
    """Mint a fresh client cert with LocalDevPKI and return ``chain_pem``."""
    backend = LocalDevPKI.generate()
    cert = backend.issue_client_cert(
        common_name="chain-newline-test",
        sans=[],
        ttl_seconds=60,
    )
    return cert.chain_pem


def _begin_blocks(body: str) -> list[int]:
    """Return the column index of every ``-----BEGIN CERTIFICATE-----``."""
    return [
        match.start() - body.rfind("\n", 0, match.start()) - 1
        for match in re.finditer(r"-----BEGIN CERTIFICATE-----", body)
    ]


class TestChainPemFormatStrict:
    """Each ``-----BEGIN CERTIFICATE-----`` must start at column 0."""

    def test_every_begin_marker_is_at_column_zero(
        self, issued_chain: str
    ) -> None:
        # Column index of every BEGIN marker must be 0 (i.e. it follows
        # a newline, or it's the very first byte). A non-zero column
        # means the previous block's END marker is on the same line —
        # the bug shape.
        columns = _begin_blocks(issued_chain)
        assert all(col == 0 for col in columns), (
            "Every -----BEGIN CERTIFICATE----- line in chain_pem must "
            "start at column 0 (immediately after a newline or at the "
            "very start of the blob). A non-zero column means a "
            f"missing newline separator. Got columns={columns} in "
            f"chain blob of length {len(issued_chain)}."
        )

    def test_chain_blob_has_at_least_two_certs(
        self, issued_chain: str
    ) -> None:
        # Sanity: dev backend is root + intermediate, so the chain blob
        # carries two PEM blocks. If the bug "fix" accidentally drops
        # one of them, this test catches the regression.
        count = issued_chain.count("-----BEGIN CERTIFICATE-----")
        assert count == 2, (
            f"LocalDevPKI chain_pem must carry both intermediate + "
            f"root certs; got {count} BEGIN blocks."
        )


class TestChainPemStrictParser:
    """The chain PEM must be loadable by strict-mode OpenSSL.

    The cryptography library's ``load_pem_x509_certificates`` is
    lenient and parses the malformed shape; OpenSSL's stock
    ``x509 -in`` and Python's ``ssl.SSLContext.load_verify_locations``
    are strict and reject it. Use the strict consumers as the
    regression oracle.
    """

    def test_loadable_by_cryptography(self, issued_chain: str) -> None:
        # Lenient parser — must work even before the bug is fixed.
        # This case guards against a "fix" that breaks the lenient
        # consumer (an over-zealous strip / split).
        certs = x509.load_pem_x509_certificates(issued_chain.encode())
        assert len(certs) >= 2, "lenient parser returned too few certs"

    def test_loadable_by_openssl_strict(
        self, issued_chain: str, tmp_path: Path
    ) -> None:
        # Strict parser. The bug shape produces:
        #   "error reading the file" / "bad end line"
        # from openssl's PEM lib.
        chain_file = tmp_path / "chain.pem"
        chain_file.write_text(issued_chain)
        proc = subprocess.run(
            ["openssl", "crl2pkcs7", "-nocrl", "-certfile", str(chain_file)],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, (
            "openssl strict PEM loader rejected chain_pem — typically "
            "'bad end line' or 'No supported data to decode'. Stderr:\n"
            f"{proc.stderr}"
        )

    def test_loadable_by_python_ssl_context(
        self, issued_chain: str, tmp_path: Path
    ) -> None:
        # The exact failure path the prod overlay's pymysql connection
        # hit: ``ssl.SSLContext.load_verify_locations`` raises
        # ``SSLError: [X509] PEM lib`` on the malformed shape.
        import ssl

        chain_file = tmp_path / "chain.pem"
        chain_file.write_text(issued_chain)
        ctx = ssl.create_default_context()
        # Will raise ssl.SSLError on the bug shape.
        ctx.load_verify_locations(cafile=str(chain_file))
