"""Tests for ``scripts/transit_bootstrap.py``.

The Vault Transit secrets engine + master key drive
:class:`wg_manager.crypto.VaultTransitBackend`. The crypto module is
deliberately dumb — it doesn't call ``create_key`` itself, so a
running prod stack with ``CRYPTO_BACKEND=vault`` will 500 the first
time anything touches the crypto router unless something else
provisioned the Transit mount + key first.

Before this script existed the bootstrap step was documented as a
manual ``client.secrets.transit.create_key(...)`` snippet in
``docs/vault-cookbook.md`` §1 — the self-bootstrapping prod stack
needs it scripted so the operator doesn't have to remember.

Pure parse-and-assert. Live execution lives in the prod stack's
``scripts/prod_bootstrap_substrate.sh`` invocation + the
end-to-end smoke (curl ``/v1/crypto/status`` returns 200, not 500).
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "transit_bootstrap.py"


@pytest.fixture(scope="module")
def body() -> str:
    assert SCRIPT.is_file(), (
        f"{SCRIPT} is missing — the prod stack's self-bootstrap needs "
        "a scripted way to enable the Transit engine + create the "
        "master key (the crypto module's `VaultTransitBackend` won't "
        "do it itself). Without this, /v1/crypto/status 500s with "
        "`no handler for route transit/keys/wg-manager`."
    )
    return SCRIPT.read_text()


class TestScriptShape:
    """Match the shape of the other bootstrap scripts so a future
    refactor that drops one trips the same kind of assertion."""

    def test_is_python_with_shebang(self, body: str) -> None:
        first = body.splitlines()[0]
        assert first.startswith("#!") and "python" in first, (
            "transit_bootstrap.py must declare a python shebang so it "
            "runs as `python scripts/transit_bootstrap.py` consistently "
            f"with pki_bootstrap.py / ssh_ca_bootstrap.py. Got {first!r}."
        )

    def test_imports_hvac(self, body: str) -> None:
        assert "import hvac" in body, (
            "transit_bootstrap.py must import hvac — the Transit engine "
            "and master key are managed via the Vault HTTP API."
        )

    def test_has_main_entrypoint(self, body: str) -> None:
        assert "def main(" in body, (
            "transit_bootstrap.py must expose a `main()` entrypoint so "
            "the CLI surface matches the other bootstrap scripts (the "
            "`make transit-bootstrap` target invokes `python ... .py`)."
        )


class TestEnablesTransitMount:
    """The script must enable the Transit secrets engine at the
    configured mount path. Re-runs against an already-mounted engine
    must be no-ops (idempotency is the whole point of self-
    bootstrap)."""

    def test_enables_transit_secrets_engine(self, body: str) -> None:
        # Either `client.sys.enable_secrets_engine(...)` directly or a
        # helper that wraps it. The grep is on the surface area.
        assert "enable_secrets_engine" in body, (
            "transit_bootstrap.py must call "
            "`client.sys.enable_secrets_engine(backend_type='transit', ...)` "
            "to make the engine available. Without this, "
            "`transit/keys/wg-manager` returns 'no handler for route'."
        )

    def test_handles_already_mounted(self, body: str) -> None:
        # The Vault API returns `path is already in use` when the mount
        # is already there. The script must catch + ignore so re-runs
        # are clean.
        already = (
            "already in use" in body
            or "ValueAlreadyExists" in body
            or "InvalidRequest" in body
        )
        assert already, (
            "transit_bootstrap.py must tolerate 'path is already in use' "
            "(catch InvalidRequest or check the mount list first) so "
            "re-running `make prod-up` doesn't fail at this step."
        )


class TestCreatesMasterKey:
    """The script must create the master Transit key with
    ``derived=True`` so the per-row context that crypto.py passes
    actually affects the derived data-encryption key. Without
    ``derived=True``, Transit silently ignores the context and the
    row-swap defence disappears."""

    def test_calls_create_key(self, body: str) -> None:
        assert "create_key" in body, (
            "transit_bootstrap.py must call "
            "`client.secrets.transit.create_key(name=..., derived=True)`."
        )

    def test_creates_key_with_derived_true(self, body: str) -> None:
        # The crypto.py docstring explicitly calls out derived=True as
        # required for the row-swap defence. Without it the script
        # produces a Transit key that silently disables context
        # binding — encrypted blobs would be re-decryptable in a
        # different row's context.
        assert "derived=True" in body or "derived = True" in body, (
            "transit_bootstrap.py must set `derived=True` on the master "
            "key. Without it, the per-row context binding "
            "wg_manager.crypto enforces is silently a no-op — the row-"
            "swap defence breaks (see crypto.py:206)."
        )

    def test_idempotent_key_creation(self, body: str) -> None:
        # `create_key` is a POST that's a no-op if the key already
        # exists (Vault returns 204 in both cases for upsert-style
        # endpoints) but we should ALSO be defensive: read first, only
        # create on miss, or catch any 4xx as benign.
        guard = (
            "read_key" in body
            or "InvalidPath" in body
            or "already" in body.lower()
            or "try:" in body
        )
        assert guard, (
            "transit_bootstrap.py should guard key creation so a re-run "
            "against an existing key is a clean no-op rather than a "
            "noisy error."
        )
