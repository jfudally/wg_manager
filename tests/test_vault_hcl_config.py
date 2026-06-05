"""Tests for the production Vault config (`docker/vault/vault.hcl`).

The prod overlay swaps the dev compose's ``vault server -dev`` for
``vault server -config=/vault/config/vault.hcl``. The dev `-dev` mode
is in-memory + auto-unsealed + ships a fixed root token; the file
under test runs a real Vault with **file storage**, a TCP listener
on the docker network, and a UI on. State persists across container
restarts (no more "every `make prod-down -v` regenerates the SSH CA
keypair and breaks bootstrap-host-installed targets" — the class of
bug that motivated this rewrite).

Pure parse-and-assert: walks the HCL text rather than spinning up
Vault. Live behaviour is exercised by the rv.vpn end-to-end smoke.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
VAULT_HCL = REPO_ROOT / "docker" / "vault" / "vault.hcl"


@pytest.fixture(scope="module")
def hcl_body() -> str:
    """Read the Vault HCL config or fail the suite."""
    assert VAULT_HCL.is_file(), (
        f"{VAULT_HCL} is missing — the prod overlay's vault service "
        "now boots from this config instead of `server -dev`."
    )
    return VAULT_HCL.read_text()


class TestStorageBackend:
    """Vault must use file storage so state survives container
    restarts. Without persistence, every restart wipes the SSH CA
    keypair and bootstrap-host-installed target hosts stop trusting
    the running api — the exact bug class that motivated this work.
    """

    def test_uses_file_storage(self, hcl_body: str) -> None:
        # The block shape is `storage "file" { path = "..." }`.
        assert re.search(
            r"^\s*storage\s+\"file\"\s*\{",
            hcl_body,
            re.MULTILINE,
        ), (
            "vault.hcl must declare `storage \"file\" { ... }` so "
            "Vault data persists across container restarts. Without "
            "this, the dev-mode bug class (CA regenerated on every "
            "restart → target hosts trust the wrong CA) comes back."
        )

    def test_file_storage_path_under_vault_data_volume(
        self, hcl_body: str
    ) -> None:
        # The compose overlay mounts `wg_manager_vault_data` at
        # `/vault/file`. The HCL must write to a path under that
        # mount so the persistence is actually persistent.
        assert re.search(
            r"path\s*=\s*\"/vault/file\"?",
            hcl_body,
        ), (
            "vault.hcl's `storage \"file\" { path = ... }` must "
            "point at `/vault/file` — the bind-mount path the prod "
            "overlay's `wg_manager_vault_data` volume already uses."
        )


class TestListener:
    """Vault's HTTP API must listen on the docker network so api / "
    worker / bootstrap-* containers can reach it."""

    def test_has_tcp_listener(self, hcl_body: str) -> None:
        assert re.search(
            r"^\s*listener\s+\"tcp\"\s*\{",
            hcl_body,
            re.MULTILINE,
        ), (
            "vault.hcl must declare `listener \"tcp\" { ... }` so "
            "the docker-network sidecars can talk to it."
        )

    def test_binds_all_interfaces_on_8200(self, hcl_body: str) -> None:
        # The docker-compose `vault:8200` DNS expects the listener
        # on 0.0.0.0:8200 — `127.0.0.1` would block the api/worker
        # containers from reaching it across the docker network.
        match = re.search(
            r"address\s*=\s*\"([^\"]+)\"",
            hcl_body,
        )
        assert match, "vault.hcl listener must set `address = \"...\"`"
        assert match.group(1) in ("0.0.0.0:8200", "[::]:8200"), (
            "Listener `address` must bind 0.0.0.0:8200 (or [::]:8200) "
            "so the docker-network DNS name `vault:8200` resolves "
            f"to a reachable port. Got {match.group(1)!r}."
        )


class TestOperationalKnobs:
    """A few non-storage knobs that meaningfully affect the
    operator experience: API + cluster addr, UI, mlock."""

    def test_disables_mlock(self, hcl_body: str) -> None:
        # Vault's docs recommend `disable_mlock = true` for setups
        # where the operating environment doesn't grant
        # `IPC_LOCK`-equivalent caps to the Vault process. The
        # compose overlay sets `cap_add: IPC_LOCK` already, but
        # disabling mlock is the safer default for portability —
        # the on-disk swap risk only matters if there's swap, and
        # operator-controlled hosts usually don't have it.
        assert re.search(
            r"^\s*disable_mlock\s*=\s*true",
            hcl_body,
            re.MULTILINE,
        ), (
            "vault.hcl should declare `disable_mlock = true` for "
            "portable boot across hosts where IPC_LOCK is not "
            "guaranteed (kernel-hardened containers, rootless docker)."
        )

    def test_enables_ui(self, hcl_body: str) -> None:
        # The UI is useful for operator debugging — peeking at the
        # SSH CA mount state, the PKI hierarchy, the transit key
        # versions. Trivial perf cost.
        assert re.search(
            r"^\s*ui\s*=\s*true",
            hcl_body,
            re.MULTILINE,
        ), (
            "vault.hcl should set `ui = true` so operators can "
            "browse to http://<host>:8200/ui for inspection. Useful "
            "for diagnosing 'why did the api fail to talk to "
            "Vault?'-shaped questions."
        )

    def test_api_addr_set(self, hcl_body: str) -> None:
        # `api_addr` is what Vault advertises to itself for
        # internal API calls. It must point at the compose-network
        # listener (vault:8200), not 127.0.0.1 (which inside the
        # container is fine for local but breaks if Vault ever
        # follows its own redirect).
        match = re.search(
            r"^\s*api_addr\s*=\s*\"([^\"]+)\"",
            hcl_body,
            re.MULTILINE,
        )
        assert match, (
            "vault.hcl must declare `api_addr = \"http://...:8200\"` "
            "so Vault's internal API calls hit the compose-network "
            "listener and not localhost."
        )


class TestNoListenerTLS:
    """Vault listener TLS is intentionally NOT enabled.

    Within the docker network the api/worker/bootstrap-* are the
    only callers, the network itself is operator-controlled, and
    adding listener TLS would require yet another set of operator-
    issued certs at bootstrap time. Listener TLS is a follow-on
    cycle, NOT this work. Keep the listener cleartext on the
    docker-network and document the gap.
    """

    def test_listener_does_not_enable_tls(self, hcl_body: str) -> None:
        # Specifically: no `tls_cert_file` / `tls_key_file` lines.
        # If a future edit adds them, the operator must also wire
        # the cert-mint path BEFORE the listener can start — which
        # would break the chicken-and-egg-free property the current
        # design relies on (api can't mint Vault TLS certs because
        # Vault is its PKI source).
        for forbidden in ("tls_cert_file", "tls_key_file"):
            assert forbidden not in hcl_body, (
                f"vault.hcl's listener must NOT enable {forbidden} "
                "in this cycle — Vault TLS is the PKI source for "
                "every other cert in the stack, so the listener "
                "can't depend on a Vault-minted cert at boot. "
                "Keep cleartext on the docker network until a "
                "dedicated listener-TLS cycle ships."
            )
