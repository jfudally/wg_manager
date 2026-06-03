"""Config-shape tests for Phase 2e audit-log cycle 2.

Cycle 2 layers a ``vector`` sidecar on top of the cycle 1 file audit
device. The sidecar tails ``/vault/logs/audit.log`` (the file Vault
writes through the audit device, persisted in the
``wg_manager_vault_audit_logs`` named volume) and echoes every record
to its own stdout. ``docker compose logs vector`` is then the live
audit feed an operator can watch during a dev session, without having
to ``docker compose exec vault tail …`` by hand.

These tests pin the docker-compose service contract and the
``vector.toml`` config shape — both files are operator-facing
infrastructure, so a drift in either is exactly the failure mode the
audit log exists to prevent (silent gap in the trail). The tests are
intentionally pure parse-and-assert: no docker daemon is required to
run them, which keeps them green inside the hermetic ``make test``
invocation.

A live-vector smoke flow (start vault → bootstrap audit device → run
vector → write to Vault → read ``docker compose logs vector``) is
documented in ``docs/vault-cookbook.md`` §6 cycle 2; it is not gated
into pytest for the same reason ``make vault-audit-bootstrap`` isn't.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
COMPOSE_PATH = REPO_ROOT / "docker-compose.yml"
VECTOR_CONFIG_PATH = REPO_ROOT / "docker" / "vector" / "vault-audit.toml"


@pytest.fixture(scope="module")
def compose() -> dict:
    """Parsed ``docker-compose.yml``. Module-scoped so the YAML parse
    runs once per test session rather than once per assertion."""
    return yaml.safe_load(COMPOSE_PATH.read_text())


@pytest.fixture(scope="module")
def vector_config() -> dict:
    """Parsed ``docker/vector/vault-audit.toml``. Module-scoped."""
    return tomllib.loads(VECTOR_CONFIG_PATH.read_text())


class TestVectorComposeService:
    """Pin the docker-compose vector-sidecar contract.

    A misconfigured sidecar can drop records, ship to the wrong sink,
    or — worst case — write back to the audit volume it is shipping.
    Each assertion below maps to one of those failure modes.
    """

    def test_vector_service_defined(self, compose: dict) -> None:
        """A ``vector`` service exists in docker-compose."""
        assert "vector" in compose["services"]

    def test_image_is_pinned_not_latest(self, compose: dict) -> None:
        """Image tag is a specific version, never ``:latest``.

        An unpinned tag means ``docker compose pull`` can silently
        swap the audit-shipping daemon under a running deploy — the
        exact opposite of the supply-chain hygiene Phase 2e ships.
        """
        image = compose["services"]["vector"]["image"]
        assert image.startswith("timberio/vector:"), (
            f"expected timberio/vector:* image, got {image!r}"
        )
        assert not image.endswith(":latest"), (
            "pin the vector image version explicitly; ``:latest`` "
            "defeats the supply-chain story Phase 2e is building"
        )

    def test_audit_volume_mounted_read_only(self, compose: dict) -> None:
        """The named volume is mounted ``:ro`` on the vector service.

        Read-only is a hard requirement: a writable mount lets the
        sidecar (or a compromised vector binary) rewrite the audit
        trail it is shipping, which is the worst possible posture for
        an audit pipeline.
        """
        volumes = compose["services"]["vector"]["volumes"]
        audit_mount = next(
            (v for v in volumes if "wg_manager_vault_audit_logs" in v),
            None,
        )
        assert audit_mount is not None, (
            "vector sidecar must mount the same named volume the "
            "vault service writes to so it tails the same audit.log"
        )
        assert audit_mount.endswith(":ro"), (
            f"audit volume must be :ro, got {audit_mount!r} — the "
            "sidecar must not be able to rewrite the audit trail"
        )
        assert "/vault/logs" in audit_mount, (
            f"mount path must match the in-container path Vault "
            f"writes to (/vault/logs/), got {audit_mount!r}"
        )

    def test_vector_config_mounted_read_only(self, compose: dict) -> None:
        """The ``vault-audit.toml`` config is bind-mounted ``:ro``."""
        volumes = compose["services"]["vector"]["volumes"]
        cfg_mount = next(
            (v for v in volumes if "vault-audit.toml" in v),
            None,
        )
        assert cfg_mount is not None, (
            "vector needs its config bind-mounted — without it the "
            "container falls back to default config and tails nothing"
        )
        assert cfg_mount.endswith(":ro"), (
            f"config mount should be :ro, got {cfg_mount!r}"
        )

    def test_depends_on_vault(self, compose: dict) -> None:
        """``depends_on: vault`` is set so vector starts after Vault.

        Without this, vector races Vault's container creation and may
        try to open ``/vault/logs/audit.log`` before the volume mount
        is visible. The form may be a list or a dict (condition map)
        — both are valid compose syntax; accept either.
        """
        deps = compose["services"]["vector"].get("depends_on", [])
        if isinstance(deps, dict):
            deps = list(deps.keys())
        assert "vault" in deps, (
            f"vector.depends_on must include 'vault', got {deps!r}"
        )

    def test_audit_volume_still_declared(self, compose: dict) -> None:
        """Cycle 1's named volume survives the cycle 2 edit.

        Belt-and-braces guard against an accidental compose-rewrite
        that drops the volume declaration but leaves the mount line
        — docker compose then silently creates an anonymous volume
        and the audit trail vanishes on the next ``compose down``.
        """
        assert "wg_manager_vault_audit_logs" in compose["volumes"]


class TestVaultServiceEnvSupportsCli:
    """Pin the env vars needed for the cookbook §6 smoke flows.

    Both the cycle 1 verify command (``docker compose exec vault
    vault kv put secret/audit-test foo=bar``) and the cycle 2 vector
    smoke command depend on the *vault CLI inside the vault
    container* being pre-authenticated. The CLI reads ``VAULT_TOKEN``
    from the process environment; without it the smoke command 403s
    on a ``GET /v1/sys/internal/ui/mounts/…`` lookup before it ever
    reaches the kv engine.

    ``VAULT_DEV_ROOT_TOKEN_ID`` is *not* the same thing: that env var
    is read by the Vault server at boot to fix the root token at
    ``dev-only-root``, but the CLI doesn't consult it. A separate
    ``VAULT_TOKEN`` entry is what makes the cookbook smoke commands
    one-liners — without it the operator has to thread
    ``-e VAULT_TOKEN=dev-only-root`` through every ``docker compose
    exec`` call, which is precisely the kind of ceremony the dev
    compose stack exists to spare.

    Safe to bake into the dev compose: the root token is already a
    literal string in the same file and the entire container's
    state is throwaway.
    """

    def test_vault_addr_set_for_cli(self, compose: dict) -> None:
        """``VAULT_ADDR`` env var present on the vault service."""
        env = compose["services"]["vault"]["environment"]
        assert "VAULT_ADDR" in env, (
            "VAULT_ADDR must be set on the vault service env so the "
            "CLI inside the container can find the local server"
        )

    def test_vault_token_set_for_cli(self, compose: dict) -> None:
        """``VAULT_TOKEN`` env var matches the configured root token.

        Catches the regression the cycle 2 PR review surfaced: the
        cookbook §6 ``docker compose exec vault vault kv put …``
        smoke commands all 403 if the CLI isn't pre-authenticated.
        Pinning the env var here means a future compose edit that
        drops it (e.g. a misguided "tidy the env block" refactor)
        re-trips this test rather than silently breaking the
        operator runbook.
        """
        env = compose["services"]["vault"]["environment"]
        assert "VAULT_TOKEN" in env, (
            "VAULT_TOKEN must be set on the vault service env so the "
            "CLI inside the container authenticates without an extra "
            "-e VAULT_TOKEN=… flag on every `docker compose exec`. "
            "Pair value with VAULT_DEV_ROOT_TOKEN_ID."
        )
        # Same root token both server-side (DEV_ROOT_TOKEN_ID) and
        # CLI-side (TOKEN). A drift between the two would also break
        # the smoke flow, just less obviously.
        assert env["VAULT_TOKEN"] == env["VAULT_DEV_ROOT_TOKEN_ID"], (
            "VAULT_TOKEN must match VAULT_DEV_ROOT_TOKEN_ID — they "
            "configure two sides of the same auth contract"
        )


class TestVectorConfig:
    """Pin the ``vector.toml`` shape: file source → console sink.

    The config is the contract between the audit-device output (cycle
    1) and the operator-visible stdout stream. Either half drifting
    silently breaks the chain, so the assertions below are
    intentionally precise about source path and sink type.
    """

    def test_file_source_tails_audit_log(self, vector_config: dict) -> None:
        """A ``file``-type source includes ``/vault/logs/audit.log``."""
        sources = vector_config["sources"]
        assert "vault_audit" in sources, (
            f"expected a [sources.vault_audit] section, found "
            f"{list(sources)!r}"
        )
        src = sources["vault_audit"]
        assert src["type"] == "file", (
            f"vault_audit source must be type=file, got {src['type']!r}"
        )
        assert "/vault/logs/audit.log" in src["include"], (
            f"file source must tail /vault/logs/audit.log, includes={src['include']!r}"
        )

    def test_console_sink_emits_stdout(self, vector_config: dict) -> None:
        """Exactly one ``console`` sink, fed from the file source.

        Multiple console sinks would either duplicate every record or
        race for the same stdout fd; the dev-visibility contract is
        one record on stdout per audit event.
        """
        sinks = vector_config["sinks"]
        console_sinks = [
            (name, defn)
            for name, defn in sinks.items()
            if defn.get("type") == "console"
        ]
        assert len(console_sinks) == 1, (
            f"expected exactly one console sink, found {len(console_sinks)}: "
            f"{[name for name, _ in console_sinks]!r}"
        )
        _, sink = console_sinks[0]
        # Inputs may either reference the file source directly or
        # route through a transform — both are valid. Accept either
        # by walking transforms back to a vault_audit source.
        inputs = sink["inputs"]
        transforms = vector_config.get("transforms", {})
        if "vault_audit" in inputs:
            return
        for input_name in inputs:
            if input_name in transforms and "vault_audit" in transforms[input_name].get(
                "inputs", []
            ):
                return
        pytest.fail(
            f"console sink inputs={inputs!r} don't trace back to "
            "vault_audit source (directly or via a transform)"
        )

    def test_config_does_not_write_to_audit_volume(
        self, vector_config: dict
    ) -> None:
        """No sink writes back to ``/vault/logs/`` — defence in depth.

        The compose mount is ``:ro`` so the kernel would reject a
        write anyway, but the test pins the config-level intent so
        a future operator reading the toml can't be misled into
        thinking vector is meant to round-trip into the audit dir.
        """
        for name, sink in vector_config["sinks"].items():
            path = sink.get("path", "")
            assert "/vault/logs" not in path, (
                f"sink {name!r} writes into the audit volume "
                f"(path={path!r}); the volume is read-only and the "
                "sidecar must never round-trip into it"
            )
