"""Tests for the self-bootstrapping shape of ``docker-compose.prod.yml``.

The prod overlay grew two bootstrap containers so an operator can
edit ``.env.prod`` and run a single ``make prod-up`` to get the whole
stack to a working state — no manual cert minting, no shell
exports, no separate `make migrate` step.

The two bootstrap services exist to break the cert/MySQL chicken-
and-egg cleanly:

  - ``bootstrap-substrate``: depends on Vault healthy. Bootstraps
    Vault PKI / SSH CA / audit, mints the MySQL server + client
    cert pair, exits. MySQL + Valkey wait for it to complete
    successfully before starting.
  - ``bootstrap-app``: depends on MySQL + Valkey healthy. Applies
    Alembic migrations, registers the bootstrap operator, mints the
    API server + operator CLI client certs, exits. api + worker + web
    wait for it to complete successfully before starting.

These tests pin the **shape** of the dependency graph (parse-and-
assert, no ``docker compose`` shell-out) so a future edit that drops
a dependency edge, breaks the restart policy on a bootstrap service,
or forgets to share the tls/ writable mount trips at test time.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
PROD_OVERLAY = REPO_ROOT / "docker-compose.prod.yml"


class _ComposeLoader(yaml.SafeLoader):
    """SafeLoader that tolerates Compose-specific ``!override`` /
    ``!reset`` tags. See ``tests/test_compose_prod_overlay.py`` for
    the rationale.
    """

    @staticmethod
    def _passthrough(loader: yaml.Loader, node: yaml.Node) -> object:
        if isinstance(node, yaml.MappingNode):
            return loader.construct_mapping(node)
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node)
        return loader.construct_scalar(node)


_ComposeLoader.add_constructor("!reset", _ComposeLoader._passthrough)
_ComposeLoader.add_constructor("!override", _ComposeLoader._passthrough)


@pytest.fixture(scope="module")
def overlay() -> dict:
    """Parsed overlay document."""
    assert PROD_OVERLAY.is_file()
    return yaml.load(PROD_OVERLAY.read_text(), Loader=_ComposeLoader)


@pytest.fixture(scope="module")
def services(overlay: dict) -> dict:
    return overlay["services"]


def _depends_on(svc: dict) -> dict[str, str]:
    """Normalise ``depends_on`` into ``{service_name: condition_str}``.

    Compose accepts a flat list (no condition) or a dict
    ``{name: {condition: ...}}`` shape. We collapse to the dict form
    using ``"none"`` for list-form entries so assertions can pin the
    condition uniformly.
    """
    raw = svc.get("depends_on") or {}
    if isinstance(raw, list):
        return dict.fromkeys(raw, "none")
    return {k: v.get("condition", "none") for k, v in raw.items()}


# ---------------------------------------------------------------------------
# Bootstrap services exist
# ---------------------------------------------------------------------------


class TestBootstrapServicesPresent:
    """Both bootstrap containers must be defined in the overlay."""

    def test_bootstrap_substrate_present(self, services: dict) -> None:
        assert "bootstrap-substrate" in services, (
            "Overlay must define `bootstrap-substrate` — the container "
            "that runs Phase 1 of self-bootstrap (Vault PKI / SSH CA / "
            "audit + MySQL cert mint)."
        )

    def test_bootstrap_app_present(self, services: dict) -> None:
        assert "bootstrap-app" in services, (
            "Overlay must define `bootstrap-app` — the container that "
            "runs Phase 2 of self-bootstrap (migrate + register operator "
            "+ mint API server + operator client cert)."
        )


# ---------------------------------------------------------------------------
# Image: bootstrap services reuse the wg-manager image
# ---------------------------------------------------------------------------


class TestBootstrapImage:
    """Both bootstrap containers must reuse the same wg-manager image
    api + worker build, so `make prod-up` builds it once."""

    @pytest.mark.parametrize(
        "name", ["bootstrap-substrate", "bootstrap-app"]
    )
    def test_bootstrap_uses_wg_manager_image(
        self, services: dict, name: str
    ) -> None:
        svc = services[name]
        has_build = "build" in svc
        image_ref = str(svc.get("image", "")).lower()
        has_wg_image = "wg-manager" in image_ref or "wg_manager" in image_ref
        assert has_build or has_wg_image, (
            f"{name} must build the repo Dockerfile or pull the "
            "wg-manager image — the bootstrap scripts depend on "
            "`wg-manager` and `alembic` being on PATH."
        )


# ---------------------------------------------------------------------------
# Restart policy: bootstrap containers should NOT restart
# ---------------------------------------------------------------------------


class TestBootstrapRestartPolicy:
    """Bootstrap containers run-to-completion. Restarting them
    indefinitely is wrong — they're meant to exit 0 once their work
    is done. `restart: "no"` is the correct policy."""

    @pytest.mark.parametrize(
        "name", ["bootstrap-substrate", "bootstrap-app"]
    )
    def test_restart_is_no(self, services: dict, name: str) -> None:
        # Compose accepts both `no` (string) and `"no"` (quoted) — YAML
        # parses both as the string "no". Compose-quoted-no avoids the
        # YAML 1.1 footgun where bare `no` becomes False.
        restart = services[name].get("restart")
        assert str(restart).lower() == "no", (
            f"{name} must declare `restart: \"no\"` — bootstrap "
            "containers run-to-completion. Any other policy makes them "
            f"loop or stay 'created'. Got: restart={restart!r}."
        )


# ---------------------------------------------------------------------------
# tls/ writable mount
# ---------------------------------------------------------------------------


class TestBootstrapTlsMount:
    """Both bootstrap containers must mount ``./tls`` WRITABLE — they
    mint cert files there. The api/worker/web mounts are read-only;
    the bootstrap mount is the one writer."""

    @pytest.mark.parametrize(
        "name", ["bootstrap-substrate", "bootstrap-app"]
    )
    def test_tls_mount_is_writable(
        self, services: dict, name: str
    ) -> None:
        volumes = services[name].get("volumes", []) or []
        joined = " ".join(str(v) for v in volumes)
        # The mount source must reference ``./tls`` and the target
        # must NOT carry the ``:ro`` flag.
        assert "./tls" in joined, (
            f"{name} must bind-mount `./tls` into the container so "
            "the cert-mint commands can write into it."
        )
        # Find the actual tls mount entry and verify it lacks :ro.
        for entry in volumes:
            s = str(entry)
            if "./tls" in s:
                assert ":ro" not in s, (
                    f"{name}'s ./tls mount must NOT be `:ro` — the "
                    "bootstrap container writes cert files there. "
                    f"Got: {s!r}."
                )


# ---------------------------------------------------------------------------
# Dependency graph: enforces the two-phase ordering
# ---------------------------------------------------------------------------


class TestPhaseOrdering:
    """The compose dependency graph encodes the cert/MySQL chicken-
    and-egg resolution."""

    def test_bootstrap_substrate_waits_for_vault(
        self, services: dict
    ) -> None:
        deps = _depends_on(services["bootstrap-substrate"])
        assert deps.get("vault") == "service_healthy", (
            "bootstrap-substrate must depend on vault healthy — Phase 1 "
            "needs Vault reachable for PKI / SSH CA / audit bootstrap. "
            f"Got deps={deps}."
        )

    def test_mysql_waits_for_substrate_completion(
        self, services: dict
    ) -> None:
        deps = _depends_on(services["mysql"])
        assert (
            deps.get("bootstrap-substrate") == "service_completed_successfully"
        ), (
            "mysql must wait for bootstrap-substrate to complete — it "
            "needs the server cert files Phase 1 mints into tls/mysql/ "
            f"before it can start. Got deps={deps}."
        )

    def test_valkey_waits_for_substrate_completion(
        self, services: dict
    ) -> None:
        # Valkey doesn't strictly need the cert files, but ordering it
        # after substrate keeps the boot order deterministic + simple.
        deps = _depends_on(services["valkey"])
        assert (
            deps.get("bootstrap-substrate") == "service_completed_successfully"
        ), (
            "valkey must wait for bootstrap-substrate to complete — "
            "ordering after Phase 1 keeps the prod-up boot sequence "
            f"deterministic. Got deps={deps}."
        )

    def test_bootstrap_app_waits_for_data_tier(
        self, services: dict
    ) -> None:
        deps = _depends_on(services["bootstrap-app"])
        for required in ("mysql", "valkey"):
            assert deps.get(required) == "service_healthy", (
                f"bootstrap-app must depend on {required} healthy "
                "— Phase 2 (migrate, register operator, mint API + "
                "operator certs) requires the data tier up. Got "
                f"deps={deps}."
            )

    @pytest.mark.parametrize("name", ["api", "worker", "web"])
    def test_app_services_wait_for_bootstrap_app(
        self, services: dict, name: str
    ) -> None:
        deps = _depends_on(services[name])
        assert (
            deps.get("bootstrap-app") == "service_completed_successfully"
        ), (
            f"{name} must wait for bootstrap-app to complete — Phase 2 "
            "is the step that produces the API server cert + operator "
            f"cert + applied migrations the app tier needs. Got "
            f"deps={deps}."
        )


# ---------------------------------------------------------------------------
# Operator bootstrap env passed through
# ---------------------------------------------------------------------------


class TestBootstrapOperatorWiring:
    """bootstrap-app must receive the operator CN env so it can
    register + mint the operator's client cert."""

    def test_bootstrap_app_receives_operator_cn(
        self, services: dict
    ) -> None:
        env = services["bootstrap-app"].get("environment") or {}
        if isinstance(env, list):
            env = dict(e.split("=", 1) for e in env if "=" in e)
        cn = env.get("BOOTSTRAP_OPERATOR_CN", "")
        assert "BOOTSTRAP_OPERATOR_CN" in cn or "${BOOTSTRAP_OPERATOR_CN" in cn, (
            "bootstrap-app must read BOOTSTRAP_OPERATOR_CN from "
            "`.env.prod` so it knows which CN to register the operator "
            f"with and bind the CLI cert to. Got env={env!r}."
        )
