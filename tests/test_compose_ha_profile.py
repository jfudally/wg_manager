"""Tests for Phase 3d cycle 4a — docker-compose ``ha`` profile.

Cycle 4a materialises the two-replica + LB topology from
``docs/deploy/ha-control-plane.md`` as a docker-compose profile so an
operator can run the HA shape end-to-end on one host. These tests pin
the **shape** of the profile: two API replica services + an nginx
TCP-passthrough LB, all gated behind ``profiles: ["ha"]`` so the
default ``docker compose up`` (dev) flow is untouched.

Pure YAML parse-and-assert — matches the ``tests/test_dockerfile.py``
pattern from Phase 2f. The tests do **not** shell out to
``docker compose``; CI's image-build workflow is the live compose
validator. Here we pin the source-of-truth shape so a future refactor
that drops a service, breaks the passthrough contract, or accidentally
unprofiles the data tier trips a clear test failure before merge.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"


@pytest.fixture(scope="module")
def compose_doc() -> dict:
    """Parsed top-level compose document.

    :return: The full ``docker-compose.yml`` body as a dict.
    :rtype: dict
    """
    assert COMPOSE_FILE.is_file(), f"{COMPOSE_FILE} missing"
    return yaml.safe_load(COMPOSE_FILE.read_text())


@pytest.fixture(scope="module")
def services(compose_doc: dict) -> dict:
    """The ``services:`` sub-tree, asserted non-empty.

    :return: Mapping of service name → service definition.
    :rtype: dict
    """
    svcs = compose_doc.get("services", {})
    assert svcs, "docker-compose.yml has no services key"
    return svcs


def _depends_on_keys(svc: dict) -> set[str]:
    """Normalise ``depends_on`` into a set of service names.

    Compose accepts ``depends_on`` as either a flat list of names or
    a dict mapping name → condition. This helper collapses both to a
    set so the assertion code can be shape-agnostic.

    :param svc: A compose service definition.
    :type svc: dict
    :return: The set of upstream service names this service depends on.
    :rtype: set[str]
    """
    raw = svc.get("depends_on") or {}
    if isinstance(raw, list):
        return set(raw)
    return set(raw.keys())


def _host_ports(svc: dict) -> set[str]:
    """Extract the host-side port numbers from a service's ``ports:`` list.

    Compose ``ports`` entries come in two shapes:
      * Short form string ``"127.0.0.1:8001:8000"`` or ``"8001:8000"``.
      * Long form dict ``{published: 8001, target: 8000, ...}``.

    :param svc: A compose service definition.
    :type svc: dict
    :return: Host-side ports as strings (so callers can compare without
        worrying about int/str mismatches).
    :rtype: set[str]
    """
    out: set[str] = set()
    for entry in svc.get("ports", []) or []:
        if isinstance(entry, str):
            # Drop optional host-IP prefix, then take the host port.
            parts = entry.split(":")
            if len(parts) == 3:
                out.add(parts[1])
            elif len(parts) == 2:
                out.add(parts[0])
        elif isinstance(entry, dict):
            published = entry.get("published")
            if published is not None:
                out.add(str(published))
    return out


# ---------------------------------------------------------------------------
# Service presence
# ---------------------------------------------------------------------------


class TestHaProfileServicesExist:
    """The cycle 4a ha profile adds exactly three services."""

    def test_api1_service_exists(self, services: dict) -> None:
        assert "api1" in services, (
            "Phase 3d cycle 4a must add an `api1` service — first of "
            "the two API replicas behind the LB."
        )

    def test_api2_service_exists(self, services: dict) -> None:
        assert "api2" in services, (
            "Phase 3d cycle 4a must add an `api2` service — second of "
            "the two API replicas behind the LB."
        )

    def test_lb_service_exists(self, services: dict) -> None:
        assert "lb" in services, (
            "Phase 3d cycle 4a must add an `lb` service — the nginx "
            "TCP-passthrough load balancer fronting api1 + api2."
        )


# ---------------------------------------------------------------------------
# Profile gating
# ---------------------------------------------------------------------------


class TestHaProfileGating:
    """All three new services must be gated behind ``profiles: ["ha"]``.

    The default ``docker compose up`` flow must remain "dev tier only"
    (mysql + valkey + vault + vector); the HA replicas + LB come up
    only under ``docker compose --profile ha up``.
    """

    @pytest.mark.parametrize("service_name", ["api1", "api2", "lb"])
    def test_service_carries_ha_profile(
        self, services: dict, service_name: str
    ) -> None:
        profiles = services[service_name].get("profiles", [])
        assert "ha" in profiles, (
            f"{service_name} must be gated behind profiles: ['ha'] so "
            "the default `docker compose up` (dev) flow doesn't drag "
            "in the HA replicas + LB."
        )

    @pytest.mark.parametrize(
        "service_name", ["mysql", "valkey", "vault", "vector"]
    )
    def test_data_tier_is_unprofiled(
        self, services: dict, service_name: str
    ) -> None:
        # The ha profile depends on the data tier; if the data tier
        # were profile-gated, `--profile ha up` would skip it. The
        # data tier must stay unprofiled so it comes up under both
        # the default flow AND the ha flow.
        profiles = services[service_name].get("profiles", [])
        assert not profiles, (
            f"{service_name} must NOT carry a profile — the ha "
            "profile's api1/api2 depend on the data tier and would "
            "skip its startup if it were profile-gated."
        )


# ---------------------------------------------------------------------------
# API replica shape
# ---------------------------------------------------------------------------


class TestApiReplicas:
    """api1 and api2 are mirror builds of the same wg-manager image."""

    @pytest.mark.parametrize("name", ["api1", "api2"])
    def test_api_uses_repo_dockerfile_or_published_image(
        self, services: dict, name: str
    ) -> None:
        svc = services[name]
        has_build = "build" in svc
        image_ref = str(svc.get("image", "")).lower()
        has_wg_image = "wg-manager" in image_ref or "wg_manager" in image_ref
        assert has_build or has_wg_image, (
            f"{name} must either build the repo Dockerfile or pull a "
            "published wg-manager image; got "
            f"build={svc.get('build')!r}, image={svc.get('image')!r}."
        )

    @pytest.mark.parametrize("name", ["api1", "api2"])
    def test_api_depends_on_data_tier(
        self, services: dict, name: str
    ) -> None:
        deps = _depends_on_keys(services[name])
        required = {"mysql", "vault", "valkey"}
        missing = required - deps
        assert not missing, (
            f"{name} must depend on mysql + vault + valkey so the data "
            f"tier is up before the replica starts; missing: {sorted(missing)}."
        )

    def test_replicas_publish_distinct_host_ports(
        self, services: dict
    ) -> None:
        # Distinct host ports let an operator curl each replica
        # directly when debugging which one served a request, on top of
        # the LB-fronted ingress port.
        p1 = _host_ports(services["api1"])
        p2 = _host_ports(services["api2"])
        assert p1, "api1 must publish at least one host port"
        assert p2, "api2 must publish at least one host port"
        assert p1.isdisjoint(p2), (
            "api1 and api2 must publish on distinct host ports so an "
            f"operator can curl each replica directly; got api1={p1}, "
            f"api2={p2}."
        )


# ---------------------------------------------------------------------------
# Load balancer shape
# ---------------------------------------------------------------------------


class TestLoadBalancer:
    """The lb service sits in front of the two replicas."""

    def test_lb_uses_nginx_image(self, services: dict) -> None:
        image = str(services["lb"].get("image", "")).lower()
        assert "nginx" in image, (
            f"lb service must use an nginx image; got {image!r}. The "
            "HA topology requires TLS passthrough, which nginx's "
            "`stream` module delivers in the OSS build."
        )

    def test_lb_depends_on_both_replicas(self, services: dict) -> None:
        deps = _depends_on_keys(services["lb"])
        missing = {"api1", "api2"} - deps
        assert not missing, (
            f"lb must depend on both api replicas so it doesn't start "
            "shovelling connections to a not-yet-up upstream; "
            f"missing: {sorted(missing)}."
        )

    def test_lb_mounts_nginx_config_read_only(self, services: dict) -> None:
        volumes = services["lb"].get("volumes", []) or []
        joined = " ".join(str(v) for v in volumes)
        assert "docker/nginx/wg-manager.conf" in joined, (
            "lb must bind-mount docker/nginx/wg-manager.conf into the "
            "container as its nginx config; not found in volumes."
        )
        # Defence in depth — a compromised LB shouldn't be able to
        # rewrite its own routing rules from inside the container.
        assert ":ro" in joined, (
            "lb's nginx config mount must be read-only (`:ro`) so a "
            "compromised LB can't rewrite its own routing rules."
        )

    def test_lb_publishes_ingress_port(self, services: dict) -> None:
        ports = _host_ports(services["lb"])
        assert ports, (
            "lb must publish at least one host ingress port — the "
            "single front door for operators talking to the HA cluster."
        )
