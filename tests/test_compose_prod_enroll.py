"""Shape tests for the Phase 3f ``enroll`` service in docker-compose.prod.yml.

The enrollment listener is a second process from the same image. It
accepts TLS clients without a client cert, so these tests check:

* it's **opt-in** (compose profile ``enroll``): upgrading an existing
  deployment must not open a new public port by itself,
* it runs the enrollment runner, not the operator API,
* it reuses the worker's environment (DB, broker, Vault SSH CA) and
  the API's server cert, and binds its own port,
* its healthcheck presents **no** client cert, which is the point of
  the separate listener.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from tests.test_compose_prod_overlay import _ComposeLoader, _depends_on_keys, _env

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def services() -> dict:
    doc = yaml.load(
        (REPO_ROOT / "docker-compose.prod.yml").read_text(), Loader=_ComposeLoader
    )
    return doc["services"]


@pytest.fixture(scope="module")
def enroll(services: dict) -> dict:
    assert "enroll" in services, "docker-compose.prod.yml has no enroll service"
    return services["enroll"]


def test_is_opt_in_via_profile(enroll: dict) -> None:
    assert enroll.get("profiles") == ["enroll"]


def test_runs_enrollment_runner(enroll: dict) -> None:
    assert enroll["command"] == ["python", "-m", "wg_manager.enroll_listener"]


def test_uses_wg_manager_image(enroll: dict) -> None:
    assert enroll["image"] == "${WG_MANAGER_IMAGE:-wg-manager:prod}"


def test_restart_always(enroll: dict) -> None:
    assert enroll["restart"] == "always"


def test_shares_worker_environment(services: dict, enroll: dict) -> None:
    """DB, broker and Vault settings must match the worker exactly."""
    env = _env(enroll)
    for key, value in _env(services["worker"]).items():
        assert env.get(key) == value, key


def test_serves_api_server_cert_and_binds_all_interfaces(enroll: dict) -> None:
    env = _env(enroll)
    assert env["TLS_CERT_PEM"] == "/app/tls/server.crt"
    assert env["TLS_KEY_PEM"] == "/app/tls/server.key"
    assert env["ENROLL_BIND_HOST"] == "0.0.0.0"
    assert env["ENROLL_BIND_PORT"] == "8001"


def test_publishes_its_own_port(enroll: dict) -> None:
    assert enroll["ports"] == [
        "${WG_MANAGER_ENROLL_BIND_ADDR:-0.0.0.0}:${WG_MANAGER_ENROLL_BIND_PORT:-8443}:8001"
    ]


def test_depends_on_bootstrap_and_data_tier(enroll: dict) -> None:
    assert {"bootstrap-app", "mysql", "vault", "valkey"} <= _depends_on_keys(enroll)


def test_healthcheck_presents_no_client_cert(enroll: dict) -> None:
    probe = " ".join(enroll["healthcheck"]["test"])
    assert "https://localhost:8001/healthz" in probe
    assert "load_cert_chain" not in probe


def test_env_example_documents_opt_in() -> None:
    body = (REPO_ROOT / ".env.prod.example").read_text()
    assert "COMPOSE_PROFILES=enroll" in body
    assert "WG_MANAGER_ENROLL_BIND_PORT" in body
