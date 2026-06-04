"""Tests for the production-shaped docker-compose overlay.

``docker-compose.prod.yml`` is the operator's path from "dev stack
running on my laptop" to "single-host non-HA stack running on a real
box". It overlays the existing ``docker-compose.yml`` (so the dev file
stays untouched) and adds ``api``, ``worker``, and ``web`` services
plus the prod-shaped overrides on ``mysql`` / ``valkey`` / ``vault``.

These tests pin the **shape** of the overlay — pure YAML parse-and-
assert, matching the Phase 2f ``test_dockerfile.py`` and cycle 4a
``test_compose_ha_profile.py`` pattern. CI's image-build workflow is
the live compose validator; here we pin the source-of-truth shape so
a future edit that:

  * accidentally bakes a dev secret into the overlay
  * drops ``DATABASE_TLS_REQUIRED=true`` off the api service
  * forgets ``restart: always`` on a long-running service
  * removes one of the three Vault-backend pins (CRYPTO / SSH_CA / PKI)

trips a clear assertion at test time rather than at deploy time.

Documented limitations of the prod stack as shipped (not enforced by
these tests, but called out in ``docs/deploy/single-host-prod.md``):

  * **Vault runs in ``server -dev``.** The root token is
    operator-provided via ``.env.prod`` instead of the dev compose's
    hardcoded ``dev-only-root``, but data is still in-memory and lost
    on restart. A real production Vault (file/raft storage + manual
    unseal) lands when the Phase 2e Vault-production cycle ships.
  * **No reverse proxy / no Prometheus.** Non-HA single-host; the API
    binds 443 directly, the dashboard binds 3000 directly. Operators
    scrape ``/metrics`` from their existing observability stack.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
PROD_OVERLAY = REPO_ROOT / "docker-compose.prod.yml"


@pytest.fixture(scope="module")
def overlay_doc() -> dict:
    """Parsed overlay document or fail the suite.

    :return: The full ``docker-compose.prod.yml`` body.
    :rtype: dict
    """
    assert PROD_OVERLAY.is_file(), (
        f"{PROD_OVERLAY} is missing — the production-shaped overlay "
        "must ship so an operator has a single-host non-HA path."
    )
    return yaml.safe_load(PROD_OVERLAY.read_text())


@pytest.fixture(scope="module")
def services(overlay_doc: dict) -> dict:
    """The ``services:`` sub-tree."""
    svcs = overlay_doc.get("services", {})
    assert svcs, "docker-compose.prod.yml has no services key"
    return svcs


def _depends_on_keys(svc: dict) -> set[str]:
    """Normalise ``depends_on`` (list or dict) into a name set."""
    raw = svc.get("depends_on") or {}
    if isinstance(raw, list):
        return set(raw)
    return set(raw.keys())


def _env(svc: dict) -> dict[str, str]:
    """Normalise ``environment`` (list or dict) into a string→string map.

    Compose accepts ``environment`` as either ``KEY=VALUE`` list or as
    a dict. This helper collapses both to a dict so the assertions can
    be shape-agnostic.
    """
    raw = svc.get("environment") or {}
    if isinstance(raw, list):
        out: dict[str, str] = {}
        for entry in raw:
            if "=" in entry:
                k, v = entry.split("=", 1)
                out[k] = v
        return out
    return {k: str(v) for k, v in raw.items()}


# ---------------------------------------------------------------------------
# Top-level shape
# ---------------------------------------------------------------------------


class TestOverlayShape:
    """The overlay must be a valid YAML doc with a services tree and
    its own named volumes."""

    def test_overlay_file_exists(self) -> None:
        assert PROD_OVERLAY.is_file()

    def test_overlay_defines_volumes(self, overlay_doc: dict) -> None:
        # The overlay either reuses base-file volumes or adds its own
        # (for the dashboard's standalone bundle, the worker's task
        # results, etc.). At minimum we expect a `volumes:` key —
        # missing entirely usually means an unintentional override.
        assert "volumes" in overlay_doc, (
            "Production overlay must declare a `volumes:` block so an "
            "operator sees at a glance which named volumes carry "
            "stateful data they must back up."
        )


# ---------------------------------------------------------------------------
# New services: api, worker, web
# ---------------------------------------------------------------------------


class TestNewServicesPresent:
    """The overlay must add api, worker, and web on top of the base."""

    @pytest.mark.parametrize("service_name", ["api", "worker", "web"])
    def test_service_defined(self, services: dict, service_name: str) -> None:
        assert service_name in services, (
            f"Production overlay must define `{service_name}` — the "
            "single-host non-HA stack needs API + Celery worker + "
            "Next.js dashboard to be deployable as one unit."
        )


# ---------------------------------------------------------------------------
# Long-running services restart policy
# ---------------------------------------------------------------------------


class TestRestartPolicy:
    """Every long-running service must `restart: always` so the box
    coming up clean from boot brings the stack with it."""

    @pytest.mark.parametrize(
        "service_name",
        ["mysql", "valkey", "vault", "api", "worker", "web"],
    )
    def test_restart_always(
        self, services: dict, service_name: str
    ) -> None:
        svc = services.get(service_name, {})
        assert svc.get("restart") == "always", (
            f"{service_name} must declare `restart: always` in the "
            "prod overlay — `unless-stopped` (the dev default) leaves "
            "the stack down after a clean shutdown, which is wrong "
            "for an unattended box."
        )


# ---------------------------------------------------------------------------
# API service shape
# ---------------------------------------------------------------------------


class TestApiServiceShape:
    """The api service must run with the full Phase 2d hardening
    posture: mTLS, MySQL TLS, all Vault-backed secret pipelines."""

    def test_api_builds_or_pulls_wg_manager_image(self, services: dict) -> None:
        svc = services["api"]
        has_build = "build" in svc
        image_ref = str(svc.get("image", "")).lower()
        has_image = "wg-manager" in image_ref or "wg_manager" in image_ref
        assert has_build or has_image, (
            "api service must either build the repo Dockerfile or pull "
            "a published wg-manager image; got "
            f"build={svc.get('build')!r}, image={svc.get('image')!r}."
        )

    def test_api_depends_on_data_tier(self, services: dict) -> None:
        deps = _depends_on_keys(services["api"])
        required = {"mysql", "vault", "valkey"}
        missing = required - deps
        assert not missing, (
            f"api must depend on the full data tier; missing: {sorted(missing)}."
        )

    def test_api_pins_tls_required_true(self, services: dict) -> None:
        env = _env(services["api"])
        val = env.get("TLS_REQUIRED", "").lower()
        assert val == "true", (
            f"api must pin TLS_REQUIRED=true in prod; got {val!r}. "
            "The MTLSAuthMiddleware is what makes operator-cert-as-"
            "identity actually work; without this it's just HTTPS."
        )

    def test_api_pins_database_tls_required_true(
        self, services: dict
    ) -> None:
        env = _env(services["api"])
        val = env.get("DATABASE_TLS_REQUIRED", "").lower()
        assert val == "true", (
            f"api must pin DATABASE_TLS_REQUIRED=true in prod; got "
            f"{val!r}. Without this, pymysql talks cleartext to MySQL "
            "over the docker network — accepting that risk in dev is "
            "fine, but the prod overlay is the wrong place for it."
        )

    @pytest.mark.parametrize(
        "key,expected",
        [
            ("CRYPTO_BACKEND", "vault"),
            ("SSH_CA_BACKEND", "vault"),
            ("PKI_BACKEND", "vault"),
        ],
    )
    def test_api_pins_vault_backend(
        self, services: dict, key: str, expected: str
    ) -> None:
        env = _env(services["api"])
        val = env.get(key, "").lower()
        assert val == expected, (
            f"api must pin {key}={expected} in prod; got {val!r}. "
            "The LocalDev* backends are dev-only — the HA startup "
            "guards (Phase 3d cycle 1) reject `local` + "
            "TLS_REQUIRED=true without pinned PEMs anyway."
        )

    def test_api_uses_no_hardcoded_vault_root_token(
        self, services: dict
    ) -> None:
        env = _env(services["api"])
        # The dev compose hardcodes ``dev-only-root``. The prod overlay
        # must source the token from .env.prod via interpolation so
        # operators set a non-shareable value.
        token = env.get("VAULT_TOKEN", "")
        assert "dev-only-root" not in token, (
            "api VAULT_TOKEN must NOT be the dev-compose's hardcoded "
            "`dev-only-root` value in the prod overlay; reference an "
            "env var (e.g. ${VAULT_ROOT_TOKEN}) so each deploy picks "
            "its own."
        )
        assert "${" in token or "$" in token, (
            "api VAULT_TOKEN must be ${VAR}-interpolated in the prod "
            "overlay so operators can rotate without editing YAML."
        )


# ---------------------------------------------------------------------------
# Worker service shape
# ---------------------------------------------------------------------------


class TestWorkerServiceShape:
    """The worker is the same image as api with the celery CMD."""

    def test_worker_runs_celery(self, services: dict) -> None:
        svc = services["worker"]
        cmd = svc.get("command")
        # Compose accepts string or list form.
        if isinstance(cmd, list):
            cmd_str = " ".join(str(part) for part in cmd)
        else:
            cmd_str = str(cmd or "")
        assert "celery" in cmd_str, (
            f"worker command must invoke celery; got {cmd!r}. The "
            "Phase 2f Dockerfile defaults to `python -m wg_manager` "
            "which is the API entrypoint — the worker MUST override."
        )
        assert "wg_manager.celery_app" in cmd_str, (
            f"worker must point celery at wg_manager.celery_app; got {cmd!r}."
        )

    def test_worker_depends_on_data_tier(self, services: dict) -> None:
        deps = _depends_on_keys(services["worker"])
        required = {"mysql", "vault", "valkey"}
        missing = required - deps
        assert not missing, (
            f"worker must depend on the full data tier; missing: "
            f"{sorted(missing)}."
        )

    def test_worker_pins_vault_backends(self, services: dict) -> None:
        env = _env(services["worker"])
        for key in ("CRYPTO_BACKEND", "SSH_CA_BACKEND", "PKI_BACKEND"):
            val = env.get(key, "").lower()
            assert val == "vault", (
                f"worker must pin {key}=vault in prod; got {val!r}. "
                "Tasks call Vault for cert / lock-mint / decrypt — a "
                "worker on LocalDev* drifts from the api."
            )


# ---------------------------------------------------------------------------
# Web (dashboard) service shape
# ---------------------------------------------------------------------------


class TestWebServiceShape:
    """The web service runs the Next.js dashboard. Its BFF proxy talks
    to the api over mTLS using the four WG_MANAGER_API_* env vars
    documented in ``web/.env.example``."""

    def test_web_builds_or_pulls_web_image(self, services: dict) -> None:
        svc = services["web"]
        has_build = "build" in svc
        image_ref = str(svc.get("image", "")).lower()
        has_image = "wg-manager" in image_ref or "wg_manager" in image_ref
        assert has_build or has_image, (
            f"web service must either build web/Dockerfile or pull a "
            "published wg-manager-web image."
        )

    def test_web_depends_on_api(self, services: dict) -> None:
        deps = _depends_on_keys(services["web"])
        assert "api" in deps, (
            "web must depend on api so the dashboard doesn't start "
            "before the upstream is up. Compose's healthcheck-gated "
            "dependency makes the BFF proxy not race a not-ready API."
        )

    def test_web_points_proxy_at_api_service(self, services: dict) -> None:
        env = _env(services["web"])
        upstream = env.get("WG_MANAGER_API_UPSTREAM", "")
        # api:8000 is the compose-network DNS for the api service.
        assert "api:8000" in upstream, (
            f"web must point WG_MANAGER_API_UPSTREAM at api:8000 "
            f"(compose-network DNS); got {upstream!r}."
        )
        assert upstream.startswith("https://"), (
            "web's WG_MANAGER_API_UPSTREAM must be https — the api "
            "binds TLS in prod; plain http would 502."
        )

    @pytest.mark.parametrize(
        "key",
        [
            "WG_MANAGER_API_CLIENT_CERT",
            "WG_MANAGER_API_CLIENT_KEY",
            "WG_MANAGER_API_CA_BUNDLE",
        ],
    )
    def test_web_pins_mtls_paths(
        self, services: dict, key: str
    ) -> None:
        env = _env(services["web"])
        val = env.get(key, "")
        assert val, (
            f"web must set {key} in prod — the BFF proxy refuses to "
            "open the mTLS connection to the api without all three "
            "(cert / key / CA bundle)."
        )


# ---------------------------------------------------------------------------
# Data tier overrides
# ---------------------------------------------------------------------------


class TestDataTierOverrides:
    """The overlay must harden mysql / valkey / vault relative to the
    dev base file — no plaintext-default passwords, root token from
    env, vault volume mounts retained."""

    def test_mysql_root_password_from_env(self, services: dict) -> None:
        env = _env(services["mysql"])
        pw = env.get("MYSQL_ROOT_PASSWORD", "")
        # Dev compose pins `rootpw`. Prod MUST interpolate.
        assert pw != "rootpw", (
            "mysql MYSQL_ROOT_PASSWORD must not be the dev compose's "
            "hardcoded `rootpw` value in the prod overlay."
        )
        assert "${" in pw or "$" in pw, (
            "mysql MYSQL_ROOT_PASSWORD must be ${VAR}-interpolated in "
            "the prod overlay (sourced from .env.prod)."
        )

    def test_mysql_app_password_from_env(self, services: dict) -> None:
        env = _env(services["mysql"])
        pw = env.get("MYSQL_PASSWORD", "")
        assert pw != "wg", (
            "mysql MYSQL_PASSWORD must not be the dev compose's "
            "hardcoded `wg` value in the prod overlay."
        )
        assert "${" in pw or "$" in pw, (
            "mysql MYSQL_PASSWORD must be ${VAR}-interpolated in the "
            "prod overlay."
        )

    def test_valkey_requires_password(self, services: dict) -> None:
        cmd = services["valkey"].get("command", []) or []
        cmd_str = " ".join(str(c) for c in cmd) if isinstance(cmd, list) else str(cmd)
        # `--requirepass` is the valkey/redis cli flag that turns on
        # AUTH. The dev compose runs without auth; prod must enforce.
        assert "requirepass" in cmd_str, (
            "valkey command must include --requirepass in the prod "
            f"overlay so the broker isn't open to anything on the docker "
            f"network; got command={cmd!r}."
        )

    def test_vault_root_token_from_env(self, services: dict) -> None:
        env = _env(services["vault"])
        # `VAULT_DEV_ROOT_TOKEN_ID` is the dev-mode boot token.
        # `VAULT_TOKEN` is the CLI's auth env.
        for key in ("VAULT_DEV_ROOT_TOKEN_ID", "VAULT_TOKEN"):
            val = env.get(key, "")
            if not val:
                # The overlay may rely on the base service's env for one
                # of these; the assertion that matters is "no dev-only-
                # root anywhere in the merged file" — and the api
                # service-level test pins that side. Skip if absent.
                continue
            assert "dev-only-root" not in val, (
                f"vault {key} must NOT be the dev-compose's hardcoded "
                "`dev-only-root` value in the prod overlay."
            )

    def test_vault_keeps_audit_log_mount(self, services: dict) -> None:
        # The Phase 2e audit cycle 1 volume mount (the vector sidecar
        # tails this) must survive the prod overlay — losing it would
        # silently break Vault audit log shipping.
        volumes = services["vault"].get("volumes", []) or []
        joined = " ".join(str(v) for v in volumes)
        assert "/vault/logs" in joined, (
            "vault prod overlay must keep the /vault/logs mount so "
            "Vault's file audit device + the vector sidecar keep "
            f"working; got volumes={volumes!r}."
        )
