"""Phase 3f spike — enrollment-only listener beside the mTLS operator API.

Pins the spike's riskiest assumption from ``ROADMAP.md`` Phase 3f:

* The operator listener (``CERT_REQUIRED``) refuses a client that
  presents no certificate — at the TLS layer, over a real socket.
* The enrollment listener, built from the same server cert, accepts
  that same cert-less client.
* The enrollment app exposes **only** the health probes and the
  enrollment route. Every operator route on the main app 404s on
  the enrollment app, so the cert-optional handshake can't be used
  to reach the operator surface.

The real-socket cases run uvicorn in a background thread on an
ephemeral loopback port with certs minted by :class:`LocalDevPKI`, so
the handshake behaviour is exercised end to end rather than mocked.
"""

from __future__ import annotations

import http.client
import re
import socket
import ssl
import threading
import time
from collections.abc import Generator, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from fastapi import FastAPI
from fastapi.testclient import TestClient

from wg_manager.config import Settings
from wg_manager.enroll_app import ENROLL_PATH, create_enroll_app
from wg_manager.main import create_app
from wg_manager.pki import LocalDevPKI
from wg_manager.routers.health import HEALTH_PATHS
from wg_manager.tls_listeners import api_ssl_kwargs, enroll_ssl_kwargs

# ---------------------------------------------------------------------------
# Route-surface tests (no sockets)
# ---------------------------------------------------------------------------


def _operator_route_samples() -> list[tuple[str, str]]:
    """Return one ``(method, concrete_path)`` per operator route.

    Built from the live main app's OpenAPI schema so a router added
    later is covered automatically. The schema is used rather than
    ``app.routes`` because newer FastAPI nests included routers behind
    a private ``_IncludedRouter`` type. Path parameters are filled with
    ``1``: the goal is to prove the route doesn't *exist* on the enroll
    app, so any well-formed value works.
    """
    samples: list[tuple[str, str]] = []
    for path, ops in create_app().openapi()["paths"].items():
        if path in HEALTH_PATHS:
            continue
        concrete = re.sub(r"\{[^}]+\}", "1", path)
        for method in sorted(ops):
            samples.append((method.upper(), concrete))
    return samples


class TestEnrollAppSurface:
    """The enrollment app is an allow-list, not the operator app."""

    @pytest.fixture()
    def enroll_client(self) -> TestClient:
        return TestClient(create_enroll_app())

    def test_healthz_answers(self, enroll_client: TestClient) -> None:
        assert enroll_client.get("/v1/healthz").status_code == 200

    def test_enroll_route_is_mounted_as_a_stub(
        self, enroll_client: TestClient
    ) -> None:
        """The spike ships the route shape only; the MVP implements it."""
        assert enroll_client.post(ENROLL_PATH, json={}).status_code == 501

    def test_operator_sample_set_is_non_trivial(self) -> None:
        """Guard: a broken sampler must not make the next test vacuous."""
        paths = {p for _, p in _operator_route_samples()}
        assert "/v1/clients/manual" in paths
        assert "/v1/servers" in paths

    @pytest.mark.parametrize(("method", "path"), _operator_route_samples())
    def test_every_operator_route_is_absent(
        self, enroll_client: TestClient, method: str, path: str
    ) -> None:
        resp = enroll_client.request(method, path)
        assert resp.status_code == 404, f"{method} {path} leaked onto enroll app"

    def test_no_openapi_docs(self, enroll_client: TestClient) -> None:
        """No schema browsing on the public listener."""
        for path in ("/docs", "/redoc", "/openapi.json"):
            assert enroll_client.get(path).status_code == 404


# ---------------------------------------------------------------------------
# Real-socket handshake tests
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def tls_material(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    """Mint a server cert, a client cert and the CA bundle; write them to disk."""
    pki = LocalDevPKI.generate()
    cert = pki.issue_server_cert(
        common_name="127.0.0.1", sans=["127.0.0.1"], ttl_seconds=3600
    )
    d = tmp_path_factory.mktemp("tls")
    paths = {
        "cert": d / "server.crt",
        "key": d / "server.key",
        "ca": d / "ca-bundle.crt",
        "client_cert": d / "client.crt",
        "client_key": d / "client.key",
    }
    client = pki.issue_client_cert(
        common_name="spike-operator", sans=[], ttl_seconds=3600
    )
    paths["client_cert"].write_text(client.cert_pem + client.chain_pem)
    paths["client_key"].write_text(client.private_pem)
    paths["cert"].write_text(cert.cert_pem + cert.chain_pem)
    paths["key"].write_text(cert.private_pem)
    paths["ca"].write_text(pki.ca_bundle_pem)
    return paths


def _settings_for(tls: dict[str, Path]) -> Settings:
    return Settings(
        tls_required=True,
        tls_cert_pem=str(tls["cert"]),
        tls_key_pem=str(tls["key"]),
        tls_ca_bundle_pem=str(tls["ca"]),
    )


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@contextmanager
def _serve(app: FastAPI, ssl_kwargs: dict[str, Any]) -> Iterator[int]:
    """Run ``app`` under uvicorn with ``ssl_kwargs`` in a thread; yield port."""
    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(
            app, host="127.0.0.1", port=port, log_level="warning", **ssl_kwargs
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        if time.monotonic() > deadline:
            raise RuntimeError("uvicorn did not start within 10s")
        time.sleep(0.05)
    try:
        yield port
    finally:
        server.should_exit = True
        thread.join(timeout=10)


def _get(
    port: int,
    ca: Path,
    path: str,
    client_cert: tuple[Path, Path] | None = None,
) -> int:
    """GET ``path`` over TLS and return the HTTP status.

    :param client_cert: ``(cert, key)`` to present, or ``None`` to
        connect with no client certificate.
    """
    ctx = ssl.create_default_context(cafile=str(ca))
    # Python 3.13 turns on VERIFY_X509_STRICT, which rejects LocalDevPKI
    # leaves (no Authority Key Identifier). Vault-issued certs carry
    # one; the handshake policy under test doesn't depend on it.
    ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    if client_cert is not None:
        ctx.load_cert_chain(str(client_cert[0]), str(client_cert[1]))
    conn = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=5)
    try:
        conn.request("GET", path)
        return conn.getresponse().status
    finally:
        conn.close()


@pytest.fixture()
def health_only_app() -> Generator[FastAPI, None, None]:
    """Minimal app for the operator listener: isolates the TLS config
    under test from the main app's DB / Vault dependencies."""
    app = FastAPI()

    @app.get("/v1/healthz")
    def _h() -> dict[str, str]:
        return {"status": "ok"}

    yield app


class TestHandshakePolicy:
    """Same server cert, two listeners, two client-cert policies."""

    def test_operator_listener_refuses_certless_client(
        self, tls_material: dict[str, Path], health_only_app: FastAPI
    ) -> None:
        kwargs = api_ssl_kwargs(_settings_for(tls_material))
        with _serve(health_only_app, kwargs) as port:
            # TLS 1.3 sends the missing-cert alert after the client's
            # handshake completes, so it surfaces on the request as a
            # dropped connection (or an SSL alert), not on connect().
            with pytest.raises((ssl.SSLError, ConnectionResetError)) as exc:
                _get(port, tls_material["ca"], "/v1/healthz")
        # The client-side server-cert check must have passed; otherwise
        # this test would be proving nothing about client certs.
        assert not isinstance(exc.value, ssl.SSLCertVerificationError)

    def test_operator_listener_accepts_valid_client_cert(
        self, tls_material: dict[str, Path], health_only_app: FastAPI
    ) -> None:
        """Positive control: the refusal above is about the missing cert."""
        kwargs = api_ssl_kwargs(_settings_for(tls_material))
        with _serve(health_only_app, kwargs) as port:
            status = _get(
                port,
                tls_material["ca"],
                "/v1/healthz",
                client_cert=(tls_material["client_cert"], tls_material["client_key"]),
            )
        assert status == 200

    def test_enroll_listener_accepts_certless_client(
        self, tls_material: dict[str, Path]
    ) -> None:
        kwargs = enroll_ssl_kwargs(_settings_for(tls_material))
        with _serve(create_enroll_app(), kwargs) as port:
            status = _get(
                port, tls_material["ca"], "/v1/healthz"
            )
        assert status == 200

    def test_enroll_listener_still_hides_operator_routes(
        self, tls_material: dict[str, Path]
    ) -> None:
        kwargs = enroll_ssl_kwargs(_settings_for(tls_material))
        with _serve(create_enroll_app(), kwargs) as port:
            status = _get(
                port, tls_material["ca"], "/v1/clients"
            )
        assert status == 404


class TestSslKwargs:
    """The kwargs builders encode each listener's policy explicitly."""

    def test_api_requires_client_cert_when_tls_required(self) -> None:
        s = Settings(
            tls_required=True, tls_cert_pem="c", tls_key_pem="k",
            tls_ca_bundle_pem="ca",
        )
        kw = api_ssl_kwargs(s)
        assert kw["ssl_cert_reqs"] == ssl.CERT_REQUIRED
        assert kw["ssl_ca_certs"] == "ca"

    def test_api_optional_client_cert_when_tls_not_required(self) -> None:
        s = Settings(
            tls_required=False, tls_cert_pem="c", tls_key_pem="k",
            tls_ca_bundle_pem="ca",
        )
        assert api_ssl_kwargs(s)["ssl_cert_reqs"] == ssl.CERT_OPTIONAL

    def test_enroll_never_requests_client_cert(self) -> None:
        """Even under TLS_REQUIRED, and with no CA bundle loaded, so the
        server doesn't advertise acceptable client-cert issuers."""
        s = Settings(
            tls_required=True, tls_cert_pem="c", tls_key_pem="k",
            tls_ca_bundle_pem="ca",
        )
        kw = enroll_ssl_kwargs(s)
        assert kw["ssl_cert_reqs"] == ssl.CERT_NONE
        assert "ssl_ca_certs" not in kw
        assert kw["ssl_certfile"] == "c"
        assert kw["ssl_keyfile"] == "k"


# ---------------------------------------------------------------------------
# Runner entrypoint (``python -m wg_manager.enroll_listener``)
# ---------------------------------------------------------------------------


class TestEnrollRunner:
    """The runner refuses to start without TLS and binds its own port."""

    def test_defaults_bind_loopback_on_8001(self) -> None:
        s = Settings()
        assert s.enroll_bind_host == "127.0.0.1"
        assert s.enroll_bind_port == 8001

    def test_refuses_without_server_cert(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from wg_manager import enroll_listener

        called: list[Any] = []
        monkeypatch.setattr(enroll_listener.uvicorn, "run", called.append)
        rc = enroll_listener.main(Settings(tls_cert_pem=None, tls_key_pem="k"))
        assert rc == 2
        assert called == []

    def test_runs_enroll_app_with_enroll_policy(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from wg_manager import enroll_listener

        captured: dict[str, Any] = {}

        def fake_run(app: Any, **kwargs: Any) -> None:
            captured["app"] = app
            captured.update(kwargs)

        monkeypatch.setattr(enroll_listener.uvicorn, "run", fake_run)
        s = Settings(
            tls_required=True, tls_cert_pem="c", tls_key_pem="k",
            tls_ca_bundle_pem="ca", enroll_bind_host="0.0.0.0",
            enroll_bind_port=9443,
        )
        assert enroll_listener.main(s) == 0
        assert captured["app"] == "wg_manager.enroll_app:create_enroll_app"
        assert captured["factory"] is True
        assert captured["host"] == "0.0.0.0"
        assert captured["port"] == 9443
        assert captured["ssl_cert_reqs"] == ssl.CERT_NONE
        assert "ssl_ca_certs" not in captured
