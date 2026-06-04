"""Tests for Phase 3d cycle 4a — nginx LB config (TCP passthrough).

The HA control plane requires **TLS passthrough** at the LB so the
mTLS handshake lands on the wg-manager replica intact — terminating
TLS at the LB would force wg-manager to trust whatever subject the
LB inserted, undermining Phase 2d's "operator cert == operator
identity" contract.

nginx's ``stream`` module (OSS build) delivers L4 passthrough; the
``http`` module would terminate TLS. These tests pin the config
shape so a future edit that accidentally swaps ``stream`` for
``http``, or adds ``proxy_pass https://...``, trips immediately.

Active HTTPS ``/readyz`` probing from nginx OSS isn't possible against
an mTLS upstream without nginx-plus; cycle 4a's passive checks
(``max_fails`` + ``fail_timeout``) take a flapping replica out of
rotation after a few connect failures, which is sufficient for the
local-dev demo. The cycle 4 follow-on can swap in an active probe
sidecar if production demand surfaces.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
NGINX_CONF = REPO_ROOT / "docker" / "nginx" / "wg-manager.conf"


@pytest.fixture(scope="module")
def conf_body() -> str:
    """Read the nginx LB config or fail the suite.

    :return: The full config file body as a string.
    :rtype: str
    """
    assert NGINX_CONF.is_file(), (
        f"{NGINX_CONF} is missing — Phase 3d cycle 4a ships the nginx "
        "LB config that the docker-compose ha profile bind-mounts into "
        "the lb container."
    )
    return NGINX_CONF.read_text()


# ---------------------------------------------------------------------------
# Passthrough invariant
# ---------------------------------------------------------------------------


class TestStreamBlock:
    """The config must use stream{} so TLS handshakes pass through."""

    def test_has_stream_block(self, conf_body: str) -> None:
        # `stream { ... }` enables L4 TCP passthrough. Without it,
        # nginx defaults to L7 http handling which would terminate TLS.
        assert re.search(r"\bstream\s*\{", conf_body), (
            "nginx LB config must contain a `stream {}` block — TCP "
            "passthrough is the only OSS-buildable way to honour the "
            "HA doc's 'no TLS termination at LB' invariant. http {} "
            "would force the LB to terminate TLS, breaking Phase 2d's "
            "operator-cert-as-identity contract."
        )

    def test_no_https_proxy_pass(self, conf_body: str) -> None:
        # Stream-mode proxy_pass takes a bare upstream name (no scheme).
        # `proxy_pass https://...` is the http{} shape and would
        # terminate TLS at the LB.
        assert not re.search(r"proxy_pass\s+https?://", conf_body), (
            "nginx LB config must use stream-mode proxy_pass (no "
            "URL scheme); `proxy_pass https://...` would terminate "
            "TLS at the LB, which the HA topology forbids."
        )


# ---------------------------------------------------------------------------
# Upstream wiring
# ---------------------------------------------------------------------------


class TestUpstreams:
    """The upstream must reference both api1 and api2 with passive
    health-check params."""

    def test_references_api1(self, conf_body: str) -> None:
        # api1 is reachable on the compose network at hostname
        # `api1` port 8000 (the container's BIND_PORT).
        assert "api1:8000" in conf_body, (
            "nginx LB config must include `api1:8000` as an upstream "
            "— the first replica in the ha-profile pair."
        )

    def test_references_api2(self, conf_body: str) -> None:
        assert "api2:8000" in conf_body, (
            "nginx LB config must include `api2:8000` as an upstream "
            "— the second replica in the ha-profile pair."
        )

    def test_has_max_fails(self, conf_body: str) -> None:
        # OSS nginx stream module supports only passive checks. Without
        # max_fails, a down replica would receive traffic forever.
        assert re.search(r"max_fails\s*=\s*\d+", conf_body), (
            "nginx LB config must declare `max_fails=N` on upstream "
            "servers so a down replica is taken out of rotation after "
            "N connect failures."
        )

    def test_has_fail_timeout(self, conf_body: str) -> None:
        assert re.search(r"fail_timeout\s*=\s*\d+\w*", conf_body), (
            "nginx LB config must declare `fail_timeout=Ns` on "
            "upstream servers so a flapping replica isn't permanently "
            "excluded — after fail_timeout, nginx re-tries the server."
        )


# ---------------------------------------------------------------------------
# Ingress listener
# ---------------------------------------------------------------------------


class TestIngressListener:
    """The LB must listen on the host-exposed ingress port."""

    def test_listens_on_8443(self, conf_body: str) -> None:
        # 8443 is the canonical https-alt port; the compose host port
        # mapping (127.0.0.1:8443 → 8443) lines up with this listener.
        # If this number ever changes, docker-compose.yml's `lb.ports`
        # entry must change in lockstep — pin them together.
        assert re.search(r"\blisten\s+8443\b", conf_body), (
            "nginx LB config must `listen 8443;` so the compose host "
            "port mapping (127.0.0.1:8443 → container 8443) reaches "
            "the right listener."
        )
