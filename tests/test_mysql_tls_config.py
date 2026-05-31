"""Phase 2d CP4.2 — docker-compose + my.cnf MySQL TLS config.

These tests don't boot any containers — they parse the on-disk YAML
and ini files so the wiring is reviewable without standing up the
stack. The actual TLS round-trip against a real ``mysqld`` is the
acceptance suite's job in CP5.

What we pin here:

1. **my.cnf drop-in** — ``docker/mysql/conf.d/wg-manager-tls.cnf``
   exists, lives in the path the docker-compose mount points at, and
   carries the four MySQL TLS knobs (`require_secure_transport`,
   `ssl-ca`, `ssl-cert`, `ssl-key`).
2. **docker-compose** — the ``mysql`` service mounts the conf drop-in
   and the operator-supplied cert directory (``tls/mysql``) into the
   paths the my.cnf snippet references.
3. **Makefile** — the ``mysql-tls-issue`` target is the canonical
   entry point that mints the server cert into ``tls/mysql/``; pinning
   its shape in a test keeps the README walkthrough honest.
"""

from __future__ import annotations

import configparser
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
MYSQL_CONF_DIR = REPO_ROOT / "docker" / "mysql" / "conf.d"
MYSQL_TLS_CONF = MYSQL_CONF_DIR / "wg-manager-tls.cnf"
COMPOSE_PATH = REPO_ROOT / "docker-compose.yml"
MAKEFILE_PATH = REPO_ROOT / "Makefile"

# Where the my.cnf snippet expects the certs inside the container.
SERVER_CERT_INSIDE = "/etc/mysql/certs/server.crt"
SERVER_KEY_INSIDE = "/etc/mysql/certs/server.key"
SERVER_CA_INSIDE = "/etc/mysql/certs/ca.crt"
CONF_INSIDE = "/etc/mysql/conf.d"


class TestMyCnfDropIn:
    """The my.cnf snippet enforces TLS at the MySQL daemon level."""

    def test_drop_in_file_exists(self) -> None:
        assert MYSQL_TLS_CONF.exists(), (
            f"{MYSQL_TLS_CONF} must exist — CP4.2 ships the drop-in"
        )

    def test_drop_in_enforces_secure_transport(self) -> None:
        cp = configparser.ConfigParser()
        cp.read(MYSQL_TLS_CONF)
        assert cp.has_section("mysqld"), "my.cnf drop-in must use [mysqld]"
        # `require_secure_transport=ON` rejects unencrypted connections.
        # Accept the boolean-y forms MySQL recognises so the test isn't
        # over-strict on casing.
        value = cp["mysqld"].get("require_secure_transport", "").strip().upper()
        assert value in {"ON", "1", "TRUE"}, (
            f"require_secure_transport must be ON, got {value!r}"
        )

    def test_drop_in_points_at_mount_paths(self) -> None:
        cp = configparser.ConfigParser()
        cp.read(MYSQL_TLS_CONF)
        section = cp["mysqld"]
        assert section.get("ssl-ca", "").strip() == SERVER_CA_INSIDE
        assert section.get("ssl-cert", "").strip() == SERVER_CERT_INSIDE
        assert section.get("ssl-key", "").strip() == SERVER_KEY_INSIDE


class TestDockerComposeMounts:
    """``mysql`` service mounts the certs + conf drop-in."""

    def test_compose_parses(self) -> None:
        data = yaml.safe_load(COMPOSE_PATH.read_text())
        assert "services" in data
        assert "mysql" in data["services"]

    def test_mysql_service_mounts_certs_and_conf(self) -> None:
        data = yaml.safe_load(COMPOSE_PATH.read_text())
        volumes = data["services"]["mysql"].get("volumes", [])
        # Volumes are strings of the form ``host:container[:flag]``.
        # We grep for the *container* side of each mount so the host
        # path can move without breaking the test.
        mounts = [v.split(":", 1)[1] for v in volumes if ":" in v]
        # Cert dir mount (read-only).
        assert any(
            m.startswith("/etc/mysql/certs") for m in mounts
        ), f"mysql service must mount cert dir; got {volumes!r}"
        # Conf drop-in mount (read-only).
        assert any(
            m.startswith("/etc/mysql/conf.d") for m in mounts
        ), f"mysql service must mount conf.d; got {volumes!r}"

    def test_mysql_service_mounts_certs_read_only(self) -> None:
        """Cert mounts are ``:ro`` so a compromised container can't
        rewrite the server's own cert from inside."""
        data = yaml.safe_load(COMPOSE_PATH.read_text())
        volumes = data["services"]["mysql"].get("volumes", [])
        for v in volumes:
            parts = v.split(":")
            if len(parts) < 2:
                continue
            container = parts[1]
            if container.startswith("/etc/mysql/certs") or container.startswith(
                "/etc/mysql/conf.d"
            ):
                assert parts[-1] == "ro", (
                    f"mount {v!r} must be read-only (`:ro`)"
                )


class TestMakefileTarget:
    """``make mysql-tls-issue`` is the canonical bootstrap entry point."""

    def test_target_declared(self) -> None:
        body = MAKEFILE_PATH.read_text()
        assert "mysql-tls-issue:" in body, (
            "Makefile must declare the mysql-tls-issue target"
        )

    def test_target_writes_to_tls_mysql_dir(self) -> None:
        """The README walkthrough tells operators to mint into
        ``tls/mysql/`` so the docker-compose bind mount picks it up."""
        body = MAKEFILE_PATH.read_text()
        # The exact command is the README's job to spell out — we just
        # check the target body mints into the bind-mount source.
        # Find the block between ``mysql-tls-issue:`` and the next blank
        # line.
        in_block = False
        block_lines: list[str] = []
        for line in body.splitlines():
            if line.startswith("mysql-tls-issue:"):
                in_block = True
                continue
            if in_block:
                if line.strip() == "":
                    break
                block_lines.append(line)
        block_body = "\n".join(block_lines)
        assert "tls/mysql/" in block_body, (
            f"target body must write into tls/mysql/ — got:\n{block_body}"
        )
        assert "--type mysql" in block_body, (
            "target body must call `wg-manager certs issue --type mysql`"
        )
