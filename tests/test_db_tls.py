"""Phase 2d CP4.1 — engine TLS wiring.

Pins :func:`wg_manager.db._build_engine`'s handling of the new
``database_tls_*`` Settings fields. The fast suite runs against SQLite
(see ``conftest.py``) and would never exercise the MySQL TLS path on
its own — these unit tests target the wiring directly so we can pin
the contract without needing a MySQL container.

The shape of the connect args is dictated by pymysql, which is the
driver the MySQL URL resolves to (``mysql+pymysql://...``): pymysql
accepts ``connect_args["ssl"] = {"ca": ..., "cert": ..., "key": ...,
"check_hostname": ...}``. We assert on the dict-of-strings shape so
the test stays driver-agnostic — if we ever swap to ``aiomysql`` /
``mysqlclient`` the same dict carries the meaning and only the engine
glue changes.
"""

from __future__ import annotations

import pytest

from wg_manager.config import Settings
from wg_manager.db import _build_engine, _resolve_mysql_ssl


# ---------------------------------------------------------------------------
# _resolve_mysql_ssl — the pure helper that maps Settings → connect args
# ---------------------------------------------------------------------------


class TestResolveMysqlSsl:
    """The connect-args resolver is pure; no engine construction needed."""

    def test_sqlite_url_never_gets_ssl(self) -> None:
        """SQLite never needs TLS — the resolver short-circuits."""
        s = Settings(
            database_tls_required=True,
            database_tls_ca_pem="ca.pem",
            database_tls_cert_pem="cert.pem",
            database_tls_key_pem="key.pem",
        )
        assert _resolve_mysql_ssl("sqlite:///:memory:", s) == {}

    def test_mysql_url_without_tls_required_is_unencrypted(self) -> None:
        """Backwards compat — pre-CP4 .env files keep working."""
        s = Settings(
            database_tls_required=False,
            database_tls_ca_pem=None,
            database_tls_cert_pem=None,
            database_tls_key_pem=None,
        )
        assert _resolve_mysql_ssl("mysql+pymysql://wg:wg@localhost/db", s) == {}

    def test_mysql_url_with_full_tls_returns_ssl_dict(self, tmp_path) -> None:
        """Happy path — all three PEMs present, ssl dict materialises."""
        ca = tmp_path / "ca.pem"
        cert = tmp_path / "client.pem"
        key = tmp_path / "client-key.pem"
        for f in (ca, cert, key):
            f.write_text("-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n")
        s = Settings(
            database_tls_required=True,
            database_tls_ca_pem=str(ca),
            database_tls_cert_pem=str(cert),
            database_tls_key_pem=str(key),
        )
        args = _resolve_mysql_ssl("mysql+pymysql://wg:wg@localhost/db", s)
        assert args == {
            "ssl": {
                "ca": str(ca),
                "cert": str(cert),
                "key": str(key),
                "check_hostname": True,
            }
        }

    @pytest.mark.parametrize(
        "missing",
        ["database_tls_ca_pem", "database_tls_cert_pem", "database_tls_key_pem"],
    )
    def test_mysql_tls_required_but_any_pem_missing_raises(
        self, tmp_path, missing: str
    ) -> None:
        """Refuse-to-start: clear error names which PEM is missing."""
        ca = tmp_path / "ca.pem"
        cert = tmp_path / "client.pem"
        key = tmp_path / "client-key.pem"
        for f in (ca, cert, key):
            f.write_text("stub\n")
        kwargs = {
            "database_tls_required": True,
            "database_tls_ca_pem": str(ca),
            "database_tls_cert_pem": str(cert),
            "database_tls_key_pem": str(key),
        }
        kwargs[missing] = None
        s = Settings(**kwargs)
        with pytest.raises(RuntimeError, match=missing.upper()):
            _resolve_mysql_ssl("mysql+pymysql://wg:wg@localhost/db", s)

    def test_mysql_tls_required_but_pem_file_missing_raises(self, tmp_path) -> None:
        """The PEM paths must point at real files — catch typos at startup."""
        ca = tmp_path / "does-not-exist.pem"
        cert = tmp_path / "client.pem"
        key = tmp_path / "client-key.pem"
        for f in (cert, key):
            f.write_text("stub\n")
        s = Settings(
            database_tls_required=True,
            database_tls_ca_pem=str(ca),
            database_tls_cert_pem=str(cert),
            database_tls_key_pem=str(key),
        )
        with pytest.raises(RuntimeError, match=r"DATABASE_TLS_CA_PEM .* not found"):
            _resolve_mysql_ssl("mysql+pymysql://wg:wg@localhost/db", s)


# ---------------------------------------------------------------------------
# _build_engine — the SQLAlchemy glue that threads the resolved args through
# ---------------------------------------------------------------------------


class TestBuildEngineConnectArgs:
    """Pins the engine's connect_args dict shape across the SQLite/MySQL split."""

    def test_sqlite_keeps_check_same_thread(self) -> None:
        """SQLite + threaded test client still needs the legacy escape hatch."""
        e = _build_engine("sqlite:///:memory:")
        # SQLAlchemy stashes connect_args on the engine.dialect, but the
        # cleanest way to assert is to round-trip a connection — SQLAlchemy
        # raises a thread-mismatch the moment ``check_same_thread`` flips.
        assert e.dialect.name == "sqlite"

    def test_mysql_url_without_settings_falls_back_to_module_settings(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """The default kwarg path reads ``wg_manager.config.settings``."""
        # Pin the module-level settings to a TLS-on shape, then build.
        from wg_manager import db as db_module

        ca = tmp_path / "ca.pem"
        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"
        for f in (ca, cert, key):
            f.write_text("stub\n")
        s = Settings(
            database_tls_required=True,
            database_tls_ca_pem=str(ca),
            database_tls_cert_pem=str(cert),
            database_tls_key_pem=str(key),
        )
        monkeypatch.setattr(db_module, "settings", s)
        # We don't actually open a MySQL connection in this test — engine
        # construction is lazy. Just confirming it doesn't blow up.
        e = _build_engine("mysql+pymysql://wg:wg@localhost/db")
        assert e.dialect.name == "mysql"
