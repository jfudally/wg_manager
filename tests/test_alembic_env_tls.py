"""Regression tests for the alembic env.py MySQL TLS wiring.

``alembic/env.py`` used to build its engine via
``engine_from_config(...)`` without applying the same MySQL TLS
``connect_args`` that :func:`wg_manager.db._build_engine` injects.
The result: ``make migrate`` against a MySQL with
``require_secure_transport=ON`` failed with
``(3159, 'Connections using insecure transport are prohibited while
--require_secure_transport=ON.')`` — exactly the deployment shape
the prod compose overlay creates.

End-to-end verification on a clean docker host caught this; these
tests pin the fix so a future env.py refactor that drops the TLS
wiring trips at test time instead of at deploy time.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_ENV = REPO_ROOT / "alembic" / "env.py"


@pytest.fixture(scope="module")
def env_body() -> str:
    """Read alembic/env.py or fail the suite."""
    assert ALEMBIC_ENV.is_file(), f"{ALEMBIC_ENV} is missing"
    return ALEMBIC_ENV.read_text()


class TestEnvImportsTlsResolver:
    """env.py must import the TLS connect-args resolver from
    ``wg_manager.db`` so its engine inherits the same TLS posture as
    the app + worker."""

    def test_imports_resolve_mysql_ssl(self, env_body: str) -> None:
        # The function lives in ``wg_manager.db`` (Phase 2d CP4.1).
        # Either a direct ``from wg_manager.db import _resolve_mysql_ssl``
        # or a re-export via ``wg_manager.db._build_engine`` (which
        # internally calls it) is acceptable. The grep is permissive on
        # which path is used; both produce the same final shape.
        has_resolve = "_resolve_mysql_ssl" in env_body
        has_build_engine = "_build_engine" in env_body
        assert has_resolve or has_build_engine, (
            "alembic/env.py must import _resolve_mysql_ssl or "
            "_build_engine from wg_manager.db so the migrations "
            "engine respects DATABASE_TLS_REQUIRED. Without this, "
            "`make migrate` against a TLS-required MySQL fails with "
            "'Connections using insecure transport are prohibited'."
        )


class TestEnvAppliesConnectArgs:
    """env.py's online-mode engine builder must pass MySQL TLS
    ``connect_args`` (when TLS is required) so pymysql opens the
    connection with the operator's client cert."""

    def test_engine_factory_receives_connect_args(
        self, env_body: str
    ) -> None:
        # Either:
        #   (a) engine_from_config(..., connect_args=...)
        #   (b) _build_engine(...)
        # is acceptable. The bug shape is the bare
        # ``engine_from_config(config_section, prefix=...)`` with no
        # connect_args.
        has_connect_args = bool(
            re.search(r"engine_from_config\([^)]*connect_args", env_body, re.S)
        )
        has_build_engine = "_build_engine" in env_body
        assert has_connect_args or has_build_engine, (
            "alembic/env.py's online-mode engine must apply MySQL "
            "TLS connect_args (or delegate to wg_manager.db."
            "_build_engine which does so). The bare "
            "`engine_from_config(section, prefix='sqlalchemy.')` form "
            "drops TLS wiring on the floor."
        )

    def test_no_bare_engine_from_config_in_online_path(
        self, env_body: str
    ) -> None:
        # The function ``run_migrations_online`` is where the engine
        # gets built. Find its body and ensure no naked
        # ``engine_from_config(`` call remains.
        match = re.search(
            r"def run_migrations_online\(\) -> None:.*?(?=\n(?:def |if __|$))",
            env_body,
            re.S,
        )
        assert match, (
            "Could not locate run_migrations_online body in env.py"
        )
        body = match.group(0)
        # If engine_from_config is still used, it must have connect_args
        # on the same call. Use balanced-paren matching to extract the
        # full argument list (nested parens from config.get_section(...)
        # otherwise truncate the search).
        for call in re.finditer(r"engine_from_config\(", body):
            depth = 1
            i = call.end()
            while i < len(body) and depth > 0:
                if body[i] == "(":
                    depth += 1
                elif body[i] == ")":
                    depth -= 1
                i += 1
            assert depth == 0, "unbalanced parens in env.py"
            call_args = body[call.end():i - 1]
            assert "connect_args" in call_args, (
                "run_migrations_online uses engine_from_config without "
                "connect_args= — that drops MySQL TLS wiring and "
                "breaks `make migrate` on the prod stack."
            )
