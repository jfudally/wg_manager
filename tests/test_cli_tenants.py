"""Tests for the Phase 3b cycle 2 ``wg-manager tenants`` +
``wg-manager operators tenants`` CLI subgroups.

Cycle 2 ships two operator-facing surfaces on top of the cycle 1
``Tenant`` row + the new ``OperatorTenant`` join:

* ``wg-manager tenants create / list / get`` — direct-DB CRUD on the
  ``Tenant`` table, mirroring the ``wg-manager operators add/list``
  shape Phase 2d CP3.3 established as the canonical bootstrap path.
* ``wg-manager operators attach-tenant / detach-tenant / list-tenants``
  — direct-DB CRUD on the ``OperatorTenant`` join. Closes the
  chicken-and-egg between "operator exists" and "operator can be
  reached via the HTTP /tenants surface".

The CLI is direct-DB (mirrors ``wg-manager db backup/restore`` and
``wg-manager certs issue``) so it works before the API listener has
even started — the same path an operator follows on a fresh install
to seed the default tenant's join rows before standing up TLS.

Tests pin:

1. **tenants create** — happy path, slug auto-derives from ``--name``
   if omitted, duplicate ``--slug`` rejected with a clear error.
2. **tenants list** — JSON array shape, includes the default tenant
   from Alembic 0014.
3. **tenants get** — by slug; unknown slug → exit 1.
4. **operators attach-tenant** — by operator CN + tenant slug + role;
   default role is ``operator``; duplicate attach exits non-zero with
   a readable error; unknown CN / unknown slug each exit non-zero
   with the lookup target named.
5. **operators detach-tenant** — removes the row; idempotent-shaped
   (unknown pair → exit 1 with a clear error).
6. **operators list-tenants** — JSON array of every join row for the
   target operator with the per-tenant role.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from sqlmodel import Session, select
from typer.testing import CliRunner

from wg_manager import cli
from wg_manager import db as db_module
from wg_manager.models import (
    Operator,
    OperatorRole,
    OperatorTenant,
    Tenant,
)


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def tenants_env(
    engine: Any,  # noqa: ARG001 — installs schema on db_module.engine
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wire ``cli._get_engine`` at the test engine + seed the default tenant.

    Mirrors the pattern ``test_cli_certs.py`` uses for the certs +
    operators CLI. The in-memory engine fixture runs SQLModel
    ``create_all`` so the tenant + operatortenant tables are present;
    seeding the default tenant matches what Alembic 0014 does at
    upgrade time.
    """
    monkeypatch.setattr(cli, "_get_engine", lambda url=None: db_module.engine)
    with Session(db_module.engine) as session:
        # Default tenant at id=1 — matches the Alembic 0014 seed and
        # the ROADMAP design.
        if not session.exec(select(Tenant).where(Tenant.id == 1)).first():
            session.add(Tenant(id=1, name="default", slug="default"))
            session.commit()


def _invoke(runner: CliRunner, *args: str) -> Any:
    return runner.invoke(cli.app, list(args))


def _insert_operator(
    cn: str, role: OperatorRole = OperatorRole.operator
) -> int:
    with Session(db_module.engine) as session:
        row = Operator(cn=cn, role=role)
        session.add(row)
        session.commit()
        session.refresh(row)
        return int(row.id or 0)


# ---------------------------------------------------------------------------
# tenants create / list / get
# ---------------------------------------------------------------------------


class TestTenantsCreate:
    def test_create_happy_path(
        self,
        runner: CliRunner,
        tenants_env: None,  # noqa: ARG002
    ) -> None:
        result = _invoke(
            runner,
            "tenants",
            "create",
            "--name",
            "Acme",
            "--slug",
            "acme",
        )
        assert result.exit_code == 0, result.output

        with Session(db_module.engine) as session:
            row = session.exec(
                select(Tenant).where(Tenant.slug == "acme")
            ).first()
        assert row is not None
        assert row.name == "Acme"
        assert row.slug == "acme"

    def test_create_derives_slug_from_name(
        self,
        runner: CliRunner,
        tenants_env: None,  # noqa: ARG002
    ) -> None:
        """If the operator omits ``--slug`` the CLI lowercases +
        kebab-cases ``--name`` so the happy path is a one-flag
        invocation."""
        result = _invoke(
            runner,
            "tenants",
            "create",
            "--name",
            "Hello World",
        )
        assert result.exit_code == 0, result.output

        with Session(db_module.engine) as session:
            row = session.exec(
                select(Tenant).where(Tenant.name == "Hello World")
            ).first()
        assert row is not None
        assert row.slug == "hello-world"

    def test_create_rejects_duplicate_slug(
        self,
        runner: CliRunner,
        tenants_env: None,  # noqa: ARG002
    ) -> None:
        """The default tenant ships at slug=``default``. A second
        attempt to claim that slug must fail with a readable error —
        not bubble a raw IntegrityError."""
        result = _invoke(
            runner,
            "tenants",
            "create",
            "--name",
            "Default Two",
            "--slug",
            "default",
        )
        assert result.exit_code != 0
        assert "default" in result.output


class TestTenantsList:
    def test_list_includes_default_tenant(
        self,
        runner: CliRunner,
        tenants_env: None,  # noqa: ARG002
    ) -> None:
        result = _invoke(runner, "tenants", "list")
        assert result.exit_code == 0, result.output
        parsed = json.loads(result.output)
        assert isinstance(parsed, list)
        slugs = {entry["slug"] for entry in parsed}
        assert "default" in slugs

    def test_list_includes_created_rows(
        self,
        runner: CliRunner,
        tenants_env: None,  # noqa: ARG002
    ) -> None:
        _invoke(
            runner,
            "tenants",
            "create",
            "--name",
            "Acme",
            "--slug",
            "acme",
        )
        result = _invoke(runner, "tenants", "list")
        assert result.exit_code == 0, result.output
        slugs = {entry["slug"] for entry in json.loads(result.output)}
        assert {"default", "acme"} <= slugs


class TestTenantsGet:
    def test_get_by_slug(
        self,
        runner: CliRunner,
        tenants_env: None,  # noqa: ARG002
    ) -> None:
        result = _invoke(runner, "tenants", "get", "default")
        assert result.exit_code == 0, result.output
        body = json.loads(result.output)
        assert body["slug"] == "default"
        assert body["id"] == 1

    def test_get_unknown_slug_fails(
        self,
        runner: CliRunner,
        tenants_env: None,  # noqa: ARG002
    ) -> None:
        result = _invoke(runner, "tenants", "get", "no-such-tenant")
        assert result.exit_code != 0
        assert "no-such-tenant" in result.output


# ---------------------------------------------------------------------------
# operators attach-tenant / detach-tenant / list-tenants
# ---------------------------------------------------------------------------


class TestOperatorsAttachTenant:
    def test_attach_happy_path(
        self,
        runner: CliRunner,
        tenants_env: None,  # noqa: ARG002
    ) -> None:
        op_id = _insert_operator("alice@wg.local", role=OperatorRole.admin)
        _invoke(
            runner,
            "tenants",
            "create",
            "--name",
            "Acme",
            "--slug",
            "acme",
        )

        result = _invoke(
            runner,
            "operators",
            "attach-tenant",
            "--cn",
            "alice@wg.local",
            "--tenant",
            "acme",
            "--role",
            "operator",
        )
        assert result.exit_code == 0, result.output

        with Session(db_module.engine) as session:
            tenant = session.exec(
                select(Tenant).where(Tenant.slug == "acme")
            ).first()
            assert tenant is not None
            join = session.exec(
                select(OperatorTenant).where(
                    OperatorTenant.operator_id == op_id,
                    OperatorTenant.tenant_id == tenant.id,
                )
            ).first()
        assert join is not None
        assert join.role == OperatorRole.operator

    def test_attach_defaults_role_to_operator(
        self,
        runner: CliRunner,
        tenants_env: None,  # noqa: ARG002
    ) -> None:
        """Principle of least privilege — ``--role`` defaults to
        ``operator``; admin must be set explicitly."""
        op_id = _insert_operator("bob@wg.local")
        result = _invoke(
            runner,
            "operators",
            "attach-tenant",
            "--cn",
            "bob@wg.local",
            "--tenant",
            "default",
        )
        assert result.exit_code == 0, result.output

        with Session(db_module.engine) as session:
            join = session.exec(
                select(OperatorTenant).where(
                    OperatorTenant.operator_id == op_id,
                    OperatorTenant.tenant_id == 1,
                )
            ).first()
        assert join is not None
        assert join.role == OperatorRole.operator

    def test_attach_unknown_cn_fails(
        self,
        runner: CliRunner,
        tenants_env: None,  # noqa: ARG002
    ) -> None:
        result = _invoke(
            runner,
            "operators",
            "attach-tenant",
            "--cn",
            "ghost@wg.local",
            "--tenant",
            "default",
        )
        assert result.exit_code != 0
        assert "ghost@wg.local" in result.output

    def test_attach_unknown_tenant_fails(
        self,
        runner: CliRunner,
        tenants_env: None,  # noqa: ARG002
    ) -> None:
        _insert_operator("alice@wg.local")
        result = _invoke(
            runner,
            "operators",
            "attach-tenant",
            "--cn",
            "alice@wg.local",
            "--tenant",
            "no-such-tenant",
        )
        assert result.exit_code != 0
        assert "no-such-tenant" in result.output

    def test_attach_duplicate_pair_fails(
        self,
        runner: CliRunner,
        tenants_env: None,  # noqa: ARG002
    ) -> None:
        _insert_operator("alice@wg.local")
        _invoke(
            runner,
            "operators",
            "attach-tenant",
            "--cn",
            "alice@wg.local",
            "--tenant",
            "default",
        )

        result = _invoke(
            runner,
            "operators",
            "attach-tenant",
            "--cn",
            "alice@wg.local",
            "--tenant",
            "default",
        )
        assert result.exit_code != 0
        # The error names both ends of the pair so the operator can
        # find them in their existing inventory.
        assert "alice@wg.local" in result.output
        assert "default" in result.output


class TestOperatorsDetachTenant:
    def test_detach_happy_path(
        self,
        runner: CliRunner,
        tenants_env: None,  # noqa: ARG002
    ) -> None:
        op_id = _insert_operator("alice@wg.local")
        _invoke(
            runner,
            "operators",
            "attach-tenant",
            "--cn",
            "alice@wg.local",
            "--tenant",
            "default",
        )

        result = _invoke(
            runner,
            "operators",
            "detach-tenant",
            "--cn",
            "alice@wg.local",
            "--tenant",
            "default",
        )
        assert result.exit_code == 0, result.output

        with Session(db_module.engine) as session:
            join = session.exec(
                select(OperatorTenant).where(
                    OperatorTenant.operator_id == op_id,
                    OperatorTenant.tenant_id == 1,
                )
            ).first()
        assert join is None

    def test_detach_unknown_pair_fails(
        self,
        runner: CliRunner,
        tenants_env: None,  # noqa: ARG002
    ) -> None:
        _insert_operator("alice@wg.local")
        result = _invoke(
            runner,
            "operators",
            "detach-tenant",
            "--cn",
            "alice@wg.local",
            "--tenant",
            "default",
        )
        assert result.exit_code != 0
        assert "alice@wg.local" in result.output


class TestOperatorsListTenants:
    def test_list_tenants_for_operator(
        self,
        runner: CliRunner,
        tenants_env: None,  # noqa: ARG002
    ) -> None:
        _insert_operator("alice@wg.local")
        _invoke(
            runner,
            "tenants",
            "create",
            "--name",
            "Acme",
            "--slug",
            "acme",
        )
        _invoke(
            runner,
            "operators",
            "attach-tenant",
            "--cn",
            "alice@wg.local",
            "--tenant",
            "default",
            "--role",
            "admin",
        )
        _invoke(
            runner,
            "operators",
            "attach-tenant",
            "--cn",
            "alice@wg.local",
            "--tenant",
            "acme",
            "--role",
            "auditor",
        )

        result = _invoke(
            runner,
            "operators",
            "list-tenants",
            "--cn",
            "alice@wg.local",
        )
        assert result.exit_code == 0, result.output
        parsed = json.loads(result.output)
        assert isinstance(parsed, list)
        by_slug = {entry["tenant_slug"]: entry for entry in parsed}
        assert by_slug["default"]["role"] == "admin"
        assert by_slug["acme"]["role"] == "auditor"

    def test_list_tenants_unknown_cn_fails(
        self,
        runner: CliRunner,
        tenants_env: None,  # noqa: ARG002
    ) -> None:
        result = _invoke(
            runner,
            "operators",
            "list-tenants",
            "--cn",
            "ghost@wg.local",
        )
        assert result.exit_code != 0
        assert "ghost@wg.local" in result.output
