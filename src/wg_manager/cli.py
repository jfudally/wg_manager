"""Command-line interface for the wg-manager control plane.

Most commands are thin HTTP wrappers over the FastAPI app. The ``db``
subgroup (backup / restore) operates **directly** on the database via
SQLModel so it works even when the API server is not running — ideal for
cross-host migrations.

The target API is configured via ``--api-url`` or the
``WG_MANAGER_API_URL`` environment variable (default ``http://127.0.0.1:8000``).
Most provisioning commands accept ``--wait``, which polls ``/tasks/{id}``
until the Celery task reaches a terminal state.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

import httpx
import typer
from sqlmodel import select

DEFAULT_API_URL = "http://127.0.0.1:8000"

app = typer.Typer(
    help="wg-manager CLI — manage WireGuard nodes via the control-plane API.",
    no_args_is_help=True,
)
keys_app = typer.Typer(help="Manage SSH credentials.", no_args_is_help=True)
servers_app = typer.Typer(help="Manage WireGuard hub servers.", no_args_is_help=True)
clients_app = typer.Typer(help="Manage WireGuard spoke clients.", no_args_is_help=True)
tasks_app = typer.Typer(help="Inspect async provisioning tasks.", no_args_is_help=True)
db_app = typer.Typer(help="Database backup and restore.", no_args_is_help=True)
crypto_app = typer.Typer(
    help="Encryption-at-rest backfills and key rotation.",
    no_args_is_help=True,
)
certs_app = typer.Typer(
    help="Issue, revoke, and list X.509 leaf certificates (Phase 2d CP3.3).",
    no_args_is_help=True,
)
operators_app = typer.Typer(
    help=(
        "Manage the API caller registry (Phase 2d CP3). The dashboard "
        "/ HTTP CRUD lands in CP3.4; this CLI is the direct-DB "
        "bootstrap glue that pairs with `wg-manager certs issue`."
    ),
    no_args_is_help=True,
)
app.add_typer(keys_app, name="keys")
app.add_typer(servers_app, name="servers")
app.add_typer(clients_app, name="clients")
app.add_typer(tasks_app, name="tasks")
app.add_typer(db_app, name="db")
app.add_typer(crypto_app, name="crypto")
app.add_typer(certs_app, name="certs")
app.add_typer(operators_app, name="operators")


def _make_http_client(api_url: str) -> httpx.Client:
    """Build an :class:`httpx.Client` pinned to the target API.

    Tests monkeypatch this function to route requests at an ASGI transport
    backed by the FastAPI app instead of hitting a real network socket.
    """
    return httpx.Client(base_url=api_url, timeout=30.0)


@app.callback()
def _main(
    ctx: typer.Context,
    api_url: str = typer.Option(
        DEFAULT_API_URL,
        "--api-url",
        envvar="WG_MANAGER_API_URL",
        help="Base URL of the wg-manager API.",
    ),
) -> None:
    """Root callback — stashes the resolved API URL on the Typer context."""
    ctx.ensure_object(dict)
    ctx.obj["api_url"] = api_url


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _client(ctx: typer.Context) -> httpx.Client:
    return _make_http_client(ctx.obj["api_url"])


def _print_json(data: Any) -> None:
    typer.echo(json.dumps(data, indent=2, default=str, sort_keys=True))


def _handle(resp: httpx.Response) -> Any:
    """Raise a CLI-friendly error on non-2xx, otherwise return decoded body."""
    if resp.status_code >= 400:
        detail: Any
        try:
            detail = resp.json().get("detail", resp.text)
        except ValueError:
            detail = resp.text
        typer.secho(
            f"[error {resp.status_code}] {detail}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1)
    if resp.status_code == 204 or not resp.content:
        return None
    return resp.json()


_TERMINAL_STATES = {"SUCCESS", "FAILURE", "REVOKED"}


def _wait_task(
    http: httpx.Client,
    task_id: str,
    timeout: float,
    interval: float,
) -> dict[str, Any]:
    """Poll ``/tasks/{task_id}`` until it reaches a terminal state.

    :param http: An already-open HTTP client against the wg-manager API.
    :param task_id: Celery task ID to poll.
    :param timeout: Abort after this many seconds.
    :param interval: Seconds between polls.
    :return: The final task status payload (as returned by the API).
    :raises typer.Exit: On timeout or when the task ends in FAILURE / REVOKED.
    """
    deadline = time.monotonic() + timeout
    last: dict[str, Any] = {}
    while True:
        data = _handle(http.get(f"/tasks/{task_id}"))
        assert isinstance(data, dict)
        last = data
        state = str(data.get("state", "UNKNOWN"))
        typer.echo(f"task {task_id}: {state}")
        if state in _TERMINAL_STATES:
            _print_json(data)
            if state != "SUCCESS":
                raise typer.Exit(code=1)
            return data
        if time.monotonic() >= deadline:
            typer.secho(
                f"timeout waiting for task {task_id} (last state={state})",
                fg=typer.colors.RED,
                err=True,
            )
            _print_json(last)
            raise typer.Exit(code=1)
        time.sleep(interval)


# ---------------------------------------------------------------------------
# keys
# ---------------------------------------------------------------------------


@keys_app.command("add")
def keys_add(
    ctx: typer.Context,
    name: str = typer.Option(..., "--name", "-n", help="Friendly label for the SSH role."),
) -> None:
    """Register a new SSH role by name.

    Phase 2c CP4.4 removed every per-row key material from the
    schema — the row is a name-and-mode label only, and every
    connection mints a fresh user cert from the SSH CA. The bound
    credential lives in Vault's SSH role configuration, not on this
    row, so no PEM body is needed.
    """
    payload: dict[str, Any] = {"name": name}
    with _client(ctx) as http:
        _print_json(_handle(http.post("/ssh-keys", json=payload)))


@keys_app.command("list")
def keys_list(ctx: typer.Context) -> None:
    """List all registered SSH keys."""
    with _client(ctx) as http:
        _print_json(_handle(http.get("/ssh-keys")))


@keys_app.command("get")
def keys_get(ctx: typer.Context, key_id: int = typer.Argument(...)) -> None:
    """Show a single SSH key by ID."""
    with _client(ctx) as http:
        _print_json(_handle(http.get(f"/ssh-keys/{key_id}")))


@keys_app.command("delete")
def keys_delete(ctx: typer.Context, key_id: int = typer.Argument(...)) -> None:
    """Delete an SSH key (fails if any server or client still references it)."""
    with _client(ctx) as http:
        _handle(http.delete(f"/ssh-keys/{key_id}"))
        typer.echo(f"deleted ssh key {key_id}")


# ---------------------------------------------------------------------------
# servers
# ---------------------------------------------------------------------------


@servers_app.command("register")
def servers_register(
    ctx: typer.Context,
    hostname: str = typer.Option(..., "--hostname", "-H", help="SSH target hostname of the hub."),
    ssh_username: str = typer.Option(..., "--ssh-user", "-u", help="SSH login on the hub."),
    ssh_key_id: int = typer.Option(..., "--key-id", "-k", help="ID of a registered SSH key."),
    endpoint_host: str = typer.Option(
        ...,
        "--endpoint-host",
        "-e",
        help="Public address clients will dial to reach the hub.",
    ),
    ssh_port: int = typer.Option(22, "--ssh-port"),
    endpoint_port: int = typer.Option(51820, "--endpoint-port"),
    interface: str = typer.Option("wg0", "--interface"),
    wait: bool = typer.Option(False, "--wait", help="Block until the provisioning task finishes."),
    timeout: float = typer.Option(300.0, "--timeout", help="Seconds to wait when --wait is set."),
) -> None:
    """Register a new WireGuard hub and kick off provisioning."""
    payload = {
        "hostname": hostname,
        "ssh_username": ssh_username,
        "ssh_key_id": ssh_key_id,
        "endpoint_host": endpoint_host,
        "ssh_port": ssh_port,
        "endpoint_port": endpoint_port,
        "interface": interface,
    }
    with _client(ctx) as http:
        data = _handle(http.post("/servers", json=payload))
        _print_json(data)
        if wait:
            _wait_task(http, data["task_id"], timeout=timeout, interval=1.0)


@servers_app.command("list")
def servers_list(ctx: typer.Context) -> None:
    """List all registered servers."""
    with _client(ctx) as http:
        _print_json(_handle(http.get("/servers")))


@servers_app.command("get")
def servers_get(ctx: typer.Context, server_id: int = typer.Argument(...)) -> None:
    """Show a single server by ID."""
    with _client(ctx) as http:
        _print_json(_handle(http.get(f"/servers/{server_id}")))


@servers_app.command("reprovision")
def servers_reprovision(
    ctx: typer.Context,
    server_id: int = typer.Argument(...),
    wait: bool = typer.Option(False, "--wait"),
    timeout: float = typer.Option(300.0, "--timeout"),
) -> None:
    """Re-run provisioning against an existing server row."""
    with _client(ctx) as http:
        data = _handle(http.post(f"/servers/{server_id}/reprovision"))
        _print_json(data)
        if wait:
            _wait_task(http, data["task_id"], timeout=timeout, interval=1.0)


@servers_app.command("discover")
def servers_discover(
    ctx: typer.Context,
    server_id: int = typer.Argument(..., help="Server to scan for peers."),
    wait: bool = typer.Option(
        False, "--wait", help="Block until the discovery task finishes."
    ),
    timeout: float = typer.Option(120.0, "--timeout"),
) -> None:
    """Run a discovery scan against a server.

    SSHes into the host and imports every WireGuard peer it observes into
    the ``discoveredpeer`` table. Existing rows are refreshed in place.
    """
    with _client(ctx) as http:
        data = _handle(http.post(f"/servers/{server_id}/discover"))
        _print_json(data)
        if wait:
            _wait_task(http, data["task_id"], timeout=timeout, interval=1.0)


@servers_app.command("discovered-peers")
def servers_discovered_peers(
    ctx: typer.Context,
    server_id: int = typer.Argument(..., help="Server whose peers to list."),
) -> None:
    """List all peers that have been discovered for a server."""
    with _client(ctx) as http:
        _print_json(_handle(http.get(f"/servers/{server_id}/discovered-peers")))


@servers_app.command("discover-all")
def servers_discover_all(
    ctx: typer.Context,
    wait: bool = typer.Option(
        False, "--wait", help="Block until the batch discovery task finishes."
    ),
    timeout: float = typer.Option(300.0, "--timeout"),
) -> None:
    """Run discovery against every registered server.

    Per-host SSH failures are logged and skipped — they do not abort the
    batch. The final result payload (visible via ``tasks status`` or
    ``--wait``) lists each server's outcome.
    """
    with _client(ctx) as http:
        data = _handle(http.post("/servers/discover-all"))
        _print_json(data)
        if wait:
            _wait_task(http, data["task_id"], timeout=timeout, interval=1.0)


# ---------------------------------------------------------------------------
# clients
# ---------------------------------------------------------------------------


@clients_app.command("register")
def clients_register(
    ctx: typer.Context,
    name: str = typer.Option(..., "--name", "-n", help="Unique client name."),
    hostname: str = typer.Option(..., "--hostname", "-H", help="SSH target hostname."),
    ssh_username: str = typer.Option(..., "--ssh-user", "-u"),
    ssh_key_id: int = typer.Option(..., "--key-id", "-k"),
    server_id: int = typer.Option(..., "--server-id", "-s"),
    ssh_port: int = typer.Option(22, "--ssh-port"),
    wait: bool = typer.Option(False, "--wait"),
    timeout: float = typer.Option(300.0, "--timeout"),
) -> None:
    """Register a new WireGuard spoke and kick off provisioning."""
    payload = {
        "name": name,
        "hostname": hostname,
        "ssh_username": ssh_username,
        "ssh_key_id": ssh_key_id,
        "server_id": server_id,
        "ssh_port": ssh_port,
    }
    with _client(ctx) as http:
        data = _handle(http.post("/clients", json=payload))
        _print_json(data)
        if wait:
            _wait_task(http, data["task_id"], timeout=timeout, interval=1.0)


@clients_app.command("list")
def clients_list(ctx: typer.Context) -> None:
    """List all registered clients."""
    with _client(ctx) as http:
        _print_json(_handle(http.get("/clients")))


@clients_app.command("get")
def clients_get(ctx: typer.Context, client_id: int = typer.Argument(...)) -> None:
    """Show a single client by ID."""
    with _client(ctx) as http:
        _print_json(_handle(http.get(f"/clients/{client_id}")))


@clients_app.command("add-manual")
def clients_add_manual(
    ctx: typer.Context,
    name: str = typer.Option(..., "--name", "-n", help="Unique client name."),
    server_id: int = typer.Option(..., "--server-id", "-s"),
    config_output: Path | None = typer.Option(
        None,
        "--config-output",
        "-o",
        help="Write the rendered wg0.conf to this file after registration.",
    ),
) -> None:
    """Register a client we won't SSH into, for hand-install on the device.

    The control plane generates a WireGuard keypair, allocates an IP out
    of the parent server's subnet, and reconfigures the hub so the new
    peer is admitted. The rendered ``wg0.conf`` body is returned in the
    same response (as ``wg_config``) and printed to stdout or written
    to the file given by ``--config-output``; copy that body onto the
    device by hand (e.g. import it into the WireGuard phone app).

    Post-redesign the control plane does **not** persist the private
    key — this response is the only moment the body can be captured.
    If you lose it, ``clients delete`` the row and register again to
    mint a fresh keypair.
    """
    payload = {"name": name, "server_id": server_id}
    with _client(ctx) as http:
        data = _handle(http.post("/clients/manual", json=payload))
    body = data["wg_config"]
    # Print the registration envelope (sans the wg_config body — we'll
    # surface that separately below so it's easier for the operator to
    # spot and copy out).
    redacted = {k: v for k, v in data.items() if k != "wg_config"}
    _print_json(redacted)
    if config_output is not None:
        config_output.write_text(body)
        typer.echo(f"wrote wg config to {config_output}")
    else:
        typer.echo("--- begin wg0.conf ---")
        typer.echo(body, nl=False)
        typer.echo("--- end wg0.conf ---")


@clients_app.command("ssh-config")
def clients_ssh_config(
    ctx: typer.Context,
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write the SSH config to this file instead of stdout.",
    ),
) -> None:
    """Print an ``~/.ssh/config`` block for every registered client.

    Each entry uses ``<client-name>.vpn`` as the alias, the wg-assigned
    IP as ``HostName``, the client's ``ssh_username`` as ``User``, and
    ``~/.ssh/<key-name>`` as ``IdentityFile`` — wg-manager assumes the
    operator has placed the SSH key under their own ``$HOME/.ssh/``
    directory. Append the result to ``~/.ssh/config`` (or drop it into
    a file referenced by an ``Include`` directive there) to ``ssh
    <client-name>.vpn`` once the VPN is up.

    With ``--output FILE`` the body is written to disk; otherwise it is
    printed to stdout.
    """
    with _client(ctx) as http:
        resp = http.get("/clients/export/ssh-config")
        if resp.status_code >= 400:
            _handle(resp)
            return
        body = resp.text
    if output is not None:
        output.write_text(body)
        typer.echo(f"wrote ssh config to {output}")
    else:
        typer.echo(body, nl=False)


@clients_app.command("reprovision")
def clients_reprovision(
    ctx: typer.Context,
    client_id: int = typer.Argument(...),
    wait: bool = typer.Option(False, "--wait"),
    timeout: float = typer.Option(300.0, "--timeout"),
) -> None:
    """Re-run provisioning against an existing client row."""
    with _client(ctx) as http:
        data = _handle(http.post(f"/clients/{client_id}/reprovision"))
        _print_json(data)
        if wait:
            _wait_task(http, data["task_id"], timeout=timeout, interval=1.0)


# ---------------------------------------------------------------------------
# tasks
# ---------------------------------------------------------------------------


@tasks_app.command("status")
def tasks_status(ctx: typer.Context, task_id: str = typer.Argument(...)) -> None:
    """Print the current state of a Celery task."""
    with _client(ctx) as http:
        _print_json(_handle(http.get(f"/tasks/{task_id}")))


@tasks_app.command("wait")
def tasks_wait(
    ctx: typer.Context,
    task_id: str = typer.Argument(...),
    timeout: float = typer.Option(300.0, "--timeout", help="Seconds to wait before giving up."),
    interval: float = typer.Option(1.0, "--interval", help="Seconds between polls."),
) -> None:
    """Block until a Celery task reaches a terminal state."""
    with _client(ctx) as http:
        _wait_task(http, task_id, timeout=timeout, interval=interval)


# ---------------------------------------------------------------------------
# db backup / restore
# ---------------------------------------------------------------------------

# Table order matters: parents before children so FK constraints are
# satisfied during restore.
_TABLE_ORDER = ("sshkey", "server", "client")

_BACKUP_VERSION = 1


def _get_engine(database_url: str | None = None) -> Any:
    """Build a SQLAlchemy engine, optionally overriding the configured URL.

    Tests monkeypatch this to return an in-memory SQLite engine.
    """
    if database_url is not None:
        from wg_manager.db import _build_engine

        return _build_engine(database_url)
    from wg_manager.db import engine

    return engine


def _serialize_row(row: Any) -> dict[str, Any]:
    """Convert a SQLModel row to a JSON-safe dictionary."""
    data: dict[str, Any] = {}
    for col in row.__table__.columns:
        val = getattr(row, col.key)
        if isinstance(val, datetime):
            data[col.key] = val.isoformat()
        elif isinstance(val, Enum):
            data[col.key] = val.value
        else:
            data[col.key] = val
    return data


@db_app.command("backup")
def db_backup(
    output: Path = typer.Option(
        ...,
        "--output",
        "-o",
        help="Path to write the JSON backup file.",
    ),
    database_url: str | None = typer.Option(
        None,
        "--database-url",
        envvar="DATABASE_URL",
        help="Override the configured DATABASE_URL.",
    ),
) -> None:
    """Dump all wg-manager data to a portable JSON file.

    The dump is database-agnostic: it serialises every row from every table
    (SSHKey, Server, Client) as plain JSON objects, preserving primary keys,
    foreign keys, and timestamps. The file can be restored into any
    supported backend (MySQL, SQLite, PostgreSQL, etc.).
    """
    from sqlmodel import Session, select

    from wg_manager.models import Client, SSHKey, Server

    engine = _get_engine(database_url)
    table_map: dict[str, type] = {
        "sshkey": SSHKey,
        "server": Server,
        "client": Client,
    }

    dump: dict[str, Any] = {"version": _BACKUP_VERSION, "tables": {}}
    with Session(engine) as session:
        for table_name in _TABLE_ORDER:
            model = table_map[table_name]
            rows = session.exec(select(model)).all()
            dump["tables"][table_name] = [_serialize_row(r) for r in rows]

    output.write_text(json.dumps(dump, indent=2, default=str, sort_keys=True))
    for table_name in _TABLE_ORDER:
        count = len(dump["tables"][table_name])
        typer.echo(f"  {table_name}: {count} row(s)")
    typer.echo(f"backup written to {output}")


@db_app.command("restore")
def db_restore(
    input_file: Path = typer.Option(
        ...,
        "--input",
        "-i",
        exists=True,
        dir_okay=False,
        readable=True,
        help="Path to a JSON backup file produced by 'db backup'.",
    ),
    database_url: str | None = typer.Option(
        None,
        "--database-url",
        envvar="DATABASE_URL",
        help="Override the configured DATABASE_URL.",
    ),
    drop_existing: bool = typer.Option(
        False,
        "--drop-existing",
        help="Delete all existing rows before inserting (required if tables are non-empty).",
    ),
) -> None:
    """Restore wg-manager data from a JSON backup file.

    Rows are inserted in FK order (SSHKey -> Server -> Client) so
    referential integrity is maintained. Primary keys from the backup
    are preserved, making the restore a faithful copy.

    By default the command refuses to proceed if any target table
    already contains rows. Pass ``--drop-existing`` to truncate first.
    """
    from sqlmodel import Session, select

    from wg_manager.models import Client, NodeStatus, SSHKey, Server

    raw = json.loads(input_file.read_text())
    version = raw.get("version", 0)
    if version != _BACKUP_VERSION:
        typer.secho(
            f"unsupported backup version {version} (expected {_BACKUP_VERSION})",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1)

    tables_data: dict[str, list[dict[str, Any]]] = raw["tables"]

    table_map: dict[str, type] = {
        "sshkey": SSHKey,
        "server": Server,
        "client": Client,
    }

    engine = _get_engine(database_url)

    with Session(engine) as session:
        # Safety check: refuse to clobber unless --drop-existing.
        for table_name in _TABLE_ORDER:
            model = table_map[table_name]
            existing = len(session.exec(select(model)).all())
            if existing > 0 and not drop_existing:
                typer.secho(
                    f"table {table_name!r} has {existing} existing row(s); "
                    "pass --drop-existing to truncate before restore",
                    fg=typer.colors.RED,
                    err=True,
                )
                raise typer.Exit(code=1)

        # Truncate in reverse FK order (children first).
        if drop_existing:
            for table_name in reversed(_TABLE_ORDER):
                model = table_map[table_name]
                rows = session.exec(select(model)).all()
                for row in rows:
                    session.delete(row)
            session.commit()

        # Insert in FK order. The set of valid column keys per model is
        # snapshotted once so a backup file that carries dropped fields
        # (e.g. a pre-0005 ``private_key`` plaintext) restores cleanly
        # against the current schema. The dropped fields are silently
        # filtered — they no longer have anywhere to land.
        for table_name in _TABLE_ORDER:
            model = table_map[table_name]
            valid_keys = {col.key for col in model.__table__.columns}
            rows_data = tables_data.get(table_name, [])
            for row_dict in rows_data:
                # Parse datetime strings back into datetime objects.
                # ``host_cert_valid_after`` / ``host_cert_valid_before``
                # are populated on every Server row post-CP4.4 (the
                # host-cert install runs unconditionally now), so the
                # backup file carries them as ISO strings and the
                # restore has to inflate them too — otherwise SQLite's
                # DateTime type rejects the str at INSERT time.
                for ts_field in (
                    "created_at",
                    "host_cert_valid_after",
                    "host_cert_valid_before",
                ):
                    if ts_field in row_dict and isinstance(row_dict[ts_field], str):
                        row_dict[ts_field] = datetime.fromisoformat(
                            row_dict[ts_field]
                        )
                # Parse status enums.
                if "status" in row_dict and isinstance(row_dict["status"], str):
                    row_dict["status"] = NodeStatus(row_dict["status"])
                filtered = {
                    k: v for k, v in row_dict.items() if k in valid_keys
                }
                row = model(**filtered)
                session.add(row)
            session.flush()
            typer.echo(f"  {table_name}: {len(rows_data)} row(s) restored")
        session.commit()
    typer.echo(f"restore complete from {input_file}")


# ---------------------------------------------------------------------------
# crypto rewrap
# ---------------------------------------------------------------------------
#
# Note: the earlier ``wg-manager crypto migrate`` command, which
# backfilled ciphertext from the legacy plaintext columns, has been
# removed alongside Alembic revision 0005's drop of those columns.
# Operators upgrading from a pre-0005 schema must run ``crypto migrate``
# from the previous wg-manager release before applying 0005; the
# cookbook walks through the exact sequence.


@crypto_app.command("rewrap")
def crypto_rewrap(
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Print what would change without writing to the database.",
    ),
    database_url: str | None = typer.Option(
        None,
        "--database-url",
        envvar="DATABASE_URL",
        help="Override the configured DATABASE_URL.",
    ),
) -> None:
    """Re-encrypt existing ciphertext under the current key version.

    Run after a Vault Transit rotation
    (``vault write -f transit/keys/wg-manager/rotate``): old blobs
    still decrypt (Transit retains prior versions) but new writes use
    the latest version, leaving the data store on a mix of versions
    until this walks every row. For each row that has ciphertext, the
    blob is decrypted under the row's per-row context and re-encrypted
    under the same context — Vault transparently uses the active
    version on the re-encrypt path. The visible effect is that every
    ``vault:vN:…`` blob lands on the same ``N`` as
    :attr:`wg_manager.crypto.CryptoBackend.key_version`.

    Rows without ciphertext (``_ct`` is ``NULL``) are **skipped** —
    rewrap is for upgrading already-encrypted material. Promote legacy
    plaintext rows with ``wg-manager crypto migrate`` first; the
    pre-drop-plaintext checklist in the cookbook covers the full
    sequence.

    For :class:`~wg_manager.crypto.LocalDevBackend` the operation is a
    no-op semantically (Fernet has no version concept), but each row's
    body is still rewritten with a fresh nonce. Operators can use that
    to smoke-test the workflow before pointing it at production.

    Idempotent: re-running after a full rewrap walks the rows again
    and produces fresh nonces but identical plaintext, so the data is
    unchanged.
    """
    from wg_manager.crypto import make_backend

    # Alembic 0008 dropped the sshkey ciphertext columns; 0009 dropped
    # the manual-client private-key ciphertext column. There is no
    # remaining encrypted-at-rest column to walk, so this command is a
    # no-op against the schema. We still execute it (so the operator's
    # post-rotation muscle memory works) and surface the active backend
    # / key version — a useful "Vault is reachable; key is at version N"
    # smoke test.
    _ = database_url  # accepted for forward-compat; nothing to query
    backend = make_backend()

    suffix = " (dry-run; no rows written)" if dry_run else ""
    typer.echo(f"crypto rewrap complete{suffix}")
    typer.echo(
        f"  backend: {backend.name} key_version={backend.key_version}"
    )
    typer.echo(
        "  no encrypted-at-rest columns remain — nothing to rewrap"
    )


# ---------------------------------------------------------------------------
# certs — Phase 2d CP3.3
# ---------------------------------------------------------------------------
#
# Direct-PKI / direct-DB: the commands wrap :mod:`wg_manager.pki` and
# write to the :class:`Certificate` audit table without going through the
# API. The motivation is bootstrap: the ``api`` cert has to exist before
# the API listener can come up, so this group must work standalone.
# Mirrors the direct-DB shape ``wg-manager db backup`` / ``restore``
# uses for the same reason (its purpose is cross-host migration, when
# the API may not be running).


class _CertType(str, Enum):
    """Operator-facing enum, mirrors :class:`wg_manager.models.CertificateType`.

    Re-declared on the CLI side so Typer renders the four values in
    ``--help`` without dragging the SQLModel-bound model enum through
    Typer's introspection (which doesn't gracefully handle the
    ``Field(default=...)`` shape SQLModel decorates the value with).
    """

    api = "api"
    cli = "cli"
    dashboard = "dashboard"
    mysql = "mysql"


# Map cert type → (default TTL days, default SAN list, requires_operator,
# uses_server_eku). The defaults match the "first run" shape an operator
# expects: the API listener gets a short-lived loopback cert; the
# operator-bound certs default to a year (rotation friction); MySQL
# mirrors the API.
_CERT_PROFILES: dict[_CertType, dict[str, Any]] = {
    _CertType.api: {
        "ttl_days": 30,
        "default_sans": ["127.0.0.1", "localhost"],
        "requires_operator": False,
        "server_eku": True,
    },
    _CertType.cli: {
        "ttl_days": 365,
        "default_sans": None,  # populated from --cn at call time
        "requires_operator": True,
        "server_eku": False,
    },
    _CertType.dashboard: {
        "ttl_days": 365,
        "default_sans": None,
        "requires_operator": True,
        "server_eku": False,
    },
    _CertType.mysql: {
        "ttl_days": 30,
        "default_sans": ["mysql", "127.0.0.1", "localhost"],
        "requires_operator": False,
        "server_eku": True,
    },
}


def _write_pem(path: Path, body: str, *, mode: int = 0o600) -> None:
    """Write ``body`` to ``path`` with the given mode.

    Private-key files default to ``0o600`` so a casual ``ls -l`` doesn't
    surface a world-readable footgun. Cert / chain files override to
    ``0o644`` at the call site.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    path.chmod(mode)


@certs_app.command("issue")
def certs_issue(
    cert_type: _CertType = typer.Option(
        ...,
        "--type",
        "-t",
        help=(
            "Logical cert purpose: api (FastAPI server), cli (operator "
            "CLI client), dashboard (browser PKCS#12 client), or mysql "
            "(DB server)."
        ),
    ),
    common_name: str = typer.Option(
        ..., "--cn", help="CN baked into the cert subject."
    ),
    sans: list[str] = typer.Option(
        None,
        "--san",
        help=(
            "Subject Alternative Name. Repeatable. Defaults vary by "
            "--type (api → 127.0.0.1+localhost; mysql → mysql+loopback; "
            "cli/dashboard → the CN)."
        ),
    ),
    ttl_days: int = typer.Option(
        None,
        "--ttl-days",
        help=(
            "Validity window in days. Defaults: api/mysql=30, "
            "cli/dashboard=365."
        ),
    ),
    operator_cn: str | None = typer.Option(
        None,
        "--operator-cn",
        help=(
            "Operator CN this cert belongs to (cli + dashboard only). "
            "Defaults to --cn for those types; required to match an "
            "active Operator row."
        ),
    ),
    out_cert: Path | None = typer.Option(
        None, "--out-cert", help="Write the leaf PEM here."
    ),
    out_key: Path | None = typer.Option(
        None, "--out-key", help="Write the private key PEM here (0o600)."
    ),
    out_chain: Path | None = typer.Option(
        None,
        "--out-chain",
        help="Write the issuing chain PEM here (intermediate + root).",
    ),
    out_pkcs12: Path | None = typer.Option(
        None,
        "--out-pkcs12",
        help=(
            "Write a PKCS#12 archive here (dashboard type only). "
            "Bundles key + leaf + chain in one browser-importable file."
        ),
    ),
    pkcs12_password: str = typer.Option(
        "",
        "--pkcs12-password",
        help=(
            "Password used to encrypt the PKCS#12 archive. Defaults to "
            "the empty string; pass a real value when minting a browser "
            "import."
        ),
    ),
    database_url: str | None = typer.Option(
        None,
        "--database-url",
        envvar="DATABASE_URL",
        help="Override the configured DATABASE_URL.",
    ),
) -> None:
    """Issue a leaf cert via the configured PKI backend and record the row.

    For ``api`` / ``mysql`` the leaf is ``serverAuth`` and no operator
    linkage is recorded. For ``cli`` / ``dashboard`` the leaf is
    ``clientAuth`` and the row's ``operator_id`` is populated from a
    lookup keyed on ``--operator-cn`` (default: ``--cn``). A
    ``--operator-cn`` that doesn't match any registered :class:`Operator`
    row aborts the issuance — no PKI round-trip happens and the
    certificate table stays untouched.

    Output paths are optional for ``dashboard`` (use ``--out-pkcs12``
    instead) and required for the other types. ``--out-key`` is
    written with mode ``0o600``; the leaf + chain land at ``0o644``.
    The private key is the **only** copy — wg-manager does not keep
    a server-side replica, so losing the file means re-issuing.
    """
    from sqlmodel import Session

    from wg_manager.models import (
        Certificate,
        CertificateType,
        Operator,
    )
    from wg_manager.pki import make_pki_backend

    profile = _CERT_PROFILES[cert_type]

    # Resolve SANs: explicit > type default > [CN] (cli/dashboard).
    if sans:
        resolved_sans = list(sans)
    elif profile["default_sans"] is not None:
        resolved_sans = list(profile["default_sans"])
    else:
        resolved_sans = [common_name]

    ttl = ttl_days if ttl_days is not None else profile["ttl_days"]
    ttl_seconds = ttl * 24 * 60 * 60

    # Argument validation. We fail before any side effect so a half-
    # issued cert can't end up on disk with no row to back it.
    if cert_type == _CertType.dashboard:
        if out_pkcs12 is None:
            typer.secho(
                "--out-pkcs12 is required for --type dashboard",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)
    else:
        missing = [
            name
            for name, value in (
                ("--out-cert", out_cert),
                ("--out-key", out_key),
                ("--out-chain", out_chain),
            )
            if value is None
        ]
        if missing:
            typer.secho(
                f"missing required output flag(s): {', '.join(missing)}",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)

    engine = _get_engine(database_url)
    operator_id: int | None = None
    if profile["requires_operator"]:
        target_cn = operator_cn or common_name
        with Session(engine) as session:
            op_row = session.exec(
                select(Operator).where(Operator.cn == target_cn)
            ).first()
            if op_row is None:
                typer.secho(
                    f"no operator registered with CN {target_cn!r} — "
                    f"run `wg-manager` (or the CP3.4 dashboard) to "
                    f"register the operator first",
                    fg=typer.colors.RED,
                    err=True,
                )
                raise typer.Exit(code=1)
            operator_id = int(op_row.id or 0)

    backend = make_pki_backend()
    if profile["server_eku"]:
        cert = backend.issue_server_cert(
            common_name=common_name,
            sans=resolved_sans,
            ttl_seconds=ttl_seconds,
        )
    else:
        cert = backend.issue_client_cert(
            common_name=common_name,
            sans=resolved_sans,
            ttl_seconds=ttl_seconds,
        )

    if cert_type == _CertType.dashboard:
        # PKCS#12: bundle key + leaf + chain so the operator imports one
        # file into their browser. Chrome / Firefox / Safari all consume
        # the PKCS#12 form natively.
        from cryptography import x509 as _x509
        from cryptography.hazmat.primitives.serialization import (
            BestAvailableEncryption,
            NoEncryption,
            load_pem_private_key,
            pkcs12,
        )

        leaf = _x509.load_pem_x509_certificate(cert.cert_pem.encode())
        key = load_pem_private_key(cert.private_pem.encode(), password=None)
        # ``load_pem_x509_certificates`` (cryptography >= 39) parses every
        # PEM block in a single body in one call — handles the
        # intermediate + root concatenation our backends produce without
        # any hand-rolled splitting.
        chain_certs = (
            _x509.load_pem_x509_certificates(cert.chain_pem.encode())
            if cert.chain_pem.strip()
            else []
        )
        encryption = (
            BestAvailableEncryption(pkcs12_password.encode())
            if pkcs12_password
            else NoEncryption()
        )
        p12_blob = pkcs12.serialize_key_and_certificates(
            name=common_name.encode(),
            key=key,
            cert=leaf,
            cas=chain_certs,
            encryption_algorithm=encryption,
        )
        assert out_pkcs12 is not None
        out_pkcs12.parent.mkdir(parents=True, exist_ok=True)
        out_pkcs12.write_bytes(p12_blob)
        out_pkcs12.chmod(0o600)
        typer.echo(f"wrote PKCS#12 to {out_pkcs12}")
    else:
        assert out_cert is not None and out_key is not None and out_chain is not None
        _write_pem(out_cert, cert.cert_pem, mode=0o644)
        _write_pem(out_key, cert.private_pem, mode=0o600)
        _write_pem(out_chain, cert.chain_pem, mode=0o644)
        typer.echo(f"wrote leaf to {out_cert}")
        typer.echo(f"wrote key to  {out_key}")
        typer.echo(f"wrote chain to {out_chain}")

    # Record the audit row only after the disk writes have succeeded so
    # a row never points at files that aren't there.
    with Session(engine) as session:
        row = Certificate(
            serial=str(cert.serial),
            cert_type=CertificateType(cert_type.value),
            operator_id=operator_id,
            common_name=cert.common_name,
            sans=",".join(cert.sans),
            not_before=cert.not_before,
            not_after=cert.not_after,
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        typer.echo(
            f"recorded certificate row id={row.id} serial={row.serial}"
        )


@certs_app.command("revoke")
def certs_revoke(
    serial: int = typer.Option(
        ..., "--serial", help="Issuer-assigned serial of the cert to revoke."
    ),
    database_url: str | None = typer.Option(
        None,
        "--database-url",
        envvar="DATABASE_URL",
        help="Override the configured DATABASE_URL.",
    ),
) -> None:
    """Revoke a previously-issued certificate.

    Two-step: tells the PKI backend to add the serial to its CRL, then
    flips the audit row's ``revoked`` flag and stamps ``revoked_at``.
    Both happen in the same logical transaction — if the backend call
    fails the row is left untouched, and if the row update fails after
    a successful backend call the operator gets a clear error so they
    can manually reconcile (the CRL is authoritative for handshake
    rejection; the row is the audit trail).

    A serial that isn't in the registry is operator error — the command
    exits non-zero with the serial named in the error so a typo is
    easy to spot.
    """
    from datetime import datetime as _dt, timezone as _tz

    from sqlmodel import Session

    from wg_manager.models import Certificate
    from wg_manager.pki import make_pki_backend

    engine = _get_engine(database_url)
    with Session(engine) as session:
        row = session.exec(
            select(Certificate).where(Certificate.serial == str(serial))
        ).first()
        if row is None:
            typer.secho(
                f"no certificate registered with serial {serial}",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)
        backend = make_pki_backend()
        backend.revoke_cert(serial=serial)
        row.revoked = True
        row.revoked_at = _dt.now(_tz.utc)
        session.add(row)
        session.commit()
        typer.echo(f"revoked certificate serial={serial}")


@certs_app.command("list")
def certs_list(
    database_url: str | None = typer.Option(
        None,
        "--database-url",
        envvar="DATABASE_URL",
        help="Override the configured DATABASE_URL.",
    ),
) -> None:
    """Print every certificate audit row as JSON.

    Output is a JSON array — pipe through ``jq`` to slice by
    ``cert_type`` / ``revoked`` / ``operator_id``. CP3.4 layers a
    dashboard view on top of the same shape.
    """
    from sqlmodel import Session

    from wg_manager.models import Certificate

    engine = _get_engine(database_url)
    with Session(engine) as session:
        rows = session.exec(select(Certificate)).all()
    payload = [
        {
            "id": row.id,
            "serial": row.serial,
            "cert_type": row.cert_type.value,
            "operator_id": row.operator_id,
            "common_name": row.common_name,
            "sans": row.sans,
            "not_before": (
                row.not_before.isoformat() if row.not_before else None
            ),
            "not_after": (
                row.not_after.isoformat() if row.not_after else None
            ),
            "revoked": row.revoked,
            "revoked_at": (
                row.revoked_at.isoformat() if row.revoked_at else None
            ),
            "created_at": (
                row.created_at.isoformat() if row.created_at else None
            ),
        }
        for row in rows
    ]
    typer.echo(json.dumps(payload, indent=2, default=str, sort_keys=True))


# ---------------------------------------------------------------------------
# operators — Phase 2d CP3.3 glue
# ---------------------------------------------------------------------------
#
# Direct-DB CRUD against the :class:`Operator` table. Exists so the
# dev / first-install workflow can register the first operator
# without already needing a registered client cert (the
# chicken-and-egg the CP3.2 ``AUTH_BOOTSTRAP_OPERATOR_CN`` env var
# closes for the API path; this command closes it for operators who
# prefer to seed the DB directly). The dashboard / HTTP CRUD lands in
# CP3.4 on top of the same table.


class _OperatorRoleArg(str, Enum):
    """Operator-facing role enum; mirrors :class:`wg_manager.models.OperatorRole`."""

    admin = "admin"
    operator = "operator"
    auditor = "auditor"


@operators_app.command("add")
def operators_add(
    cn: str = typer.Option(
        ...,
        "--cn",
        help="Common Name on the operator's client cert. Unique.",
    ),
    role: _OperatorRoleArg = typer.Option(
        _OperatorRoleArg.operator,
        "--role",
        help=(
            "Coarse-grained permission tier. Defaults to 'operator' "
            "(principle of least privilege — admins must be set "
            "explicitly)."
        ),
    ),
    display_name: str | None = typer.Option(
        None,
        "--display-name",
        help="Optional human-readable label for the dashboard.",
    ),
    database_url: str | None = typer.Option(
        None,
        "--database-url",
        envvar="DATABASE_URL",
        help="Override the configured DATABASE_URL.",
    ),
) -> None:
    """Register a new operator by CN.

    The CN must match the Subject CN baked into the operator's client
    cert at issue time; the :class:`MTLSAuthMiddleware` (Phase 2d
    CP3.2) keys admission on this row. Refuses with a non-zero exit
    if the CN is already taken — the unique index on ``operator.cn``
    raises before we commit.
    """
    from sqlmodel import Session

    from wg_manager.models import Operator, OperatorRole, OperatorStatus

    engine = _get_engine(database_url)
    with Session(engine) as session:
        existing = session.exec(
            select(Operator).where(Operator.cn == cn)
        ).first()
        if existing is not None:
            typer.secho(
                f"operator with CN {cn!r} already exists "
                f"(id={existing.id}, role={existing.role.value})",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)
        row = Operator(
            cn=cn,
            display_name=display_name,
            role=OperatorRole(role.value),
            status=OperatorStatus.active,
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        typer.echo(
            f"registered operator id={row.id} cn={row.cn!r} "
            f"role={row.role.value}"
        )


@operators_app.command("list")
def operators_list(
    database_url: str | None = typer.Option(
        None,
        "--database-url",
        envvar="DATABASE_URL",
        help="Override the configured DATABASE_URL.",
    ),
) -> None:
    """Print every operator row as JSON.

    Output is a JSON array — pipe through ``jq`` to slice by ``role``
    or ``status``.
    """
    from sqlmodel import Session

    from wg_manager.models import Operator

    engine = _get_engine(database_url)
    with Session(engine) as session:
        rows = session.exec(select(Operator)).all()
    payload = [
        {
            "id": row.id,
            "cn": row.cn,
            "display_name": row.display_name,
            "role": row.role.value,
            "status": row.status.value,
            "created_at": (
                row.created_at.isoformat() if row.created_at else None
            ),
        }
        for row in rows
    ]
    typer.echo(json.dumps(payload, indent=2, default=str, sort_keys=True))


def main() -> None:  # pragma: no cover - thin entrypoint
    """Console-script entrypoint."""
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
