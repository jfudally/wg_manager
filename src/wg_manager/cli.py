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
app.add_typer(keys_app, name="keys")
app.add_typer(servers_app, name="servers")
app.add_typer(clients_app, name="clients")
app.add_typer(tasks_app, name="tasks")
app.add_typer(db_app, name="db")
app.add_typer(crypto_app, name="crypto")


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


def main() -> None:  # pragma: no cover - thin entrypoint
    """Console-script entrypoint."""
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
