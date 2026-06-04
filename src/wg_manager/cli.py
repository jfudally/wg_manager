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

from wg_manager.bootstrap_ssh import BootstrapSSHRunner, bootstrap_host
from wg_manager.config import Settings
from wg_manager.ssh import SSHConnectionError
from wg_manager.ssh_ca import SSHCAError, make_ssh_ca_backend

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
evidence_app = typer.Typer(
    help=(
        "Generate SOC 2-style evidence packs (Phase 2e cycle 4). "
        "Pulls audit events, cert + operator inventory, Vault audit "
        "log slice, and deployment context into a tarball."
    ),
    no_args_is_help=True,
)
tenants_app = typer.Typer(
    help=(
        "Manage the tenant namespace registry (Phase 3b cycle 2). "
        "Tenants are the multi-tenant boundary; per-operator access "
        "is granted via `wg-manager operators attach-tenant`."
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
app.add_typer(evidence_app, name="evidence")
app.add_typer(tenants_app, name="tenants")


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


# ---------------------------------------------------------------------------
# Phase 2e backup cycle 2 — envelope encryption for backup files
# ---------------------------------------------------------------------------

# Constants chosen to match the AESGCM defaults the cryptography lib
# already exposes. 256-bit DEK + 96-bit nonce + GCM tag in-line with
# the ciphertext. Recovering operators care about these values so they
# can re-implement the decrypt path in a hostile environment — keep
# them centralised here.
_DEK_BYTES = 32  # AES-256
_NONCE_BYTES = 12  # GCM standard


def _envelope_context() -> str:
    """Return a per-backup context string used to bind the DEK wrap.

    Vault Transit's ``encrypt_data`` accepts a ``context`` parameter
    only when the key is ``derived=True``. The LocalDevBackend's Fernet
    wrap silently ignores the context. Binding the context here keeps
    the production path defended against a "swap the DEK between two
    backups" attack — see ``test_db_backup_encrypt.py``
    ``test_swapped_dek_ct_fails_restore`` — and the LocalDev mode
    benefits at minimum from the context appearing in the envelope as
    a public audit field even if the wrap doesn't enforce it.
    """
    from datetime import timezone

    return "backup:" + datetime.now(timezone.utc).isoformat(
        timespec="microseconds"
    )


def _envelope_encrypt(plaintext: bytes) -> dict[str, Any]:
    """Build the on-disk envelope around ``plaintext``.

    Mints a random 256-bit DEK + 96-bit nonce, AES-256-GCM-encrypts the
    plaintext, then wraps the DEK via
    :func:`wg_manager.crypto.make_backend`. The wrap goes through the
    same backend the rest of the app uses for at-rest encryption — so a
    production wg-manager deployment that has Vault Transit gets the
    Transit data-key flow without additional configuration.
    """
    import secrets

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from wg_manager.crypto import make_backend

    dek = secrets.token_bytes(_DEK_BYTES)
    nonce = secrets.token_bytes(_NONCE_BYTES)
    aesgcm = AESGCM(dek)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    context = _envelope_context()
    backend = make_backend()
    dek_ct = backend.encrypt(dek, context=context)

    # Zero the DEK before returning so the plaintext key doesn't sit in
    # the caller's memory longer than necessary. The bytes object is
    # immutable in CPython, so we rebind to a sentinel — best-effort.
    del dek

    return {
        "version": _BACKUP_VERSION,
        "encrypted": True,
        "created_at": datetime.now().isoformat(),
        "context": context,
        "dek_ct": dek_ct,
        "nonce_b64": _b64(nonce),
        "ciphertext_b64": _b64(ciphertext),
    }


def _envelope_decrypt(envelope: dict[str, Any]) -> bytes:
    """Inverse of :func:`_envelope_encrypt`. Returns the plaintext JSON.

    Raises if the envelope is malformed, the DEK wrap is invalid, or
    the AES-GCM tag fails to verify (the GCM tag is what catches a
    flipped ciphertext / nonce bit; the wrap failure catches a swapped
    ``dek_ct``).
    """
    from base64 import b64decode

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from wg_manager.crypto import make_backend

    required = {"dek_ct", "nonce_b64", "ciphertext_b64", "context"}
    missing = required - envelope.keys()
    if missing:
        raise ValueError(f"envelope missing required fields: {sorted(missing)}")

    backend = make_backend()
    dek = backend.decrypt(envelope["dek_ct"], context=envelope["context"])
    nonce = b64decode(envelope["nonce_b64"])
    ciphertext = b64decode(envelope["ciphertext_b64"])

    aesgcm = AESGCM(dek)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    del dek
    return plaintext


def _b64(raw: bytes) -> str:
    """Base64-encode ``raw`` as an ASCII string. Centralised so the
    envelope helpers stay readable."""
    from base64 import b64encode

    return b64encode(raw).decode("ascii")


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
    encrypt: bool = typer.Option(
        False,
        "--encrypt",
        help=(
            "Wrap the dump in a Transit-data-key envelope (Phase 2e "
            "backup cycle 2). Mints a per-backup AES-256-GCM key, "
            "encrypts the JSON with it, wraps the key via the configured "
            "CryptoBackend (Transit in production, LocalDev in tests). "
            "Restore with `wg-manager db restore --decrypt`."
        ),
    ),
) -> None:
    """Dump all wg-manager data to a portable JSON file.

    The dump is database-agnostic: it serialises every row from every table
    (SSHKey, Server, Client) as plain JSON objects, preserving primary keys,
    foreign keys, and timestamps. The file can be restored into any
    supported backend (MySQL, SQLite, PostgreSQL, etc.).

    Pass ``--encrypt`` to wrap the dump in an envelope-encrypted form
    so a leaked backup file is not equivalent to a leaked database
    (closes a residual variant of T-1). The wrap path uses the
    :class:`wg_manager.crypto.CryptoBackend` selected by
    ``CRYPTO_BACKEND``, so a production deployment with Vault
    Transit gets the Transit data-key flow without additional config.
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

    plaintext = json.dumps(dump, indent=2, default=str, sort_keys=True)

    if encrypt:
        envelope = _envelope_encrypt(plaintext.encode("utf-8"))
        output.write_text(json.dumps(envelope, indent=2, sort_keys=True))
        for table_name in _TABLE_ORDER:
            count = len(dump["tables"][table_name])
            typer.echo(f"  {table_name}: {count} row(s)")
        typer.echo(
            f"encrypted backup written to {output} "
            f"(DEK wrapped via {envelope['dek_ct'].split(':', 1)[0]} backend)"
        )
        return

    output.write_text(plaintext)
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
    decrypt: bool = typer.Option(
        False,
        "--decrypt",
        help=(
            "Unwrap a Transit-data-key envelope (Phase 2e backup cycle "
            "2) before restoring. Required for files produced by "
            "`wg-manager db backup --encrypt`; rejected on a plain "
            "JSON dump."
        ),
    ),
) -> None:
    """Restore wg-manager data from a JSON backup file.

    Rows are inserted in FK order (SSHKey -> Server -> Client) so
    referential integrity is maintained. Primary keys from the backup
    are preserved, making the restore a faithful copy.

    By default the command refuses to proceed if any target table
    already contains rows. Pass ``--drop-existing`` to truncate first.

    Pass ``--decrypt`` to unwrap an envelope-encrypted backup produced
    by ``db backup --encrypt``. The DEK is unwrapped via the
    :class:`wg_manager.crypto.CryptoBackend` selected by
    ``CRYPTO_BACKEND`` — must be the same backend that wrapped it.
    """
    from sqlmodel import Session, select

    from wg_manager.models import Client, NodeStatus, SSHKey, Server

    raw_text = input_file.read_text()
    try:
        raw = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        typer.secho(
            f"backup file is not valid JSON: {exc}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1) from exc

    # Mode-mismatch ergonomics: tell the operator exactly which flag is
    # missing or extra. Without this, an encrypted file restored without
    # ``--decrypt`` would land on a confusing version-mismatch error
    # because the envelope JSON has no ``tables`` key.
    file_is_encrypted = bool(raw.get("encrypted"))
    if file_is_encrypted and not decrypt:
        typer.secho(
            "backup file is encrypted; pass --decrypt to restore",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1)
    if decrypt and not file_is_encrypted:
        typer.secho(
            "backup file is plain JSON, not encrypted — drop --decrypt",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1)

    if decrypt:
        try:
            plaintext = _envelope_decrypt(raw)
        except Exception as exc:  # noqa: BLE001 — surface every failure shape
            typer.secho(
                f"decrypt failed: {exc}",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1) from exc
        raw = json.loads(plaintext.decode("utf-8"))

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
    mysql_client = "mysql-client"


# Map cert type → (default TTL days, default SAN list, requires_operator,
# uses_server_eku). The defaults match the "first run" shape an operator
# expects: the API listener gets a short-lived loopback cert; the
# operator-bound certs default to a year (rotation friction); MySQL
# mirrors the API; mysql-client carries a clientAuth EKU so the app +
# worker can present it back to MySQL once require_secure_transport is
# enforced (Phase 2d CP4.2).
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
    _CertType.mysql_client: {
        "ttl_days": 30,
        "default_sans": None,  # populated from --cn at call time
        "requires_operator": False,
        "server_eku": False,
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
            "CLI client), dashboard (browser PKCS#12 client), mysql "
            "(DB server), or mysql-client (app/worker → DB client)."
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
            "Validity window in days. Defaults: api/mysql/"
            "mysql-client=30, cli/dashboard=365."
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
    # a row never points at files that aren't there. Phase 2d CP4.3 also
    # stashes the three PEM paths so ``wg-manager certs renew`` can
    # rewrite the leaf in place without re-asking the operator. PKCS#12
    # bundles (dashboard) skip the path columns — there is no separate
    # leaf/key/chain trio for the renewer to overwrite.
    with Session(engine) as session:
        row = Certificate(
            serial=str(cert.serial),
            cert_type=CertificateType(cert_type.value),
            operator_id=operator_id,
            common_name=cert.common_name,
            sans=",".join(cert.sans),
            not_before=cert.not_before,
            not_after=cert.not_after,
            out_cert_path=str(out_cert) if out_cert is not None else None,
            out_key_path=str(out_key) if out_key is not None else None,
            out_chain_path=(
                str(out_chain) if out_chain is not None else None
            ),
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


# ---------------------------------------------------------------------------
# renew — Phase 2d CP4.3
# ---------------------------------------------------------------------------


def _renew_row(
    session: Any,
    backend: Any,
    row: Any,
    *,
    out_cert: Path | None,
    out_key: Path | None,
    out_chain: Path | None,
) -> Any:
    """Mint a fresh leaf for ``row`` and write it to disk.

    Returns the new :class:`Certificate` row (already committed). The
    caller is responsible for catching exceptions and presenting them
    to the operator — this helper is the I/O-heavy core that both the
    single-id path and the ``--due`` walker share.

    Write-path resolution: explicit ``--out-*`` paths win over the
    row's stored ``out_*_path`` columns. If neither source supplies a
    full triple, :class:`RuntimeError` is raised so the operator gets
    a clear message instead of partial files.
    """
    from wg_manager.models import Certificate, CertificateType

    cert_path = out_cert or (
        Path(row.out_cert_path) if row.out_cert_path else None
    )
    key_path = out_key or (
        Path(row.out_key_path) if row.out_key_path else None
    )
    chain_path = out_chain or (
        Path(row.out_chain_path) if row.out_chain_path else None
    )
    if cert_path is None or key_path is None or chain_path is None:
        raise RuntimeError(
            f"cannot renew certificate id={row.id}: the row has no "
            "stored out-paths and the command was not invoked with "
            "--out-cert / --out-key / --out-chain. Re-issue the cert "
            "via `wg-manager certs issue` with --out-cert/... to "
            "populate the path columns, or call `renew --id` with "
            "explicit --out-* flags."
        )

    sans = [s for s in row.sans.split(",") if s]
    ttl_seconds = max(
        1,
        int(
            (_as_utc(row.not_after) - _as_utc(row.not_before)).total_seconds()
        ),
    )

    profile = _CERT_PROFILES[_CertType(row.cert_type.value)]
    if profile["server_eku"]:
        cert = backend.issue_server_cert(
            common_name=row.common_name, sans=sans, ttl_seconds=ttl_seconds
        )
    else:
        cert = backend.issue_client_cert(
            common_name=row.common_name, sans=sans, ttl_seconds=ttl_seconds
        )

    _write_pem(cert_path, cert.cert_pem, mode=0o644)
    _write_pem(key_path, cert.private_pem, mode=0o600)
    _write_pem(chain_path, cert.chain_pem, mode=0o644)

    new_row = Certificate(
        serial=str(cert.serial),
        cert_type=row.cert_type,
        operator_id=row.operator_id,
        common_name=cert.common_name,
        sans=",".join(cert.sans),
        not_before=cert.not_before,
        not_after=cert.not_after,
        out_cert_path=str(cert_path),
        out_key_path=str(key_path),
        out_chain_path=str(chain_path),
    )
    session.add(new_row)
    session.commit()
    session.refresh(new_row)
    return new_row


def _as_utc(dt: Any) -> Any:
    """Coerce ``dt`` to a tz-aware UTC datetime.

    SQLite drops the tzinfo on round-trip, so a datetime that went in
    as ``datetime(2026, 5, 31, tzinfo=UTC)`` comes back naive. The
    walker has to subtract these against a ``datetime.now(UTC)`` which
    is always tz-aware; without normalisation Python raises
    ``TypeError: can't subtract offset-naive and offset-aware
    datetimes``.
    """
    from datetime import timezone as _tz

    if dt.tzinfo is None:
        return dt.replace(tzinfo=_tz.utc)
    return dt


def _row_is_due(row: Any, threshold_pct: float, now: Any) -> bool:
    """Return ``True`` when ``row`` has burned more than the threshold
    percentage of its issued lifetime.

    Threshold semantics match the cert-manager / smallstep convention:
    ``--threshold-pct 50`` renews any cert that has less than 50% of
    its TTL remaining (i.e. has used more than 50%). A freshly-issued
    cert at 0% elapsed is not due regardless of threshold.
    """
    not_before = _as_utc(row.not_before)
    not_after = _as_utc(row.not_after)
    window = not_after - not_before
    if window.total_seconds() <= 0:
        return True  # malformed window — renew defensively
    elapsed = (now - not_before).total_seconds()
    return (elapsed / window.total_seconds()) * 100 >= threshold_pct


@certs_app.command("renew")
def certs_renew(
    cert_id: int | None = typer.Option(
        None,
        "--id",
        help=(
            "Renew a specific row. Mutually exclusive with --due."
        ),
    ),
    due: bool = typer.Option(
        False,
        "--due/--no-due",
        help=(
            "Walk the registry and renew every non-revoked cert past "
            "the threshold percentage of its lifetime."
        ),
    ),
    threshold_pct: float = typer.Option(
        50.0,
        "--threshold-pct",
        help=(
            "Percentage of the cert's lifetime that must have elapsed "
            "for --due mode to consider the row stale. Default 50 — "
            "renew any cert past the halfway mark of its window."
        ),
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run/--no-dry-run",
        help=(
            "Print which certs would be renewed without minting or "
            "writing any files. Always exits 0."
        ),
    ),
    out_cert: Path | None = typer.Option(
        None,
        "--out-cert",
        help="Override the row's stored leaf path (single-id mode only).",
    ),
    out_key: Path | None = typer.Option(
        None,
        "--out-key",
        help="Override the row's stored key path (single-id mode only).",
    ),
    out_chain: Path | None = typer.Option(
        None,
        "--out-chain",
        help="Override the row's stored chain path (single-id mode only).",
    ),
    database_url: str | None = typer.Option(
        None,
        "--database-url",
        envvar="DATABASE_URL",
        help="Override the configured DATABASE_URL.",
    ),
) -> None:
    """Re-mint a leaf cert in place.

    Phase 2d CP4.3. Two modes:

    \b
    * ``--id N`` — renew one row. The new leaf is written to the
      row's stored ``out_*_path`` triple unless ``--out-cert/...``
      are passed explicitly.
    * ``--due`` — walk the registry and renew any non-revoked row
      whose lifetime has crossed the ``--threshold-pct`` mark.
      Rows without stored ``out_*_path`` columns are skipped (the
      walker has nowhere to write them); the operator gets a
      warning line per skip.

    A revoked row is never renewed — that would mint a fresh leaf
    for an identity the operator already decommissioned. The command
    is idempotent under ``--due``: re-running it after a recent
    successful renewal is a no-op because the fresh row's elapsed
    fraction is below the threshold.

    The systemd-timer pattern (see ``docs/deploy/systemd-timer.md``)
    runs ``wg-manager certs renew --due`` every hour; the threshold
    is the knob operators tune to trade rotation churn for headroom
    before expiry.
    """
    from datetime import datetime as _dt, timezone as _tz

    from sqlmodel import Session

    from wg_manager.models import Certificate
    from wg_manager.pki import make_pki_backend

    if (cert_id is None and not due) or (cert_id is not None and due):
        typer.secho(
            "exactly one of --id or --due must be supplied",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2)

    engine = _get_engine(database_url)
    backend = make_pki_backend() if not dry_run else None

    if cert_id is not None:
        with Session(engine) as session:
            row = session.get(Certificate, cert_id)
            if row is None:
                typer.secho(
                    f"no certificate registered with id={cert_id}",
                    fg=typer.colors.RED,
                    err=True,
                )
                raise typer.Exit(code=1)
            if row.revoked:
                typer.secho(
                    f"certificate id={cert_id} is revoked; "
                    "renewal is not supported for revoked certs",
                    fg=typer.colors.RED,
                    err=True,
                )
                raise typer.Exit(code=1)
            if dry_run:
                typer.echo(
                    f"DRY-RUN: would renew id={cert_id} "
                    f"serial={row.serial} cn={row.common_name!r}"
                )
                return
            try:
                new_row = _renew_row(
                    session,
                    backend,
                    row,
                    out_cert=out_cert,
                    out_key=out_key,
                    out_chain=out_chain,
                )
            except RuntimeError as exc:
                typer.secho(str(exc), fg=typer.colors.RED, err=True)
                raise typer.Exit(code=1)
            typer.echo(
                f"renewed certificate id={cert_id} -> new id={new_row.id} "
                f"serial={new_row.serial}"
            )
        return

    # --due walker. Out-* overrides are not honoured here because they
    # only make sense for a single row.
    if out_cert or out_key or out_chain:
        typer.secho(
            "--out-cert/--out-key/--out-chain only apply with --id",
            fg=typer.colors.YELLOW,
            err=True,
        )

    now = _dt.now(_tz.utc)
    with Session(engine) as session:
        rows = list(
            session.exec(
                select(Certificate).where(Certificate.revoked == False)  # noqa: E712
            )
        )
        due_rows = [
            r for r in rows if _row_is_due(r, threshold_pct, now)
        ]
        if not due_rows:
            typer.echo(
                f"no certs past --threshold-pct={threshold_pct} "
                f"(scanned {len(rows)} live row(s))"
            )
            return

        renewed = 0
        skipped = 0
        for r in due_rows:
            if dry_run:
                typer.echo(
                    f"DRY-RUN: would renew id={r.id} serial={r.serial} "
                    f"cn={r.common_name!r}"
                )
                continue
            try:
                new_row = _renew_row(
                    session,
                    backend,
                    r,
                    out_cert=None,
                    out_key=None,
                    out_chain=None,
                )
            except RuntimeError as exc:
                typer.secho(
                    f"skipping id={r.id}: {exc}",
                    fg=typer.colors.YELLOW,
                    err=True,
                )
                skipped += 1
                continue
            typer.echo(
                f"renewed id={r.id} -> new id={new_row.id} "
                f"serial={new_row.serial}"
            )
            renewed += 1

        if not dry_run:
            typer.echo(
                f"summary: renewed={renewed} skipped={skipped} "
                f"scanned={len(rows)}"
            )


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


# ---------------------------------------------------------------------------
# tenants — Phase 3b cycle 2
# ---------------------------------------------------------------------------
#
# Direct-DB CRUD against :class:`wg_manager.models.Tenant` + the new
# :class:`wg_manager.models.OperatorTenant` join. Mirrors the
# ``wg-manager operators add/list`` shape Phase 2d CP3.3 established
# as the canonical bootstrap path: works before the API listener is
# up, so an operator on a fresh install can seed tenants and their
# join rows without first standing up TLS. The dashboard / HTTP
# surface lands on top of the same tables — the CLI stays the
# canonical install / disaster-recovery path.


import re as _tenant_re


def _slugify(name: str) -> str:
    """Lowercase + collapse non-alphanumeric runs to single hyphens.

    Matches the cycle 5 validator shape (``^[a-z0-9-]+$``) so a tenant
    created via the CLI today will still parse cleanly once the cycle
    5 dashboard tightens the slug to a regex.
    """
    slug = _tenant_re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug or "tenant"


@tenants_app.command("create")
def tenants_create(
    name: str = typer.Option(
        ...,
        "--name",
        help="Human-readable tenant name. Unique.",
    ),
    slug: str | None = typer.Option(
        None,
        "--slug",
        help=(
            "URL-/CLI-safe identifier. Defaults to a kebab-case form "
            "of --name."
        ),
    ),
    subnet_pool: str | None = typer.Option(
        None,
        "--subnet-pool",
        help=(
            "CIDR carving the tenant's slice of the WireGuard IP "
            "space (Phase 3b cycle 4). Required to be disjoint from "
            "every existing tenant's pool. Defaults to the model "
            "fallback ('10.0.0.0/8') when omitted."
        ),
    ),
    database_url: str | None = typer.Option(
        None,
        "--database-url",
        envvar="DATABASE_URL",
        help="Override the configured DATABASE_URL.",
    ),
) -> None:
    """Create a new tenant namespace.

    The tenant becomes the home of any resource later created with
    ``--tenant <slug>`` (cycle 3+ wires the routers). The default
    tenant (``slug='default'``) is created by Alembic 0014 — every
    pre-Phase-3b row gets back-filled there.
    """
    from ipaddress import IPv4Network

    from sqlmodel import Session

    from wg_manager.ipam import pools_overlap
    from wg_manager.models import Tenant

    target_slug = slug or _slugify(name)
    if subnet_pool is not None:
        try:
            IPv4Network(subnet_pool, strict=True)
        except (ValueError, TypeError) as exc:
            typer.secho(
                f"invalid --subnet-pool {subnet_pool!r}: {exc}",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)
    engine = _get_engine(database_url)
    with Session(engine) as session:
        existing = session.exec(
            select(Tenant).where(Tenant.slug == target_slug)
        ).first()
        if existing is not None:
            typer.secho(
                f"tenant with slug {target_slug!r} already exists "
                f"(id={existing.id}, name={existing.name!r})",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)
        existing_name = session.exec(
            select(Tenant).where(Tenant.name == name)
        ).first()
        if existing_name is not None:
            typer.secho(
                f"tenant with name {name!r} already exists "
                f"(id={existing_name.id}, slug={existing_name.slug!r})",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)
        if subnet_pool is not None:
            for other in session.exec(select(Tenant)).all():
                if other.subnet_pool and pools_overlap(
                    subnet_pool, other.subnet_pool
                ):
                    typer.secho(
                        f"--subnet-pool {subnet_pool!r} overlaps "
                        f"tenant {other.slug!r}'s pool "
                        f"{other.subnet_pool!r}",
                        fg=typer.colors.RED,
                        err=True,
                    )
                    raise typer.Exit(code=1)
        row = Tenant(name=name, slug=target_slug)
        if subnet_pool is not None:
            row.subnet_pool = subnet_pool
        session.add(row)
        session.commit()
        session.refresh(row)
        typer.echo(
            f"created tenant id={row.id} name={row.name!r} "
            f"slug={row.slug!r} subnet_pool={row.subnet_pool!r}"
        )


@tenants_app.command("list")
def tenants_list(
    database_url: str | None = typer.Option(
        None,
        "--database-url",
        envvar="DATABASE_URL",
        help="Override the configured DATABASE_URL.",
    ),
) -> None:
    """Print every tenant row as JSON.

    Output is a JSON array — pipe through ``jq`` to filter by ``slug``.
    """
    from sqlmodel import Session

    from wg_manager.models import Tenant

    engine = _get_engine(database_url)
    with Session(engine) as session:
        rows = session.exec(select(Tenant)).all()
    payload = [
        {
            "id": row.id,
            "name": row.name,
            "slug": row.slug,
            "subnet_pool": row.subnet_pool,
            "created_at": (
                row.created_at.isoformat() if row.created_at else None
            ),
        }
        for row in rows
    ]
    typer.echo(json.dumps(payload, indent=2, default=str, sort_keys=True))


@tenants_app.command("get")
def tenants_get(
    slug: str = typer.Argument(..., help="Tenant slug."),
    database_url: str | None = typer.Option(
        None,
        "--database-url",
        envvar="DATABASE_URL",
        help="Override the configured DATABASE_URL.",
    ),
) -> None:
    """Print a single tenant row by slug.

    Exits non-zero with a clear error if the slug is unknown so a
    pipeline (``wg-manager tenants get acme | jq ...``) fails fast.
    """
    from sqlmodel import Session

    from wg_manager.models import Tenant

    engine = _get_engine(database_url)
    with Session(engine) as session:
        row = session.exec(
            select(Tenant).where(Tenant.slug == slug)
        ).first()
    if row is None:
        typer.secho(
            f"no tenant with slug {slug!r}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1)
    payload = {
        "id": row.id,
        "name": row.name,
        "slug": row.slug,
        "subnet_pool": row.subnet_pool,
        "created_at": (
            row.created_at.isoformat() if row.created_at else None
        ),
    }
    typer.echo(json.dumps(payload, indent=2, default=str, sort_keys=True))


# ---------------------------------------------------------------------------
# operators attach-tenant / detach-tenant / list-tenants — Phase 3b cycle 2
# ---------------------------------------------------------------------------
#
# Manage the :class:`wg_manager.models.OperatorTenant` join. The
# subcommands live under ``operators`` rather than ``tenants`` so the
# subject of the action (the operator whose access is being granted /
# revoked) is the first noun in the command path.


def _lookup_operator(session: Any, cn: str) -> Any:
    """Return the :class:`Operator` row keyed by CN, or None."""
    from wg_manager.models import Operator

    return session.exec(select(Operator).where(Operator.cn == cn)).first()


def _lookup_tenant(session: Any, slug: str) -> Any:
    """Return the :class:`Tenant` row keyed by slug, or None."""
    from wg_manager.models import Tenant

    return session.exec(select(Tenant).where(Tenant.slug == slug)).first()


@operators_app.command("attach-tenant")
def operators_attach_tenant(
    cn: str = typer.Option(..., "--cn", help="Operator CN."),
    tenant: str = typer.Option(
        ...,
        "--tenant",
        help="Tenant slug to grant the operator access to.",
    ),
    role: _OperatorRoleArg = typer.Option(
        _OperatorRoleArg.operator,
        "--role",
        help=(
            "Per-tenant permission tier. Defaults to 'operator' "
            "(principle of least privilege — admins must be set "
            "explicitly per tenant too)."
        ),
    ),
    database_url: str | None = typer.Option(
        None,
        "--database-url",
        envvar="DATABASE_URL",
        help="Override the configured DATABASE_URL.",
    ),
) -> None:
    """Attach an operator to a tenant with a per-tenant role.

    Refuses with a non-zero exit if the operator or tenant doesn't
    exist, or if the pair is already joined. The DB has a unique
    constraint on ``(operator_id, tenant_id)`` — this command surfaces
    the lookup failure first so the operator gets a clean error rather
    than a raw IntegrityError.
    """
    from sqlmodel import Session

    from wg_manager.models import OperatorRole, OperatorTenant

    engine = _get_engine(database_url)
    with Session(engine) as session:
        op_row = _lookup_operator(session, cn)
        if op_row is None:
            typer.secho(
                f"no operator with CN {cn!r}",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)
        tenant_row = _lookup_tenant(session, tenant)
        if tenant_row is None:
            typer.secho(
                f"no tenant with slug {tenant!r}",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)
        existing = session.exec(
            select(OperatorTenant).where(
                OperatorTenant.operator_id == op_row.id,
                OperatorTenant.tenant_id == tenant_row.id,
            )
        ).first()
        if existing is not None:
            typer.secho(
                f"operator {cn!r} already attached to tenant "
                f"{tenant!r} (role={existing.role.value})",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)
        join = OperatorTenant(
            operator_id=int(op_row.id or 0),
            tenant_id=int(tenant_row.id or 0),
            role=OperatorRole(role.value),
        )
        session.add(join)
        session.commit()
        session.refresh(join)
        typer.echo(
            f"attached operator cn={cn!r} to tenant slug={tenant!r} "
            f"role={join.role.value}"
        )


@operators_app.command("detach-tenant")
def operators_detach_tenant(
    cn: str = typer.Option(..., "--cn", help="Operator CN."),
    tenant: str = typer.Option(
        ...,
        "--tenant",
        help="Tenant slug to revoke the operator's access from.",
    ),
    database_url: str | None = typer.Option(
        None,
        "--database-url",
        envvar="DATABASE_URL",
        help="Override the configured DATABASE_URL.",
    ),
) -> None:
    """Detach an operator from a tenant.

    Refuses with a non-zero exit if the operator or tenant doesn't
    exist, or if the operator isn't currently attached to the tenant.
    """
    from sqlmodel import Session

    from wg_manager.models import OperatorTenant

    engine = _get_engine(database_url)
    with Session(engine) as session:
        op_row = _lookup_operator(session, cn)
        if op_row is None:
            typer.secho(
                f"no operator with CN {cn!r}",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)
        tenant_row = _lookup_tenant(session, tenant)
        if tenant_row is None:
            typer.secho(
                f"no tenant with slug {tenant!r}",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)
        join = session.exec(
            select(OperatorTenant).where(
                OperatorTenant.operator_id == op_row.id,
                OperatorTenant.tenant_id == tenant_row.id,
            )
        ).first()
        if join is None:
            typer.secho(
                f"operator {cn!r} is not attached to tenant {tenant!r}",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)
        session.delete(join)
        session.commit()
        typer.echo(
            f"detached operator cn={cn!r} from tenant slug={tenant!r}"
        )


@operators_app.command("list-tenants")
def operators_list_tenants(
    cn: str = typer.Option(..., "--cn", help="Operator CN."),
    database_url: str | None = typer.Option(
        None,
        "--database-url",
        envvar="DATABASE_URL",
        help="Override the configured DATABASE_URL.",
    ),
) -> None:
    """Print every tenant the operator is attached to as JSON.

    Each entry surfaces the join's per-tenant role + the tenant's
    slug + name so a pipeline can render a human-readable summary
    without a second lookup.
    """
    from sqlmodel import Session

    from wg_manager.models import OperatorTenant, Tenant

    engine = _get_engine(database_url)
    with Session(engine) as session:
        op_row = _lookup_operator(session, cn)
        if op_row is None:
            typer.secho(
                f"no operator with CN {cn!r}",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)
        joins = session.exec(
            select(OperatorTenant, Tenant)
            .join(Tenant, Tenant.id == OperatorTenant.tenant_id)
            .where(OperatorTenant.operator_id == op_row.id)
        ).all()
    payload = [
        {
            "id": join.id,
            "tenant_id": tenant.id,
            "tenant_slug": tenant.slug,
            "tenant_name": tenant.name,
            "role": join.role.value,
            "created_at": (
                join.created_at.isoformat() if join.created_at else None
            ),
        }
        for join, tenant in joins
    ]
    typer.echo(json.dumps(payload, indent=2, default=str, sort_keys=True))


# ---------------------------------------------------------------------------
# bootstrap-host — Phase 2c CP4.5
# ---------------------------------------------------------------------------
#
# Operator-facing seam between a fresh box (only a long-lived
# operator SSH key works against it) and a wg-manager-managed box
# (the production runner needs CA-mode trust). Lays down the three
# files the production path needs and exits; the operator follows
# up with ``wg-manager servers register`` / ``clients register`` to
# catalogue the box in the state store. No DB writes here on
# purpose — bootstrap and registration are two operator actions so
# the operator can verify the install before committing a row.


@app.command("bootstrap-host")
def bootstrap_host_cmd(
    hostname: str = typer.Option(
        ...,
        "--hostname",
        "-H",
        help=(
            "SSH-dial-name / IP of the target host. Also the cert "
            "principal when --principal is not supplied."
        ),
    ),
    ssh_key: Path = typer.Option(
        ...,
        "--ssh-key",
        "-k",
        exists=True,
        dir_okay=False,
        readable=True,
        help=(
            "Path to the operator's long-lived OOB SSH private key "
            "(e.g. ~/.ssh/id_ed25519). Used once to TOFU the host "
            "so the CA + host cert can be installed; the production "
            "path subsequently uses Vault-minted certs."
        ),
    ),
    ssh_key_passphrase: str | None = typer.Option(
        None,
        "--ssh-key-passphrase",
        envvar="WG_MANAGER_BOOTSTRAP_SSH_KEY_PASSPHRASE",
        help=(
            "Passphrase protecting --ssh-key. Reads from "
            "WG_MANAGER_BOOTSTRAP_SSH_KEY_PASSPHRASE if not passed "
            "on the command line; omit both for an unencrypted key."
        ),
    ),
    ssh_user: str = typer.Option(
        "ubuntu",
        "--ssh-user",
        "-u",
        help=(
            "Remote SSH user for the bootstrap session. Must already "
            "exist on the box and have passwordless sudo."
        ),
    ),
    ssh_port: int = typer.Option(
        22,
        "--ssh-port",
        help="SSH port on the target host (default 22).",
    ),
    principal: str | None = typer.Option(
        None,
        "--principal",
        "-p",
        help=(
            "Cert principal baked into the new host cert. Defaults "
            "to --hostname; pass a different value when the SSH "
            "dial-name and the cert principal differ (e.g. public "
            "IP vs internal DNS)."
        ),
    ),
    ttl_seconds: int | None = typer.Option(
        None,
        "--ttl-seconds",
        help=(
            "TTL the host cert asks the CA for. Defaults to "
            "Settings.ssh_host_cert_ttl_seconds (24h). Vault caps "
            "this at the host-role's max_ttl."
        ),
    ),
    connect_timeout: float = typer.Option(
        15.0,
        "--connect-timeout",
        help="Seconds to wait for TCP handshake / banner / auth.",
    ),
) -> None:
    """Install the wg-manager SSH CA trust + a host cert on a fresh host.

    Phase 2c CP4.5. Closes the bootstrap gap CP4.4 created: the
    production SSH path is locked to CA-only auth, so a brand-new
    box has nothing for it to talk to. This command opens an
    out-of-band SSH session with the operator's long-lived key,
    drops the CA pubkey + a CA-signed host cert + an sshd drop-in
    onto the box, reloads sshd, and exits.

    \b
    Prerequisites:
    * Vault SSH CA already bootstrapped (`make ssh-ca-bootstrap`).
      Vault unreachable → exit 1.
    * Operator SSH key already authorized on the target host. SSH
      refused → exit 1 (with the underlying paramiko reason).
    * The target user has passwordless sudo. Missing sudo → exit 1
      (the install will surface SSHCommandError mid-flight).

    \b
    No database writes happen here. Run `wg-manager servers register`
    (or `clients register`) after a successful bootstrap to catalogue
    the box in the state store.
    """
    settings = Settings()

    try:
        ca = make_ssh_ca_backend(settings)
    except SSHCAError as exc:
        typer.secho(
            f"failed to reach the SSH CA backend: {exc}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1) from exc

    effective_principal = principal or hostname
    effective_ttl = (
        ttl_seconds
        if ttl_seconds is not None
        else settings.ssh_host_cert_ttl_seconds
    )

    runner = BootstrapSSHRunner(
        host=hostname,
        port=ssh_port,
        username=ssh_user,
        key_path=ssh_key,
        passphrase=ssh_key_passphrase,
        connect_timeout=connect_timeout,
    )

    try:
        with runner as session:
            cert = bootstrap_host(
                runner=session,
                hostname=hostname,
                principal=effective_principal,
                ca=ca,
                ttl_seconds=effective_ttl,
                cn=ssh_user,
            )
    except SSHConnectionError as exc:
        typer.secho(
            f"SSH connection to {hostname}:{ssh_port} failed: {exc}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1) from exc
    except SSHCAError as exc:
        typer.secho(
            f"SSH CA refused to sign: {exc}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1) from exc

    # One-line summary so operator scripts can grep ``^[OK]`` to
    # confirm the install landed. The serial is the join key against
    # the future ``servers register`` row.
    typer.echo(
        f"[OK] bootstrapped {hostname}: "
        f"cert serial={cert.serial} "
        f"valid_until={cert.valid_before.isoformat()}"
    )


# ---------------------------------------------------------------------------
# evidence pack — Phase 2e cycle 4
# ---------------------------------------------------------------------------


@evidence_app.command("pack")
def evidence_pack(
    output: Path = typer.Option(
        ...,
        "--output",
        "-o",
        help="Path to write the tar.gz evidence pack.",
    ),
    since_days: int = typer.Option(
        30,
        "--since-days",
        help=(
            "Window applied to time-filtered sources (auditevent table + "
            "Vault audit log slice). The ROADMAP default is 30."
        ),
    ),
    vault_audit_log: Path = typer.Option(
        Path("/vault/logs/audit.log"),
        "--vault-audit-log",
        help=(
            "Path to the Vault audit log file. Default matches the path "
            "the docker-compose ``vault`` service mounts. A missing file "
            "is recorded in vault_audit_integrity.json rather than "
            "failing the pack — production stacks may not co-locate the "
            "log with the host running ``make evidence``."
        ),
    ),
    database_url: str | None = typer.Option(
        None,
        "--database-url",
        envvar="DATABASE_URL",
        help="Override the configured DATABASE_URL.",
    ),
) -> None:
    """Generate a SOC 2-style evidence pack as a tar.gz.

    Pulls together four sources — auditevent table (last N days), the
    full certificate + operator registries, and a Vault audit log
    slice with a structural integrity report — plus a deployment-
    context snapshot and a MANIFEST + SHA256SUMS for tamper-evidence.

    The tarball is self-contained: extract and run ``sha256sum -c
    SHA256SUMS`` inside the pack directory to verify every file.
    """
    from sqlmodel import Session

    from wg_manager.evidence import build_pack

    engine = _get_engine(database_url)
    with Session(engine) as session:
        build_pack(
            output,
            session=session,
            since_days=since_days,
            vault_audit_log=vault_audit_log,
        )

    typer.echo(f"evidence pack written to {output}")


def main() -> None:  # pragma: no cover - thin entrypoint
    """Console-script entrypoint."""
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
