"""High-level WireGuard provisioning operations.

All public functions are idempotent and safe to re-run — repeated invocations
overwrite the remote ``wg0.conf``, reuse the existing keypair (so the public
key stays stable), and restart ``wg-quick`` to pick up changes.
"""

from __future__ import annotations

import base64
from collections.abc import Iterable
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from wg_manager.models import Client, Server
from wg_manager.ssh import SSHRunner

_SERVER_INTERFACE_TEMPLATE = """\
[Interface]
Address = {address}
ListenPort = {listen_port}
PrivateKey = $(cat /etc/wireguard/privatekey)
PostUp = iptables -A FORWARD -i {interface} -j ACCEPT; iptables -A FORWARD -o {interface} -j ACCEPT; iptables -t nat -A POSTROUTING -s {subnet} -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i {interface} -j ACCEPT; iptables -D FORWARD -o {interface} -j ACCEPT; iptables -t nat -D POSTROUTING -s {subnet} -o eth0 -j MASQUERADE
"""

_SERVER_PEER_TEMPLATE = """
[Peer]
# {name}
PublicKey = {public_key}
AllowedIPs = {allowed_ips}
"""

_CLIENT_CONF_TEMPLATE = """\
[Interface]
Address = {address}
PrivateKey = $(cat /etc/wireguard/privatekey)

[Peer]
PublicKey = {server_pubkey}
Endpoint = {endpoint_host}:{endpoint_port}
AllowedIPs = {subnet}
PersistentKeepalive = 25
"""


# Manual-install variant of the client config: the private key is rendered
# inline rather than read from a file on the remote device, since the whole
# point of the manual flow is that wg-manager never touches the device. The
# operator drops this body into ``/etc/wireguard/wg0.conf`` (or imports it
# into a phone's WireGuard app) by hand.
_MANUAL_CLIENT_CONF_TEMPLATE = """\
[Interface]
PrivateKey = {private_key}
Address = {address}

[Peer]
PublicKey = {server_pubkey}
Endpoint = {endpoint_host}:{endpoint_port}
AllowedIPs = {subnet}
PersistentKeepalive = 25
"""


def generate_wireguard_keypair() -> tuple[str, str]:
    """Generate a fresh WireGuard X25519 keypair.

    WireGuard keys are raw 32-byte X25519 values encoded with standard
    base64 (no PEM, no PKCS framing). ``wg genkey`` / ``wg pubkey`` on the
    command line produce the same byte format; the keys this function
    returns are interchangeable with anything written into
    ``/etc/wireguard/privatekey`` by the SSH-provisioned flow.

    :return: ``(private_key_b64, public_key_b64)`` — both are 44-character
        base64 strings safe to drop straight into ``wg0.conf``.
    :rtype: tuple[str, str]
    """
    priv = X25519PrivateKey.generate()
    priv_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return (
        base64.b64encode(priv_raw).decode("ascii"),
        base64.b64encode(pub_raw).decode("ascii"),
    )


def render_manual_client_config(
    client: Client, server: Server, *, private_key: str
) -> str:
    """Render a stand-alone ``wg0.conf`` body for a manually-installed client.

    Unlike :func:`provision_client`, the private key is baked into the
    rendered text because wg-manager has no way to push it to the device
    over SSH. The caller is responsible for ``client.is_manual is True``
    and for supplying the *decrypted* private key — the row itself no
    longer carries plaintext (Phase 2b's drop-plaintext migration
    removed the ``client.private_key`` column).

    :param client: The manual :class:`wg_manager.models.Client` row.
    :type client: Client
    :param server: The hub :class:`wg_manager.models.Server` the client
        connects to. Its ``public_key``, ``endpoint_host``,
        ``endpoint_port`` and ``subnet`` fields are interpolated into
        the rendered config.
    :type server: Server
    :param private_key: Decrypted WireGuard private key to render into
        the ``[Interface]`` block. Use
        :func:`wg_manager.crypto.resolve_client_private_key` to obtain
        it from the row's ciphertext column.
    :type private_key: str
    :return: The body of the WireGuard config file as text.
    :rtype: str
    :raises ValueError: If ``client`` is not a manual client or the
        supplied private key is empty.
    """
    if not client.is_manual:
        raise ValueError("render_manual_client_config requires a manual client")
    if not private_key:
        raise ValueError("manual client has no stored private key")
    return _MANUAL_CLIENT_CONF_TEMPLATE.format(
        private_key=private_key,
        address=client.address,
        server_pubkey=server.public_key,
        endpoint_host=server.endpoint_host,
        endpoint_port=server.endpoint_port,
        subnet=server.subnet,
    )


def _install_wireguard(runner: SSHRunner) -> None:
    """Ensure WireGuard is installed on the remote host (idempotent)."""
    runner.sudo("apt-get update -y")
    runner.sudo("DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard iptables")


def _ensure_keypair(runner: SSHRunner) -> str:
    """Generate a WireGuard keypair on the remote host if one is not already present.

    Returns the remote node's public key, stripped of whitespace. Existing
    keys are never overwritten — preserving the public key means previously
    registered peers stay valid after a re-provision.
    """
    runner.sudo("mkdir -p /etc/wireguard")
    runner.sudo("chmod 700 /etc/wireguard")
    runner.sudo(
        "sh -c 'test -s /etc/wireguard/privatekey || "
        "(wg genkey | tee /etc/wireguard/privatekey | wg pubkey > /etc/wireguard/publickey)'"
    )
    runner.sudo("chmod 600 /etc/wireguard/privatekey")
    result = runner.sudo("cat /etc/wireguard/publickey")
    return result.stdout.strip()


def _render_server_config(server: Server, clients: Iterable[Client]) -> str:
    """Render the full ``wg0.conf`` body for the server.

    The server's private key is represented as the literal placeholder
    ``$(cat /etc/wireguard/privatekey)`` which is substituted on the remote
    host via ``sed`` at write time — the control-plane never sees the key.
    """
    body = _SERVER_INTERFACE_TEMPLATE.format(
        address=server.address,
        listen_port=server.endpoint_port,
        interface=server.interface,
        subnet=server.subnet,
    )
    for peer in clients:
        body += _SERVER_PEER_TEMPLATE.format(
            name=peer.name,
            public_key=peer.public_key,
            allowed_ips=peer.address,
        )
    return body


def _write_server_config(
    runner: SSHRunner,
    server: Server,
    clients: Iterable[Client],
) -> None:
    """Render the server's ``wg0.conf`` and atomically overwrite it on the host.

    The file is always rewritten from scratch based on ``clients``, so this
    function is safe to call on a partially-configured node.
    """
    conf = _render_server_config(server, clients)
    conf_path = f"/etc/wireguard/{server.interface}.conf"
    runner.sudo(
        "sh -c 'cat > /tmp/wg0.conf.tpl <<\"WGEOF\"\n"
        + conf
        + "WGEOF'"
    )
    runner.sudo(
        "sh -c 'PK=$(cat /etc/wireguard/privatekey) && "
        "sed \"s|\\$(cat /etc/wireguard/privatekey)|$PK|\" /tmp/wg0.conf.tpl "
        f"> {conf_path}'"
    )
    runner.sudo(f"chmod 600 {conf_path}")
    runner.sudo("rm -f /tmp/wg0.conf.tpl")


def _enable_ip_forwarding(runner: SSHRunner) -> None:
    """Turn on IPv4 forwarding and persist it across reboots."""
    runner.sudo("sysctl -w net.ipv4.ip_forward=1")
    runner.write_file(
        "/etc/sysctl.d/99-wg-manager.conf",
        "net.ipv4.ip_forward=1\n",
        mode="644",
        sudo=True,
    )


def _restart_interface(runner: SSHRunner, interface: str) -> None:
    """Enable and (re)start the ``wg-quick@<interface>`` systemd unit."""
    runner.sudo(f"systemctl enable wg-quick@{interface}")
    runner.sudo(
        f"sh -c 'systemctl restart wg-quick@{interface} || "
        f"systemctl start wg-quick@{interface}'"
    )


def _ensure_interface_down(runner: SSHRunner, interface: str) -> None:
    """Bring down any pre-existing wg interface before rewriting its config.

    Called from :func:`provision_server` and :func:`provision_client` so a
    reprovision against a host that already has a tunnel up (typically the
    debris of an earlier half-failed run) starts from a clean slate. The new
    ``<interface>.conf`` is then written into place and ``wg-quick up`` is
    invoked by :func:`_restart_interface`.

    All three steps are tolerant of "nothing to do" — fresh hosts have no
    config, no running interface, and no enabled systemd unit, so the calls
    are safe no-ops there. The command sequence is:

    1. ``systemctl stop wg-quick@<iface>`` — stop the unit first so it can't
       race the teardown by auto-restarting; ``check=False`` because the
       unit may not exist yet on a brand-new host.
    2. ``wg-quick down <iface>`` if ``/etc/wireguard/<iface>.conf`` exists.
       ``wg-quick`` refuses to run without a config, so guard with
       ``test -f`` and ``|| true`` to keep first-provision happy.
    3. ``ip link delete <iface>`` if the interface is still present —
       belt-and-braces for the pathological case where the conf was missing
       but the link was somehow still up (e.g. ``wg-quick down`` errored
       mid-cleanup on the previous attempt).

    Skipping this leaves stale keys/peers bound to the kernel interface, and
    the subsequent rewrite of ``<interface>.conf`` either fails to bind or
    silently never takes effect — the operator sees "reprovision succeeded"
    while the box is still running the old config.

    :param runner: Open SSH runner bound to the target node.
    :type runner: SSHRunner
    :param interface: WireGuard interface name (e.g. ``"wg0"``).
    :type interface: str
    """
    conf_path = f"/etc/wireguard/{interface}.conf"
    runner.sudo(f"systemctl stop wg-quick@{interface}", check=False)
    runner.sudo(
        f"sh -c 'test -f {conf_path} && wg-quick down {interface} || true'"
    )
    runner.sudo(
        f"sh -c 'ip link show {interface} >/dev/null 2>&1 && "
        f"ip link delete {interface} || true'"
    )


def provision_server(
    runner: SSHRunner,
    server: Server,
    clients: Iterable[Client] = (),
) -> str:
    """Install WireGuard, write the full ``wg0.conf``, and (re)start the interface.

    :param runner: Open SSH runner bound to the server node.
    :type runner: SSHRunner
    :param server: The :class:`Server` row being provisioned.
    :type server: Server
    :param clients: Currently-registered peers to seed the config with. Pass
        an empty iterable on first registration; pass the current ready
        clients when re-provisioning so existing peers are preserved.
    :type clients: Iterable[Client]
    :return: The server's WireGuard public key.
    :rtype: str
    """
    _install_wireguard(runner)
    public_key = _ensure_keypair(runner)
    # Tear down any pre-existing tunnel before rewriting its config — see
    # the docstring on _ensure_interface_down for the full rationale. Safe
    # no-op on first provision when no config / interface yet exists.
    _ensure_interface_down(runner, server.interface)
    _write_server_config(runner, server, clients)
    _enable_ip_forwarding(runner)
    _restart_interface(runner, server.interface)
    return public_key


def reconfigure_server(
    runner: SSHRunner,
    server: Server,
    clients: Iterable[Client],
) -> None:
    """Regenerate ``wg0.conf`` from ``clients`` and restart the interface.

    Does **not** run ``apt-get`` or touch the keypair — this is the fast
    path taken after a client join/leave, not a full re-provision.
    """
    _write_server_config(runner, server, clients)
    _restart_interface(runner, server.interface)


def provision_client(runner: SSHRunner, client: Client, server: Server) -> str:
    """Install and configure WireGuard on a spoke node.

    Safe to re-run: the keypair is preserved and ``wg0.conf`` is overwritten.

    :param runner: Open SSH runner bound to the client node.
    :type runner: SSHRunner
    :param client: The :class:`Client` row being provisioned.
    :type client: Client
    :param server: The hub :class:`Server` the client connects to.
    :type server: Server
    :return: The client's WireGuard public key.
    :rtype: str
    """
    _install_wireguard(runner)
    public_key = _ensure_keypair(runner)
    # Tear down any pre-existing wg0 before rewriting it — without this a
    # reprovision against a host that's still running the old tunnel ends
    # up writing the new config while the kernel is still bound to the
    # stale keys/peers, and the new config silently doesn't take effect.
    _ensure_interface_down(runner, "wg0")

    conf = _CLIENT_CONF_TEMPLATE.format(
        address=client.address,
        server_pubkey=server.public_key,
        endpoint_host=server.endpoint_host,
        endpoint_port=server.endpoint_port,
        subnet=server.subnet,
    )
    runner.sudo(
        "sh -c 'cat > /tmp/wg0.conf.tpl <<\"WGEOF\"\n"
        + conf
        + "WGEOF'"
    )
    runner.sudo(
        "sh -c 'PK=$(cat /etc/wireguard/privatekey) && "
        "sed \"s|\\$(cat /etc/wireguard/privatekey)|$PK|\" /tmp/wg0.conf.tpl "
        "> /etc/wireguard/wg0.conf'"
    )
    runner.sudo("chmod 600 /etc/wireguard/wg0.conf")
    runner.sudo("rm -f /tmp/wg0.conf.tpl")

    _restart_interface(runner, "wg0")
    return public_key


# ---------------------------------------------------------------------------
# Peer discovery
# ---------------------------------------------------------------------------


@dataclass(slots=True, frozen=True)
class InterfaceInfo:
    """Local interface info parsed from line 1 of ``wg show <iface> dump``.

    :ivar public_key: The interface's WireGuard public key.
    :ivar listen_port: UDP port the interface listens on.
    :ivar fwmark: Optional firewall mark, or ``None`` when reported as ``off``.
    """

    public_key: str
    listen_port: int
    fwmark: int | None


@dataclass(slots=True, frozen=True)
class PeerInfo:
    """One peer parsed from a ``wg show <iface> dump`` line.

    Field order matches the columns ``wg(8)`` prints: ``public-key``,
    ``preshared-key``, ``endpoint``, ``allowed-ips``, ``latest-handshake``
    (unix seconds, ``0`` means "never"), ``transfer-rx``, ``transfer-tx``,
    ``persistent-keepalive`` (``off`` when disabled).
    """

    public_key: str
    preshared_key: str | None
    endpoint: str | None
    allowed_ips: str
    last_handshake_epoch: int
    rx_bytes: int
    tx_bytes: int
    persistent_keepalive: int | None


def _nullable(value: str) -> str | None:
    """Return ``None`` for WireGuard's sentinel ``(none)`` / ``off`` values."""
    if value in {"(none)", "off", ""}:
        return None
    return value


def parse_wg_dump(dump: str) -> tuple[InterfaceInfo, list[PeerInfo]]:
    """Parse the tab-separated output of ``wg show <iface> dump``.

    The first non-blank line describes the local interface (private-key,
    public-key, listen-port, fwmark). Each subsequent non-blank line is one
    peer. Blank lines are ignored so noisy SSH output won't break parsing.

    :param dump: Raw stdout of ``wg show <iface> dump``.
    :type dump: str
    :return: ``(interface, peers)`` parsed from the dump.
    :rtype: tuple[InterfaceInfo, list[PeerInfo]]
    :raises ValueError: If the interface line is missing or malformed.
    """
    lines = [line for line in dump.splitlines() if line.strip()]
    if not lines:
        raise ValueError("empty wg dump output")

    iface_cols = lines[0].split("\t")
    if len(iface_cols) < 4:
        raise ValueError(f"malformed interface line: {lines[0]!r}")
    _priv, pub, listen_port, fwmark = iface_cols[:4]
    interface = InterfaceInfo(
        public_key=pub,
        listen_port=int(listen_port),
        fwmark=None if fwmark == "off" else int(fwmark, 16) if fwmark.startswith("0x") else int(fwmark),
    )

    peers: list[PeerInfo] = []
    for line in lines[1:]:
        cols = line.split("\t")
        if len(cols) < 8:
            # Skip rows we can't safely interpret rather than blowing up the
            # whole discovery — operators value partial data over none.
            continue
        public_key, preshared, endpoint, allowed_ips, handshake, rx, tx, keepalive = cols[:8]
        peers.append(
            PeerInfo(
                public_key=public_key,
                preshared_key=_nullable(preshared),
                endpoint=_nullable(endpoint),
                allowed_ips=allowed_ips,
                last_handshake_epoch=int(handshake) if handshake.isdigit() else 0,
                rx_bytes=int(rx) if rx.isdigit() else 0,
                tx_bytes=int(tx) if tx.isdigit() else 0,
                persistent_keepalive=int(keepalive) if keepalive.isdigit() else None,
            )
        )
    return interface, peers


def discover_peers(runner: SSHRunner, server: Server) -> tuple[InterfaceInfo, list[PeerInfo]]:
    """Run ``wg show <interface> dump`` on the host and parse the output.

    :param runner: Open SSH runner bound to the server node.
    :type runner: SSHRunner
    :param server: The :class:`Server` whose peers should be enumerated.
    :type server: Server
    :return: Parsed interface info and peer list (may be empty).
    :rtype: tuple[InterfaceInfo, list[PeerInfo]]
    """
    result = runner.sudo(f"wg show {server.interface} dump")
    return parse_wg_dump(result.stdout)
