"""IP address management for the WireGuard subnet."""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network, ip_interface
from typing import cast

from sqlmodel import Session, select

from wg_manager.models import Client, Server


class IPPoolExhausted(RuntimeError):
    """Raised when no free host addresses remain in the subnet."""


def _host_from_cidr(value: str) -> IPv4Address:
    """Return the host part of a CIDR-annotated address.

    :param value: CIDR string such as ``10.9.0.5/32``.
    :type value: str
    :return: The parsed host address.
    :rtype: IPv4Address
    """
    return cast(IPv4Address, ip_interface(value).ip)


def allocate_client_ip(session: Session, server: Server) -> IPv4Address:
    """Allocate the lowest free host address in ``server.subnet``.

    The network address, broadcast address, and the server's own address
    (conventionally ``.1``) are reserved. Existing ``Client`` rows for the
    given server are excluded from the pool.

    :param session: Active SQLModel session used to query existing clients.
    :type session: Session
    :param server: The WireGuard server whose subnet is being allocated from.
    :type server: Server
    :return: The next available host address.
    :rtype: IPv4Address
    :raises IPPoolExhausted: When every host address has been consumed.
    """
    network = IPv4Network(server.subnet, strict=False)
    server_ip = _host_from_cidr(server.address)

    taken: set[IPv4Address] = {network.network_address, network.broadcast_address, server_ip}

    rows = session.exec(select(Client.address).where(Client.server_id == server.id)).all()
    for addr in rows:
        if addr:
            taken.add(_host_from_cidr(addr))

    for host in network.hosts():
        if host not in taken:
            return host

    raise IPPoolExhausted(f"No free addresses remain in {server.subnet}")
