"""IP address management for the WireGuard subnet.

Phase 3b cycle 4 partitions IP space per tenant. Each
:class:`wg_manager.models.Tenant` carries a ``subnet_pool`` CIDR;
every server's ``subnet`` must lie inside its tenant's pool, and two
tenants' pools must be disjoint so a client IP in one tenant cannot
collide with a client IP in another. The new :func:`subnet_in_pool`
and :func:`pools_overlap` helpers are the two predicates the routers
+ CLI consult; :func:`allocate_client_ip` (Phase 1) is unchanged
because it already walks the *server's* subnet — which is now
guaranteed to live inside the tenant's pool.
"""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network, ip_interface
from typing import cast

from sqlmodel import Session, select

from wg_manager.models import Client, Server


class IPPoolExhausted(RuntimeError):
    """Raised when no free host addresses remain in the subnet."""


# ---------------------------------------------------------------------------
# Phase 3b cycle 4 — per-tenant pool predicates
# ---------------------------------------------------------------------------


def _parse_pool(value: str) -> IPv4Network:
    """Strictly parse a CIDR string. Raises :class:`ValueError` on
    malformed input — callers translate to the right HTTP / CLI shape."""
    return IPv4Network(value, strict=True)


def subnet_in_pool(subnet: str, pool: str) -> bool:
    """Return ``True`` iff ``subnet`` lies fully inside ``pool``.

    A subnet that overlaps but isn't a strict subnet (e.g. a /16
    candidate against a /17 pool) returns ``False`` — partial
    overlap is still a collision risk, so the predicate is "strict
    containment", not "overlap".

    Both arguments are CIDR strings; malformed input raises
    :class:`ValueError`.
    """
    s = _parse_pool(subnet)
    p = _parse_pool(pool)
    return s.subnet_of(p)


def pools_overlap(a: str, b: str) -> bool:
    """Return ``True`` iff the two CIDR pools share any addresses.

    Two non-overlapping pools is the cycle 4 invariant the
    ``POST /tenants`` overlap-rejection enforces. Identical pools
    overlap; a subset overlaps its parent.
    """
    pa = _parse_pool(a)
    pb = _parse_pool(b)
    return pa.overlaps(pb)


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
