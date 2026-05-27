"""Unit tests for the IP allocator."""

from __future__ import annotations

from ipaddress import IPv4Address

import pytest
from sqlmodel import Session

from wg_manager.ipam import IPPoolExhausted, allocate_client_ip
from wg_manager.models import Client, NodeStatus, Server


def _make_server(session: Session, subnet: str = "10.9.0.0/24") -> Server:
    server = Server(
        hostname="hub.example.com",
        ssh_username="ubuntu",
        ssh_key_id=1,
        endpoint_host="hub.example.com",
        subnet=subnet,
        address="10.9.0.1/24",
        public_key="srvpk",
        status=NodeStatus.ready,
    )
    session.add(server)
    session.commit()
    session.refresh(server)
    return server


class TestAllocateClientIP:
    def test_allocates_sequentially_skipping_reserved(self, session: Session) -> None:
        server = _make_server(session)
        first = allocate_client_ip(session, server)
        assert first == IPv4Address("10.9.0.2")

        session.add(
            Client(
                name="c1",
                hostname="c1",
                ssh_username="ubuntu",
                ssh_key_id=1,
                server_id=server.id or 0,
                address="10.9.0.2/32",
                public_key="pk",
                status=NodeStatus.ready,
            )
        )
        session.commit()

        second = allocate_client_ip(session, server)
        assert second == IPv4Address("10.9.0.3")

    def test_skips_holes(self, session: Session) -> None:
        server = _make_server(session)
        session.add(
            Client(
                name="c3",
                hostname="c3",
                ssh_username="ubuntu",
                ssh_key_id=1,
                server_id=server.id or 0,
                address="10.9.0.3/32",
                public_key="pk",
                status=NodeStatus.ready,
            )
        )
        session.commit()

        # Lowest free is still .2 because it's not taken.
        assert allocate_client_ip(session, server) == IPv4Address("10.9.0.2")

    def test_raises_when_exhausted(self, session: Session) -> None:
        # Use a /30 so there are only two host addresses total (.1 and .2);
        # server reserves .1, leaving only .2 for clients.
        server = _make_server(session, subnet="10.9.0.0/30")
        session.add(
            Client(
                name="c2",
                hostname="c2",
                ssh_username="ubuntu",
                ssh_key_id=1,
                server_id=server.id or 0,
                address="10.9.0.2/32",
                public_key="pk",
                status=NodeStatus.ready,
            )
        )
        session.commit()
        with pytest.raises(IPPoolExhausted):
            allocate_client_ip(session, server)
