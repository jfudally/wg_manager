"""PROXY protocol (v1 + v2) for the enrollment listener (Phase 3f hardening).

Behind an L4 load balancer (the HA nginx ``stream {}`` block, an AWS
NLB, HAProxy) every connection to the enroll port comes *from the
proxy*. The per-IP rate limiter in :mod:`wg_manager.enroll_app` would
then put every caller in one bucket, and one attacker's bad tokens
would lock out every host. With PROXY protocol, the proxy sends a short
header naming the real client before any other byte, and this module
reads it.

The header arrives **before** the TLS handshake, so uvicorn can't do the
TLS itself: :func:`make_proxy_protocol_class` builds a uvicorn ``http=``
protocol class that, for each connection:

1. drops the connection unless the TCP peer is a trusted proxy (else
   anyone reaching the port directly could forge source addresses);
2. reads and validates the header, within ``header_timeout``;
3. starts server-side TLS on the same transport, feeding it any
   ClientHello bytes that arrived in the same segment as the header;
4. hands the decrypted stream to uvicorn's normal HTTP protocol with
   ``client`` set to the address from the header, so ``request.client``
   (and so the rate limiter and audit log) sees the real caller.

The header is **mandatory** in this mode: a connection without one is
dropped, never served with the proxy's address.

Step 3 uses :class:`asyncio.sslproto.SSLProtocol` because
:meth:`asyncio.loop.start_tls` has no way to pass in bytes that were
already read. The module is private, but it's what ``start_tls`` itself
uses. Python is pinned to 3.13, and ``tests/test_proxy_protocol.py``
exercises it over real sockets, including the coalesced-segment case.

Spec: https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import ssl
import struct
from asyncio.sslproto import SSLProtocol
from collections.abc import Iterable
from typing import Any, ClassVar, cast

from uvicorn.protocols.http.auto import AutoHTTPProtocol

logger = logging.getLogger(__name__)

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
Client = tuple[str, int]

V1_PREFIX = b"PROXY "
# A v1 header, CRLF included, is at most 107 bytes (spec section 2.1).
V1_MAX_LEN = 107
V2_SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"
_V2_HEADER_LEN = 16
# The spec allows up to 64 KiB of address + TLV data. Real proxies send
# far less (an NLB's TLVs are tens of bytes), and anything bigger is
# more likely an attack on our buffer than a real header.
V2_MAX_BODY = 4096

_V2_CMD_LOCAL, _V2_CMD_PROXY = 0x0, 0x1
_V2_AF_UNSPEC, _V2_TCP4, _V2_TCP6 = 0x00, 0x11, 0x21
# family -> (address bytes needed, address length)
_V2_ADDR = {_V2_TCP4: (12, 4), _V2_TCP6: (36, 16)}


class ProxyProtocolError(ValueError):
    """The bytes at the start of the connection aren't a valid PROXY header."""


def parse_header(buf: bytes) -> tuple[Client | None, int] | None:
    """Parse a PROXY v1 or v2 header at the start of ``buf``.

    :param buf: Every byte received on the connection so far.
    :return: ``None`` if more bytes are needed; otherwise ``(client,
        consumed)``. ``client`` is the real ``(host, port)``, or
        ``None`` for a v1 ``UNKNOWN`` / v2 ``LOCAL`` / ``AF_UNSPEC``
        header, meaning "use the TCP peer" (proxies send these for
        their own health checks). ``consumed`` is the header's length;
        whatever follows is the start of the TLS stream.
    :raises ProxyProtocolError: If ``buf`` can't be (the start of) a
        valid header. Checked as early as possible, so a bare TLS
        ClientHello fails on its first byte.
    """
    if not buf:
        return None
    if buf[:1] == V1_PREFIX[:1]:
        return _parse_v1(buf)
    if buf[:1] == V2_SIGNATURE[:1]:
        return _parse_v2(buf)
    raise ProxyProtocolError("connection does not start with a PROXY header")


def _parse_v1(buf: bytes) -> tuple[Client | None, int] | None:
    """v1: ``PROXY TCP4|TCP6 <src> <dst> <sport> <dport>\\r\\n`` or ``PROXY UNKNOWN…``."""
    if not buf.startswith(V1_PREFIX[: len(buf)]):
        raise ProxyProtocolError("bad v1 prefix")
    end = buf.find(b"\r\n", 0, V1_MAX_LEN)
    if end < 0:
        if len(buf) >= V1_MAX_LEN:
            raise ProxyProtocolError("v1 header longer than 107 bytes")
        return None
    try:
        line = buf[:end].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ProxyProtocolError("v1 header is not ASCII") from exc
    # split(" ") rather than split(): a doubled space must yield an
    # empty field and fail, as the spec requires single spaces.
    parts = line.split(" ")
    if len(parts) >= 2 and parts[1] == "UNKNOWN":
        return None, end + 2
    if len(parts) != 6 or parts[1] not in ("TCP4", "TCP6"):
        raise ProxyProtocolError(f"malformed v1 header: {line[:64]!r}")
    version = 4 if parts[1] == "TCP4" else 6
    src = _v1_address(parts[2], version)
    _v1_address(parts[3], version)
    sport = _v1_port(parts[4])
    _v1_port(parts[5])
    return (src, sport), end + 2


def _v1_address(text: str, version: int) -> str:
    try:
        addr = ipaddress.ip_address(text)
    except ValueError as exc:
        raise ProxyProtocolError(f"bad v1 address {text!r}") from exc
    if addr.version != version or "%" in text:
        raise ProxyProtocolError(f"bad v1 address {text!r}")
    return str(addr)


def _v1_port(text: str) -> int:
    # Digits only, no sign, no leading zeros (spec section 2.1).
    if not text.isdigit() or (len(text) > 1 and text[0] == "0"):
        raise ProxyProtocolError(f"bad v1 port {text!r}")
    port = int(text)
    if port > 65535:
        raise ProxyProtocolError(f"bad v1 port {text!r}")
    return port


def _parse_v2(buf: bytes) -> tuple[Client | None, int] | None:
    """v2: 12-byte signature, version/command, family, length, then addresses + TLVs."""
    if not buf.startswith(V2_SIGNATURE[: len(buf)]):
        raise ProxyProtocolError("bad v2 signature")
    if len(buf) < _V2_HEADER_LEN:
        return None
    ver_cmd, family = buf[12], buf[13]
    (length,) = struct.unpack("!H", buf[14:16])
    if ver_cmd >> 4 != 2:
        raise ProxyProtocolError(f"unsupported v2 version {ver_cmd >> 4}")
    command = ver_cmd & 0x0F
    if command not in (_V2_CMD_LOCAL, _V2_CMD_PROXY):
        raise ProxyProtocolError(f"unsupported v2 command {command}")
    if length > V2_MAX_BODY:
        raise ProxyProtocolError(f"v2 header body too long ({length} bytes)")
    if command == _V2_CMD_PROXY and family != _V2_AF_UNSPEC:
        if family not in _V2_ADDR:
            # UDP and AF_UNIX make no sense for a TCP listener.
            raise ProxyProtocolError(f"unsupported v2 family 0x{family:02x}")
        if length < _V2_ADDR[family][0]:
            raise ProxyProtocolError("v2 address block too short")
    total = _V2_HEADER_LEN + length
    if len(buf) < total:
        return None
    if command == _V2_CMD_LOCAL or family == _V2_AF_UNSPEC:
        return None, total
    _, addr_len = _V2_ADDR[family]
    body = buf[_V2_HEADER_LEN:total]
    src = ipaddress.ip_address(body[:addr_len])
    (sport,) = struct.unpack("!H", body[2 * addr_len : 2 * addr_len + 2])
    return (str(src), sport), total


class ProxyProtocolTLS(asyncio.Protocol):
    """uvicorn ``http=`` protocol: PROXY header, then TLS, then HTTP.

    Don't use it directly: :func:`make_proxy_protocol_class` returns a
    subclass with the class attributes below filled in. uvicorn
    instantiates it once per connection with its usual protocol
    arguments, which are passed on to the HTTP protocol unchanged.

    :cvar ssl_context: Server-side TLS context for the handshake.
    :cvar trusted: Networks allowed to send PROXY headers.
    :cvar header_timeout: Seconds a peer gets to send the whole header.
    :cvar handshake_timeout: TLS handshake timeout, in seconds.
    """

    ssl_context: ClassVar[ssl.SSLContext]
    trusted: ClassVar[tuple[IPNetwork, ...]]
    header_timeout: ClassVar[float]
    handshake_timeout: ClassVar[float]

    def __init__(
        self, *, _loop: asyncio.AbstractEventLoop | None = None, **uvicorn_args: Any
    ) -> None:
        """:param uvicorn_args: ``config`` / ``server_state`` / ``app_state``,
        forwarded to the HTTP protocol once the header is read.
        """
        self._uvicorn_args = uvicorn_args
        self._loop = _loop or asyncio.get_running_loop()
        self._transport: asyncio.Transport | None = None
        self._buf = bytearray()
        self._timer: asyncio.TimerHandle | None = None
        self._peer = "?"

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Drop untrusted peers; start the header timer for the rest."""
        # uvloop's transports implement the interface without subclassing
        # asyncio.Transport, so cast rather than isinstance-check.
        self._transport = cast(asyncio.Transport, transport)
        peername = transport.get_extra_info("peername")
        self._peer = str(peername[0]) if peername else "?"
        if not _is_trusted(self._peer, self.trusted):
            logger.warning(
                "enroll listener: dropped connection from %s, which is not in "
                "ENROLL_PROXY_TRUSTED_CIDRS",
                self._peer,
            )
            transport.abort()
            return
        self._timer = self._loop.call_later(self.header_timeout, self._on_timeout)

    def data_received(self, data: bytes) -> None:
        """Accumulate bytes until the header is complete, then switch to TLS."""
        assert self._transport is not None
        self._buf += data
        try:
            parsed = parse_header(bytes(self._buf))
        except ProxyProtocolError as exc:
            logger.info("enroll listener: dropped connection from %s: %s", self._peer, exc)
            self._close()
            return
        if parsed is None:
            return
        client, consumed = parsed
        self._cancel_timer()
        self._start_tls(client, bytes(self._buf[consumed:]))

    def eof_received(self) -> bool:
        """The peer hung up before finishing the header: close."""
        return False

    def connection_lost(self, exc: Exception | None) -> None:
        """Clean up the header timer if the peer went away first."""
        self._cancel_timer()

    def _start_tls(self, client: Client | None, leftover: bytes) -> None:
        """Hand the transport to TLS + uvicorn's HTTP protocol."""
        assert self._transport is not None
        http = _ProxiedHTTPProtocol(**self._uvicorn_args, _loop=self._loop)
        http.proxied_client = client
        tls = SSLProtocol(
            self._loop,
            http,
            self.ssl_context,
            None,
            server_side=True,
            ssl_handshake_timeout=self.handshake_timeout,
        )
        self._transport.set_protocol(tls)
        tls.connection_made(self._transport)
        # Bytes that arrived with the header are the start of the
        # ClientHello; feed them to TLS as if just read from the socket.
        view = memoryview(leftover)
        while view:
            buf = tls.get_buffer(len(view))
            n = min(len(buf), len(view))
            buf[:n] = view[:n]
            tls.buffer_updated(n)
            view = view[n:]
        self._buf.clear()

    def _on_timeout(self) -> None:
        logger.info("enroll listener: PROXY header from %s timed out", self._peer)
        self._close()

    def _cancel_timer(self) -> None:
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None

    def _close(self) -> None:
        self._cancel_timer()
        if self._transport is not None:
            self._transport.abort()


class _ProxiedHTTPProtocol(AutoHTTPProtocol):  # type: ignore[misc, valid-type]
    """uvicorn's HTTP protocol, reporting the PROXY header's client address.

    uvicorn reads ``client`` from the socket's peer in
    ``connection_made``; that's the proxy. Overriding it there, before
    any request is parsed, is what makes ``request.client`` the real
    caller.
    """

    proxied_client: Client | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:  # type: ignore[override]
        super().connection_made(transport)
        if self.proxied_client is not None:
            self.client = self.proxied_client


def _is_trusted(host: str, trusted: Iterable[IPNetwork]) -> bool:
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    # A dual-stack socket reports IPv4 peers as ::ffff:a.b.c.d.
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return any(addr in net for net in trusted)


def make_proxy_protocol_class(
    ssl_context: ssl.SSLContext,
    *,
    trusted: Iterable[IPNetwork],
    header_timeout: float = 5.0,
    handshake_timeout: float = 10.0,
) -> type[ProxyProtocolTLS]:
    """Build the uvicorn ``http=`` class for a PROXY-protocol enroll listener.

    Run uvicorn **without** its own ``ssl_*`` settings when using this
    class: TLS starts only after the PROXY header.

    :param ssl_context: Server TLS context (see
        :func:`wg_manager.tls_listeners.enroll_ssl_context`).
    :param trusted: Networks whose connections may carry a PROXY
        header. Every other peer is dropped. Must not be empty.
    :param header_timeout: Seconds to wait for the complete header.
    :param handshake_timeout: TLS handshake timeout, in seconds.
    :return: A :class:`ProxyProtocolTLS` subclass.
    :raises ValueError: If ``trusted`` is empty.
    """
    networks = tuple(trusted)
    if not networks:
        raise ValueError("PROXY protocol needs at least one trusted proxy network")
    return type(
        "EnrollProxyProtocolTLS",
        (ProxyProtocolTLS,),
        {
            "ssl_context": ssl_context,
            "trusted": networks,
            "header_timeout": header_timeout,
            "handshake_timeout": handshake_timeout,
        },
    )
