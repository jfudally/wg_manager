"""PROXY protocol support on the enrollment listener (Phase 3f hardening).

Behind an L4 proxy (the HA nginx ``stream {}`` block, an AWS NLB,
HAProxy) every TCP connection to the enroll port comes from the proxy,
so the per-IP rate limiter would put every caller in one bucket, and
one attacker's bad tokens would lock out every host. With PROXY
protocol, the proxy prepends a header naming the real client, and the
enroll listener reads it **before** the TLS handshake.

These tests pin:

* the header parser (:func:`wg_manager.proxy_protocol.parse_header`)
  for v1 (nginx) and v2 (NLB / HAProxy), including incomplete and
  malformed input;
* the listener protocol over real sockets: the real client address
  reaches the app, even when the header and the TLS ClientHello arrive
  in one TCP segment; untrusted peers, missing headers and slow headers
  are dropped; LOCAL / UNKNOWN headers fall back to the TCP peer;
* the runner wiring and settings guard rails.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
import struct
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from fastapi import FastAPI, Request
from pydantic import ValidationError

from wg_manager.config import Settings
from wg_manager.pki import LocalDevPKI
from wg_manager.proxy_protocol import (
    V2_SIGNATURE,
    ProxyProtocolError,
    make_proxy_protocol_class,
    parse_header,
)

# ---------------------------------------------------------------------------
# Header parser
# ---------------------------------------------------------------------------


def _v2(cmd: int, family: int, addr: bytes, tlvs: bytes = b"") -> bytes:
    body = addr + tlvs
    return V2_SIGNATURE + bytes([0x20 | cmd, family]) + struct.pack("!H", len(body)) + body


def _v2_tcp4(src: str, sport: int, dst: str = "10.0.0.1", dport: int = 8443) -> bytes:
    addr = (
        ipaddress.IPv4Address(src).packed
        + ipaddress.IPv4Address(dst).packed
        + struct.pack("!HH", sport, dport)
    )
    return _v2(0x1, 0x11, addr)


class TestParseV1:
    def test_tcp4(self) -> None:
        hdr = b"PROXY TCP4 203.0.113.7 10.0.0.1 51234 8443\r\n"
        assert parse_header(hdr + b"rest") == (("203.0.113.7", 51234), len(hdr))

    def test_tcp6(self) -> None:
        hdr = b"PROXY TCP6 2001:db8::7 2001:db8::1 51234 8443\r\n"
        assert parse_header(hdr) == (("2001:db8::7", 51234), len(hdr))

    def test_unknown_means_use_the_tcp_peer(self) -> None:
        hdr = b"PROXY UNKNOWN\r\n"
        assert parse_header(hdr) == (None, len(hdr))

    @pytest.mark.parametrize("partial", [b"", b"PRO", b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2"])
    def test_incomplete_needs_more(self, partial: bytes) -> None:
        assert parse_header(partial) is None

    @pytest.mark.parametrize(
        "bad",
        [
            b"\x16\x03\x01\x02\x00",                             # a bare TLS ClientHello
            b"GET / HTTP/1.1\r\n",                               # plain HTTP
            b"PROXY TCP4 999.1.1.1 10.0.0.1 1 2\r\n",            # bad address
            b"PROXY TCP4 2001:db8::1 10.0.0.1 1 2\r\n",          # family mismatch
            b"PROXY TCP4 1.2.3.4 10.0.0.1 70000 2\r\n",          # port out of range
            b"PROXY TCP4 1.2.3.4 10.0.0.1 01 2\r\n",             # leading zero
            b"PROXY TCP4 1.2.3.4 10.0.0.1 1\r\n",                # missing field
            b"PROXY UDP4 1.2.3.4 10.0.0.1 1 2\r\n",              # unsupported protocol
            b"PROXY TCP4 1.2.3.4  10.0.0.1 1 2\r\n",             # double space
            b"PROXY TCP4 " + b"1" * 120,                         # over 107 bytes, no CRLF
        ],
    )
    def test_malformed_raises(self, bad: bytes) -> None:
        with pytest.raises(ProxyProtocolError):
            parse_header(bad)


class TestParseV2:
    def test_proxy_tcp4(self) -> None:
        hdr = _v2_tcp4("203.0.113.7", 51234)
        assert parse_header(hdr + b"\x16") == (("203.0.113.7", 51234), len(hdr))

    def test_proxy_tcp6(self) -> None:
        addr = (
            ipaddress.IPv6Address("2001:db8::7").packed
            + ipaddress.IPv6Address("2001:db8::1").packed
            + struct.pack("!HH", 51234, 8443)
        )
        hdr = _v2(0x1, 0x21, addr)
        assert parse_header(hdr) == (("2001:db8::7", 51234), len(hdr))

    def test_tlvs_are_skipped(self) -> None:
        """AWS NLB appends TLVs (e.g. the VPC endpoint id) after the addresses."""
        addr = (
            ipaddress.IPv4Address("203.0.113.7").packed
            + ipaddress.IPv4Address("10.0.0.1").packed
            + struct.pack("!HH", 1, 2)
        )
        hdr = _v2(0x1, 0x11, addr, tlvs=b"\xea\x00\x04abcd")
        assert parse_header(hdr) == (("203.0.113.7", 1), len(hdr))

    def test_local_means_use_the_tcp_peer(self) -> None:
        hdr = _v2(0x0, 0x00, b"")
        assert parse_header(hdr) == (None, len(hdr))

    def test_incomplete_needs_more(self) -> None:
        hdr = _v2_tcp4("203.0.113.7", 1)
        for cut in (5, 12, 15, len(hdr) - 1):
            assert parse_header(hdr[:cut]) is None, cut

    @pytest.mark.parametrize(
        "bad",
        [
            V2_SIGNATURE + bytes([0x11, 0x11]) + struct.pack("!H", 12) + b"\0" * 12,  # version 1
            V2_SIGNATURE + bytes([0x22, 0x11]) + struct.pack("!H", 12) + b"\0" * 12,  # command 2
            V2_SIGNATURE + bytes([0x21, 0x12]) + struct.pack("!H", 12) + b"\0" * 12,  # UDP
            V2_SIGNATURE + bytes([0x21, 0x31]) + struct.pack("!H", 216) + b"\0" * 216,  # AF_UNIX
            V2_SIGNATURE + bytes([0x21, 0x11]) + struct.pack("!H", 4),               # too short
            V2_SIGNATURE + bytes([0x21, 0x11]) + struct.pack("!H", 5000),            # too long
        ],
    )
    def test_malformed_raises(self, bad: bytes) -> None:
        with pytest.raises(ProxyProtocolError):
            parse_header(bad + b"\0" * 64)


# ---------------------------------------------------------------------------
# Listener protocol over real sockets
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def tls_files(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    pki = LocalDevPKI.generate()
    cert = pki.issue_server_cert(common_name="127.0.0.1", sans=["127.0.0.1"], ttl_seconds=3600)
    d = tmp_path_factory.mktemp("pp-tls")
    paths = {"cert": d / "server.crt", "key": d / "server.key", "ca": d / "ca.crt"}
    paths["cert"].write_text(cert.cert_pem + cert.chain_pem)
    paths["key"].write_text(cert.private_pem)
    paths["ca"].write_text(pki.ca_bundle_pem)
    return paths


def _server_ctx(tls: dict[str, Path]) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(tls["cert"]), str(tls["key"]))
    return ctx


def _client_ctx(tls: dict[str, Path]) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=str(tls["ca"]))
    # LocalDevPKI leaves have no AKI; see tests/test_enroll_listener.py.
    ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    return ctx


def _echo_app() -> FastAPI:
    app = FastAPI()

    @app.get("/whoami")
    def _whoami(request: Request) -> dict[str, Any]:
        client = request.client
        return {
            "host": client.host if client else None,
            "port": client.port if client else None,
            "scheme": request.url.scheme,
        }

    return app


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@contextmanager
def _serve(http_cls: type, loop: str) -> Iterator[int]:
    """Run the echo app with ``http=http_cls`` and no uvicorn TLS; yield port.

    :param loop: uvicorn loop implementation. Production runs ``auto``,
        which is uvloop when installed; both are covered because their
        transports differ (uvloop's don't subclass asyncio.Transport).
    """
    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(
            _echo_app(), host="127.0.0.1", port=port, log_level="warning", http=http_cls, loop=loop
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        if time.monotonic() > deadline:
            raise RuntimeError("uvicorn did not start within 10s")
        time.sleep(0.05)
    try:
        yield port
    finally:
        server.should_exit = True
        thread.join(timeout=10)


def _tls_get(
    port: int, tls: dict[str, Path], prefix: bytes, path: str = "/whoami"
) -> bytes:
    """Send ``prefix`` and the first TLS flight in **one** ``sendall``.

    Drives the client side of TLS through memory BIOs so the PROXY header
    and the ClientHello share a TCP segment. That's the case a naive
    ``start_tls`` after reading the header would get wrong.

    :return: The raw HTTP response (empty if the server hung up).
    """
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls_obj = _client_ctx(tls).wrap_bio(incoming, outgoing, server_hostname="127.0.0.1")
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        try:
            tls_obj.do_handshake()
        except ssl.SSLWantReadError:
            pass
        sock.sendall(prefix + outgoing.read())
        while True:
            try:
                tls_obj.do_handshake()
                break
            except ssl.SSLWantReadError:
                if pending := outgoing.read():
                    sock.sendall(pending)
                data = sock.recv(65536)
                if not data:
                    return b""
                incoming.write(data)
        if pending := outgoing.read():
            sock.sendall(pending)
        tls_obj.write(f"GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode())
        sock.sendall(outgoing.read())
        # Read until the response is complete by Content-Length rather
        # than until close: the server's TLS shutdown waits for a
        # close_notify this hand-driven client never sends.
        response = b""
        while not _complete(response):
            data = sock.recv(65536)
            if not data:
                break
            incoming.write(data)
            try:
                while chunk := tls_obj.read(65536):
                    response += chunk
            except ssl.SSLWantReadError:
                continue
            except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
                break
        return response
    except (ConnectionResetError, ssl.SSLError):
        return b""
    finally:
        sock.close()


def _complete(response: bytes) -> bool:
    """True once ``response`` holds the headers and the whole body."""
    head, sep, body = response.partition(b"\r\n\r\n")
    if not sep:
        return False
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            return len(body) >= int(value.strip())
    return False


def _json_body(response: bytes) -> dict[str, Any]:
    import json

    assert response.startswith(b"HTTP/1.1 200"), response[:200]
    return json.loads(response.split(b"\r\n\r\n", 1)[1])


def _closed_without_reply(port: int, payload: bytes, wait: float = 3.0) -> bool:
    """Send ``payload`` and report whether the server hung up without replying."""
    with socket.create_connection(("127.0.0.1", port), timeout=wait) as sock:
        sock.sendall(payload)
        try:
            return sock.recv(1024) == b""
        except ConnectionResetError:
            return True


_LOOPBACK = [ipaddress.ip_network("127.0.0.0/8")]


@pytest.mark.parametrize("loop_impl", ["asyncio", "uvloop"])
class TestListenerProtocol:
    def test_v1_header_sets_client_even_when_coalesced_with_client_hello(
        self, loop_impl: str, tls_files: dict[str, Path]
    ) -> None:
        cls = make_proxy_protocol_class(_server_ctx(tls_files), trusted=_LOOPBACK)
        with _serve(cls, loop_impl) as port:
            body = _json_body(
                _tls_get(port, tls_files, b"PROXY TCP4 203.0.113.7 10.0.0.1 51234 8443\r\n")
            )
        assert body == {"host": "203.0.113.7", "port": 51234, "scheme": "https"}

    def test_v2_header_sets_client(self, loop_impl: str, tls_files: dict[str, Path]) -> None:
        cls = make_proxy_protocol_class(_server_ctx(tls_files), trusted=_LOOPBACK)
        with _serve(cls, loop_impl) as port:
            body = _json_body(_tls_get(port, tls_files, _v2_tcp4("198.51.100.9", 4000)))
        assert (body["host"], body["port"]) == ("198.51.100.9", 4000)

    def test_unknown_header_falls_back_to_tcp_peer(
        self, loop_impl: str, tls_files: dict[str, Path]
    ) -> None:
        cls = make_proxy_protocol_class(_server_ctx(tls_files), trusted=_LOOPBACK)
        with _serve(cls, loop_impl) as port:
            body = _json_body(_tls_get(port, tls_files, b"PROXY UNKNOWN\r\n"))
        assert body["host"] == "127.0.0.1"

    def test_untrusted_peer_is_dropped(self, loop_impl: str, tls_files: dict[str, Path]) -> None:
        """Otherwise anyone reaching the port directly could forge source IPs."""
        cls = make_proxy_protocol_class(
            _server_ctx(tls_files), trusted=[ipaddress.ip_network("10.0.0.0/8")]
        )
        with _serve(cls, loop_impl) as port:
            assert _tls_get(port, tls_files, b"PROXY TCP4 203.0.113.7 10.0.0.1 1 2\r\n") == b""

    def test_missing_header_is_dropped(self, loop_impl: str, tls_files: dict[str, Path]) -> None:
        """A direct TLS client (no header) never reaches the app."""
        cls = make_proxy_protocol_class(_server_ctx(tls_files), trusted=_LOOPBACK)
        with _serve(cls, loop_impl) as port:
            assert _tls_get(port, tls_files, b"") == b""

    def test_malformed_header_is_dropped(self, loop_impl: str, tls_files: dict[str, Path]) -> None:
        cls = make_proxy_protocol_class(_server_ctx(tls_files), trusted=_LOOPBACK)
        with _serve(cls, loop_impl) as port:
            assert _closed_without_reply(port, b"PROXY TCP4 nonsense\r\n")

    def test_slow_header_times_out(self, loop_impl: str, tls_files: dict[str, Path]) -> None:
        cls = make_proxy_protocol_class(
            _server_ctx(tls_files), trusted=_LOOPBACK, header_timeout=0.3
        )
        with _serve(cls, loop_impl) as port:
            started = time.monotonic()
            assert _closed_without_reply(port, b"PROXY TCP4 ", wait=5)
            assert time.monotonic() - started < 3


# ---------------------------------------------------------------------------
# Settings + runner wiring
# ---------------------------------------------------------------------------


class TestSettings:
    def test_off_by_default(self) -> None:
        s = Settings()
        assert s.enroll_proxy_protocol is False
        assert s.enroll_proxy_trusted_networks == []

    def test_parses_trusted_cidrs(self) -> None:
        s = Settings(enroll_proxy_trusted_cidrs="10.0.0.0/8, 2001:db8::/32")
        assert s.enroll_proxy_trusted_networks == [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("2001:db8::/32"),
        ]

    def test_rejects_bad_cidr(self) -> None:
        with pytest.raises(ValidationError):
            Settings(enroll_proxy_trusted_cidrs="10.0.0.0/8,not-a-cidr")

    def test_proxy_mode_requires_trusted_cidrs(self) -> None:
        with pytest.raises(ValidationError, match="ENROLL_PROXY_TRUSTED_CIDRS"):
            Settings(enroll_proxy_protocol=True)


class TestRunner:
    def _run(self, monkeypatch: pytest.MonkeyPatch, settings: Settings) -> dict[str, Any]:
        from wg_manager import enroll_listener

        captured: dict[str, Any] = {}

        def fake_run(app: Any, **kwargs: Any) -> None:
            captured["app"] = app
            captured.update(kwargs)

        monkeypatch.setattr(enroll_listener.uvicorn, "run", fake_run)
        assert enroll_listener.main(settings) == 0
        return captured

    def test_proxy_mode_does_tls_in_the_protocol_not_uvicorn(
        self, monkeypatch: pytest.MonkeyPatch, tls_files: dict[str, Path]
    ) -> None:
        s = Settings(
            tls_cert_pem=str(tls_files["cert"]), tls_key_pem=str(tls_files["key"]),
            enroll_proxy_protocol=True, enroll_proxy_trusted_cidrs="10.0.0.0/8",
        )
        captured = self._run(monkeypatch, s)
        # uvicorn must not wrap the socket in TLS itself: the PROXY header
        # comes before the handshake.
        assert not any(k.startswith("ssl_") for k in captured)
        http_cls = captured["http"]
        assert http_cls.trusted == (ipaddress.ip_network("10.0.0.0/8"),)
        assert http_cls.ssl_context.verify_mode == ssl.CERT_NONE

    def test_default_mode_unchanged(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured = self._run(monkeypatch, Settings(tls_cert_pem="c", tls_key_pem="k"))
        assert "http" not in captured
        assert captured["ssl_cert_reqs"] == ssl.CERT_NONE
