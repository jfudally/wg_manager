"""CP5 acceptance #4 — a plain-HTTP connect to the mTLS listener is refused.

The Phase 2d goal calls out "the plain HTTP listener is removed; the
``.env.example`` no longer contains an unauthenticated path." The
unit-test surface for that lives in ``test_main_tls_wiring.py``
(``ssl_cert_reqs=CERT_REQUIRED`` is threaded through ``__main__``).
This module is the *behavioural* counterpart: take a real listener
running with the same SSL kwargs production uses, and prove that

1. A raw HTTP/1.1 request line at the socket layer does not produce an
   HTTP response, and
2. An ``httpx`` operator pointing at ``http://…`` raises a transport
   error rather than ever returning a :class:`httpx.Response`.

Both tests share the :func:`live_api_server` session fixture so the
listener cold-starts exactly once for the whole module.
"""

from __future__ import annotations

import socket

import httpx
import pytest

from tests.e2e.tls.conftest import LiveAPIEnv


def test_plain_http_socket_request_no_response(
    live_api_server: LiveAPIEnv,
) -> None:
    """A raw HTTP/1.1 request line never produces an HTTP status response.

    The strongest form of the acceptance criterion: regardless of what
    error mode uvicorn / OpenSSL choose (EOF, ``HTTP/1.1 400``-shaped
    error page, connection reset), the listener must not return a
    ``HTTP/`` status line. Anything that starts with ``HTTP/`` would
    mean uvicorn is *also* answering plain HTTP — which is exactly the
    posture Phase 2d set out to remove.
    """
    with socket.create_connection(
        (live_api_server.host, live_api_server.port), timeout=5.0
    ) as sock:
        sock.sendall(
            b"GET / HTTP/1.1\r\n"
            b"Host: "
            + f"{live_api_server.host}:{live_api_server.port}".encode()
            + b"\r\n"
            b"User-Agent: cp5-plain-http\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        sock.settimeout(5.0)
        try:
            data = sock.recv(4096)
        except (ConnectionResetError, TimeoutError, OSError):
            # Either of these is a legitimate "rejected" shape — the
            # listener closed before answering or refused to ack the
            # bytes at all. Both satisfy the criterion.
            data = b""

    assert not data.startswith(b"HTTP/"), (
        "mTLS listener answered a plain-HTTP request with an HTTP "
        "status line, which means uvicorn is also serving plain HTTP. "
        "Phase 2d explicitly removes that surface — see ROADMAP Phase "
        f"2d CP5 acceptance criterion #4. First 80 bytes: {data[:80]!r}"
    )


def test_plain_http_via_httpx_raises_transport_error(
    live_api_server: LiveAPIEnv,
) -> None:
    """``httpx.get('http://…')`` against the listener raises a transport error.

    The operator-perspective shape of the acceptance criterion: any
    consumer that *forgets* to use ``https://`` should fail loudly at
    the transport layer rather than being silently redirected or
    receiving a successful response. The exact subclass of
    :class:`httpx.TransportError` (``RemoteProtocolError``,
    ``ConnectError``, ``ReadError``) depends on whether uvicorn closes
    the socket before or after the kernel sends the bytes, so the test
    asserts the base class.
    """
    url = f"http://{live_api_server.host}:{live_api_server.port}/certs/whoami"
    with pytest.raises(httpx.TransportError):
        httpx.get(url, timeout=5.0)
