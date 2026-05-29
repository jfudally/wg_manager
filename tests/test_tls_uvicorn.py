"""Tests for :mod:`wg_manager._tls_uvicorn` — Phase 2d CP2 uvicorn shim.

uvicorn 0.44 doesn't implement the ASGI-TLS extension
(`encode/uvicorn#1530`_), so the production CP2 auth middleware
wouldn't see the client cert chain even when uvicorn rejects a
missing cert at handshake time. This module monkey-patches uvicorn's
``RequestResponseCycle.__init__`` to backfill the extension from
``transport.get_extra_info("ssl_object")``.

The tests exercise the extraction helper and the
:class:`RequestResponseCycle` patch in isolation — both against a fake
SSL object that wraps a real :class:`wg_manager.pki.LocalDevPKI`-issued
cert — so the contract is provable without spinning up a real TLS
socket. Delete this test file along with the source module once
upstream uvicorn ships the extension natively.

.. _encode/uvicorn#1530: https://github.com/encode/uvicorn/issues/1530
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography import x509

from wg_manager._tls_uvicorn import (
    _inject_tls_extension,
    _ssl_object_to_chain,
    enable_tls_extension,
)
from wg_manager.auth import parse_subject_from_pem
from wg_manager.pki import LocalDevPKI


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _FakeSSLObject:
    """Stand-in for :class:`ssl.SSLObject` returning a fixed peer cert.

    Mirrors the only :class:`ssl.SSLObject` API the shim cares about
    (``getpeercert(binary_form=True)``) so tests don't need a real
    TLS socket.
    """

    def __init__(self, der: bytes | None) -> None:
        self._der = der

    def getpeercert(self, binary_form: bool = False) -> Any:
        if not binary_form:
            return {}
        return self._der


class _FakeTransport:
    """Stand-in for :class:`asyncio.Transport` carrying an SSL object.

    ``get_extra_info("ssl_object")`` returns the configured object;
    every other key returns ``None`` (matches asyncio's contract).
    """

    def __init__(self, ssl_object: _FakeSSLObject | None) -> None:
        self._ssl_object = ssl_object

    def get_extra_info(self, key: str, default: Any = None) -> Any:
        if key == "ssl_object":
            return self._ssl_object
        return default


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def ca() -> LocalDevPKI:
    return LocalDevPKI.generate()


@pytest.fixture
def client_cert_der(ca: LocalDevPKI) -> bytes:
    """A real client-cert DER blob — the byte shape uvicorn sees."""
    cert = ca.issue_client_cert(
        common_name="ops@wg.local",
        sans=["ops@wg.local"],
        ttl_seconds=300,
    )
    return x509.load_pem_x509_certificate(
        cert.cert_pem.encode()
    ).public_bytes(__import__("cryptography").hazmat.primitives.serialization.Encoding.DER)


# ---------------------------------------------------------------------------
# _ssl_object_to_chain
# ---------------------------------------------------------------------------


class TestSSLObjectToChain:
    """Pure helper: SSL object → list of PEM strings."""

    def test_none_ssl_object_returns_empty(self) -> None:
        assert _ssl_object_to_chain(None) == []

    def test_no_peer_cert_returns_empty(self) -> None:
        """A TLS session without a client cert (e.g. server-only auth)
        yields an empty list, not an error."""
        assert _ssl_object_to_chain(_FakeSSLObject(der=None)) == []

    def test_real_der_returns_pem(
        self, ca: LocalDevPKI, client_cert_der: bytes
    ) -> None:
        chain = _ssl_object_to_chain(_FakeSSLObject(der=client_cert_der))
        assert len(chain) == 1
        # Round-trip through the production parser to prove the PEM is
        # the shape the CP2 middleware can consume.
        subject = parse_subject_from_pem(chain[0])
        assert subject.common_name == "ops@wg.local"


# ---------------------------------------------------------------------------
# _inject_tls_extension
# ---------------------------------------------------------------------------


class TestInjectTlsExtension:
    """Mutates an ASGI scope in place to add the TLS extension."""

    def test_scope_gets_extension_when_ssl_present(
        self, client_cert_der: bytes
    ) -> None:
        scope: dict[str, Any] = {"type": "http"}
        transport = _FakeTransport(_FakeSSLObject(der=client_cert_der))

        _inject_tls_extension(scope, transport)

        chain = scope["extensions"]["tls"]["client_cert_chain"]
        assert len(chain) == 1
        assert "BEGIN CERTIFICATE" in chain[0]

    def test_existing_extensions_preserved(
        self, client_cert_der: bytes
    ) -> None:
        """If uvicorn (or another middleware) put something on
        ``scope['extensions']`` already, we add to it rather than
        replace it."""
        scope: dict[str, Any] = {
            "type": "http",
            "extensions": {"http.response.template": {}},
        }
        transport = _FakeTransport(_FakeSSLObject(der=client_cert_der))

        _inject_tls_extension(scope, transport)

        assert "http.response.template" in scope["extensions"]
        assert "tls" in scope["extensions"]

    def test_non_http_scope_skipped(self, client_cert_der: bytes) -> None:
        """Websocket / lifespan scopes are out of scope for CP2 — leave
        them alone."""
        scope: dict[str, Any] = {"type": "lifespan"}
        transport = _FakeTransport(_FakeSSLObject(der=client_cert_der))

        _inject_tls_extension(scope, transport)

        assert "extensions" not in scope

    def test_plain_http_transport_unchanged(self) -> None:
        """A non-TLS transport must not produce an empty TLS extension —
        the middleware decision logic differentiates 'no extension' from
        'empty chain'."""
        scope: dict[str, Any] = {"type": "http"}
        transport = _FakeTransport(ssl_object=None)

        _inject_tls_extension(scope, transport)

        assert "extensions" not in scope


# ---------------------------------------------------------------------------
# enable_tls_extension idempotency
# ---------------------------------------------------------------------------


class TestEnableTlsExtensionIdempotent:
    """``enable_tls_extension`` must be safe to call repeatedly."""

    def test_double_call_does_not_double_wrap(self) -> None:
        """Two back-to-back calls leave the cycle's ``__init__`` patched
        exactly once. We assert via a wrap-count attribute the
        implementation stamps; a double-wrap would silently chain two
        injection passes per request."""
        from uvicorn.protocols.http import h11_impl

        # Idempotency is the contract: call twice, verify the cycle
        # ``__init__`` still has the wrapper marker (not a marker-of-a-
        # marker).
        enable_tls_extension()
        enable_tls_extension()

        init = h11_impl.RequestResponseCycle.__init__
        assert getattr(init, "_wg_manager_tls_wrapped", False)
        # The wrapper closes over the *original* init, not another
        # wrapper. Walk one level: __wrapped__ should point at the
        # uvicorn-shipped function, which itself is not marked.
        original = getattr(init, "__wrapped__", None)
        assert original is not None
        assert not getattr(original, "_wg_manager_tls_wrapped", False)
