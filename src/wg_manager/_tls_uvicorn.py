"""Backfill the ASGI-TLS extension on uvicorn (Phase 2d CP2).

uvicorn 0.44 — the version this repo is currently pinned to — doesn't
implement the `ASGI-TLS extension`_ natively
(`encode/uvicorn#1530`_). Without that extension the wg-manager auth
middleware can't read ``scope["extensions"]["tls"]
["client_cert_chain"]`` and every request 401s even when the operator
has presented a valid client cert (uvicorn validates the cert at the
TLS handshake but never tells the app about it).

This module is the workaround: :func:`enable_tls_extension` wraps
uvicorn's HTTP-protocol ``RequestResponseCycle.__init__`` so each
request's scope is enriched with the TLS extension before the app
runs. The injection runs in process — it inherits cleanly to a
``--reload`` worker that re-imports ``wg_manager.main`` on every
restart, because the wiring lives at module import time
(:mod:`wg_manager.main` calls :func:`enable_tls_extension` once).

The patch is intentionally a small, isolated surface: a single ASGI
helper (``_inject_tls_extension``) and a single wrap that delegates to
the original ``__init__`` after enrichment. **Delete this module
outright** once upstream uvicorn ships the extension natively — the
auth middleware doesn't depend on anything in here.

.. _ASGI-TLS extension: https://asgi.readthedocs.io/en/latest/extensions.html#tls
.. _encode/uvicorn#1530: https://github.com/encode/uvicorn/issues/1530
"""

from __future__ import annotations

import functools
import logging
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)

_PATCHED = False


def _ssl_object_to_chain(ssl_object: Any) -> list[str]:
    """Extract the peer cert PEM chain from an :class:`ssl.SSLObject`.

    Stdlib's :class:`ssl.SSLObject` only exposes the leaf cert (not the
    issuing chain) via ``getpeercert(binary_form=True)``, so this
    returns at most one entry — sufficient for the wg-manager auth
    middleware, which keys off the leaf subject.

    :param ssl_object: The SSL wrapper from
        ``transport.get_extra_info("ssl_object")``, or ``None`` for a
        plain-HTTP transport.
    :returns: A list with one PEM string, or an empty list when no
        client cert was sent. Any parsing error logs at WARNING and
        returns ``[]`` so a malformed peer cert never crashes the
        middleware path — it surfaces as a 401 instead.
    """
    if ssl_object is None:
        return []
    try:
        der = ssl_object.getpeercert(binary_form=True)
    except (AttributeError, OSError) as exc:
        logger.warning("could not read peer cert from ssl_object: %s", exc)
        return []
    if not der:
        return []
    try:
        cert = x509.load_der_x509_certificate(der)
    except (ValueError, TypeError) as exc:
        logger.warning("could not parse peer DER as x509 certificate: %s", exc)
        return []
    return [cert.public_bytes(serialization.Encoding.PEM).decode("ascii")]


def _inject_tls_extension(scope: dict, transport: Any) -> None:
    """Mutate an ASGI ``scope`` in place to add the TLS extension.

    No-op for:

    * non-``http`` scopes (websocket / lifespan — out of scope for CP2),
    * transports without an SSL object (plain HTTP),
    * transports whose peer cert is missing or unparseable (the
      middleware decides what to do with "no chain" — we just don't
      lie by stamping an empty extension).

    :param scope: The ASGI scope dict uvicorn passes to the app.
    :param transport: The :class:`asyncio.Transport` (or duck-equivalent)
        backing the connection.
    """
    if scope.get("type") != "http":
        return
    chain = _ssl_object_to_chain(transport.get_extra_info("ssl_object"))
    if not chain:
        return
    extensions = dict(scope.get("extensions") or {})
    tls = dict(extensions.get("tls") or {})
    tls["client_cert_chain"] = chain
    extensions["tls"] = tls
    scope["extensions"] = extensions


def _wrap_cycle_init(cycle_cls: type) -> None:
    """Wrap a ``RequestResponseCycle.__init__`` to inject TLS data first.

    Idempotent via a marker attribute on the wrapper. We use
    :func:`functools.wraps` so :attr:`__wrapped__` resolves back to
    uvicorn's original ``__init__`` — useful for the idempotency test
    and for any future un-patch path.
    """
    original = cycle_cls.__init__
    if getattr(original, "_wg_manager_tls_wrapped", False):
        return

    @functools.wraps(original)
    def wrapped(self: Any, *args: Any, **kwargs: Any) -> None:
        scope = kwargs.get("scope")
        transport = kwargs.get("transport")
        if scope is not None and transport is not None:
            try:
                _inject_tls_extension(scope, transport)
            except Exception as exc:  # pragma: no cover — defensive
                # Never raise out of __init__: a broken extension is a
                # 401-shaped failure (the middleware sees no subject
                # and returns 401), not a 500.
                logger.warning("TLS extension injection failed: %s", exc)
        original(self, *args, **kwargs)

    wrapped._wg_manager_tls_wrapped = True  # type: ignore[attr-defined]
    cycle_cls.__init__ = wrapped  # type: ignore[method-assign]


def enable_tls_extension() -> None:
    """Idempotently install the TLS-extension shim on uvicorn.

    Safe to call from any number of import paths; the module-level
    ``_PATCHED`` flag and the per-class wrapper marker keep the patch
    applied exactly once per process.
    """
    global _PATCHED
    if _PATCHED:
        return

    from uvicorn.protocols.http import h11_impl

    _wrap_cycle_init(h11_impl.RequestResponseCycle)

    # httptools is the high-performance default on CPython; patch it too
    # so the operator who runs ``uvicorn --http httptools`` (or who
    # uses the default ``auto`` resolution that picks httptools) still
    # gets cert injection. Optional dep — fall back cleanly when it's
    # not installed (e.g. PyPy).
    try:
        from uvicorn.protocols.http import httptools_impl
    except ImportError:  # pragma: no cover — httptools is in our lockfile
        pass
    else:
        _wrap_cycle_init(httptools_impl.RequestResponseCycle)

    _PATCHED = True


__all__ = ["enable_tls_extension"]
