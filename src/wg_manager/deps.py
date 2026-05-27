"""Shared FastAPI dependency-injection helpers.

This module exists so routers can depend on cross-cutting services
(``CryptoBackend``, future auth context, …) without each grabbing its
own private singleton. Centralising the dependency callable also makes
``app.dependency_overrides[…]`` straightforward in tests when we want
to swap in a fake.
"""

from __future__ import annotations

from functools import lru_cache

from wg_manager.crypto import CryptoBackend, make_backend


@lru_cache(maxsize=1)
def get_crypto_backend() -> CryptoBackend:
    """Return the process-wide :class:`CryptoBackend` singleton.

    The first call constructs the backend per the ``CRYPTO_BACKEND``
    setting (see :func:`wg_manager.crypto.make_backend`); subsequent
    calls return the cached instance, which is what we want for both
    backends — ``LocalDevBackend`` keeps a single Fernet, and
    ``VaultTransitBackend`` wraps a long-lived ``hvac.Client``.

    Tests that want a stub backend should override the dependency via
    ``app.dependency_overrides[get_crypto_backend] = lambda: …`` rather
    than mutating the cache.
    """
    return make_backend()


__all__ = ["get_crypto_backend"]
