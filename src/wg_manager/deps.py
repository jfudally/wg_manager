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
from wg_manager.pki import PKIBackend, make_pki_backend


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


@lru_cache(maxsize=1)
def get_pki_backend() -> PKIBackend:
    """Return the process-wide :class:`PKIBackend` singleton.

    Mirrors :func:`get_crypto_backend`. The first call constructs the
    backend per the ``PKI_BACKEND`` setting (see
    :func:`wg_manager.pki.make_pki_backend`); subsequent calls return
    the cached instance. For the local backend ``make_pki_backend``
    already memoises per-process via ``_LOCAL_PKI_CACHE`` (so the API
    and Celery worker share one root); wrapping in ``lru_cache`` here
    additionally avoids the cache-key tuple build on the hot path.

    Tests that want a stub backend should override the dependency via
    ``app.dependency_overrides[get_pki_backend] = lambda: …`` rather
    than mutating the cache.
    """
    return make_pki_backend()


__all__ = ["get_crypto_backend", "get_pki_backend"]
