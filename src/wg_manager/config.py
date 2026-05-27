"""Application configuration via pydantic-settings."""

from __future__ import annotations

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration loaded from environment / ``.env``.

    :cvar database_url: SQLAlchemy connection URL for the state store.
    :cvar bind_host: Address the API binds to (localhost by default).
    :cvar bind_port: TCP port the API listens on.
    :cvar default_subnet: CIDR used when a ``POST /servers`` payload omits
        the ``subnet`` field. Validated at construction time so a broken
        ``.env`` value fails on app startup rather than at the first
        registration attempt.
    :cvar default_wg_port: UDP port WireGuard listens on at the server.
    :cvar crypto_backend: Which encryption-at-rest backend
        :func:`wg_manager.crypto.make_backend` will return. One of
        ``"local"`` (Fernet, dev only) or ``"vault"`` (Transit, prod).
        Defaults to ``"local"`` so the test suite is hermetic; the
        deployment must set this to ``"vault"`` explicitly.
    :cvar crypto_local_dev_key: Fernet key (urlsafe-base64, 32 bytes)
        used when ``crypto_backend == "local"``. Required in that mode;
        ignored otherwise. **Never set this in production** — see the
        warning on :class:`wg_manager.crypto.LocalDevBackend`.
    :cvar crypto_vault_addr: Vault listener URL. Also picks up the
        standard ``VAULT_ADDR`` env var for parity with the Vault CLI.
    :cvar crypto_vault_token: Vault auth token. Also picks up
        ``VAULT_TOKEN``. Phase 2e replaces this with AppRole credentials.
    :cvar crypto_vault_transit_key: Name of the Transit key used to wrap
        wg-manager secrets. Must be created with ``derived=true`` so the
        per-row context binding actually takes effect.
    :cvar crypto_vault_transit_mount: Mount path of the Transit engine.
    """

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False)

    database_url: str = "mysql+pymysql://wg:wg@localhost:3306/wg_manager"
    bind_host: str = "127.0.0.1"
    bind_port: int = 8000
    default_subnet: str = "10.9.0.0/24"
    default_wg_port: int = 51820
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/0"

    # ----- Encryption at rest (Phase 2b, see wg_manager.crypto) -----
    crypto_backend: str = "local"
    crypto_local_dev_key: str | None = None
    crypto_vault_addr: str = Field(
        default="http://127.0.0.1:8200",
        validation_alias=AliasChoices("CRYPTO_VAULT_ADDR", "VAULT_ADDR"),
    )
    crypto_vault_token: str | None = Field(
        default=None,
        validation_alias=AliasChoices("CRYPTO_VAULT_TOKEN", "VAULT_TOKEN"),
    )
    crypto_vault_transit_key: str = "wg-manager"
    crypto_vault_transit_mount: str = "transit"

    @field_validator("default_subnet")
    @classmethod
    def _validate_default_subnet(cls, value: str) -> str:
        """Reject malformed / too-narrow defaults from the environment.

        Delegates to :func:`wg_manager.schemas._parse_strict_subnet`. The
        import is inline because ``schemas`` itself imports from
        ``wg_manager.models``, and pulling that chain in at module top
        would create an import cycle.
        """
        from wg_manager.schemas import _parse_strict_subnet

        return str(_parse_strict_subnet(value))
    # Comma-separated list of origins permitted to call the API from a
    # browser. The shipped default covers Next.js dev (3000) and the
    # Vite/Vercel preview port (3001). Set ``CORS_ORIGINS`` to override —
    # use ``"*"`` to allow any origin (dev only; not safe for production).
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000,http://localhost:3001"


settings = Settings()
