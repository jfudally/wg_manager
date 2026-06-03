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
    :cvar ssh_ca_backend: Which SSH-CA backend
        :func:`wg_manager.ssh_ca.make_ssh_ca_backend` will return.
        One of ``"local"`` (in-process throwaway ed25519 CA, dev / tests
        only) or ``"vault"`` (Vault SSH secrets engine). Defaults to
        ``"local"`` so the test suite stays hermetic.
    :cvar ssh_ca_local_dev_pem: Optional PEM body of an ed25519 private
        key used as the CA when ``ssh_ca_backend == "local"``. When unset
        the backend generates an ephemeral CA at construction. **Never
        set this in production** — Phase 2c production is Vault.
    :cvar ssh_ca_vault_mount: Mount path of the Vault SSH secrets engine
        wg-manager talks to.
    :cvar ssh_ca_vault_user_role: Vault role name used for short-lived
        operator-facing user certificates (i.e. the certs the wg-manager
        worker presents when SSHing into managed hosts).
    :cvar ssh_ca_vault_host_role: Vault role name used for managed-host
        certificates installed on the remote sshd.
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

    # ----- SSH CA (Phase 2c, see wg_manager.ssh_ca) -----
    ssh_ca_backend: str = "local"
    ssh_ca_local_dev_pem: str | None = None
    ssh_ca_vault_mount: str = "ssh"
    ssh_ca_vault_user_role: str = "wg-manager-provision"
    ssh_ca_vault_host_role: str = "wg-manager-hosts"
    # Comma-separated principals the Vault user-cert role accepts. The
    # default covers the cloud-image accounts (``root``, ``ubuntu``,
    # ``ec2-user``, ``azureuser``, ``debian``, ``admin``) so the first
    # ``wg-manager ssh migrate-to-ca`` against a stock AMI/Azure image
    # works without re-bootstrapping the role. Production deployments
    # should tighten this to the specific accounts in use — feeds
    # straight into :meth:`wg_manager.ssh_ca.VaultSSHCA.bootstrap`'s
    # ``allowed_users`` kwarg via ``scripts/ssh_ca_bootstrap.py``.
    ssh_ca_vault_allowed_users: str = (
        "root,ubuntu,ec2-user,azureuser,debian,admin"
    )
    # Comma-separated list of domains the host-cert role accepts as
    # principals. Empty (the default) means "any principal" — see the
    # extended discussion on
    # :meth:`wg_manager.ssh_ca.VaultSSHCA.bootstrap`'s
    # ``allowed_host_domains`` kwarg. Set to a real domain list (e.g.
    # ``"prod.example.com"``) once the fleet has stable DNS.
    ssh_ca_vault_allowed_host_domains: str = ""
    # **Deprecated since Phase 2c CP4.1** — left in place so existing
    # ``.env`` files don't trip pydantic's ``extra='forbid'`` shape,
    # but the task layer no longer reads this. Routing is now driven
    # by :attr:`wg_manager.models.SSHKey.mode` on each individual row;
    # use ``wg-manager ssh migrate-to-ca <id>`` (Phase 2c CP4.2) to
    # flip a row from ``legacy`` to ``ca``. CP4.4 removes the setting
    # outright once every row in production is on ``mode='ca'``.
    ssh_auth_mode: str = "legacy"
    # TTL the task layer asks for when minting a user certificate.
    # 5 minutes is long enough for one provisioning round-trip and
    # short enough that a leaked cert dies on its own; the Vault role
    # bootstrap also caps ``max_ttl`` so the CA can't be coerced into
    # signing anything longer.
    ssh_user_cert_ttl_seconds: int = 300
    # TTL the host-cert install path asks the CA for. 24 h matches the
    # default Vault role bootstrap (see
    # :meth:`wg_manager.ssh_ca.VaultSSHCA.bootstrap`'s
    # ``host_default_ttl``); operators can dial this down for short-
    # lived prod environments and pair it with a more frequent run of
    # ``POST /servers/{id}/rotate-host-cert`` (Phase 2c CP3). Must be
    # ``<= max_ttl`` on the configured host role.
    ssh_host_cert_ttl_seconds: int = 86400

    # ----- PKI (Phase 2d, see wg_manager.pki) -----
    # Which X.509 backend :func:`wg_manager.pki.make_pki_backend`
    # returns. One of ``"local"`` (in-process root + intermediate
    # built on ``cryptography``, dev / tests only) or ``"vault"``
    # (Vault PKI secrets engine, production). Defaults to ``"local"``
    # so the test suite stays hermetic; the production deploy must
    # set this to ``"vault"`` explicitly. Mirrors the Phase 2b /
    # Phase 2c selector shapes.
    pki_backend: str = "local"
    # Optional PEM bodies for pinning the LocalDevPKI hierarchy across
    # process restarts. Without these, each process generates a fresh
    # root + intermediate; the API and the Celery worker therefore
    # mistrust each other's certs. Pin all four (or none) — partial
    # pins are rejected at backend construction. **Never set in
    # production** — Phase 2d production is Vault.
    pki_local_dev_root_pem: str | None = None
    pki_local_dev_root_key_pem: str | None = None
    pki_local_dev_int_pem: str | None = None
    pki_local_dev_int_key_pem: str | None = None
    # Vault PKI mount paths. The cookbook convention is ``pki`` for
    # the root (10y) and ``pki_int`` for the intermediate (1y); the
    # intermediate is the surface wg-manager issues leaves from so
    # the root key can stay offline in production.
    pki_vault_root_mount: str = "pki"
    pki_vault_int_mount: str = "pki_int"
    # Vault role names used when issuing leaf certs. The bootstrap
    # creates two: one with ``serverAuth`` for the API + MySQL
    # server cert, one with ``clientAuth`` for operator / CLI
    # client certs. Both live on the intermediate mount.
    pki_vault_server_role: str = "wg-manager-server"
    pki_vault_client_role: str = "wg-manager-client"
    # Comma-separated list of domains the Vault PKI roles accept.
    # Empty (the default) is interpreted by :meth:`VaultPKI.bootstrap`
    # as "any name" — appropriate for dev / IP-only fleets and the
    # ``make pki-bootstrap`` first run. Production deployments should
    # set this to the real domain list (e.g. ``"wg.local,vpn.example.com"``).
    pki_vault_allowed_domains: str = ""

    # ----- TLS / mTLS (Phase 2d CP2, see wg_manager.auth) -----
    # When ``True``, :class:`wg_manager.auth.MTLSAuthMiddleware` demands a
    # client certificate on every non-``OPTIONS`` request and 401s when
    # one isn't on the ASGI scope. Defaults to ``False`` so the test
    # suite (which uses :class:`starlette.testclient.TestClient` and
    # never speaks TLS) stays hermetic; **production must set this to
    # ``True``** — see ``.env.example``.
    tls_required: bool = False
    # PEM body path passed to uvicorn's ``--ssl-certfile``. Read by the
    # ``make run`` target; the application doesn't open the file
    # itself (uvicorn does at socket-bind time). ``None`` in dev /
    # tests; required in production when ``tls_required=True``.
    tls_cert_pem: str | None = None
    # PEM body path passed to uvicorn's ``--ssl-keyfile``. Pair with
    # :attr:`tls_cert_pem`; ``make run`` refuses to start without both.
    tls_key_pem: str | None = None
    # PEM body path passed to uvicorn's ``--ssl-ca-certs``. The trust
    # anchor uvicorn uses to verify the *client* cert (matched with
    # ``--ssl-cert-reqs 2``); usually the same bundle :class:`wg_manager.pki`
    # advertises via :attr:`PKIBackend.ca_bundle_pem`. Required in
    # production when ``tls_required=True`` so peers actually get
    # validated rather than waved through.
    tls_ca_bundle_pem: str | None = None

    # ----- Database TLS (Phase 2d CP4.1, see wg_manager.db) -----
    # When ``True`` and :attr:`database_url` resolves to a MySQL driver,
    # :func:`wg_manager.db._build_engine` injects a pymysql ``ssl`` dict
    # built from the three PEM paths below — the connection refuses to
    # open if any are missing or unreadable. Defaults to ``False`` so
    # SQLite-backed tests and pre-Phase-2d-CP4 deployments keep working
    # untouched. **Production must set this to ``True``** once CP4.2
    # ships the matching server-side ``require_secure_transport=ON``
    # config (see ``docs/migrations/2d-mysql-tls.md``).
    database_tls_required: bool = False
    # Path to the PEM bundle pymysql passes as ``ssl.ca`` — the trust
    # anchor it uses to verify the MySQL server certificate. Typically
    # the same CA bundle :class:`wg_manager.pki` advertises via
    # :attr:`PKIBackend.ca_bundle_pem`. Required when
    # ``database_tls_required=True``.
    database_tls_ca_pem: str | None = None
    # Path to the PEM body pymysql passes as ``ssl.cert`` — the client
    # certificate the app + worker present to MySQL for mutual
    # authentication. Mint with
    # ``wg-manager certs issue --type mysql --cn <operator-svc-CN>``.
    database_tls_cert_pem: str | None = None
    # Path to the private-key PEM pymysql passes as ``ssl.key``. Pair
    # with :attr:`database_tls_cert_pem`; required when
    # ``database_tls_required=True``.
    database_tls_key_pem: str | None = None

    # ----- Operator registry (Phase 2d CP3.2, see wg_manager.auth) -----
    # CN of the operator that the middleware self-registers the first
    # time it sees that CN on a request. Solves the chicken-and-egg
    # bootstrap: with mTLS enforced and the ``operator`` table empty,
    # there would otherwise be no way to add the first row through the
    # API. Set on a fresh install, unset (or rotate) once the row exists
    # and additional operators are added through the dashboard / CLI.
    # ``None`` (default) disables the self-register path — every unknown
    # CN is a 401.
    auth_bootstrap_operator_cn: str | None = None
    # Role assigned to the bootstrap operator at self-register time.
    # Defaults to ``admin`` because the bootstrap operator's whole
    # purpose is registry management (adding the rest of the team);
    # production deploys can pin a different value if the first cert
    # belongs to a service account that only needs read access. Stored
    # as the enum's string value so :class:`Settings` doesn't have to
    # import :class:`wg_manager.models.OperatorRole` (that import would
    # pull SQLModel into config-time evaluation, which the rest of
    # ``config.py`` is careful to avoid).
    auth_bootstrap_operator_role: str = "admin"

    # ----- Tracing (Phase 3a cycle 2, see wg_manager.tracing) -----
    # Which OTLP exporter to install at startup. ``none`` (default)
    # ships a NoOp tracer with zero overhead — wg-manager v0.1.0
    # operators who don't run a collector pay nothing. ``console``
    # prints finished spans to stderr (local dev). ``otlp-http``
    # POSTs to :attr:`otel_exporter_otlp_endpoint` — typically a
    # local collector that fans out to Jaeger / Tempo / Honeycomb.
    otel_exporter: str = "none"
    # OTLP/HTTP collector endpoint. Default matches the standard
    # OpenTelemetry collector port (``/v1/traces`` is appended by
    # the SDK).
    otel_exporter_otlp_endpoint: str = "http://localhost:4318"
    # Service name carried on every span. Pinned at module level so
    # all spans (API, worker, CLI) share one resource identity.
    otel_service_name: str = "wg-manager"

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
